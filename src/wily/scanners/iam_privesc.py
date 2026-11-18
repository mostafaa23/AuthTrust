"""IAM over-privilege / privilege-escalation path finder.

Unlike every other scanner, makes no HTTP requests: the input is the JSON
output of ``aws iam get-account-authorization-details`` (a single
read-only call), loaded into dataclasses and built into a permission graph
(``build_privesc_graph``) that ``find_privesc_paths`` walks for known
escalation edges (self-mutation, PassRole chains, trust-policy abuse,
resource hijacks).

Scope: identity-to-identity edges only - resource-based policies (S3/KMS
bucket and key policies) are not modeled, and Explicit Deny/SCPs/
Permissions Boundaries are not yet applied, so an edge is "possible", not
confirmed-effective.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from wily.core.scope_manager import account_in_scope
from wily.scanners.base import Finding

# --- IAM Self-Mutation: the first 8 of Rhino Security Labs' 21 methods ---
SELF_MUTATION_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AddUserToGroup",
}

# --- PassRole + Service: the second full category (6 documented methods
# from Rhino Security Labs' list of 21). Each key is the service name
# used in service_principal (f"{key}.amazonaws.com", or an explicit
# override). ---
PASS_ROLE_SERVICE_COMBOS = {
    "lambda": {"lambda:CreateFunction", "lambda:InvokeFunction"},
    "ec2": {"ec2:RunInstances"},
    # glue:CreateDevEndpoint is Rhino Security Labs' actual documented Glue
    # method (#19); CreateJob/StartJobRun is an equally valid PassRole sink
    # for a Glue job role - keep both so detection stays broad.
    "glue": {"glue:CreateJob", "glue:StartJobRun", "glue:CreateDevEndpoint"},
    "ecs": {"ecs:RegisterTaskDefinition", "ecs:RunTask"},
    "cloudformation": {"cloudformation:CreateStack"},
    "datapipeline": {"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"},
    # Rhino #27: pass a role to a new SageMaker notebook, then open it.
    "sagemaker": {"sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"},
    # Rhino #24: pass a role to a new CodeStar project.
    "codestar": {"codestar:CreateProject"},
}

# Some services use a service principal different from the default
# "{service}.amazonaws.com" (e.g. ECS task execution uses
# ecs-tasks.amazonaws.com, not ecs.amazonaws.com).
SERVICE_PRINCIPAL_OVERRIDES = {
    "ecs": "ecs-tasks.amazonaws.com",
}

# --- Trust-Policy Abuse (Rhino Security Labs method #14): rewrite a
# role's AssumeRolePolicyDocument so it trusts you, then assume it. Needs
# BOTH actions together (editing the trust alone is useless without being
# able to call sts:AssumeRole afterwards), so this is detected as a combo
# rather than a single self-mutation action. ---
TRUST_POLICY_ABUSE_ACTIONS = {"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"}

# --- Resource Hijack: a SINGLE permission that lets a principal take over
# an existing service resource and inherit the (possibly far more
# powerful) role already attached to it - no iam:PassRole required. Each
# key is the AWS action detection keys on; the value is the technique slug
# used in the category/evidence. Covers Rhino Security Labs methods #18,
# #26, #20, #28 and #23. ---
RESOURCE_HIJACK_ACTIONS = {
    "lambda:UpdateFunctionCode": "lambda_update_code",
    "lambda:UpdateFunctionConfiguration": "lambda_update_config",
    "glue:UpdateDevEndpoint": "glue_update_dev_endpoint",
    "sagemaker:CreatePresignedNotebookInstanceUrl": "sagemaker_notebook_url",
    "codestar:CreateProjectFromTemplate": "codestar_create_from_template",
}


# ---------------------------------------------------------------------------
# IAM Collector + Policy Parser (dataclasses holding the parsed JSON)
# ---------------------------------------------------------------------------


@dataclass
class PolicyStatement:
    effect: str
    actions: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyStatement":
        actions = data.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = data.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        return cls(
            effect=data.get("Effect", "Deny"),
            actions=set(actions),
            resources=set(resources),
        )


@dataclass
class Principal:
    """A single IAM User or Role, with every action it is allowed to
    perform (across all attached policies - inline + managed) flattened
    into one set. v0.1: assumes Allow with no opposing Deny (TODO v0.2)."""

    arn: str
    name: str
    principal_type: str  # "user" | "role"
    allowed_actions: set[str] = field(default_factory=set)
    # If this is a role, who can assume it (trust policy) - names/ARNs.
    assumable_by: set[str] = field(default_factory=set)

    def can(self, action: str) -> bool:
        if action in self.allowed_actions:
            return True
        # Simple wildcard support (iam:* covers iam:PassRole, and so on).
        service_wildcard = action.split(":")[0] + ":*"
        return service_wildcard in self.allowed_actions or "*" in self.allowed_actions


def _collect_statements(policy_document: dict) -> list[PolicyStatement]:
    stmts = policy_document.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [PolicyStatement.from_dict(s) for s in stmts]


def _default_version_document(policy: dict) -> dict:
    """Return the Document of a managed policy's default version, or {}
    if it has none (malformed export, or the version list was omitted)."""
    for version in policy.get("PolicyVersionList", []):
        if version.get("IsDefaultVersion"):
            return version.get("Document", {}) or {}
    return {}


def _build_managed_policy_index(data: dict) -> dict[str, dict]:
    """Map every managed policy's ARN to its default version's document,
    from the top-level "Policies" list that
    `aws iam get-account-authorization-details` includes alongside the
    per-principal AttachedManagedPolicies references."""
    index: dict[str, dict] = {}
    for policy in data.get("Policies", []):
        arn = policy.get("Arn")
        if not arn:
            continue
        index[arn] = _default_version_document(policy)
    return index


def _allowed_actions_from_managed_policies(
    attached: list[dict], managed_policy_index: dict[str, dict]
) -> set[str]:
    """Resolve a principal's AttachedManagedPolicies references
    (name + ARN pairs) against the managed-policy index built above, and
    return the union of every Allow action across them.

    Without this, a principal whose privilege-escalation path comes
    entirely from an attached AWS-managed or customer-managed policy
    (rather than an inline one) would be invisible to the graph - a real
    gap, since attached managed policies are at least as common as
    inline ones in real AWS accounts.
    """
    actions: set[str] = set()
    for ref in attached:
        arn = ref.get("PolicyArn")
        document = managed_policy_index.get(arn)
        if not document:
            continue
        for stmt in _collect_statements(document):
            if stmt.effect == "Allow":
                actions |= stmt.actions
    return actions


def load_authorization_details(path: Path) -> list[Principal]:
    """Load the output of `aws iam get-account-authorization-details` and
    turn it into a list of Principal, each with every action it is
    allowed to perform (inline + attached managed policies) flattened
    into one set."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    managed_policy_index = _build_managed_policy_index(data)
    principals: list[Principal] = []

    for user in data.get("UserDetailList", []):
        actions: set[str] = set()
        for pol in user.get("UserPolicyList", []):
            for stmt in _collect_statements(pol.get("PolicyDocument", {})):
                if stmt.effect == "Allow":
                    actions |= stmt.actions
        actions |= _allowed_actions_from_managed_policies(
            user.get("AttachedManagedPolicies", []), managed_policy_index
        )
        principals.append(
            Principal(
                arn=user["Arn"],
                name=user["UserName"],
                principal_type="user",
                allowed_actions=actions,
            )
        )

    for role in data.get("RoleDetailList", []):
        actions = set()
        for pol in role.get("RolePolicyList", []):
            for stmt in _collect_statements(pol.get("PolicyDocument", {})):
                if stmt.effect == "Allow":
                    actions |= stmt.actions
        actions |= _allowed_actions_from_managed_policies(
            role.get("AttachedManagedPolicies", []), managed_policy_index
        )
        assumable_by: set[str] = set()
        trust_doc = role.get("AssumeRolePolicyDocument", {})
        for stmt in trust_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal_block = stmt.get("Principal", {})
            if isinstance(principal_block, dict):
                for v in principal_block.values():
                    if isinstance(v, list):
                        assumable_by.update(v)
                    elif isinstance(v, str):
                        assumable_by.add(v)
        principals.append(
            Principal(
                arn=role["Arn"],
                name=role["RoleName"],
                principal_type="role",
                allowed_actions=actions,
                assumable_by=assumable_by,
            )
        )

    return principals


def filter_principals_in_scope(
    principals: list[Principal], scope
) -> list[Principal]:
    """Drop principals whose AWS account is outside the configured scope.

    ``scope`` may be a :class:`~wily.core.scope_manager.ScopeManager` (anything
    exposing ``is_account_in_scope``) or a plain iterable of account ids / ARN
    prefixes. The IAM analyzer makes no HTTP requests, so this is the guard
    that keeps it from reasoning about a *third-party* account that happened to
    appear in an exported ``get-account-authorization-details`` file. With no
    account scope configured (the common case - the user exported their own
    account) nothing is filtered out.
    """
    check = getattr(scope, "is_account_in_scope", None)
    if check is None:
        accounts = tuple(scope or ())
        if not accounts:
            return principals

        def check(arn: str) -> bool:
            return account_in_scope(arn, accounts)
    elif not getattr(scope, "has_account_scope", True):
        return principals
    return [p for p in principals if check(p.arn)]


# ---------------------------------------------------------------------------
# Permission Graph Engine
# ---------------------------------------------------------------------------


def build_privesc_graph(principals: list[Principal]) -> nx.DiGraph:
    """Build a directed graph: node = ARN, edge = "this can reach that",
    labeled with the method (self_mutation | pass_role_lambda |
    pass_role_ec2 | sts_assume_role). Like PMapper: identity-to-identity
    edges only in v0.1."""
    graph = nx.DiGraph()

    for p in principals:
        graph.add_node(p.arn, name=p.name, principal_type=p.principal_type)

    for p in principals:
        # --- IAM Self-Mutation: if it has any action from the list, it
        # can expand its own privileges - a self-loop edge for
        # self-escalation. ---
        self_mutation_hits = p.allowed_actions & SELF_MUTATION_ACTIONS
        if self_mutation_hits:
            graph.add_edge(
                p.arn, p.arn,
                method="self_mutation",
                evidence_actions=sorted(self_mutation_hits),
            )

        # A full-wildcard ("*") principal is already an admin - every edge
        # below would be a true-but-useless admin-to-admin escalation (a
        # known source of noise in PMapper/Cloudsplaining), so stop here.
        # (self_mutation above intentionally uses literal set membership,
        # so "*" never triggers it.)
        if "*" in p.allowed_actions:
            continue

        # --- Trust-Policy Abuse (self-loop): rewrite a role's trust to
        # trust yourself, then assume it. Both actions required. ---
        if TRUST_POLICY_ABUSE_ACTIONS <= p.allowed_actions or all(
            p.can(a) for a in TRUST_POLICY_ABUSE_ACTIONS
        ):
            graph.add_edge(
                p.arn, p.arn,
                method="assume_role_policy_update",
                evidence_actions=sorted(TRUST_POLICY_ABUSE_ACTIONS),
            )

        # --- Resource Hijack (self-loop): a single permission that takes
        # over an existing Lambda / Glue dev-endpoint / SageMaker notebook
        # / CodeStar project and the role already attached to it. ---
        for action, technique in RESOURCE_HIJACK_ACTIONS.items():
            if p.can(action):
                graph.add_edge(
                    p.arn, p.arn,
                    method=f"resource_hijack_{technique}",
                    evidence_actions=[action],
                )

        # --- PassRole + Service: if it has PassRole plus any other
        # combo, it can reach any role whose trust policy lets that
        # service assume it. ---
        if not p.can("iam:PassRole"):
            continue

        for service, required_actions in PASS_ROLE_SERVICE_COMBOS.items():
            if not (required_actions & p.allowed_actions or
                    any(p.can(a) for a in required_actions)):
                continue
            service_principal = SERVICE_PRINCIPAL_OVERRIDES.get(
                service, f"{service}.amazonaws.com"
            )
            for target in principals:
                if target.principal_type != "role":
                    continue
                if target.arn == p.arn:
                    continue  # passing a role to itself isn't a real escalation - noise
                if service_principal not in target.assumable_by:
                    continue
                graph.add_edge(
                    p.arn, target.arn,
                    method=f"pass_role_{service}",
                    evidence_actions=sorted(
                        {"iam:PassRole"} | (required_actions & p.allowed_actions)
                    ),
                )

    return graph


# ---------------------------------------------------------------------------
# Privilege Escalation Analyzer
# ---------------------------------------------------------------------------

_METHOD_SEVERITY = {
    "self_mutation": "critical",
    "assume_role_policy_update": "critical",
    "pass_role_lambda": "critical",
    "pass_role_ec2": "critical",
    "pass_role_glue": "critical",
    "pass_role_ecs": "critical",
    "pass_role_cloudformation": "critical",
    "pass_role_sagemaker": "critical",
    "pass_role_datapipeline": "high",
    "pass_role_codestar": "high",
    "resource_hijack_lambda_update_code": "critical",
    "resource_hijack_lambda_update_config": "high",
    "resource_hijack_glue_update_dev_endpoint": "high",
    "resource_hijack_sagemaker_notebook_url": "high",
    "resource_hijack_codestar_create_from_template": "high",
}

_METHOD_REMEDIATION = {
    "self_mutation": (
        "Remove permissions that let the user/role modify its own "
        "permissions (iam:PutUserPolicy, iam:AttachUserPolicy, ...) - any "
        "IAM change must go through a separate, higher-privilege path, "
        "never self-service."
    ),
    "pass_role_lambda": (
        "Restrict iam:PassRole with a Condition (iam:PassedToService) that "
        "scopes it to the required service only, and attach fewer "
        "permissions (not AdministratorAccess) to the target role."
    ),
    "pass_role_ec2": (
        "Same recommendation as Lambda - restrict iam:PassRole with a "
        "Condition, and reduce the target instance role's permissions."
    ),
    "assume_role_policy_update": (
        "Remove iam:UpdateAssumeRolePolicy from this principal (or scope it "
        "with a Resource/Condition) - the ability to rewrite a role's trust "
        "policy plus sts:AssumeRole lets it grant itself any role."
    ),
    "resource_hijack_lambda_update_code": (
        "lambda:UpdateFunctionCode lets this principal overwrite an existing "
        "function's code and run it under that function's execution role. "
        "Scope the action by Resource and separate deploy from runtime roles."
    ),
    "resource_hijack_lambda_update_config": (
        "lambda:UpdateFunctionConfiguration lets this principal attach a "
        "malicious layer to an existing function and inherit its role. Scope "
        "the action by Resource."
    ),
    "resource_hijack_glue_update_dev_endpoint": (
        "glue:UpdateDevEndpoint lets this principal change an existing Glue "
        "dev endpoint and run code under its role. Scope the action by "
        "Resource."
    ),
    "resource_hijack_sagemaker_notebook_url": (
        "sagemaker:CreatePresignedNotebookInstanceUrl grants shell access to "
        "an existing SageMaker notebook under its attached role. Scope the "
        "action by Resource and limit who holds it."
    ),
    "resource_hijack_codestar_create_from_template": (
        "codestar:CreateProjectFromTemplate can provision resources under a "
        "CodeStar service role more privileged than the caller. Remove or "
        "tightly scope this permission."
    ),
}


def find_privesc_paths(graph: nx.DiGraph, principals: list[Principal]) -> list[Finding]:
    """Walk every edge in the graph (each one already represents a
    discovered escalation method) and turn it into a Finding. v0.1: one
    edge = one finding (multi-hop path-finding is not implemented yet -
    TODO v0.2)."""
    by_arn = {p.arn: p for p in principals}
    findings: list[Finding] = []

    for source, target, data in graph.edges(data=True):
        method = data["method"]
        source_p = by_arn[source]
        target_p = by_arn.get(target)

        if method == "self_mutation":
            findings.append(
                Finding(
                    asset=source,
                    category="iam-privesc-self-mutation",
                    severity=_METHOD_SEVERITY[method],
                    confidence=0.85,
                    discovery_source="scanner",
                    evidence={
                        "technique": method,
                        "principal": source_p.name,
                        "principal_type": source_p.principal_type,
                        "evidence_actions": data["evidence_actions"],
                        "caveat": (
                            "v0.1: Explicit Deny/SCP/Permissions Boundary have "
                            "not been checked yet - review manually before "
                            "remediating."
                        ),
                    },
                    remediation=_METHOD_REMEDIATION[method],
                )
            )
        elif method == "assume_role_policy_update" or method.startswith("resource_hijack_"):
            # Self-loop escalations with no distinct target principal (the
            # victim is a role's trust policy or a hijacked service
            # resource), so they share the self_mutation finding shape but
            # keep their own category/technique.
            findings.append(
                Finding(
                    asset=source,
                    category=f"iam-privesc-{method}",
                    severity=_METHOD_SEVERITY.get(method, "high"),
                    confidence=0.8,
                    discovery_source="scanner",
                    evidence={
                        "technique": method,
                        "principal": source_p.name,
                        "principal_type": source_p.principal_type,
                        "evidence_actions": data["evidence_actions"],
                        "caveat": (
                            "v0.1: Explicit Deny/SCP/Permissions Boundary have "
                            "not been checked yet - review manually before "
                            "remediating."
                        ),
                    },
                    remediation=_METHOD_REMEDIATION.get(
                        method, "Review and scope this principal's IAM permissions."
                    ),
                )
            )
        elif method.startswith("pass_role_"):
            findings.append(
                Finding(
                    asset=source,
                    category=f"iam-privesc-{method}",
                    severity=_METHOD_SEVERITY.get(method, "high"),
                    confidence=0.8,
                    discovery_source="scanner",
                    evidence={
                        "technique": method,
                        "principal": source_p.name,
                        "target_role": target_p.name if target_p else target,
                        "target_role_actions": sorted(target_p.allowed_actions) if target_p else [],
                        "evidence_actions": data["evidence_actions"],
                        "caveat": (
                            "v0.1: Explicit Deny/SCP/Permissions Boundary have "
                            "not been checked yet - review manually before "
                            "remediating."
                        ),
                    },
                    remediation=_METHOD_REMEDIATION.get(method, "Review PassRole permissions."),
                )
            )

    return findings
