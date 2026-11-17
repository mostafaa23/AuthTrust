"""IAM privilege-escalation scanner: analysis-only, no AWS calls.

Every fixture here is a synthetic `aws iam get-account-authorization-details`
document (fake account id 111111111111, no real ARNs/secrets). The tests drive
the real pipeline end to end: load_authorization_details -> build_privesc_graph
-> find_privesc_paths, asserting that each enriched technique fires on the AWS
action it keys on, that benign look-alikes do NOT fire, and that malformed /
missing metadata is tolerated rather than crashing.
"""

from __future__ import annotations

import json

from wily.scanners.iam_privesc import (
    build_privesc_graph,
    find_privesc_paths,
    load_authorization_details,
)

_ACCT = "111111111111"


def _user(name: str, actions: list[str]) -> dict:
    return {
        "UserName": name,
        "Arn": f"arn:aws:iam::{_ACCT}:user/{name}",
        "UserPolicyList": [
            {
                "PolicyName": f"{name}Inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": actions, "Resource": "*"}
                    ],
                },
            }
        ],
        "AttachedManagedPolicies": [],
    }


def _role(name: str, service_principal: str, actions: list[str] | None = None) -> dict:
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{_ACCT}:role/{name}",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service_principal},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "RolePolicyList": [
            {
                "PolicyName": f"{name}Inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": actions or ["*"], "Resource": "*"}
                    ],
                },
            }
        ],
    }


def _run(tmp_path, doc: dict):
    path = tmp_path / "authz.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    principals = load_authorization_details(path)
    graph = build_privesc_graph(principals)
    return find_privesc_paths(graph, principals)


def _categories(findings) -> set[str]:
    return {f.category for f in findings}


# --------------------------------------------------------------------------
# Trust-policy abuse (Rhino #14)
# --------------------------------------------------------------------------


def test_trust_policy_abuse_fires_with_both_actions(tmp_path):
    doc = {
        "UserDetailList": [
            _user("Trustee", ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"])
        ],
        "RoleDetailList": [],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-assume_role_policy_update" in _categories(findings)
    hit = next(f for f in findings if f.category == "iam-privesc-assume_role_policy_update")
    assert hit.severity == "critical"
    assert set(hit.evidence["evidence_actions"]) == {
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
    }


def test_trust_policy_abuse_requires_both_actions(tmp_path):
    # UpdateAssumeRolePolicy alone (no sts:AssumeRole) must NOT fire.
    doc = {
        "UserDetailList": [_user("HalfTrustee", ["iam:UpdateAssumeRolePolicy"])],
        "RoleDetailList": [],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-assume_role_policy_update" not in _categories(findings)


# --------------------------------------------------------------------------
# Resource hijack (single permission, no PassRole) - Rhino #18/#26/#20/#28/#23
# --------------------------------------------------------------------------


def test_resource_hijack_lambda_update_code(tmp_path):
    doc = {
        "UserDetailList": [_user("LambdaDev", ["lambda:UpdateFunctionCode"])],
        "RoleDetailList": [],
    }
    findings = _run(tmp_path, doc)
    cat = "iam-privesc-resource_hijack_lambda_update_code"
    assert cat in _categories(findings)
    assert next(f for f in findings if f.category == cat).severity == "critical"


def test_resource_hijack_covers_all_single_permission_techniques(tmp_path):
    cases = {
        "lambda:UpdateFunctionConfiguration": "iam-privesc-resource_hijack_lambda_update_config",
        "glue:UpdateDevEndpoint": "iam-privesc-resource_hijack_glue_update_dev_endpoint",
        "sagemaker:CreatePresignedNotebookInstanceUrl": "iam-privesc-resource_hijack_sagemaker_notebook_url",
        "codestar:CreateProjectFromTemplate": "iam-privesc-resource_hijack_codestar_create_from_template",
    }
    for action, expected_cat in cases.items():
        doc = {
            "UserDetailList": [_user("Hijacker", [action])],
            "RoleDetailList": [],
        }
        findings = _run(tmp_path, doc)
        assert expected_cat in _categories(findings), action


def test_resource_hijack_benign_permission_does_not_fire(tmp_path):
    # Read-only lambda/sagemaker permissions must not look like a hijack.
    doc = {
        "UserDetailList": [
            _user("ReadOnly", ["lambda:GetFunction", "sagemaker:DescribeNotebookInstance"])
        ],
        "RoleDetailList": [],
    }
    findings = _run(tmp_path, doc)
    assert findings == []


# --------------------------------------------------------------------------
# New PassRole combos: SageMaker (#27), CodeStar (#24), Glue CreateDevEndpoint (#19)
# --------------------------------------------------------------------------


def test_pass_role_sagemaker(tmp_path):
    doc = {
        "UserDetailList": [
            _user(
                "MlUser",
                [
                    "iam:PassRole",
                    "sagemaker:CreateNotebookInstance",
                    "sagemaker:CreatePresignedNotebookInstanceUrl",
                ],
            )
        ],
        "RoleDetailList": [_role("SageMakerAdminRole", "sagemaker.amazonaws.com")],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-pass_role_sagemaker" in _categories(findings)


def test_pass_role_codestar(tmp_path):
    doc = {
        "UserDetailList": [_user("CsUser", ["iam:PassRole", "codestar:CreateProject"])],
        "RoleDetailList": [_role("CodeStarRole", "codestar.amazonaws.com")],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-pass_role_codestar" in _categories(findings)


def test_pass_role_glue_create_dev_endpoint(tmp_path):
    doc = {
        "UserDetailList": [
            _user("GlueDev", ["iam:PassRole", "glue:CreateDevEndpoint"])
        ],
        "RoleDetailList": [_role("GlueRole", "glue.amazonaws.com")],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-pass_role_glue" in _categories(findings)


def test_pass_role_without_matching_trust_does_not_fire(tmp_path):
    # Has PassRole + sagemaker actions, but the only role trusts ec2, not
    # sagemaker -> no reachable target -> no finding.
    doc = {
        "UserDetailList": [
            _user(
                "MlUser",
                ["iam:PassRole", "sagemaker:CreateNotebookInstance",
                 "sagemaker:CreatePresignedNotebookInstanceUrl"],
            )
        ],
        "RoleDetailList": [_role("Ec2Role", "ec2.amazonaws.com")],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-pass_role_sagemaker" not in _categories(findings)


# --------------------------------------------------------------------------
# Regression: existing techniques still fire; admins stay quiet
# --------------------------------------------------------------------------


def test_existing_self_mutation_still_fires(tmp_path):
    doc = {
        "UserDetailList": [_user("Mutator", ["s3:GetObject", "iam:PutUserPolicy"])],
        "RoleDetailList": [],
    }
    findings = _run(tmp_path, doc)
    assert "iam-privesc-self-mutation" in _categories(findings)


def test_full_wildcard_admin_does_not_report_new_techniques(tmp_path):
    # A "*" admin is already at the top - trust-policy / resource-hijack
    # edges below the admin short-circuit must not fire.
    doc = {
        "UserDetailList": [_user("Admin", ["*"])],
        "RoleDetailList": [],
    }
    findings = _run(tmp_path, doc)
    assert findings == []


# --------------------------------------------------------------------------
# Malformed / missing metadata is tolerated
# --------------------------------------------------------------------------


def test_missing_role_metadata_does_not_crash(tmp_path):
    # Role with no AssumeRolePolicyDocument and no RolePolicyList.
    doc = {
        "UserDetailList": [],
        "RoleDetailList": [
            {"RoleName": "Bare", "Arn": f"arn:aws:iam::{_ACCT}:role/Bare"}
        ],
    }
    findings = _run(tmp_path, doc)
    assert findings == []


def test_empty_document_yields_no_findings(tmp_path):
    findings = _run(tmp_path, {})
    assert findings == []
