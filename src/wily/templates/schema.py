"""pydantic schema for validating YAML rules before they are executed.

Fields beyond the classic (Nuclei-style) rule shape:
  authorization.mode                 : passive | active | destructive
  authorization.requires_tenant_pair : bool  (for modules like BOLA)
  authorization.requires_owned_infra : bool  (for modules like IMDS SSRF)
"""

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"  # always excluded from an ordinary scan


class Authorization(BaseModel):
    mode: AuthorizationMode = AuthorizationMode.PASSIVE
    requires_tenant_pair: bool = False
    requires_owned_infra: bool = False


class TemplateInfo(BaseModel):
    name: str
    severity: Severity
    category: str
    description: str | None = None


class RuleRequest(BaseModel):
    method: str
    path: str
    headers: dict[str, str] | None = None
    body: str | None = None


class RuleMatcher(BaseModel):
    type: str  # status | word | regex | dsl
    # TODO: extra fields depending on type (words, regex, dsl, part, condition...)


class Template(BaseModel):
    id: str
    info: TemplateInfo
    asset_type: str = Field(alias="asset-type")
    authorization: Authorization = Authorization()
    request: list[RuleRequest]
    matchers: list[RuleMatcher]
    matchers_condition: str = Field(default="and", alias="matchers-condition")
    evidence: list[str] = []
    remediation: str | None = None

    class Config:
        populate_by_name = True
