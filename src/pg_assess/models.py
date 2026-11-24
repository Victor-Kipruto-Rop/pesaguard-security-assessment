from datetime import datetime, timezone
from enum import StrEnum
from pydantic import BaseModel, Field, HttpUrl

class Environment(StrEnum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"

class CheckName(StrEnum):
    HTTP_HEADERS = "http_headers"
    TLS = "tls"
    OPENAPI_EXPOSURE = "openapi_exposure"
    COOKIE_FLAGS = "cookie_flags"

class TargetAuthorization(BaseModel):
    target_id: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    base_url: HttpUrl
    environment: Environment
    owner: str = Field(min_length=3, max_length=160)
    authorization_reference: str = Field(min_length=3, max_length=200)
    approved_by: str = Field(min_length=3, max_length=160)
    approved_at: datetime
    expires_at: datetime
    allowed_checks: list[CheckName]
    approved_ip_addresses: list[str] = Field(default_factory=list, max_length=8)
    max_requests_per_minute: int = Field(default=10, ge=1, le=60)
    active: bool = True

    def is_current(self) -> bool:
        now = datetime.now(timezone.utc)
        if self.approved_at.tzinfo is None or self.expires_at.tzinfo is None:
            return False
        return self.active and self.approved_at <= now < self.expires_at

class Finding(BaseModel):
    check: str
    title: str
    severity: str
    confidence: str
    description: str
    evidence: dict[str, str] = Field(default_factory=dict)
    recommendation: str
    verified: bool = True

class AssessmentReport(BaseModel):
    assessment_id: str
    target_id: str
    target_url: str
    environment: Environment
    started_at: datetime
    completed_at: datetime
    status: str
    findings: list[Finding]
    checks_run: list[str]
    notes: list[str] = Field(default_factory=list)
