from datetime import datetime, timezone
from uuid import uuid4
from .config import settings
from .models import AssessmentReport, CheckName, Finding, TargetAuthorization
from .policy import validate_target
from .scanners.http import run_http_checks, run_openapi_check, run_tls_check

async def assess(auth: TargetAuthorization, requested_checks: list[CheckName]) -> AssessmentReport:
    names = [c.value for c in requested_checks]
    validate_target(auth, names)
    started = datetime.now(timezone.utc)
    findings: list[Finding] = []
    if CheckName.HTTP_HEADERS in requested_checks or CheckName.COOKIE_FLAGS in requested_checks:
        http_findings = await run_http_checks(auth, settings.http_timeout_seconds, settings.user_agent)
        if CheckName.HTTP_HEADERS not in requested_checks:
            http_findings = [item for item in http_findings if item.check == CheckName.COOKIE_FLAGS.value]
        if CheckName.COOKIE_FLAGS not in requested_checks:
            http_findings = [item for item in http_findings if item.check != CheckName.COOKIE_FLAGS.value]
        findings.extend(http_findings)
    if CheckName.OPENAPI_EXPOSURE in requested_checks:
        findings.extend(await run_openapi_check(auth, settings.http_timeout_seconds, settings.user_agent))
    if CheckName.TLS in requested_checks:
        findings.append(run_tls_check(auth, settings.http_timeout_seconds))
    return AssessmentReport(assessment_id=str(uuid4()), target_id=auth.target_id,
        target_url=str(auth.base_url), environment=auth.environment, started_at=started,
        completed_at=datetime.now(timezone.utc), status="completed", findings=findings,
        checks_run=names, notes=["Non-destructive checks only; owner review is required."])

