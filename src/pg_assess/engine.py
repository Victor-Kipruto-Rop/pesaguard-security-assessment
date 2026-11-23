from datetime import datetime, timezone
from uuid import uuid4
import ssl
import socket
from urllib.parse import urlparse
from .config import settings
from .models import AssessmentReport, CheckName, Finding, TargetAuthorization
from .policy import validate_target
from .scanners.http import run_http_checks, run_openapi_check

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
        findings.append(_tls_check(auth))
    return AssessmentReport(assessment_id=str(uuid4()), target_id=auth.target_id,
        target_url=str(auth.base_url), environment=auth.environment, started_at=started,
        completed_at=datetime.now(timezone.utc), status="completed", findings=findings,
        checks_run=names, notes=["Non-destructive checks only; owner review is required."])

def _tls_check(auth: TargetAuthorization) -> Finding:
    parsed = urlparse(str(auth.base_url))
    host, port = parsed.hostname, parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=settings.http_timeout_seconds) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                version = sock.version() or "unknown"
                cert = sock.getpeercert()
        return Finding(check="tls", title="TLS certificate validation succeeded",
            severity="info", confidence="high",
            description="The platform trust store accepted the presented certificate.",
            evidence={"tls_version": version, "certificate_subject_present": str(bool(cert.get("subject")))},
            recommendation="Maintain certificate renewal monitoring and modern TLS configuration.")
    except (OSError, ssl.SSLError, ValueError) as exc:
        return Finding(check="tls", title="TLS validation failed", severity="high",
            confidence="high", description="TLS handshake or certificate validation failed.",
            evidence={"error_type": type(exc).__name__},
            recommendation="Inspect certificate chain, hostname coverage, expiry, and supported TLS versions.")
