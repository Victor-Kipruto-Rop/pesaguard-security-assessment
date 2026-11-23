from datetime import datetime, timedelta, timezone
from pg_assess.models import CheckName, Environment, TargetAuthorization
from pg_assess.scanners.http import run_tls_check

def test_tls_check_does_not_attempt_tls_for_local_http():
    now = datetime.now(timezone.utc)
    auth = TargetAuthorization(
        target_id="local-http",
        base_url="http://127.0.0.1:8000",
        environment=Environment.LOCAL,
        owner="test owner",
        authorization_reference="TEST-HTTP",
        approved_by="test approver",
        approved_at=now-timedelta(minutes=1),
        expires_at=now+timedelta(hours=1),
        allowed_checks=[CheckName.TLS],
    )
    finding = run_tls_check(auth, 1)
    assert finding.severity == "info"
    assert "not applicable" in finding.title.lower()
