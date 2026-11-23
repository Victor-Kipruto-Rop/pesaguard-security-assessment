from datetime import datetime, timedelta, timezone
import pytest
from pg_assess.models import CheckName, Environment, TargetAuthorization
from pg_assess.policy import PolicyError, validate_target

def make_auth(**overrides):
    now = datetime.now(timezone.utc)
    data = dict(target_id="local-app", base_url="http://127.0.0.1:8000",
        environment=Environment.LOCAL, owner="PesaGuard engineering",
        authorization_reference="CHANGE-123", approved_by="system owner",
        approved_at=now-timedelta(minutes=1), expires_at=now+timedelta(hours=1),
        allowed_checks=[CheckName.HTTP_HEADERS], max_requests_per_minute=5)
    data.update(overrides)
    return TargetAuthorization(**data)

def test_accepts_authorized_loopback_target():
    validate_target(make_auth(), ["http_headers"])

def test_rejects_expired_authorization():
    auth = make_auth(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1))
    with pytest.raises(PolicyError):
        validate_target(auth, ["http_headers"])

def test_rejects_unapproved_check():
    with pytest.raises(PolicyError):
        validate_target(make_auth(), ["tls"])

def test_local_must_be_loopback():
    with pytest.raises(PolicyError):
        validate_target(make_auth(base_url="https://example.com"), ["http_headers"])

def test_production_is_blocked():
    auth = make_auth(environment=Environment.PRODUCTION, base_url="https://example.com")
    with pytest.raises(PolicyError):
        validate_target(auth, ["http_headers"])

def test_naive_timestamp_is_rejected():
    auth = make_auth(approved_at=datetime.now(), expires_at=datetime.now()+timedelta(hours=1))
    with pytest.raises(PolicyError):
        validate_target(auth, ["http_headers"])
