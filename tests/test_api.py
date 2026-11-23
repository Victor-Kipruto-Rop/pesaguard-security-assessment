from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from pg_assess.api import app
from pg_assess.config import settings

def payload():
    now = datetime.now(timezone.utc)
    return {"authorization": {
        "target_id": "local-api-test",
        "base_url": "http://127.0.0.1:8000",
        "environment": "local",
        "owner": "test owner",
        "authorization_reference": "TEST-001",
        "approved_by": "test approver",
        "approved_at": (now-timedelta(minutes=1)).isoformat(),
        "expires_at": (now+timedelta(hours=1)).isoformat(),
        "allowed_checks": ["http_headers"]
    }, "checks": ["http_headers"]}

def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_assessment_fails_closed_when_api_key_is_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "assessment_api_key", "")
    client = TestClient(app)
    response = client.post("/v1/assessments", json=payload())
    assert response.status_code == 503

def test_assessment_requires_valid_api_key(monkeypatch):
    monkeypatch.setattr(settings, "assessment_api_key", "a-strong-test-assessment-key-with-more-than-32-chars")
    client = TestClient(app)
    response = client.post("/v1/assessments", json=payload())
    assert response.status_code == 401
