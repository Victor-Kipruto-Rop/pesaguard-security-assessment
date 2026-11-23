from fastapi.testclient import TestClient
from pg_assess.api import app
from pg_assess.config import settings

def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_assessment_fails_closed_when_api_key_is_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "assessment_api_key", "")
    client = TestClient(app)
    response = client.post("/v1/assessments", json={})
    assert response.status_code == 503

def test_assessment_requires_valid_api_key(monkeypatch):
    monkeypatch.setattr(settings, "assessment_api_key", "a-strong-test-assessment-key-with-more-than-32-chars")
    client = TestClient(app)
    response = client.post("/v1/assessments", json={})
    assert response.status_code == 401
