from fastapi.testclient import TestClient
from pg_assess.api import app

def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_assessment_requires_api_key():
    client = TestClient(app)
    response = client.post("/v1/assessments", json={})
    assert response.status_code == 401
