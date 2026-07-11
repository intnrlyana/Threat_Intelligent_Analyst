from fastapi.testclient import TestClient

from backend.main import app


def test_health_returns_multi_provider_service_status() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "threat-intelligent-analyst"
    assert response.json()["mode"] == "multi_provider"


def test_readiness_reports_component_checks() -> None:
    response = TestClient(app).get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["prompt_guard"] is True
    assert body["checks"]["providers"]["mitre_attack"] is True
    assert {"entries", "hits", "misses", "ttl_seconds"} <= body["cache"].keys()
