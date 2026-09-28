import asyncio
import json
from pathlib import Path

import httpx

from reprise.api import app

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/fixtures/alternate-path.json"


def request(method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_health_is_explicitly_local_and_read_only():
    response = request("GET", "/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "read-only-replay"
    assert response.headers["x-reprise-mode"] == "read-only-replay"


def test_capabilities_expose_no_mutation_endpoint():
    response = request("GET", "/v1/capabilities")
    assert response.status_code == 200
    assert response.json()["mutation_endpoints"] == []
    assert response.json()["live_kubernetes"] is False


def test_replay_returns_validated_evidence_package():
    payload = EXAMPLE.read_bytes()
    response = request(
        "POST",
        "/v1/replay",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200
    package = response.json()
    assert package["package_type"] == "reprise_incident_evidence"
    assert len(package["findings"]) == 1
    assert len(package["findings"][0]["candidate_proposals"]) == 2


def test_replay_rejects_sensitive_fixture_fields():
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["audit_events"][0]["requestObject"] = {"metadata": {"data": "nope"}}
    response = request(
        "POST",
        "/v1/replay",
        json=raw,
    )
    assert response.status_code == 422
    assert "sensitive field" in response.json()["detail"]


def test_replay_rejects_wrong_content_type():
    response = request(
        "POST",
        "/v1/replay",
        content=EXAMPLE.read_bytes(),
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 415


def test_replay_rejects_oversized_body():
    response = request(
        "POST",
        "/v1/replay",
        content=b"{" + b"x" * 1_000_001,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_no_mutation_route_is_exposed():
    response = request("POST", "/v1/execute", json={"action": "delete_role_binding"})
    assert response.status_code == 404
