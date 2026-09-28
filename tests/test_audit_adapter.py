import json

import pytest

from reprise.audit_adapter import AuditAdapterError, merge_audit_events, parse_audit_jsonl
from reprise.fixture import load_fixture
from reprise.report import build_evidence_package


def audit_line(audit_id="audit-1", name="synthetic-canary", **extra):
    event = {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "stageTimestamp": "2026-09-28T08:00:00Z",
        "verb": "get",
        "user": {"username": "system:serviceaccount:reprise-demo:preview-bot"},
        "objectRef": {
            "apiGroup": "",
            "resource": "secrets",
            "namespace": "reprise-demo",
            "name": name,
        },
        "responseStatus": {"code": 200},
    }
    event.update(extra)
    return json.dumps(event).encode("utf-8")


def test_normalizes_metadata_level_kubernetes_event():
    events = parse_audit_jsonl(audit_line())

    assert events == [
        {
            "audit_id": "audit-1",
            "stage": "ResponseComplete",
            "stage_timestamp": "2026-09-28T08:00:00Z",
            "verb": "get",
            "user": {"username": "system:serviceaccount:reprise-demo:preview-bot"},
            "object_ref": {
                "api_group": "",
                "resource": "secrets",
                "namespace": "reprise-demo",
                "name": "synthetic-canary",
            },
            "response_code": 200,
        }
    ]


def test_falls_back_to_request_received_timestamp():
    event = json.loads(audit_line())
    event.pop("stageTimestamp")
    event["requestReceivedTimestamp"] = "2026-09-28T08:00:00Z"
    normalized = parse_audit_jsonl(json.dumps(event).encode())[0]
    assert normalized["stage_timestamp"] == "2026-09-28T08:00:00Z"


@pytest.mark.parametrize("field", ["requestObject", "responseObject", "requestObjectRaw", "data"])
def test_rejects_bodies_and_secret_data(field):
    event = json.loads(audit_line())
    event[field] = {"value": "must-not-enter-reprise"}
    with pytest.raises(AuditAdapterError, match="must not contain"):
        parse_audit_jsonl(json.dumps(event).encode())


def test_rejects_duplicate_identity_and_oversize():
    payload = audit_line() + b"\n" + audit_line()
    with pytest.raises(AuditAdapterError, match="duplicate"):
        parse_audit_jsonl(payload)
    with pytest.raises(AuditAdapterError, match="limit"):
        parse_audit_jsonl(audit_line(), max_bytes=10)


def test_merge_reconstructs_the_flagship_finding(fixture_file):
    fixture = load_fixture(fixture_file())
    event = parse_audit_jsonl(audit_line())[0]
    merged = merge_audit_events(
        fixture,
        [
            {
                "audit_id": "binding-change",
                "stage": "ResponseComplete",
                "stage_timestamp": "2026-09-28T07:59:00Z",
                "verb": "create",
                "user": {"username": "system:serviceaccount:reprise-demo:deployment-automation"},
                "object_ref": {
                    "api_group": "rbac.authorization.k8s.io",
                    "resource": "rolebindings",
                    "namespace": "reprise-demo",
                    "name": "diagnostics-access",
                },
                "response_code": 201,
            },
            event | {"audit_id": "canary-read"},
        ],
    )
    package = build_evidence_package(merged)

    assert len(package["findings"]) == 1
    assert package["findings"][0]["principal"].endswith(":preview-bot")
