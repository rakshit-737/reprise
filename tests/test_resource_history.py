import json

import pytest

from reprise.resource_history import ResourceHistoryError, parse_watch_jsonl


def watch_event(event_type="ADDED", version="10", name="reader", **object_overrides):
    obj = {
        "kind": "Role",
        "metadata": {
            "name": name,
            "namespace": "reprise-demo",
            "uid": f"uid-{name}",
            "resourceVersion": version,
        },
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}],
        "observedAt": "2026-09-28T08:00:00Z",
    }
    obj.update(object_overrides)
    return json.dumps({"type": event_type, "object": obj}).encode("utf-8")


def test_watch_history_preserves_versions_and_latest_state():
    payload = b"\n".join(
        [
            watch_event("ADDED", "10"),
            watch_event("MODIFIED", "11", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]),
            json.dumps({"type": "BOOKMARK", "object": {"metadata": {"resourceVersion": "11"}}}).encode(),
        ]
    )
    history = parse_watch_jsonl(payload)

    assert len(history.observations) == 2
    assert history.bookmarks == ("11",)
    assert history.continuity_complete is True
    latest = history.latest()
    assert latest[("Role", "reprise-demo", "reader")].resource_version == "11"


def test_delete_removes_latest_object():
    deleted = json.loads(watch_event("DELETED", "12").decode())
    history = parse_watch_jsonl(b"\n".join([watch_event(), json.dumps(deleted).encode()]))
    assert history.latest() == {}


def test_expired_watch_is_an_explicit_gap():
    payload = json.dumps({"type": "ERROR", "object": {"kind": "Status", "code": 410}}).encode()
    history = parse_watch_jsonl(payload)
    assert history.continuity_complete is False
    assert "410" in history.gaps[0]


def test_non_resource_rules_are_skipped_but_other_versions_survive():
    payload = watch_event(
        rules=[
            {"verbs": ["get"], "nonResourceURLs": ["/healthz"]},
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
        ]
    )
    history = parse_watch_jsonl(payload)
    assert len(history.observations) == 1


@pytest.mark.parametrize("field", ["data", "stringData", "requestObject"])
def test_watch_rejects_sensitive_fields(field):
    event = json.loads(watch_event().decode())
    event["object"][field] = {"value": "not-allowed"}
    with pytest.raises(ResourceHistoryError, match="forbidden"):
        parse_watch_jsonl(json.dumps(event).encode())


def test_watch_rejects_duplicate_json_keys_and_conflicting_replay():
    with pytest.raises(ResourceHistoryError, match="duplicate"):
        parse_watch_jsonl(b'{"type":"ADDED","type":"MODIFIED","object":{}}')
    first = watch_event("ADDED", "10")
    conflicting = watch_event("ADDED", "10", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}])
    with pytest.raises(ResourceHistoryError, match="changed"):
        parse_watch_jsonl(first + b"\n" + conflicting)


def test_watch_event_limit():
    with pytest.raises(ResourceHistoryError, match="limit"):
        parse_watch_jsonl(watch_event(), max_events=0)
