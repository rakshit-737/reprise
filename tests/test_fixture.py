import json

import pytest

from reprise.fixture import FixtureError, load_fixture


def test_core_api_group_and_empty_rules_are_valid(raw_fixture, fixture_file):
    raw_fixture["roles"][1]["rules"] = []
    fixture = load_fixture(fixture_file())
    assert fixture.roles[0].rules[0].api_groups == ("",)
    assert fixture.roles[1].rules == ()


@pytest.mark.parametrize("field", ["data", "stringData", "requestObject", "response_object"])
def test_sensitive_and_unknown_fields_are_rejected(field, raw_fixture, fixture_file):
    raw_fixture["audit_events"][0][field] = {"secret": "synthetic-not-a-credential"}
    with pytest.raises(FixtureError):
        load_fixture(fixture_file())


@pytest.mark.parametrize("value", [True, "200", 600, 99])
def test_status_code_is_strict(value, raw_fixture, fixture_file):
    raw_fixture["audit_events"][0]["response_code"] = value
    with pytest.raises(FixtureError):
        load_fixture(fixture_file())


def test_duplicate_object_identity_is_rejected(raw_fixture, fixture_file):
    raw_fixture["roles"].append(raw_fixture["roles"][0].copy())
    with pytest.raises(FixtureError):
        load_fixture(fixture_file())


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"0.1","schema_version":"0.2"}')
    with pytest.raises(FixtureError):
        load_fixture(path)


def test_original_bytes_are_retained(fixture_file):
    path = fixture_file()
    fixture = load_fixture(path)
    assert fixture.source_bytes == path.read_bytes()
    assert json.loads(fixture.source_bytes)["environment"]["id"] == fixture.environment["id"]


def test_input_limit(fixture_file):
    with pytest.raises(FixtureError):
        load_fixture(fixture_file(), max_bytes=20)


def test_role_binding_without_subjects_is_valid_but_cannot_grant(raw_fixture, fixture_file):
    raw_fixture["role_bindings"][0]["subjects"] = []
    fixture = load_fixture(fixture_file(raw_fixture))
    assert fixture.role_bindings[0].subjects == ()


@pytest.mark.parametrize("timestamp", ["yesterday", "2026-09-27T10:00:00"])
def test_timestamp_requires_timezone(timestamp, raw_fixture, fixture_file):
    raw_fixture["audit_events"][0]["stage_timestamp"] = timestamp
    with pytest.raises(FixtureError):
        load_fixture(fixture_file())
