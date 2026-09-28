from reprise.detect import detect_findings
from reprise.fixture import load_fixture
from reprise.rbac import enumerate_paths


def test_detection_and_alternate_paths_are_explicit(fixture_file):
    fixture = load_fixture(fixture_file())
    findings = detect_findings(fixture)

    assert len(findings) == 1
    finding = findings[0]
    analysis = enumerate_paths(fixture, finding.principal, finding.action)
    assert analysis.allowed is True
    assert [path.binding_name for path in analysis.paths] == [
        "diagnostics-access",
        "legacy-debug-access",
    ]


def test_excluding_one_binding_leaves_a_counterexample(fixture_file):
    fixture = load_fixture(fixture_file())
    finding = detect_findings(fixture)[0]
    original = enumerate_paths(fixture, finding.principal, finding.action)
    first_uid = original.paths[0].binding_uid
    remaining = enumerate_paths(
        fixture,
        finding.principal,
        finding.action,
        excluded_binding_uids=frozenset({first_uid}),
    )

    assert remaining.allowed is True
    assert len(remaining.paths) == 1


def test_excluding_all_supported_paths_blocks_only_the_tested_action(fixture_file):
    fixture = load_fixture(fixture_file())
    finding = detect_findings(fixture)[0]
    original = enumerate_paths(fixture, finding.principal, finding.action)
    all_uids = frozenset(path.binding_uid for path in original.paths)
    remaining = enumerate_paths(
        fixture,
        finding.principal,
        finding.action,
        excluded_binding_uids=all_uids,
    )

    assert remaining.allowed is False
    workflow = fixture.workflow_contracts[0]
    assert enumerate_paths(fixture, workflow.principal, workflow.action).allowed is True


def test_resource_names_are_exact_not_wildcards(raw_fixture, fixture_file):
    raw_fixture["audit_events"][1]["object_ref"]["name"] = "another-secret"
    fixture = load_fixture(fixture_file(raw_fixture))
    finding = detect_findings(fixture)[0]
    assert enumerate_paths(fixture, finding.principal, finding.action).allowed is False


def test_wildcards_match_supported_action(raw_fixture, fixture_file):
    raw_fixture["roles"][0]["rules"][0]["api_groups"] = ["*"]
    raw_fixture["roles"][0]["rules"][0]["resources"] = ["*"]
    raw_fixture["roles"][0]["rules"][0]["verbs"] = ["*"]
    raw_fixture["roles"][0]["rules"][0].pop("resource_names")
    fixture = load_fixture(fixture_file(raw_fixture))
    finding = detect_findings(fixture)[0]
    assert enumerate_paths(fixture, finding.principal, finding.action).allowed is True


def test_aggregated_role_is_reported_as_incomplete(raw_fixture, fixture_file):
    raw_fixture["roles"][0]["kind"] = "ClusterRole"
    raw_fixture["roles"][0]["namespace"] = None
    raw_fixture["roles"][0]["aggregated"] = True
    raw_fixture["role_bindings"][0]["role_ref"]["kind"] = "ClusterRole"
    raw_fixture["role_bindings"][1]["role_ref"]["kind"] = "ClusterRole"
    fixture = load_fixture(fixture_file(raw_fixture))
    finding = detect_findings(fixture)[0]
    analysis = enumerate_paths(fixture, finding.principal, finding.action)
    assert analysis.allowed is False
    assert any("aggregated ClusterRole" in warning for warning in analysis.coverage_warnings)
