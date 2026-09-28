import json

from reprise.fixture import load_fixture
from reprise.report import build_evidence_package, render_markdown, write_outputs


def test_package_has_evidence_for_every_material_claim(fixture_file):
    package = build_evidence_package(load_fixture(fixture_file()))
    artifact_ids = {artifact["artifact_id"] for artifact in package["artifacts"]}
    finding = package["findings"][0]

    assert finding["claim_evidence_complete"] is True
    assert all(ref in artifact_ids for claim in finding["claims"] for ref in claim["support"])
    assert finding["candidate_proposals"][0]["tested_action_blocked_under_supported_model"] is False
    assert finding["candidate_proposals"][1]["tested_action_blocked_under_supported_model"] is True


def test_markdown_explains_the_ineffective_fix(fixture_file):
    package = build_evidence_package(load_fixture(fixture_file()))
    report = render_markdown(package)

    assert "naive_first_path_only" in report
    assert "still allowed" in report
    assert "all_supported_paths" in report
    assert "blocked" in report
    assert "not_executed" in report


def test_outputs_are_parseable_and_reproducible(tmp_path, fixture_file):
    package = build_evidence_package(load_fixture(fixture_file()))
    first = write_outputs(package, tmp_path / "one")
    second = write_outputs(package, tmp_path / "two")

    assert json.loads(first[0].read_text(encoding="utf-8")) == json.loads(second[0].read_text(encoding="utf-8"))
    assert first[1].read_text(encoding="utf-8") == second[1].read_text(encoding="utf-8")
