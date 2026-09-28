import json
from pathlib import Path

from reprise.contracts import (
    ClaimContract,
    EvidencePackageContract,
    RemediationProposalContract,
    ShadowValidationContract,
)


def test_checked_in_schemas_match_contract_models():
    root = Path(__file__).resolve().parents[1]
    expected = {
        "claim.schema.json": ClaimContract,
        "proposal.schema.json": RemediationProposalContract,
        "evidence-package.schema.json": EvidencePackageContract,
        "validation.schema.json": ShadowValidationContract,
    }
    for filename, model in expected.items():
        actual = json.loads((root / "schemas" / filename).read_text(encoding="utf-8"))
        assert actual == model.model_json_schema()
