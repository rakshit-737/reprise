"""Export versioned JSON Schemas for the public REPRISE contracts."""

from __future__ import annotations

import json
from pathlib import Path

from reprise.contracts import (
    ApprovalContract,
    ClaimContract,
    EvidencePackageContract,
    RemediationProposalContract,
    ShadowValidationContract,
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    output_dir = root / "schemas"
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, model in (
        ("claim.schema.json", ClaimContract),
        ("proposal.schema.json", RemediationProposalContract),
        ("evidence-package.schema.json", EvidencePackageContract),
        ("validation.schema.json", ShadowValidationContract),
        ("approval.schema.json", ApprovalContract),
    ):
        path = output_dir / filename
        path.write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {path.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
