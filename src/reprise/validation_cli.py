"""CLI for deterministic paired shadow validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .fixture import FixtureError, load_fixture
from .report import build_evidence_package
from .validator import validate_candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reprise-validate",
        description="Run paired attack and benign workflow validation without cluster mutation.",
    )
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--candidate", required=True, help="proposal label from the evidence package")
    parser.add_argument("--finding-index", type=int, default=0)
    parser.add_argument("--out", type=Path, default=Path("artifacts/validation"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        fixture = load_fixture(args.fixture)
        package = build_evidence_package(fixture)
        validation = validate_candidate(
            fixture,
            package,
            label=args.candidate,
            finding_index=args.finding_index,
        )
        args.out.mkdir(parents=True, exist_ok=True)
        result_path = args.out / f"{args.candidate}.json"
        result_path.write_text(
            json.dumps(validation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (FixtureError, OSError, ValueError) as exc:
        print(f"REPRISE validation error: {exc}")
        return 2
    print(f"Validation result written to {result_path}")
    print(f"Status: {validation.status}")
    print(f"Attack passed: {validation.attack.passed}")
    print(f"Benign workflows passed: {sum(item.passed for item in validation.benign_workflows)}/{len(validation.benign_workflows)}")
    return 0 if validation.status == "passed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
