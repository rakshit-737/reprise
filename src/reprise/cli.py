"""Command-line entry point for the offline REPRISE slice."""

from __future__ import annotations

import argparse
from pathlib import Path

from .artifacts import ArtifactStore
from .fixture import FixtureError, load_fixture
from .report import build_evidence_package, write_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reprise",
        description="Build an evidence-linked REPRISE report from a sanitized fixture.",
    )
    parser.add_argument("fixture", type=Path, help="metadata-only JSON fixture")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts/demo"),
        help="output directory (default: artifacts/demo)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1_000_000,
        help="maximum fixture size in bytes (default: 1000000)",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("artifacts/store"),
        help="content-addressed artifact store (default: artifacts/store)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        fixture = load_fixture(args.fixture, max_bytes=args.max_bytes)
        package = build_evidence_package(fixture, artifact_store=ArtifactStore(args.artifact_root))
        json_path, markdown_path = write_outputs(package, args.out)
    except (FixtureError, OSError, ValueError) as exc:
        print(f"REPRISE input error: {exc}")
        return 2

    findings = package["findings"]
    print(f"Evidence package written to {json_path}")
    print(f"Readable report written to {markdown_path}")
    print(f"Findings: {len(findings)}")
    for finding in findings:
        authorization = finding["authorization"]
        proposals = finding["candidate_proposals"]
        print(f"- {finding['finding_id']}: {len(authorization['paths'])} supported path(s), {len(proposals)} candidate proposal(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
