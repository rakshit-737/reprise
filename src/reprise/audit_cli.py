"""CLI for attaching sanitized Kubernetes audit events to an RBAC fixture."""

from __future__ import annotations

import argparse

from .artifacts import ArtifactStore
from .audit_adapter import AuditAdapterError, merge_audit_events, parse_audit_file
from .fixture import FixtureError, load_fixture
from .kubernetes_adapter import write_fixture
from .report import build_evidence_package, write_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reprise-audit",
        description="Attach bounded Metadata-level Kubernetes audit events to an RBAC fixture.",
    )
    parser.add_argument("--rbac-fixture", required=True, help="accepted REPRISE RBAC fixture JSON")
    parser.add_argument("--audit-log", required=True, help="Metadata-level Kubernetes audit JSONL")
    parser.add_argument("--out", default="artifacts/audit-replay")
    parser.add_argument("--artifact-root", default="artifacts/store")
    parser.add_argument("--max-bytes", type=int, default=10_000_000)
    parser.add_argument("--max-events", type=int, default=5_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        base = load_fixture(args.rbac_fixture)
        events = parse_audit_file(
            args.audit_log,
            max_bytes=args.max_bytes,
            max_events=args.max_events,
        )
        fixture = merge_audit_events(base, events)
        output_dir = write_fixture(fixture, f"{args.out}/merged-fixture.json").parent
        package = build_evidence_package(
            fixture,
            artifact_store=ArtifactStore(args.artifact_root),
            source_mode="audit-replay",
            package_limitations=(
                "Audit events were parsed from a supplied JSONL export; source completeness was not independently verified.",
                "No Secret contents were ingested; audit request and response bodies are rejected.",
                "No live SubjectAccessReview, API action, approval, or mutation was executed.",
                "Authorization conclusions are limited to the supplied RBAC snapshot and supported model.",
            ),
        )
        write_outputs(package, output_dir)
    except (AuditAdapterError, FixtureError, OSError, ValueError) as exc:
        print(f"REPRISE audit error: {exc}")
        return 2
    print(f"Parsed {len(events)} audit event(s)")
    print(f"Merged fixture written to {output_dir / 'merged-fixture.json'}")
    print(f"Evidence package written to {output_dir / 'evidence-package.json'}")
    print(f"Readable report written to {output_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
