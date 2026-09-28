"""CLI for a read-only live Kubernetes RBAC snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .artifacts import ArtifactStore
from .kubernetes_adapter import KubernetesAdapterError, KubernetesRBACSnapshotter, write_fixture
from .report import build_evidence_package, write_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reprise-snapshot",
        description="Capture a bounded, metadata-only RBAC snapshot from one kubeconfig context.",
    )
    parser.add_argument("--context", required=True, help="explicit kubeconfig context to read")
    parser.add_argument("--environment-id", required=True, help="stable REPRISE environment identifier")
    parser.add_argument("--kubeconfig", type=Path, help="optional kubeconfig path")
    parser.add_argument("--out", type=Path, default=Path("artifacts/live-rbac"))
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts/store"))
    parser.add_argument("--page-size", type=int, default=200)
    parser.add_argument("--max-items", type=int, default=5_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        fixture, summary = KubernetesRBACSnapshotter(
            context=args.context,
            environment_id=args.environment_id,
            kubeconfig=args.kubeconfig,
            page_size=args.page_size,
            max_items=args.max_items,
        ).capture()
        output_dir = args.out
        output_dir.mkdir(parents=True, exist_ok=True)
        fixture_path = write_fixture(fixture, output_dir / "rbac-fixture.json")
        package = build_evidence_package(
            fixture,
            artifact_store=ArtifactStore(args.artifact_root),
            source_mode="live-read-only",
            package_limitations=(
                "This snapshot collected RBAC and ServiceAccount metadata only; it did not collect audit events.",
                "No Secret objects, Secret contents, tokens, labels, or annotations were requested or stored.",
                "No SubjectAccessReview, API action, approval, or mutation was executed.",
                "The complete API-server authorizer chain was not verified; conclusions are limited to supported RBAC metadata.",
            ),
        )
        json_path, markdown_path = write_outputs(package, output_dir)
        (output_dir / "snapshot-summary.json").write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (KubernetesAdapterError, OSError, ValueError) as exc:
        print(f"REPRISE snapshot error: {exc}")
        return 2

    print(f"RBAC fixture written to {fixture_path}")
    print(f"Evidence package written to {json_path}")
    print(f"Readable report written to {markdown_path}")
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
