"""CLI for one read-only SubjectAccessReview and optional fixture comparison."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .fixture import load_fixture
from .models import Action
from .sar import KubernetesSubjectAccessReviewer, SubjectAccessReviewError, differential_check


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reprise-sar",
        description="Run one read-only SubjectAccessReview against an explicit context.",
    )
    parser.add_argument("--context", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--verb", required=True)
    parser.add_argument("--api-group", default="")
    parser.add_argument("--resource", required=True)
    parser.add_argument("--namespace")
    parser.add_argument("--name")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--rbac-fixture", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    action = Action(
        verb=args.verb,
        api_group=args.api_group,
        resource=args.resource,
        namespace=args.namespace,
        resource_name=args.name,
    )
    try:
        reviewer = KubernetesSubjectAccessReviewer(context=args.context, kubeconfig=args.kubeconfig)
        if args.rbac_fixture:
            result = differential_check(load_fixture(args.rbac_fixture), reviewer, args.principal, action)
            payload = result.to_dict()
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0 if result.match else 3
        result = reviewer.check(args.principal, action)
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    except (SubjectAccessReviewError, OSError, ValueError) as exc:
        print(f"REPRISE SAR error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
