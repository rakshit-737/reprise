"""CLI for creating and advancing local REPRISE cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .case_store import CaseStore, CaseStoreError
from .contracts import validate_evidence_package


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reprise-case")
    parser.add_argument("--db", type=Path, default=Path("artifacts/reprise-cases.db"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--package", type=Path, required=True)
    create.add_argument("--case-id", required=True)

    transition = subparsers.add_parser("transition")
    transition.add_argument("--case-id", required=True)
    transition.add_argument("--expected-version", type=int, required=True)
    transition.add_argument("--to", required=True)
    transition.add_argument("--actor", required=True)
    transition.add_argument("--reason", required=True)
    transition.add_argument("--idempotency-key", required=True)

    show = subparsers.add_parser("show")
    show.add_argument("--case-id", required=True)
    return parser


def _package_metadata(path: Path) -> tuple[dict[str, object], str, str]:
    source = path.read_bytes()
    package = json.loads(source.decode("utf-8"))
    validate_evidence_package(package)
    findings = package.get("findings", [])
    finding_id = findings[0]["finding_id"] if findings else "no-finding"
    metadata = {
        "evidence_package_sha256": hashlib.sha256(source).hexdigest(),
        "evidence_package_type": package["package_type"],
        "finding_ids": [finding["finding_id"] for finding in findings],
    }
    return metadata, package["environment"]["id"], finding_id


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = CaseStore(args.db)
    try:
        if args.command == "create":
            metadata, environment_id, finding_id = _package_metadata(args.package)
            case = store.create_case(
                case_id=args.case_id,
                environment_id=environment_id,
                finding_id=finding_id,
                metadata=metadata,
            )
            print(json.dumps(case.to_dict(), indent=2, sort_keys=True))
            return 0
        if args.command == "transition":
            case = store.transition(
                case_id=args.case_id,
                expected_version=args.expected_version,
                to_state=args.to,
                actor=args.actor,
                reason=args.reason,
                idempotency_key=args.idempotency_key,
            )
            print(json.dumps(case.to_dict(), indent=2, sort_keys=True))
            return 0
        case = store.get_case(args.case_id)
        payload = {"case": case.to_dict(), "events": [event.to_dict() for event in store.list_events(args.case_id)]}
        store.verify_chain(args.case_id)
        payload["chain_verified"] = True
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (CaseStoreError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"REPRISE case error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
