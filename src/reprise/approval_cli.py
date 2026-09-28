"""CLI for local approval-record creation and single-use consumption."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .approval import ApprovalError, ApprovalGateway, load_validation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reprise-approve")
    parser.add_argument("--db", type=Path, default=Path("artifacts/approvals.db"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--validation", type=Path, required=True)
    create.add_argument("--approver", required=True)
    create.add_argument("--ttl-seconds", type=int, default=300)
    create.add_argument("--out", type=Path, default=Path("artifacts/approval.json"))

    consume = subparsers.add_parser("consume")
    consume.add_argument("--approval", type=Path, required=True)
    consume.add_argument("--nonce", required=True)
    consume.add_argument("--environment-id", required=True)
    consume.add_argument("--proposal-digest", required=True)
    consume.add_argument("--validation-digest", required=True)

    show = subparsers.add_parser("show")
    show.add_argument("--approval-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    gateway = ApprovalGateway(args.db)
    try:
        if args.command == "create":
            validation, _digest = load_validation(args.validation)
            record = gateway.create(
                environment_id=validation.environment_id,
                proposal_digest=validation.proposal_digest,
                validation=validation,
                approver=args.approver,
                ttl_seconds=args.ttl_seconds,
            )
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"Approval written to {args.out}")
            print(f"Approval ID: {record.approval_id}")
            print(f"Expires: {record.expires_at}")
            return 0
        if args.command == "consume":
            approval = json.loads(args.approval.read_text(encoding="utf-8"))
            record = gateway.consume(
                approval_id=approval["approval_id"],
                nonce=args.nonce,
                environment_id=args.environment_id,
                proposal_digest=args.proposal_digest,
                validation_digest_value=args.validation_digest,
            )
            print(json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True))
            return 0
        record = gateway.get(args.approval_id)
        print(json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    except (ApprovalError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        print(f"REPRISE approval error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
