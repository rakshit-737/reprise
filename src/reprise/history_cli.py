"""CLI for replaying bounded Kubernetes RBAC watch history."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .resource_history import ResourceHistoryError, parse_watch_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reprise-history",
        description="Replay bounded RBAC watch JSONL and report continuity gaps.",
    )
    parser.add_argument("watch_log", type=Path)
    parser.add_argument("--max-bytes", type=int, default=10_000_000)
    parser.add_argument("--max-events", type=int, default=5_000)
    parser.add_argument("--out", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        history = parse_watch_file(
            args.watch_log,
            max_bytes=args.max_bytes,
            max_events=args.max_events,
        )
    except (ResourceHistoryError, OSError, ValueError) as exc:
        print(f"REPRISE history error: {exc}")
        return 2
    payload = json.dumps(history.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
        print(f"Resource history written to {args.out}")
    else:
        print(payload, end="")
    print(f"Observations: {len(history.observations)}; bookmarks: {len(history.bookmarks)}; gaps: {len(history.gaps)}; continuity_complete: {history.continuity_complete}")
    return 0 if history.continuity_complete else 3


if __name__ == "__main__":
    raise SystemExit(main())
