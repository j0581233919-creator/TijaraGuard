"""CLI entrypoint for TijaraGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

sys.dont_write_bytecode = True

from .demo import run_demo
from .deps import inspect_dependencies
from .ledger import verify_audit_database_readonly


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tijaraguard",
        description="TijaraGuard isolated integration MVP CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo_cmd = sub.add_parser(
        "demo",
        help="Run the complete 4-gate synthetic Arabic business demonstration.",
    )
    demo_cmd.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="Optional directory for demo SQLite databases (defaults to .state/demo-<id>).",
    )

    sub.add_parser(
        "inspect-deps",
        help="Inspect resolved read-only sibling repositories and bytecode guard state.",
    )

    verify_cmd = sub.add_parser(
        "verify-audit",
        help="Verify hash-chain integrity of an existing TijaraGuard ledger database.",
    )
    verify_cmd.add_argument("ledger_db", type=Path, help="Path to ledger SQLite database.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "inspect-deps":
        print(json.dumps(inspect_dependencies(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "demo":
        summary = run_demo(state_dir=args.state_dir)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        sec = summary["security_and_audit_proof"]
        if (
            not sec["shadow_audit_chain_valid"]
            or not sec["live_audit_chain_valid"]
            or sec["shadow_ledger_pii_leaks"] != 0
            or sec["live_ledger_pii_leaks"] != 0
            or sec["receiver_and_outbox_pii_leaks"] != 0
            or sec["application_log_pii_leaks"] != 0
        ):
            return 1
        return 0

    if args.command == "verify-audit":
        db_path = Path(args.ledger_db).resolve()
        if not db_path.exists():
            print(json.dumps({"valid": False, "error": f"Database not found: {db_path}"}))
            return 1
        valid, event_count, errors = verify_audit_database_readonly(db_path)
        print(
            json.dumps(
                {
                    "ledger_db": str(db_path),
                    "event_count": event_count,
                    "valid": valid,
                    "errors": errors,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if valid else 1

    return 2
