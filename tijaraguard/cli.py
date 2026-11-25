"""Documented CLI entrypoint for TijaraGuard."""

from __future__ import annotations

import argparse
import dataclasses
import json
import signal
import sys
from pathlib import Path
from typing import List, Optional

sys.dont_write_bytecode = True

from .api import TijaraGuardHTTPServer
from .config import load_config, validate_config
from .demo import run_demo
from .deps import DependencyLoadError, inspect_dependencies
from .ledger import restore_ledger_backup, verify_audit_database_readonly
from .models import ApprovalToken, InboundMessage, TijaraGuardError
from .runtime import build_pipeline_from_config
from .security import scrub_secrets_from_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tijaraguard",
        description="TijaraGuard commercial support & verification platform CLI.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional JSON configuration file (overlaid with TIJARAGUARD_* env vars).",
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
        help="Inspect resolved dependencies (sibling/vendored) and manifest integrity.",
    )

    verify_cmd = sub.add_parser(
        "verify-audit",
        help="Verify hash-chain integrity of an existing TijaraGuard ledger database.",
    )
    verify_cmd.add_argument("ledger_db", type=Path, help="Path to ledger SQLite database.")

    sub.add_parser(
        "check-config",
        help="Validate configuration, secrets, SSRF rules, providers, and channels.",
    )

    serve_cmd = sub.add_parser(
        "serve",
        help="Start the TijaraGuard HTTP REST API, webhooks, and operator dashboard.",
    )
    serve_cmd.add_argument("--host", default=None, help="Bind host (overrides config).")
    serve_cmd.add_argument("--port", type=int, default=None, help="Bind port (overrides config).")

    cat_cmd = sub.add_parser(
        "catalog-search",
        help="Resolve a product query (Arabic or English) against the configured catalog.",
    )
    cat_cmd.add_argument("query", help="Product query string.")
    cat_cmd.add_argument("--lang", default="ar", choices=("ar", "en"))

    ing_cmd = sub.add_parser(
        "ingest",
        help="Process a customer inquiry through Gate 1 (Privacy), Gate 2 (Commerce), and Gate 3 (Ledger).",
    )
    ing_cmd.add_argument("--message-id", required=True)
    ing_cmd.add_argument("--conversation-id", required=True)
    ing_cmd.add_argument("--customer-handle", required=True)
    ing_cmd.add_argument("--contact-target", required=True)
    ing_cmd.add_argument("--channel", default="whatsapp")
    ing_cmd.add_argument("--consent", required=True, help="true or false")
    ing_cmd.add_argument("--consent-evidence", default="")
    ing_cmd.add_argument("--lang", default="ar", choices=("ar", "en"))
    ing_cmd.add_argument("--text", required=True)
    ing_cmd.add_argument("--sku", default=None)

    drafts_cmd = sub.add_parser("drafts", help="List drafts from the ledger.")
    drafts_cmd.add_argument("--state", default=None)
    drafts_cmd.add_argument("--limit", type=int, default=50)

    appr_cmd = sub.add_parser("approve", help="Issue a single-use human approval lease.")
    appr_cmd.add_argument("draft_id")
    appr_cmd.add_argument("--reviewer", required=True)
    appr_cmd.add_argument("--payload-sha256", required=True)
    appr_cmd.add_argument("--notes", default="")
    appr_cmd.add_argument("--ttl", type=int, default=900)

    rej_cmd = sub.add_parser("reject", help="Reject a draft.")
    rej_cmd.add_argument("draft_id")
    rej_cmd.add_argument("--reviewer", required=True)
    rej_cmd.add_argument("--reason", required=True)

    edit_cmd = sub.add_parser("edit", help="Edit draft body, re-verify, and revoke old approval.")
    edit_cmd.add_argument("draft_id")
    edit_cmd.add_argument("--actor", required=True)
    edit_cmd.add_argument("--body", required=True)

    esc_cmd = sub.add_parser("escalate", help="Escalate a draft to human operator handoff.")
    esc_cmd.add_argument("draft_id")
    esc_cmd.add_argument("--actor", required=True)
    esc_cmd.add_argument("--reason", required=True)

    disp_cmd = sub.add_parser("dispatch", help="Consume active approval lease and dispatch draft.")
    disp_cmd.add_argument("draft_id")
    disp_cmd.add_argument("--target", default=None, help="Optional explicit recipient target.")
    disp_cmd.add_argument("--no-confirm", action="store_true")

    rec_cmd = sub.add_parser("recover", help="Reconcile UNKNOWN/interrupted delivery without resending POST.")
    rec_cmd.add_argument("draft_id")

    sub.add_parser("providers-health", help="Run health checks on all configured AI providers.")

    bak_cmd = sub.add_parser("backup", help="Create a verified hot SQLite backup of the ledger.")
    bak_cmd.add_argument("dest", type=Path, help="Destination backup file path.")

    rest_cmd = sub.add_parser("restore", help="Verify and restore a ledger backup file.")
    rest_cmd.add_argument("backup_file", type=Path)
    rest_cmd.add_argument("target_db", type=Path)

    sub.add_parser("purge-retention", help="Purge expired terminal inquiry text and old replay events.")
    return parser


def _dispatch_command(args: argparse.Namespace) -> int:
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

    if args.command == "restore":
        res = restore_ledger_backup(args.backup_file, args.target_db)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    cfg = load_config(config_file=args.config)

    if args.command == "check-config":
        report = validate_config(cfg)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["valid"] else 1

    if args.command == "serve":
        cfg = dataclasses.replace(
            cfg,
            bind_host=args.host or cfg.bind_host,
            bind_port=cfg.bind_port if args.port is None else args.port,
        )
        report = validate_config(cfg)
        if not report["valid"]:
            print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)
            return 1
        server = TijaraGuardHTTPServer(cfg).start()
        print(
            json.dumps(
                {
                    "listening": server.base_url,
                    "mode": cfg.mode.value,
                    "warnings": report["warnings"],
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

        def _stop_handler(_signum: int, _frame: object) -> None:
            server.stop()

        signal.signal(signal.SIGINT, _stop_handler)
        signal.signal(signal.SIGTERM, _stop_handler)
        try:
            server.serve_forever()
        finally:
            server.stop()
        return 0

    pipe = build_pipeline_from_config(cfg)

    if args.command == "catalog-search":
        res = pipe.commercial_gate.catalog.resolve_item_fuzzy(args.query, lang=args.lang)
        print(
            json.dumps(
                {
                    "query": args.query,
                    "has_match": res.has_match,
                    "is_ambiguous": res.is_ambiguous,
                    "resolved_item": res.resolved_item.to_dict() if res.resolved_item else None,
                    "notes": res.resolution_notes,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "ingest":
        msg = InboundMessage(
            message_id=args.message_id,
            conversation_id=args.conversation_id,
            customer_handle=args.customer_handle,
            raw_contact_target=args.contact_target,
            contact_channel=args.channel,
            consent_to_contact=args.consent,
            consent_evidence=args.consent_evidence,
            preferred_language=args.lang,
            raw_text=args.text,
            requested_sku=args.sku,
            tenant_id=cfg.tenant_id,
        )
        res = pipe.process_inbound(msg)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.command == "drafts":
        rows = pipe.ledger.list_drafts(
            tenant_id=cfg.tenant_id,
            state=args.state,
            limit=args.limit,
        )
        print(json.dumps({"drafts": rows}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "approve":
        tok = pipe.approve(
            args.draft_id,
            reviewer_id=args.reviewer,
            expected_payload_sha256=args.payload_sha256,
            notes=args.notes,
            ttl_seconds=args.ttl,
        )
        print(
            json.dumps(
                {
                    "lease_id": tok.lease_id,
                    "draft_id": tok.draft_id,
                    "payload_sha256": tok.payload_sha256,
                    "reviewer_id": tok.reviewer_id,
                    "expires_at": tok.expires_at,
                    "approval_mac": tok.approval_mac,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "reject":
        row = pipe.reject(args.draft_id, reviewer_id=args.reviewer, reason=args.reason)
        print(json.dumps(row, ensure_ascii=False, indent=2))
        return 0

    if args.command == "edit":
        row = pipe.edit_draft(args.draft_id, new_body=args.body, actor=args.actor)
        print(json.dumps(row, ensure_ascii=False, indent=2))
        return 0

    if args.command == "escalate":
        row = pipe.escalate(args.draft_id, actor=args.actor, reason=args.reason)
        print(json.dumps(row, ensure_ascii=False, indent=2))
        return 0

    if args.command == "dispatch":
        active = pipe.ledger.get_active_approval(args.draft_id)
        if active is None:
            print(json.dumps({"error": f"No active approval lease for {args.draft_id}"}), file=sys.stderr)
            return 1
        token = ApprovalToken(
            lease_id=active["lease_id"],
            draft_id=args.draft_id,
            payload_sha256=active["payload_sha256"],
            reviewer_id=active["reviewer_id"],
            approved_at=float(active["approved_at"]),
            expires_at=float(active["expires_at"]),
            approval_mac=active["approval_mac"],
        )
        outcome = pipe.dispatch(
            args.draft_id,
            token,
            confirm_delivered=not args.no_confirm,
            recipient_target=args.target,
        )
        print(json.dumps(outcome.__dict__, ensure_ascii=False, indent=2))
        return 0

    if args.command == "recover":
        outcome = pipe.recover_delivery(args.draft_id)
        print(json.dumps(outcome.__dict__, ensure_ascii=False, indent=2))
        return 0

    if args.command == "providers-health":
        results = [r.to_dict() for r in pipe.ai_router.health_check_all()] if pipe.ai_router else []
        print(json.dumps({"results": results}, ensure_ascii=False, indent=2))
        return 0 if all(r["healthy"] for r in results) else 1

    if args.command == "backup":
        res = pipe.ledger.backup_to(args.dest)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.command == "purge-retention":
        res = pipe.ledger.purge_expired_retention(
            channel_event_max_age_seconds=cfg.retention.channel_event_retention_days * 86400
        )
        if pipe.route_store is not None:
            res["purged_routes"] = pipe.route_store.purge_expired()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    return 2


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch_command(args)
    except (TijaraGuardError, DependencyLoadError, OSError) as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "detail": scrub_secrets_from_text(str(exc)),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1
