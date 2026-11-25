"""End-to-end 4-gate integration, malformed input, and CLI verification tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.demo import run_demo
from tijaraguard.models import MalformedInputError

from helpers import ALL_SYNTH_PII_SECRETS, REPO_ROOT, make_inbound_message, scan_sqlite_for_secrets


class TestE2EPipelineAndCLI(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="e2e_", dir=str(base_tmp)))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_malformed_inputs_fail_cleanly(self) -> None:
        malformed_cases = [
            {"raw_text": "   "},
            {"raw_text": None},
            {"message_id": "invalid id with spaces"},
            {"contact_channel": "unsupported_channel"},
            {"consent_to_contact": "maybe"},
            {"preferred_language": "fr"},
        ]
        for kwargs in malformed_cases:
            with self.assertRaises(MalformedInputError):
                make_inbound_message(**kwargs)

    def test_full_demo_runs_and_passes_all_assertions(self) -> None:
        demo_dir = self.tmpdir / "demo_state"
        summary = run_demo(state_dir=demo_dir)

        self.assertEqual(summary["scenario_a_shadow"]["resolved_sku"], "SONY-WH1000XM5")
        self.assertEqual(summary["scenario_a_shadow"]["verification_status"], "PASS")
        self.assertEqual(summary["scenario_a_shadow"]["dispatch_state"], "SHADOW_RECORDED")
        self.assertFalse(summary["scenario_a_shadow"]["dispatched_externally"])

        self.assertEqual(summary["scenario_b_adversarial_llm"]["verification_status"], "FAIL")
        self.assertEqual(summary["scenario_b_adversarial_llm"]["ledger_state"], "VERIFIED_BLOCKED")

        self.assertTrue(summary["scenario_c_payload_tamper"]["tampered_dispatch_rejected"])
        self.assertEqual(summary["scenario_c_payload_tamper"]["final_ledger_state"], "VERIFIED_BLOCKED")

        sc_d = summary["scenario_d_lost_ack_recovery"]
        self.assertEqual(sc_d["initial_state_after_drop_ack"], "UNKNOWN_DELIVERY")
        self.assertEqual(sc_d["initial_shield_state"], "UNKNOWN")
        self.assertEqual(sc_d["recovered_state"], "DELIVERED")
        self.assertEqual(sc_d["recovered_shield_state"], "DELIVERED")
        self.assertEqual(sc_d["receiver_logical_inbox_rows"], 1)
        self.assertEqual(sc_d["receiver_post_attempts"], 1)

        sec = summary["security_and_audit_proof"]
        self.assertTrue(sec["shadow_audit_chain_valid"])
        self.assertTrue(sec["live_audit_chain_valid"])
        self.assertEqual(sec["shadow_ledger_pii_leaks"], 0)
        self.assertEqual(sec["live_ledger_pii_leaks"], 0)
        self.assertEqual(sec["receiver_and_outbox_pii_leaks"], 0)
        self.assertEqual(sec["application_log_pii_leaks"], 0)

        for db_name in ("shadow_ledger.sqlite3", "ledger.sqlite3", "outbox.sqlite3", "receiver.sqlite3"):
            self.assertEqual(scan_sqlite_for_secrets(demo_dir / db_name, ALL_SYNTH_PII_SECRETS), [])

    def test_cli_subcommands_via_subprocess(self) -> None:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

        # 1. inspect-deps
        p_deps = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "inspect-deps"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        deps_json = json.loads(p_deps.stdout)
        self.assertTrue(deps_json["dont_write_bytecode"])
        self.assertEqual(set(deps_json["dependencies"].keys()), {"bayan_gate", "catalog_copilot", "message_shield"})

        # 2. demo
        cli_state = self.tmpdir / "cli_demo"
        p_demo = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "demo", "--state-dir", str(cli_state)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        demo_json = json.loads(p_demo.stdout)
        self.assertEqual(demo_json["scenario_d_lost_ack_recovery"]["receiver_logical_inbox_rows"], 1)

        # 3. verify-audit
        p_audit = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "verify-audit", str(cli_state / "ledger.sqlite3")],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        audit_json = json.loads(p_audit.stdout)
        self.assertTrue(audit_json["valid"])
        self.assertEqual(audit_json["errors"], [])
