"""Clean-room installation & standalone vendored dependency verification tests."""

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

from tijaraguard.deps import verify_vendor_manifest
from helpers import REPO_ROOT


class TestCleanRoomInstall(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="cleanroom_", dir=str(base_tmp)))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_vendor_manifest_checksums_valid(self) -> None:
        ok, errs = verify_vendor_manifest()
        self.assertTrue(ok, f"Vendor manifest errors: {errs}")

    def test_isolated_checkout_without_sibling_repos_uses_vendored_deps_and_passes_demo(self) -> None:
        # Copy TijaraGuard into an isolated subdirectory with NO sibling repos around it
        isolated = self.tmpdir / "isolated_parent" / "TijaraGuard"
        isolated.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            REPO_ROOT / "tijaraguard",
            isolated / "tijaraguard",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        shutil.copytree(REPO_ROOT / "examples", isolated / "examples")
        for f in ("pyproject.toml", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copy2(REPO_ROOT / f, isolated / f)

        clean_env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("TIJARAGUARD_")
        }
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"

        p_deps = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "inspect-deps"],
            cwd=str(isolated),
            env=clean_env,
            capture_output=True,
            text=True,
            check=True,
        )
        deps_info = json.loads(p_deps.stdout)
        self.assertTrue(deps_info["vendor_manifest_verified"])
        for dep_key in ("bayan_gate", "catalog_copilot", "message_shield"):
            self.assertEqual(deps_info["dependencies"][dep_key]["source"], "vendored")

        p_demo = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "tijaraguard",
                "demo",
                "--state-dir",
                str(self.tmpdir / "clean_demo_state"),
            ],
            cwd=str(isolated),
            env=clean_env,
            capture_output=True,
            text=True,
            check=True,
        )
        demo_out = json.loads(p_demo.stdout)
        sec = demo_out["security_and_audit_proof"]
        self.assertTrue(sec["shadow_audit_chain_valid"])
        self.assertTrue(sec["live_audit_chain_valid"])
        self.assertEqual(sec["shadow_ledger_pii_leaks"], 0)
        self.assertEqual(sec["live_ledger_pii_leaks"], 0)
        self.assertEqual(sec["receiver_and_outbox_pii_leaks"], 0)
        self.assertEqual(sec["application_log_pii_leaks"], 0)
