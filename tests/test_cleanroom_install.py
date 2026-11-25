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

    def test_installed_wheel_style_layout_without_examples_uses_bundled_catalog(self) -> None:
        # Simulate site-packages installation where neither examples/ nor pyproject.toml exists next to tijaraguard/
        site_dir = self.tmpdir / "fake_site_packages"
        site_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            REPO_ROOT / "tijaraguard",
            site_dir / "tijaraguard",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        work_cwd = self.tmpdir / "user_workdir"
        work_cwd.mkdir(parents=True, exist_ok=True)

        clean_env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("TIJARAGUARD_")
        }
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        clean_env["PYTHONPATH"] = str(site_dir)
        clean_env["TIJARAGUARD_STATE_DIR"] = str(work_cwd / "state")

        p_chk = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "check-config"],
            cwd=str(work_cwd),
            env=clean_env,
            capture_output=True,
            text=True,
            check=True,
        )
        chk = json.loads(p_chk.stdout)
        self.assertTrue(chk["valid"], chk["errors"])
        self.assertTrue(chk["summary"]["catalog_path"].endswith("catalog.json"))

        p_demo = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "demo"],
            cwd=str(work_cwd),
            env=clean_env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue(json.loads(p_demo.stdout)["security_and_audit_proof"]["live_audit_chain_valid"])
