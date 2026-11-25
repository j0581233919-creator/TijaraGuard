"""Dependency resolver for BayanGate, CatalogCopilot, and MessageShield.

Resolution priority per dependency:
1. Explicit environment variable override (TIJARAGUARD_*_PATH). Fails closed if invalid.
2. Read-only sibling repository (../<repo>/repo) when present.
3. MIT-attributed vendored snapshot bundled under tijaraguard/_vendor/<key>.
4. Installed Python package on sys.path.

Enforces sys.dont_write_bytecode = True prior to path injection and module import
so read-only sibling repositories are never contaminated with __pycache__ files.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import sys

# MUST execute before importing any external/sibling package.
sys.dont_write_bytecode = True

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class DependencyLoadError(RuntimeError):
    """Raised when a required dependency package cannot be resolved or fails verification."""


_ENV_VARS = {
    "bayan_gate": "TIJARAGUARD_BAYAN_GATE_PATH",
    "catalog_copilot": "TIJARAGUARD_CATALOG_COPILOT_PATH",
    "message_shield": "TIJARAGUARD_MESSAGE_SHIELD_PATH",
}

_SIBLING_DIRS = {
    "bayan_gate": "bayan-gate",
    "catalog_copilot": "catalog-copilot",
    "message_shield": "message-shield",
}

_PINNED_COMMITS = {
    "bayan_gate": "1d6b83a46cb75484a434efe17be2e7d97885050c",
    "catalog_copilot": "12522d3b17767ae9a4766499b6495fd4231ebcfc",
    "message_shield": "4ccbc2641c18b47a9feadbe41010a06fb2791275",
}


def _default_github_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _vendor_root() -> Path:
    return Path(__file__).resolve().parent / "_vendor"


def verify_vendor_manifest() -> Tuple[bool, list[str]]:
    """Verifies SHA-256 checksums of bundled vendored dependencies against MANIFEST.json."""
    vendor_dir = _vendor_root()
    manifest_path = vendor_dir / "MANIFEST.json"
    if not manifest_path.is_file():
        return False, [f"Missing vendor manifest: {manifest_path}"]

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"Failed to parse vendor manifest: {exc}"]

    errors: list[str] = []
    deps = manifest.get("dependencies")
    if not isinstance(deps, dict):
        return False, ["Vendor manifest missing 'dependencies' object."]

    for key in ("bayan_gate", "catalog_copilot", "message_shield"):
        entry = deps.get(key)
        if not isinstance(entry, dict):
            errors.append(f"Vendor manifest missing dependency '{key}'.")
            continue
        files_map = entry.get("files")
        if not isinstance(files_map, dict) or not files_map:
            errors.append(f"Vendor manifest missing file checksums for '{key}'.")
            continue
        for rel_path, expected_sha in files_map.items():
            file_path = (vendor_dir / rel_path).resolve()
            try:
                file_path.relative_to(vendor_dir.resolve())
            except ValueError:
                errors.append(f"Vendor manifest path escapes vendor directory: {rel_path}")
                continue
            if not file_path.is_file():
                errors.append(f"Missing vendored file: {rel_path}")
                continue
            actual_sha = hashlib.sha256(file_path.read_bytes()).hexdigest()
            if actual_sha != str(expected_sha).lower():
                errors.append(f"Checksum mismatch for vendored file: {rel_path}")

    return len(errors) == 0, errors


def _resolve_single_dependency(key: str) -> Tuple[Optional[Path], str]:
    """Resolves a dependency path and source label."""
    env_name = _ENV_VARS[key]
    env_override = os.environ.get(env_name)
    if env_override is not None and env_override.strip():
        candidate = Path(env_override).expanduser().resolve()
        if not candidate.is_dir() or not (candidate / key).is_dir():
            raise DependencyLoadError(
                f"Configured {env_name}='{candidate}' does not contain '{key}' package."
            )
        return candidate, "env_override"

    sibling = (_default_github_root() / _SIBLING_DIRS[key] / "repo").resolve()
    if sibling.is_dir() and (sibling / key).is_dir():
        return sibling, "sibling_repo"

    vendored = (_vendor_root() / key).resolve()
    if vendored.is_dir() and (vendored / key).is_dir():
        return vendored, "vendored"

    spec = importlib.util.find_spec(key)
    if spec is not None and spec.origin:
        return Path(spec.origin).resolve().parent.parent, "installed"

    raise DependencyLoadError(
        f"Missing dependency '{key}': checked {env_name}, sibling repo '{sibling}', "
        f"vendored snapshot '{vendored}', and installed packages."
    )


def _resolve_repo_paths() -> Tuple[Dict[str, Path], Dict[str, str]]:
    paths: Dict[str, Path] = {}
    sources: Dict[str, str] = {}
    for key in ("bayan_gate", "catalog_copilot", "message_shield"):
        path, source = _resolve_single_dependency(key)
        if path is None:
            raise DependencyLoadError(f"Failed to resolve path for '{key}'.")
        paths[key] = path
        sources[key] = source
    return paths, sources


@dataclass(frozen=True)
class DependencyBundle:
    """Container of verified dependency modules and provenance metadata."""

    paths: Dict[str, Path]
    bayan_gate: Any
    catalog_copilot: Any
    message_shield: Any
    sources: Dict[str, str] = field(default_factory=dict)
    manifest_verified: bool = False

    def metadata(self) -> Dict[str, Dict[str, str]]:
        """Returns version, resolution source, pinned commit, and resolved paths."""
        mods = {
            "bayan_gate": self.bayan_gate,
            "catalog_copilot": self.catalog_copilot,
            "message_shield": self.message_shield,
        }
        return {
            key: {
                "path": str(self.paths[key]),
                "version": str(getattr(mod, "__version__", "unknown")),
                "source": self.sources.get(key, "unknown"),
                "pinned_commit": _PINNED_COMMITS[key],
            }
            for key, mod in mods.items()
        }


_CACHED_BUNDLE: DependencyBundle | None = None


def load_dependencies() -> DependencyBundle:
    """Validates and imports BayanGate, CatalogCopilot, and MessageShield."""
    global _CACHED_BUNDLE
    sys.dont_write_bytecode = True
    if _CACHED_BUNDLE is not None:
        return _CACHED_BUNDLE

    paths, sources = _resolve_repo_paths()
    using_vendored = any(src == "vendored" for src in sources.values())
    manifest_ok = False
    if using_vendored:
        manifest_ok, manifest_errs = verify_vendor_manifest()
        if not manifest_ok:
            raise DependencyLoadError(
                f"Vendored dependency integrity verification failed: {'; '.join(manifest_errs)}"
            )

    for key in ("bayan_gate", "catalog_copilot", "message_shield"):
        repo_path = paths[key]
        if sources[key] != "installed":
            repo_str = str(repo_path)
            if repo_str not in sys.path:
                sys.path.append(repo_str)

    bayan_gate = importlib.import_module("bayan_gate")
    catalog_copilot = importlib.import_module("catalog_copilot")
    message_shield = importlib.import_module("message_shield")

    _CACHED_BUNDLE = DependencyBundle(
        paths=paths,
        bayan_gate=bayan_gate,
        catalog_copilot=catalog_copilot,
        message_shield=message_shield,
        sources=sources,
        manifest_verified=manifest_ok,
    )
    return _CACHED_BUNDLE


def inspect_dependencies() -> Dict[str, Any]:
    """Returns structured diagnostics for resolved dependencies."""
    bundle = load_dependencies()
    manifest_ok, manifest_errs = verify_vendor_manifest()
    return {
        "dont_write_bytecode": bool(sys.dont_write_bytecode),
        "vendor_manifest_verified": manifest_ok,
        "vendor_manifest_errors": manifest_errs,
        "dependencies": bundle.metadata(),
    }
