"""Read-only dependency resolver for BayanGate, CatalogCopilot, and MessageShield.

Prevents Python bytecode caches (.pyc/__pycache__) from being written into the
external read-only repositories by enforcing sys.dont_write_bytecode = True
prior to path injection and module import.
"""

from __future__ import annotations

import os
import sys

# MUST execute before importing any read-only sibling package.
sys.dont_write_bytecode = True

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


class DependencyLoadError(RuntimeError):
    """Raised when a required read-only local repository cannot be resolved."""


def _default_github_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_repo_paths() -> Dict[str, Path]:
    github_root = _default_github_root()
    return {
        "bayan_gate": Path(
            os.environ.get(
                "TIJARAGUARD_BAYAN_GATE_PATH",
                str(github_root / "bayan-gate" / "repo"),
            )
        ).resolve(),
        "catalog_copilot": Path(
            os.environ.get(
                "TIJARAGUARD_CATALOG_COPILOT_PATH",
                str(github_root / "catalog-copilot" / "repo"),
            )
        ).resolve(),
        "message_shield": Path(
            os.environ.get(
                "TIJARAGUARD_MESSAGE_SHIELD_PATH",
                str(github_root / "message-shield" / "repo"),
            )
        ).resolve(),
    }


@dataclass(frozen=True)
class DependencyBundle:
    """Container of verified read-only sibling modules and metadata."""

    paths: Dict[str, Path]
    bayan_gate: Any
    catalog_copilot: Any
    message_shield: Any

    def metadata(self) -> Dict[str, Dict[str, str]]:
        """Returns version and resolved read-only repository paths."""
        return {
            "bayan_gate": {
                "path": str(self.paths["bayan_gate"]),
                "version": str(getattr(self.bayan_gate, "__version__", "unknown")),
            },
            "catalog_copilot": {
                "path": str(self.paths["catalog_copilot"]),
                "version": str(getattr(self.catalog_copilot, "__version__", "unknown")),
            },
            "message_shield": {
                "path": str(self.paths["message_shield"]),
                "version": str(getattr(self.message_shield, "__version__", "unknown")),
            },
        }


_CACHED_BUNDLE: DependencyBundle | None = None


def load_dependencies() -> DependencyBundle:
    """Validates and imports the three read-only local dependency packages."""
    global _CACHED_BUNDLE
    sys.dont_write_bytecode = True
    if _CACHED_BUNDLE is not None:
        return _CACHED_BUNDLE

    paths = _resolve_repo_paths()
    expected_packages = {
        "bayan_gate": "bayan_gate",
        "catalog_copilot": "catalog_copilot",
        "message_shield": "message_shield",
    }

    for key, repo_path in paths.items():
        pkg_dir = repo_path / expected_packages[key]
        if not repo_path.is_dir() or not pkg_dir.is_dir():
            raise DependencyLoadError(
                f"Missing read-only dependency '{key}' at '{repo_path}'."
            )
        repo_str = str(repo_path)
        if repo_str not in sys.path:
            sys.path.append(repo_str)

    import bayan_gate  # type: ignore[import-not-found]
    import catalog_copilot  # type: ignore[import-not-found]
    import message_shield  # type: ignore[import-not-found]

    _CACHED_BUNDLE = DependencyBundle(
        paths=paths,
        bayan_gate=bayan_gate,
        catalog_copilot=catalog_copilot,
        message_shield=message_shield,
    )
    return _CACHED_BUNDLE


def inspect_dependencies() -> Dict[str, Any]:
    """Returns structured diagnostics for read-only local dependencies."""
    bundle = load_dependencies()
    return {
        "dont_write_bytecode": bool(sys.dont_write_bytecode),
        "dependencies": bundle.metadata(),
    }
