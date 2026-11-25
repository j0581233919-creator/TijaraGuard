"""Module execution entrypoint for `python3 -B -m tijaraguard`."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
