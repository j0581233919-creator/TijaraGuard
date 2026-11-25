"""Test package bootstrap preventing bytecode writes into read-only sibling repos."""

import sys

sys.dont_write_bytecode = True
