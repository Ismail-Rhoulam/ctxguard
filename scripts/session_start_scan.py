#!/usr/bin/env python3
"""SessionStart hook entry point for the ctxguard Claude Code plugin.

Thin wrapper: all logic lives in the ctxguard package, which sits next to
this scripts/ directory inside the plugin root, so no pip install is needed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctxguard.hooks import run_session_start  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_session_start())
