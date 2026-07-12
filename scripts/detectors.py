#!/usr/bin/env python3
"""Shared secret-detection logic, re-exported for the plugin hook scripts.

The implementation lives in ctxguard/detectors.py (one shared location, no
duplication). This shim exists so hook code inside scripts/ can simply
`import detectors` without the package being pip-installed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctxguard.detectors import *  # noqa: E402,F401,F403
from ctxguard.detectors import __all__  # noqa: E402,F401
