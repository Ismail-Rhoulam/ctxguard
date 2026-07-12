#!/usr/bin/env python3
"""Safe, deterministic ctxguard demonstration using synthetic values only."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    hook = root / "scripts" / "pretooluse_guard.py"
    fake_values = (
        "AWS_ACCESS_KEY_ID=AKIAEXAMPLEONLY1234\n"
        "STRIPE_SECRET_KEY=sk_test_example_not_real\n"
    )

    with tempfile.TemporaryDirectory(prefix="ctxguard-demo-") as directory:
        project = Path(directory)
        target = project / ".env"
        target.write_text(fake_values, encoding="utf-8")
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
            "cwd": str(project),
        }
        proc = subprocess.run(
            [sys.executable, str(hook)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
        )

    print("1. Claude Code attempts: Read .env")
    print("2. ctxguard intercepts: PreToolUse")
    print(f"3. Tool call result: {'DENIED' if proc.returncode == 2 else 'ALLOWED'}")
    if proc.stdout:
        reason = json.loads(proc.stdout)["hookSpecificOutput"][
            "permissionDecisionReason"
        ]
        print(f"4. Explanation: {reason}")
    print("5. Raw values printed: no")
    return 0 if proc.returncode == 2 and "EXAMPLEONLY" not in proc.stdout else 1


if __name__ == "__main__":
    raise SystemExit(main())
