"""Distribution, plugin layout, and safe demonstration tests."""

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import RAW_SECRETS, REPO_ROOT


def test_plugin_manifest_and_marketplace_are_consistent():
    manifest = json.loads(
        (REPO_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    marketplace = json.loads(
        (REPO_ROOT / ".claude-plugin" / "marketplace.json").read_text(
            encoding="utf-8"
        )
    )
    entry = marketplace["plugins"][0]
    assert manifest["name"] == entry["name"] == "ctxguard"
    assert manifest["version"] == entry["version"] == "0.1.0"
    assert entry["source"] == "."
    assert not (REPO_ROOT / "plugin.json").exists()


def test_hook_commands_resolve_in_plugin_root_with_spaces(tmp_path):
    plugin_root = tmp_path / "plugin root with spaces"
    plugin_root.symlink_to(REPO_ROOT, target_is_directory=True)
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text())
    command = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    command = command.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root))
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / ".env")},
        "cwd": str(tmp_path),
    }
    proc = subprocess.run(
        command,
        shell=True,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_plugin_hook_runs_without_installed_package(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / ".env")},
        "cwd": str(tmp_path),
    }
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        [sys.executable, "-I", str(REPO_ROOT / "scripts" / "pretooluse_guard.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=30,
    )
    assert proc.returncode == 2


def test_demo_denies_without_printing_values():
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "demo.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Tool call result: DENIED" in proc.stdout
    assert "Raw values printed: no" in proc.stdout
    assert "AKIAEXAMPLEONLY1234" not in proc.stdout + proc.stderr
    assert "sk_test_example_not_real" not in proc.stdout + proc.stderr
    for raw in RAW_SECRETS:
        assert raw not in proc.stdout + proc.stderr
