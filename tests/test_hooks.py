"""End-to-end tests of the hook scripts' stdin/stdout contract.

Each test invokes the actual plugin script in a subprocess, feeding hook
input JSON on stdin exactly as Claude Code does, and asserts on exit code
and the JSON emitted on stdout.
"""

import json
import subprocess
import sys

import pytest

from conftest import (
    API_TOKEN_VAL,
    PRETOOLUSE_SCRIPT,
    RAW_SECRETS,
    SECRETS_DIR,
    SESSION_START_SCRIPT,
    STRIPE_LIVE,
)

FIXTURE_ENV = SECRETS_DIR / "dotenv" / ".env"


def run_hook(script, payload, raw_stdin=None):
    stdin = raw_stdin if raw_stdin is not None else json.dumps(payload)
    return subprocess.run(
        [sys.executable, str(script)],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
    )


def pretooluse(tool_name, tool_input, cwd):
    return run_hook(
        PRETOOLUSE_SCRIPT,
        {
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": str(cwd),
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        },
    )


def decision_of(proc):
    output = json.loads(proc.stdout)
    hso = output["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    return hso


# ---------------------------------------------------------------------------
# Read / Edit / Write


class TestFileTools:
    def test_read_dotenv_denied(self, tmp_path):
        proc = pretooluse("Read", {"file_path": str(FIXTURE_ENV)}, tmp_path)
        assert proc.returncode == 2
        hso = decision_of(proc)
        assert hso["permissionDecision"] == "deny"
        assert ".env" in hso["permissionDecisionReason"]
        assert "additionalContext" in hso
        assert proc.stderr.strip()

    @pytest.mark.parametrize("tool", ["Read", "Edit", "Write"])
    def test_all_file_tools_guarded(self, tool, tmp_path):
        proc = pretooluse(tool, {"file_path": str(FIXTURE_ENV)}, tmp_path)
        assert proc.returncode == 2

    def test_read_clean_file_allowed(self, tmp_path):
        clean = tmp_path / "notes.md"
        clean.write_text("nothing secret here\n", encoding="utf-8")
        proc = pretooluse("Read", {"file_path": str(clean)}, tmp_path)
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""

    def test_relative_path_resolved_against_cwd(self):
        proc = pretooluse("Read", {"file_path": "dotenv/.env"}, SECRETS_DIR)
        assert proc.returncode == 2

    def test_nonexistent_env_still_denied_by_name(self, tmp_path):
        proc = pretooluse("Read", {"file_path": str(tmp_path / ".env")}, tmp_path)
        assert proc.returncode == 2

    def test_secret_values_never_in_output(self, tmp_path):
        proc = pretooluse("Read", {"file_path": str(FIXTURE_ENV)}, tmp_path)
        combined = proc.stdout + proc.stderr
        for raw in RAW_SECRETS:
            assert raw not in combined
            assert raw[4:-2] not in combined


# ---------------------------------------------------------------------------
# Bash


class TestBash:
    def test_cat_env_denied(self, tmp_path):
        proc = pretooluse("Bash", {"command": "cat .env"}, tmp_path)
        assert proc.returncode == 2
        assert decision_of(proc)["permissionDecision"] == "deny"

    def test_inline_secret_denied(self, tmp_path):
        command = f"curl -H 'Authorization: Bearer {STRIPE_LIVE}'"
        proc = pretooluse("Bash", {"command": command}, tmp_path)
        assert proc.returncode == 2
        assert STRIPE_LIVE not in proc.stdout + proc.stderr

    def test_env_dump_denied(self, tmp_path):
        proc = pretooluse("Bash", {"command": "env | grep AWS"}, tmp_path)
        assert proc.returncode == 2

    def test_harmless_command_allowed(self, tmp_path):
        proc = pretooluse("Bash", {"command": "ls -la && git status"}, tmp_path)
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Grep / Glob


class TestSearchTools:
    def test_grep_sensitive_path_denied(self, tmp_path):
        proc = pretooluse(
            "Grep", {"pattern": "TODO", "path": str(FIXTURE_ENV)}, tmp_path
        )
        assert proc.returncode == 2

    def test_grep_sensitive_glob_denied(self, tmp_path):
        proc = pretooluse(
            "Grep", {"pattern": "x", "glob": "*.pem", "path": str(tmp_path)}, tmp_path
        )
        assert proc.returncode == 2

    def test_grep_normal_search_allowed(self, tmp_path):
        proc = pretooluse(
            "Grep", {"pattern": "def main", "path": str(tmp_path)}, tmp_path
        )
        assert proc.returncode == 0

    def test_glob_env_pattern_denied(self, tmp_path):
        proc = pretooluse("Glob", {"pattern": "**/.env"}, tmp_path)
        assert proc.returncode == 2

    def test_glob_broad_pattern_allowed(self, tmp_path):
        for pattern in ("**/*.py", "*", "src/**"):
            proc = pretooluse("Glob", {"pattern": pattern}, tmp_path)
            assert proc.returncode == 0, pattern


# ---------------------------------------------------------------------------
# Config-driven behavior: warn mode, allowlist


class TestModes:
    def test_warn_mode_allows_with_warning(self, tmp_path):
        (tmp_path / ".ctxguard.toml").write_text('mode = "warn"\n', encoding="utf-8")
        env = tmp_path / ".env"
        env.write_text(f"API_TOKEN={API_TOKEN_VAL}\n", encoding="utf-8")
        proc = pretooluse("Read", {"file_path": str(env)}, tmp_path)
        assert proc.returncode == 0
        hso = decision_of(proc)
        assert hso["permissionDecision"] == "allow"
        assert "warning" in hso["additionalContext"].lower()
        assert API_TOKEN_VAL not in proc.stdout + proc.stderr

    def test_allowlisted_path_allowed_silently(self, tmp_path):
        (tmp_path / ".ctxguard.toml").write_text(
            'allowlist = ["fixtures/*"]\n', encoding="utf-8"
        )
        env = tmp_path / "fixtures" / ".env"
        env.parent.mkdir()
        env.write_text(f"API_TOKEN={API_TOKEN_VAL}\n", encoding="utf-8")
        proc = pretooluse("Read", {"file_path": str(env)}, tmp_path)
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Robustness: the hook must fail open, never break a session


class TestFailOpen:
    def test_invalid_json_stdin(self):
        proc = run_hook(PRETOOLUSE_SCRIPT, None, raw_stdin="this is not json")
        assert proc.returncode == 0

    def test_empty_stdin(self):
        proc = run_hook(PRETOOLUSE_SCRIPT, None, raw_stdin="")
        assert proc.returncode == 0

    def test_unknown_tool_allowed(self, tmp_path):
        proc = pretooluse("WebFetch", {"url": "https://example.com"}, tmp_path)
        assert proc.returncode == 0

    def test_missing_tool_input(self, tmp_path):
        proc = run_hook(
            PRETOOLUSE_SCRIPT,
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "cwd": str(tmp_path),
            },
        )
        assert proc.returncode == 0


# ---------------------------------------------------------------------------
# SessionStart


class TestSessionStart:
    def test_flags_repo_with_secrets(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text(f"API_TOKEN={API_TOKEN_VAL}\n", encoding="utf-8")
        (tmp_path / "readme.md").write_text("hello\n", encoding="utf-8")
        proc = run_hook(
            SESSION_START_SCRIPT,
            {
                "hook_event_name": "SessionStart",
                "source": "startup",
                "cwd": str(tmp_path),
            },
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        hso = output["hookSpecificOutput"]
        assert hso["hookEventName"] == "SessionStart"
        assert "potential secret" in hso["additionalContext"]
        assert ".env" in hso["additionalContext"]
        assert API_TOKEN_VAL not in proc.stdout + proc.stderr

    def test_silent_on_clean_repo(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
        proc = run_hook(
            SESSION_START_SCRIPT,
            {
                "hook_event_name": "SessionStart",
                "source": "startup",
                "cwd": str(tmp_path),
            },
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == ""

    def test_fail_open_on_garbage_stdin(self):
        proc = run_hook(SESSION_START_SCRIPT, None, raw_stdin="{broken")
        assert proc.returncode == 0
