"""Claude Code hook handlers for ctxguard.

Both handlers read the hook input JSON from stdin and follow the Claude Code
hooks contract:

- PreToolUse deny: exit code 2 plus a JSON `hookSpecificOutput` payload with
  `permissionDecision: "deny"` on stdout, and a human-readable reason on
  stderr. Warn mode allows the call (exit 0) but injects a warning via
  `additionalContext`.
- SessionStart: exit 0 with `additionalContext` summarizing a fast repo scan.

Every unexpected error fails open (exit 0): a broken hook must never take
down a session.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional, TextIO

from . import detectors as det

GUARDED_FILE_TOOLS = {"Read", "Edit", "Write"}

_ADVICE = (
    "Do not read this content into context. Suggested fixes: keep secrets in a "
    "secrets manager or untracked local env, ensure the file is in .gitignore, "
    'or allowlist a false positive in .ctxguard.toml (allowlist = ["<pattern>"]).'
)


def _describe(finding: det.Finding) -> str:
    where = finding.file or "tool input"
    if finding.pattern_name == "sensitive_filename":
        return f"{where}: sensitive file by name: {finding.matched_snippet_masked}"
    loc = f"{where}:{finding.line_number}" if finding.line_number else where
    return (
        f"{loc}: {finding.pattern_name} "
        f"({finding.matched_snippet_masked}, {finding.confidence} confidence)"
    )


def _pretooluse_payload(decision: str, reason: str) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
                "additionalContext": reason,
            }
        }
    )


def _resolve(path_str: str, cwd: Path) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else cwd / p


def _check_file_tool(tool_input: dict, cwd: Path, config: det.Config) -> List[str]:
    file_path = str(tool_input.get("file_path") or "")
    if not file_path:
        return []
    path = _resolve(file_path, cwd)
    display = file_path
    findings = det.scan_file(path, config, display=display)
    return [_describe(f) for f in findings]


def _check_bash_tool(tool_input: dict, config: det.Config) -> List[str]:
    command = str(tool_input.get("command") or "")
    if not command:
        return []
    analysis = det.analyze_bash_command(command, config)
    reasons: List[str] = []
    for finding in analysis.inline_secrets:
        reasons.append(
            f"command contains a secret literal: {finding.pattern_name} "
            f"({finding.matched_snippet_masked})"
        )
    for name in analysis.sensitive_reads:
        reasons.append(f"command reads sensitive file: {name}")
    if analysis.env_dump:
        reasons.append(
            "command prints environment variables, which may contain credentials"
        )
    return reasons


def _check_grep_tool(tool_input: dict, config: det.Config) -> List[str]:
    reasons: List[str] = []
    target = str(tool_input.get("path") or "")
    if target:
        reason = det.sensitive_filename_reason(target)
        if reason and not det.is_allowlisted(target, config):
            reasons.append(
                f"search target {Path(target).name} is a sensitive file ({reason})"
            )
    glob = str(tool_input.get("glob") or "")
    if glob:
        probe = det.pattern_targets_sensitive(glob)
        if probe:
            reasons.append(
                f"glob filter {glob!r} targets sensitive files (e.g. {probe})"
            )
    return reasons


def _check_glob_tool(tool_input: dict, config: det.Config) -> List[str]:
    pattern = str(tool_input.get("pattern") or "")
    probe = det.pattern_targets_sensitive(pattern)
    if probe:
        return [f"glob pattern {pattern!r} targets sensitive files (e.g. {probe})"]
    return []


def _handle_pretooluse(data: dict, stdout: TextIO, stderr: TextIO) -> int:
    tool_name = str(data.get("tool_name") or "")
    tool_input = data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return 0
    cwd = Path(str(data.get("cwd") or os.getcwd()))
    config = det.load_config(cwd)

    if tool_name in GUARDED_FILE_TOOLS:
        reasons = _check_file_tool(tool_input, cwd, config)
    elif tool_name == "Bash":
        reasons = _check_bash_tool(tool_input, config)
    elif tool_name == "Grep":
        reasons = _check_grep_tool(tool_input, config)
    elif tool_name == "Glob":
        reasons = _check_glob_tool(tool_input, config)
    else:
        reasons = []

    if not reasons:
        return 0

    summary = "; ".join(reasons)
    if config.mode == "warn":
        reason = (
            f"ctxguard warning (mode=warn, call allowed): {summary}. "
            "Avoid echoing any secret values back in your response."
        )
        print(_pretooluse_payload("allow", reason), file=stdout)
        print(f"ctxguard [warn] {tool_name}: {summary}", file=stderr)
        return 0

    reason = f"ctxguard blocked this {tool_name} call: {summary}. {_ADVICE}"
    print(_pretooluse_payload("deny", reason), file=stdout)
    print(f"ctxguard [block] {tool_name}: {summary}", file=stderr)
    return 2


def run_pretooluse(
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    try:
        data = json.load(stdin)
        if not isinstance(data, dict):
            return 0
        return _handle_pretooluse(data, stdout, stderr)
    except Exception as exc:  # fail open, never break the session
        print(f"ctxguard: hook error ({exc}); allowing tool call", file=stderr)
        return 0


# ---------------------------------------------------------------------------
# SessionStart

_SESSION_MAX_FILES = 4000
_SESSION_TIME_BUDGET = 0.8  # seconds


def _session_summary(findings: List[det.Finding], truncated: bool, mode: str) -> str:
    per_file = Counter(f.file or "?" for f in findings)
    parts = [f"{count} in {name}" for name, count in per_file.most_common(5)]
    more = len(per_file) - 5
    if more > 0:
        parts.append(f"and {more} more file(s)")
    categories = Counter(f.pattern_name for f in findings)
    category_text = ", ".join(
        f"{name} x{count}" for name, count in categories.most_common()
    )
    note = " (scan truncated for speed)" if truncated else ""
    return (
        f"ctxguard: {len(findings)} potential secret(s) in {len(per_file)} file(s){note}: "
        f"{', '.join(parts)}. Categories: {category_text}. Mode is '{mode}': "
        f"{'reads of these will be blocked' if mode == 'block' else 'reads will be allowed with warnings'}. "
        "Never read or echo these files' contents. Run `ctxguard scan` for a full masked report."
    )


def run_session_start(
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    try:
        try:
            data = json.load(stdin)
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        cwd = Path(str(data.get("cwd") or os.getcwd()))
        config = det.load_config(cwd)
        findings, _scanned, truncated = det.scan_path(
            cwd, config, max_files=_SESSION_MAX_FILES, time_budget=_SESSION_TIME_BUDGET
        )
        if not findings:
            return 0
        payload = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": _session_summary(findings, truncated, config.mode),
            }
        }
        print(json.dumps(payload), file=stdout)
        return 0
    except Exception as exc:  # fail open
        print(f"ctxguard: session scan error ({exc})", file=stderr)
        return 0
