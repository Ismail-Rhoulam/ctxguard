"""ctxguard command-line interface.

Commands:
    ctxguard scan [path] [--json]   audit a repo for secrets (exit 1 if found)
    ctxguard init [path] [--yes]    write .ctxguard.toml and register hooks
    ctxguard doctor [path] [--json] verify PATH resolution and hook registration
    ctxguard hook <event>           run a hook handler (used by Claude Code)
    ctxguard --version
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import detectors as det

DEFAULT_TOML = """\
# ctxguard configuration. See https://github.com/Ismail-Rhoulam/ctxguard
# mode: "block" denies flagged tool calls; "warn" allows them but injects a warning.
mode = "block"

# Paths or fnmatch patterns that ctxguard should never flag (e.g. test fixtures).
allowlist = [
    # "tests/fixtures/*",
]

# Extra detection patterns. Uncomment and adapt:
# [[custom_patterns]]
# name = "acme_internal_token"
# regex = "acme_[A-Za-z0-9]{32}"
# confidence = "high"
"""

_HOOK_TIMEOUT = 10

_CONFIDENCE_STYLE = {"high": "red", "medium": "yellow", "low": "cyan"}


def _hook_settings_entries() -> dict:
    return {
        "PreToolUse": {
            "matcher": "Read|Edit|Write|Bash|Grep|Glob",
            "hooks": [
                {
                    "type": "command",
                    "command": "ctxguard hook pretooluse",
                    "timeout": _HOOK_TIMEOUT,
                }
            ],
        },
        "SessionStart": {
            "hooks": [
                {
                    "type": "command",
                    "command": "ctxguard hook session-start",
                    "timeout": _HOOK_TIMEOUT,
                }
            ],
        },
    }


# ---------------------------------------------------------------------------
# scan


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"ctxguard: path not found: {root}", file=sys.stderr)
        return 2
    config = det.load_config(root)
    findings, scanned, _truncated = det.scan_path(root, config)
    findings.sort(key=lambda f: (f.file or "", f.line_number))
    flagged_files = sorted({f.file or "?" for f in findings})

    if args.as_json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "path": str(root),
                    "mode": config.mode,
                    "files_scanned": scanned,
                    "files_flagged": len(flagged_files),
                    "findings_count": len(findings),
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
            )
        )
        return 1 if findings else 0

    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    if not findings:
        console.print(
            f"[bold green]clean[/] - scanned {scanned} file(s) under {root}, "
            "no potential secrets found."
        )
        return 0

    for file in flagged_files:
        table = Table(
            title=f"[bold]{file}[/]",
            title_justify="left",
            show_edge=True,
            header_style="bold dim",
        )
        table.add_column("line", justify="right", style="dim")
        table.add_column("pattern")
        table.add_column("match (masked)", style="bold")
        table.add_column("confidence")
        for f in findings:
            if (f.file or "?") != file:
                continue
            style = _CONFIDENCE_STYLE.get(f.confidence, "white")
            table.add_row(
                str(f.line_number) if f.line_number else "-",
                f.pattern_name,
                f.matched_snippet_masked,
                f"[{style}]{f.confidence}[/]",
            )
        console.print(table)

    console.print(
        Panel(
            f"[bold red]{len(findings)} potential secret(s)[/] in "
            f"{len(flagged_files)} file(s) ({scanned} scanned). "
            "Values are masked; nothing was transmitted anywhere.",
            border_style="red",
        )
    )
    return 1


# ---------------------------------------------------------------------------
# init


def _entries_have_ctxguard(entries: object) -> bool:
    """True if a hooks[event] list already contains a ctxguard-invoking entry."""
    if not isinstance(entries, list):
        return False
    return any(
        "ctxguard" in hook.get("command", "")
        for item in entries
        if isinstance(item, dict)
        for hook in item.get("hooks", [])
        if isinstance(hook, dict)
    )


def _register_hooks(settings: dict) -> bool:
    """Merge ctxguard hook entries into a settings dict. True if changed."""
    hooks = settings.setdefault("hooks", {})
    changed = False
    for event, entry in _hook_settings_entries().items():
        entries = hooks.setdefault(event, [])
        if not _entries_have_ctxguard(entries):
            entries.append(entry)
            changed = True
    return changed


def _cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"ctxguard: not a directory: {root}", file=sys.stderr)
        return 2

    config_path = root / det.CONFIG_FILENAME
    if config_path.exists():
        print(f"ctxguard: {config_path.name} already exists, leaving it untouched.")
    else:
        config_path.write_text(DEFAULT_TOML, encoding="utf-8")
        print(f"ctxguard: wrote {config_path}")

    settings_path = root / ".claude" / "settings.json"
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ctxguard: cannot parse {settings_path}: {exc}", file=sys.stderr)
            return 2
        if not isinstance(settings, dict):
            print(
                f"ctxguard: unexpected settings format in {settings_path}",
                file=sys.stderr,
            )
            return 2
        preview = json.dumps({"hooks": _hook_settings_entries()}, indent=2)
        if not _register_hooks(json.loads(json.dumps(settings))):
            print("ctxguard: hooks already registered in .claude/settings.json")
            return 0
        if not args.yes:
            if not sys.stdin.isatty():
                print(
                    "ctxguard: .claude/settings.json exists; re-run with --yes to "
                    f"modify it, or add this yourself:\n{preview}"
                )
                return 0
            answer = input(f"Modify {settings_path} to register ctxguard hooks? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print(
                    f"ctxguard: skipped. Add this to {settings_path} manually:\n{preview}"
                )
                return 0
        _register_hooks(settings)
        settings_path.write_text(
            json.dumps(settings, indent=2) + "\n", encoding="utf-8"
        )
        print(f"ctxguard: registered hooks in {settings_path}")
    else:
        settings = {}
        _register_hooks(settings)
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(
            json.dumps(settings, indent=2) + "\n", encoding="utf-8"
        )
        print(f"ctxguard: created {settings_path} with ctxguard hooks")

    print("ctxguard: done. Start a new Claude Code session to activate the hooks.")
    return 0


# ---------------------------------------------------------------------------
# doctor


def _check_python_version() -> dict:
    ok = sys.version_info >= (3, 9)
    version = ".".join(str(part) for part in sys.version_info[:3])
    return {
        "name": "python_version",
        "status": "ok" if ok else "fail",
        "detail": f"Python {version}" + ("" if ok else " (ctxguard requires 3.9+)"),
    }


def _check_path_resolution() -> tuple:
    """Returns (check_dict, resolved_path_or_None)."""
    resolved = shutil.which("ctxguard")
    if resolved is None:
        return (
            {
                "name": "path_resolution",
                "status": "fail",
                "detail": (
                    "`ctxguard` was not found on PATH. The standalone hooks "
                    "registered by `ctxguard init` invoke it by name at "
                    "session/tool-call time, so Claude Code won't be able to "
                    "run them. (Not needed if you installed ctxguard as a "
                    "Claude Code plugin instead - those hooks call python3 "
                    "directly.) Try `pip install ctxguard` or check your venv "
                    "is activated in the shell Claude Code launches from."
                ),
            },
            None,
        )
    return (
        {"name": "path_resolution", "status": "ok", "detail": resolved},
        resolved,
    )


def _check_version_match(resolved_path: Optional[str]) -> Optional[dict]:
    if resolved_path is None:
        return None
    try:
        out = subprocess.run(
            [resolved_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "name": "version_match",
            "status": "fail",
            "detail": f"could not run `{resolved_path} --version`: {exc}",
        }
    running = f"ctxguard {__version__}"
    if out == running:
        return {"name": "version_match", "status": "ok", "detail": out}
    return {
        "name": "version_match",
        "status": "warn",
        "detail": (
            f"PATH resolves to {out!r} but this check is running from "
            f"{running!r}. Multiple installs may be shadowing each other."
        ),
    }


def _check_settings_and_hooks(root: Path) -> List[dict]:
    settings_path = root / ".claude" / "settings.json"
    if not settings_path.exists():
        msg = (
            f"{settings_path} does not exist. Run `ctxguard init` to create it "
            "and register the hooks."
        )
        return [
            {"name": "settings_file", "status": "fail", "detail": msg},
            {"name": "pretooluse_hook", "status": "fail", "detail": "not registered"},
            {"name": "sessionstart_hook", "status": "fail", "detail": "not registered"},
        ]

    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"{settings_path} could not be parsed: {exc}"
        return [
            {"name": "settings_file", "status": "fail", "detail": msg},
            {
                "name": "pretooluse_hook",
                "status": "fail",
                "detail": "unknown (settings file invalid)",
            },
            {
                "name": "sessionstart_hook",
                "status": "fail",
                "detail": "unknown (settings file invalid)",
            },
        ]

    checks = [{"name": "settings_file", "status": "ok", "detail": str(settings_path)}]
    hooks = settings.get("hooks", {}) if isinstance(settings, dict) else {}
    expected = _hook_settings_entries()

    for event, key in (
        ("PreToolUse", "pretooluse_hook"),
        ("SessionStart", "sessionstart_hook"),
    ):
        entries = hooks.get(event, []) if isinstance(hooks, dict) else []
        if not _entries_have_ctxguard(entries):
            checks.append(
                {
                    "name": key,
                    "status": "fail",
                    "detail": f"no ctxguard entry under hooks.{event}; run `ctxguard init`",
                }
            )
            continue
        if event == "PreToolUse":
            expected_matcher = expected["PreToolUse"]["matcher"]
            matchers = [
                item.get("matcher")
                for item in entries
                if isinstance(item, dict) and _entries_have_ctxguard([item])
            ]
            if expected_matcher not in matchers:
                checks.append(
                    {
                        "name": key,
                        "status": "warn",
                        "detail": (
                            f"registered, but matcher is {matchers!r}, expected "
                            f"{expected_matcher!r}; some tool calls may not be guarded"
                        ),
                    }
                )
                continue
        checks.append({"name": key, "status": "ok", "detail": "registered"})
    return checks


def _check_config_file(root: Path) -> dict:
    config_path = root / det.CONFIG_FILENAME
    if not config_path.exists():
        return {
            "name": "config_file",
            "status": "warn",
            "detail": f"{config_path} not found; using built-in defaults (mode=block, no allowlist)",
        }
    if det._toml is None:
        return {
            "name": "config_file",
            "status": "warn",
            "detail": f"{config_path} exists but no TOML parser is available to validate it",
        }
    try:
        det._toml.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "name": "config_file",
            "status": "fail",
            "detail": f"{config_path} has invalid TOML syntax: {exc}",
        }
    return {"name": "config_file", "status": "ok", "detail": str(config_path)}


def _check_hook_smoke_test(resolved_path: Optional[str], root: Path) -> Optional[dict]:
    if resolved_path is None:
        return None
    payload = json.dumps(
        {
            "cwd": str(root),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(root / "ctxguard-doctor-smoke-test.tmp")},
        }
    )
    try:
        proc = subprocess.run(
            [resolved_path, "hook", "pretooluse"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "name": "hook_smoke_test",
            "status": "fail",
            "detail": f"`{resolved_path} hook pretooluse` could not be run: {exc}",
        }
    if proc.returncode != 0:
        return {
            "name": "hook_smoke_test",
            "status": "fail",
            "detail": (
                f"`{resolved_path} hook pretooluse` on a benign, non-existent "
                f"path exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}"
            ),
        }
    return {
        "name": "hook_smoke_test",
        "status": "ok",
        "detail": "end-to-end hook invocation succeeded",
    }


def _cmd_doctor(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"ctxguard: not a directory: {root}", file=sys.stderr)
        return 2

    path_check, resolved = _check_path_resolution()
    checks = [_check_python_version(), path_check]
    version_check = _check_version_match(resolved)
    if version_check is not None:
        checks.append(version_check)
    checks.extend(_check_settings_and_hooks(root))
    checks.append(_check_config_file(root))
    smoke_check = _check_hook_smoke_test(resolved, root)
    if smoke_check is not None:
        checks.append(smoke_check)

    failed = any(c["status"] == "fail" for c in checks)

    if args.as_json:
        print(
            json.dumps(
                {"path": str(root), "healthy": not failed, "checks": checks}, indent=2
            )
        )
        return 1 if failed else 0

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(
        title="ctxguard doctor",
        title_justify="left",
        show_edge=True,
        header_style="bold dim",
    )
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")
    icon = {
        "ok": "[bold green]ok[/]",
        "warn": "[bold yellow]warn[/]",
        "fail": "[bold red]fail[/]",
    }
    for c in checks:
        table.add_row(c["name"], icon.get(c["status"], c["status"]), c["detail"])
    console.print(table)

    if failed:
        console.print(
            "[bold red]ctxguard is not fully set up.[/] See the failed checks above."
        )
    else:
        console.print("[bold green]ctxguard is set up correctly.[/]")
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# hook (internal, used by the settings.json registration)


def _cmd_hook(args: argparse.Namespace) -> int:
    from .hooks import run_pretooluse, run_session_start

    if args.event == "pretooluse":
        return run_pretooluse()
    return run_session_start()


# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ctxguard",
        description="Keep secrets out of your AI agent's context window.",
    )
    parser.add_argument(
        "--version", action="version", version=f"ctxguard {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="scan a file or directory for secrets")
    scan_parser.add_argument(
        "path", nargs="?", default=".", help="file or directory (default: .)"
    )
    scan_parser.add_argument(
        "--json", dest="as_json", action="store_true", help="machine-readable output"
    )

    init_parser = sub.add_parser(
        "init", help="write .ctxguard.toml and register Claude Code hooks"
    )
    init_parser.add_argument(
        "path", nargs="?", default=".", help="project root (default: .)"
    )
    init_parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="modify an existing .claude/settings.json without prompting",
    )

    doctor_parser = sub.add_parser(
        "doctor",
        help="verify PATH resolution and Claude Code hook registration",
    )
    doctor_parser.add_argument(
        "path", nargs="?", default=".", help="project root (default: .)"
    )
    doctor_parser.add_argument(
        "--json", dest="as_json", action="store_true", help="machine-readable output"
    )

    hook_parser = sub.add_parser(
        "hook", help="run a Claude Code hook handler (internal)"
    )
    hook_parser.add_argument("event", choices=["pretooluse", "session-start"])

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "hook":
        return _cmd_hook(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
