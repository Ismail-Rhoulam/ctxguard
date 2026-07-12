"""ctxguard command-line interface.

Commands:
    ctxguard scan [path] [--json]   audit a repo for secrets (exit 1 if found)
    ctxguard init [path] [--yes]    write .ctxguard.toml and register hooks
    ctxguard hook <event>           run a hook handler (used by Claude Code)
    ctxguard --version
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import detectors as det

DEFAULT_TOML = """\
# ctxguard configuration. See https://github.com/irhoulam/ctxguard
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


def _register_hooks(settings: dict) -> bool:
    """Merge ctxguard hook entries into a settings dict. True if changed."""
    hooks = settings.setdefault("hooks", {})
    changed = False
    for event, entry in _hook_settings_entries().items():
        entries = hooks.setdefault(event, [])
        already = any(
            "ctxguard" in hook.get("command", "")
            for item in entries
            if isinstance(item, dict)
            for hook in item.get("hooks", [])
            if isinstance(hook, dict)
        )
        if not already:
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

    hook_parser = sub.add_parser(
        "hook", help="run a Claude Code hook handler (internal)"
    )
    hook_parser.add_argument("event", choices=["pretooluse", "session-start"])

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "hook":
        return _cmd_hook(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
