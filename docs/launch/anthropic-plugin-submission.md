# Claude Code plugin submission draft

- **Plugin name:** ctxguard
- **Repository:** https://github.com/Ismail-Rhoulam/ctxguard
- **One-line description:** Blocks secrets, credentials, and sensitive files before they enter an AI coding agent's context window.
- **License:** MIT
- **Maintainer:** Ismail Rhoulam

## Detailed description

ctxguard is a local Claude Code plugin and standalone Python CLI. Its
`PreToolUse` hook inspects selected file, shell, and search tool inputs before
execution and denies calls that target sensitive filenames or contain likely
credentials. A capped `SessionStart` scan gives Claude a masked list of files to
avoid. The plugin and CLI share the same pattern- and entropy-based detectors.

## Installation

```text
/plugin marketplace add Ismail-Rhoulam/rhoulam
/plugin install ctxguard@rhoulam
/reload-plugins
```

Requires `python3` 3.9+ on `PATH`; installing the Python package is not required
for plugin use.

## Security and privacy

Detection runs locally. The project makes no network calls and includes no
telemetry. Findings are reported with masked matches. Private vulnerability
reports should use GitHub Security Advisories and must contain only synthetic
or revoked credentials.

## Limitations

Detection is heuristic and may miss secrets or flag benign values. ctxguard
blocks calls rather than redacting tool results. Bash inspection is incomplete,
large and binary files are not content-scanned, session scans are capped, and
hook errors fail open. It is not a sandbox, secret manager, or replacement for
repository scanning.

## Testing instructions

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
python3 scripts/demo.py
claude plugin validate .
claude --plugin-dir .
```

The synthetic demo must print `DENIED` and `Raw values printed: no`. No approval
or submission is claimed by this draft.
