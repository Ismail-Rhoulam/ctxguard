# ctxguard

**Your AI agent should never see your API keys. This makes sure it doesn't.**

ctxguard is a Claude Code plugin plus a standalone CLI that stops secrets, credentials, and sensitive files from entering the model's context window. It hooks Claude Code's `PreToolUse` event for `Read`, `Edit`, `Write`, `Bash`, `Grep`, and `Glob`, scans the target before the tool runs, and denies the call when it detects a likely secret. Claude gets a clear, masked explanation instead of your credentials.

## 30-second install

```bash
pip install ctxguard && ctxguard init
```

`ctxguard init` writes a default `.ctxguard.toml` and registers the hooks in `.claude/settings.json` (it asks before touching an existing settings file). Start a new Claude Code session and you are protected.

Prefer the plugin route? Install this repo as a Claude Code plugin (see [Installing as a plugin](#installing-as-a-plugin)) and skip `init` entirely.

## How it works

Claude Code hooks can allow, deny, or ask about a tool call. They cannot rewrite what a tool returns. ctxguard is therefore **block-and-report, not silent redaction**: when a tool call would pull a likely secret into context, the call is denied with exit code 2 and Claude receives a masked, human-readable reason it can act on (for example, suggesting you add the file to `.gitignore` or move the value to a secrets manager). Nothing is ever redacted in flight, and the raw secret value never appears in any output, log, or report; matches are always masked to the first 4 and last 2 characters.

Three layers:

1. **PreToolUse guard**: checks `Read`/`Edit`/`Write` file paths (by filename and, for small text files, by content), `Bash` commands (reads of sensitive files, environment dumps, and secret literals inline in the command), and `Grep`/`Glob` patterns that specifically target sensitive files.
2. **SessionStart scan**: a fast, capped scan of the project at session start that injects a masked summary ("3 potential secrets in 2 files...") so Claude knows which files to avoid. It skips `.git`, gitignored files, binaries, and anything over 1 MB, and is budgeted to finish in well under a second.
3. **Standalone CLI**: `ctxguard scan` audits a whole repo outside any session, with a pretty terminal report or `--json` for CI. Exit code 1 when findings exist, 0 when clean.

## What it detects

- AWS access key IDs and secret access keys
- GitHub personal access tokens (classic and fine-grained)
- Slack tokens (`xoxb-`, `xoxp-`, ...)
- Stripe live and test secret keys
- Private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- JWT-shaped strings
- `KEY=` / `TOKEN=` / `SECRET=` / `PASSWORD=` assignments with non-trivial values (length, digit, and entropy thresholds filter out placeholders like `TOKEN=your-key-here`)
- High-entropy strings assigned to any variable whose name contains `key`, `secret`, `token`, `password`, or `credential`
- Sensitive files by name alone, regardless of content: `.env`, `.env.*` (except `.env.example` and friends), `id_rsa`, `id_ed25519`, `*.pem`, `*.pfx`, `credentials.json`, `service-account*.json`, and similar

Detection is pattern- and entropy-based, entirely local, with no network calls and no ML.

## Configuration

Copy `.ctxguard.toml.example` to `.ctxguard.toml` in your project root (or let `ctxguard init` write one):

```toml
# "block" denies flagged tool calls; "warn" allows them but injects a warning.
mode = "block"

# fnmatch patterns ctxguard should never flag (test fixtures, examples).
allowlist = [
    "tests/fixtures/*",
]

# Your own patterns, applied everywhere the built-ins are.
[[custom_patterns]]
name = "acme_internal_token"
regex = "acme_[A-Za-z0-9]{32}"
confidence = "high"
```

## CLI usage

```bash
ctxguard scan              # scan the current directory, pretty report
ctxguard scan path/ --json # machine-readable, for CI (exit 1 if findings)
ctxguard init              # write config + register hooks in .claude/settings.json
ctxguard --version
```

## Installing as a plugin

The repo is a self-contained Claude Code plugin: `plugin.json` plus `hooks/hooks.json` register the two hook scripts via `${CLAUDE_PLUGIN_ROOT}`, so no pip install is needed inside the plugin. Add it through Claude Code's plugin system (for example from a marketplace entry pointing at this repo), then verify with a new session: ask Claude to read a `.env` file and it should be denied with a ctxguard message, and `/hooks` should list both registrations.

## Honest limitations

- Pattern and entropy matching cannot catch every secret format. A secret that looks like plain prose will slip through; an unusual but random-looking value might only be caught if its variable name suggests a credential. Treat ctxguard as a strong seatbelt, not a cryptographic guarantee.
- ctxguard blocks tool calls; it does not redact. If a secret is already inside a file Claude legitimately reads (say, buried in an otherwise normal source file under the thresholds), it can still surface.
- The Bash guard is heuristic. It catches common read patterns (`cat .env`, `env | grep ...`, secrets inline in commands), not every possible shell construction.
- Hooks require `python3` on PATH (Python 3.9+; no third-party packages needed for the hooks themselves).

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

Scanning this repo with ctxguard flags the files under `tests/fixtures/`: that is expected, they exist to be found.

## Contributing

Issues and PRs welcome. Useful contributions, roughly in order of impact:

- New detector patterns (add the regex to `ctxguard/detectors.py` **with both a positive and a negative fixture** and tests for each)
- False-positive reports: real-world values that got flagged and should not be
- A `--fix` mode that appends flagged files to `.gitignore`

Keep detection logic in `ctxguard/detectors.py` only; the hooks and the CLI both import from there. Run the full test suite before submitting.

## License

MIT, see [LICENSE](LICENSE).
