# ctxguard

[![CI](https://github.com/Ismail-Rhoulam/ctxguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Ismail-Rhoulam/ctxguard/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Your AI coding agent should never see your API keys.**

**ctxguard blocks secrets before they enter the model's context.**

ctxguard is a local Claude Code plugin and standalone Python CLI. It intercepts
sensitive tool calls before execution and returns a masked explanation instead
of letting likely secrets, credentials, or sensitive files enter context.

<!-- Add demo GIF here: docs/assets/ctxguard-demo.gif -->

## 30-second installation

### Claude Code plugin (no Python package install)

Inside Claude Code, add this repository as a marketplace and install ctxguard:

```text
/plugin marketplace add Ismail-Rhoulam/ctxguard
/plugin install ctxguard@ctxguard-plugins
/reload-plugins
```

The plugin includes its own Python source. It requires `python3` 3.9 or newer
on `PATH`, but does not require `pip install ctxguard`.

For local development, run `claude --plugin-dir .` from this repository.

### Standalone CLI

```bash
python3 -m pip install ctxguard
ctxguard init
```

`ctxguard init` creates `.ctxguard.toml` if absent and registers CLI-backed
hooks in `.claude/settings.json`. If that settings file already exists, ctxguard
asks before modifying it; non-interactive use requires the explicit `--yes`
flag. It merges entries and preserves unrelated settings.

## Why ctxguard?

| Tool | Primary protection |
| --- | --- |
| `.gitignore` | Prevents selected files from being committed |
| Gitleaks / TruffleHog | Detects secrets in repositories and commits |
| ctxguard | Blocks sensitive content before an AI coding agent reads it |

ctxguard complements repository scanners; it does not replace them. Gitleaks
and TruffleHog protect repository history and workflows. ctxguard addresses a
different boundary: the agent tool call immediately before content enters the
model context.

## How it works

Claude Code hooks can allow or deny a tool call, but cannot rewrite its result.
ctxguard is therefore **block-and-report, not silent redaction**:

1. A `PreToolUse` hook inspects `Read`, `Edit`, `Write`, `Bash`, `Grep`, and
   `Glob` inputs before execution.
2. Sensitive filenames, small text-file contents, common shell reads,
   environment dumps, and inline high-confidence secrets are checked locally.
3. In `block` mode, a flagged call is denied with a masked reason. In `warn`
   mode, it is allowed with warning context.
4. A capped `SessionStart` scan tells Claude which files to avoid without
   returning their raw contents.

The CLI uses the same detector module as both plugin hooks.

### Example blocked tool call

```text
Claude Code attempts: Read .env
ctxguard intercepts: PreToolUse
Tool call result: DENIED
Explanation: ctxguard blocked this Read call: .env is a sensitive file by name
Raw values printed: no
```

Run the synthetic demonstration with `python3 scripts/demo.py`. See
[docs/demo.md](docs/demo.md) for details and safe GIF-recording instructions.

## What it detects

- AWS access key IDs and secret access keys
- GitHub classic and fine-grained personal access tokens
- Slack tokens
- Stripe live and test secret keys
- GCP API keys (`AIza...`) and service-account JSON (content marker plus the filename rule)
- Azure storage, Service Bus, Event Hub, and IoT Hub connection string keys
  (`AccountKey=...`, `SharedAccessKey=...`)
- Twilio API key SIDs and SendGrid API keys
- OpenAI-style keys (`sk-...`, `sk-proj-...`) and Anthropic keys (`sk-ant-...`)
- Database URLs with inline passwords: Postgres, MySQL/MariaDB (including
  SQLAlchemy dialect+driver and Rails `mysql2://` schemes), MongoDB, Redis,
  AMQP, and MSSQL
- private key blocks and JWT-shaped strings
- credential-like assignments that pass length, digit, and entropy thresholds
- high-entropy values assigned to names containing `key`, `secret`, `token`,
  `password`, or `credential`
- sensitive filenames including `.env`, non-template `.env.*`, SSH keys,
  `*.pem`, `*.pfx`, `credentials.json`, and `service-account*.json`

Detection is heuristic and local. ctxguard makes no network calls and uses no
telemetry or machine learning.

## Configuration

Copy `.ctxguard.toml.example` to `.ctxguard.toml`, or run `ctxguard init`:

```toml
mode = "block" # or "warn"

allowlist = [
    "tests/fixtures/*",
]

[[custom_patterns]]
name = "acme_internal_token"
regex = "acme_[A-Za-z0-9]{32}"
confidence = "high"
```

Allowlisting suppresses detection and should be narrow. Custom regular
expressions are applied alongside built-ins.

## CLI

```bash
ctxguard scan               # scan current directory; exit 1 on findings
ctxguard scan path/ --json  # machine-readable masked report
ctxguard init               # create config and register Claude Code hooks
ctxguard --version
```

## Honest limitations

- Pattern and entropy matching has false positives and false negatives. A
  secret that resembles prose may pass; an unusual random value may be flagged.
- ctxguard blocks calls; it cannot redact tool output in flight. If a detector
  misses sensitive content in a normal-looking file, that content can enter
  context.
- The Bash parser is heuristic and cannot model every shell construction.
- Filename checks intentionally deny some files without inspecting content.
- Files over 1 MB and binary files are not content-scanned. Session scans are
  time- and file-capped for responsiveness.
- Hook errors fail open so ctxguard cannot break a Claude Code session. This
  preserves availability but means a broken hook does not provide protection.
- Native Windows compatibility is not claimed; current testing covers the
  Python package and hook contract on Unix-like CI runners.

Use layered controls: least-privilege credentials, a secrets manager,
`.gitignore`, repository secret scanning, short-lived tokens, and revocation.

## Security model

ctxguard trusts the local Python runtime, Claude Code's hook execution, the
installed plugin files, and project configuration. Detection and reporting stay
on the local machine. Reports contain masked matches, filenames, categories,
and line numbers, never intentionally the full matched value.

An attacker who can alter the plugin, configuration, interpreter, hook input,
or files between inspection and execution may bypass it. ctxguard is a
preventive guardrail, not a sandbox, secrets manager, or formal non-disclosure
guarantee. See [SECURITY.md](SECURITY.md) for private reporting guidance.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/python -m build
.venv/bin/twine check dist/*
```

Test the plugin locally with `claude plugin validate .` and
`claude --plugin-dir .`. Fixtures containing detector-positive synthetic values
are confined to `tests/fixtures/` and allowlisted by the repository example
configuration.

## Contributing

Issues and pull requests are welcome. Detector changes must include positive
and negative tests, and outputs must never reveal an unmasked match. Keep the
project local, dependency-light, auditable, and honest about limitations. Run
the complete test suite before submitting. See [SECURITY.md](SECURITY.md) for
security reports rather than opening a public bypass report.

## License

MIT. See [LICENSE](LICENSE).
