# Reddit launch draft

## Title

I built ctxguard — a Claude Code hook that blocks API keys before they enter the model's context

## Post

I built ctxguard, an open-source MIT-licensed Claude Code plugin and Python CLI.
It intercepts selected tool calls locally with `PreToolUse` and denies the call
when a sensitive filename or likely secret is detected. The explanation is
masked; the raw match is not intentionally returned to Claude.

Installation in Claude Code:

```text
/plugin marketplace add Ismail-Rhoulam/rhoulam
/plugin install ctxguard@rhoulam
```

This is complementary to Gitleaks and TruffleHog. Those tools protect repos and
commits; ctxguard focuses on the moment before an AI coding agent reads content.

It is heuristic, not a guarantee: false positives and false negatives are
possible, Bash parsing is limited, and hooks fail open on errors. Detection
happens locally with no network calls or telemetry.

Repository: https://github.com/Ismail-Rhoulam/ctxguard

Technically useful feedback is welcome, especially sanitized bypass cases,
false positives, hook-contract issues, and detector tests. Please never include
live credentials in a report.
