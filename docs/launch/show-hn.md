# Show HN launch draft

## Title

Show HN: ctxguard – Block secrets before Claude Code sees them

## Submission text

ctxguard is a local, open-source Claude Code plugin and Python CLI that blocks
likely secrets and sensitive files before selected agent tool calls execute.

Repository: https://github.com/Ismail-Rhoulam/ctxguard

## First comment

I built this after noticing a gap between repository secret scanning and agent
context protection. A file can be untracked and never committed, yet still be
read by an AI coding agent.

ctxguard registers a Claude Code `PreToolUse` hook for file, shell, and search
tools. The hook examines the tool input locally. On a match it denies execution
and provides a masked reason, so it is block-and-report rather than redaction.
Gitleaks and TruffleHog remain useful for repositories and commits; ctxguard is
intended as a complementary control at a different boundary.

Limitations are important: matching is heuristic, false positives and false
negatives exist, shell parsing is incomplete, and hook errors fail open. It is
not a sandbox or secrets manager.

To test it:

```text
/plugin marketplace add Ismail-Rhoulam/ctxguard
/plugin install ctxguard@ctxguard-plugins
```

Or clone the repository and run `python3 scripts/demo.py` for a synthetic demo.
