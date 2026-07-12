# Security policy

## Supported versions

Until the first stable release, security fixes are provided for the latest
`0.1.x` release only. Users should upgrade to the newest patch version before
reporting a problem.

## Reporting a vulnerability

GitHub private vulnerability reporting is the preferred channel, but it is not
currently enabled for this repository. Open a minimal public issue asking the
maintainer to arrange a private channel. Do not include vulnerability details
in that issue and do not disclose the vulnerability publicly. Once private
reporting is enabled, use the repository's **Security > Report a vulnerability**
flow instead.

Never include live credentials in a report. Revoke any credential that may
have been exposed, and reproduce the issue with synthetic or already-revoked
values. Security-sensitive examples and attachments must follow the same rule.

A useful report includes:

- affected ctxguard and Claude Code versions;
- operating system and Python version;
- installation method (plugin or Python package);
- the tool name and a sanitized hook input or reproduction;
- expected and actual behavior;
- whether the issue is a detection bypass, false positive, or possible leak;
- logs with all sensitive values removed.

Detection bypasses and any path that could expose a raw secret are treated as
security-sensitive. Reports will be acknowledged and assessed as quickly as
maintainer availability allows; no fixed response-time guarantee is made.
