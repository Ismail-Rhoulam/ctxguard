"""Shared secret-detection logic for ctxguard.

Single source of truth for detection: the PreToolUse hook, the SessionStart
hook, and the standalone CLI all import from this module. It deliberately has
no third-party dependencies so the hook scripts run on a bare python3.
"""

from __future__ import annotations

import fnmatch
import math
import os
import re
import shlex
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Pattern

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ModuleNotFoundError:
        _toml = None  # type: ignore[assignment]  # config support degrades gracefully

CONFIG_FILENAME = ".ctxguard.toml"
MAX_SCAN_BYTES = 1_000_000

__all__ = [
    "Finding",
    "Config",
    "BashAnalysis",
    "CONFIG_FILENAME",
    "MAX_SCAN_BYTES",
    "mask_secret",
    "shannon_entropy",
    "is_placeholder",
    "sensitive_filename_reason",
    "scan_text",
    "scan_file",
    "scan_path",
    "iter_scannable_files",
    "analyze_bash_command",
    "pattern_targets_sensitive",
    "is_allowlisted",
    "find_config_file",
    "load_config",
]


# ---------------------------------------------------------------------------
# Results


@dataclass
class Finding:
    """One potential secret. The snippet is always masked, never the raw value."""

    pattern_name: str
    matched_snippet_masked: str
    confidence: str  # "high" | "medium" | "low"
    line_number: int  # 1-based; 0 for filename-only findings
    file: Optional[str] = None

    def to_dict(self) -> dict:
        data = {
            "pattern_name": self.pattern_name,
            "matched_snippet_masked": self.matched_snippet_masked,
            "confidence": self.confidence,
            "line_number": self.line_number,
        }
        if self.file is not None:
            data["file"] = self.file
        return data

    def __str__(self) -> str:
        where = self.file or "<text>"
        loc = f"{where}:{self.line_number}" if self.line_number else where
        return f"{loc} [{self.confidence}] {self.pattern_name}: {self.matched_snippet_masked}"


# ---------------------------------------------------------------------------
# Masking and entropy


def mask_secret(value: str) -> str:
    """Mask a secret for display: first 4 and last 2 characters only.

    The number of mask characters is capped so output never reveals the
    secret's exact length either.
    """
    value = value.strip()
    if len(value) <= 6:
        return "*" * max(len(value), 3)
    hidden = min(len(value) - 6, 12)
    return f"{value[:4]}{'*' * hidden}{value[-2:]}"


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in Counter(value).values())


# ---------------------------------------------------------------------------
# Placeholder rejection (keeps docs/examples from false-positiving)

_PLACEHOLDER_EXACT = {
    "changeme",
    "change-me",
    "change_me",
    "password",
    "passw0rd",
    "secret",
    "example",
    "true",
    "false",
    "none",
    "null",
    "nil",
    "todo",
    "tbd",
    "undefined",
    "dummy",
    "test",
    "testing",
    "foobar",
    "foo",
    "bar",
    "baz",
    "admin",
    "root",
    "user",
    "guest",
    "empty",
    "unset",
    "disabled",
    "string",
    "pass",
    "pwd",
    "1234",
    "12345",
    "123456",
}

_PLACEHOLDER_SUBSTRINGS = (
    "example",
    "placeholder",
    "changeme",
    "change-me",
    "your-",
    "your_",
    "yourkey",
    "sample",
    "dummy",
    "fake",
    "insert",
    "redacted",
    "not-a-real",
    "notareal",
    "xxxx",
    "****",
)

_PLACEHOLDER_WRAPPED = re.compile(r"^(<.*>|\$\{.*\}|\{.*\}|%.*%|__.*__|\[.*\]|\$\w+)$")

# Well-known, publicly documented development keys that are constant across
# every install and are not secrets. Checked from is_placeholder() so every
# detector (not just the one whose regex happens to capture them) rejects
# them consistently, regardless of which pattern matches the surrounding text.
_KNOWN_BENIGN_VALUES = {
    # Azurite / Azure Storage Emulator default account key (Microsoft docs)
    (
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
        "K1SZFPTOtr/KBHBeksoGMGw=="
    ).lower(),
}


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'").lower()
    if not v or v in _PLACEHOLDER_EXACT:
        return True
    if v in _KNOWN_BENIGN_VALUES:
        return True
    if _PLACEHOLDER_WRAPPED.match(v):
        return True
    if any(s in v for s in _PLACEHOLDER_SUBSTRINGS):
        return True
    if len(set(v)) <= 2:  # aaaa, xxxxx, 000000
        return True
    if v.endswith("..."):
        return True
    return False


# ---------------------------------------------------------------------------
# Detector specs

_SECRETIVE_NAME_RE = re.compile(r"(?i)(key|token|secret|passw(?:or)?d|pwd|credential)")

_ENV_ASSIGN_RE = re.compile(
    r"^[ \t]*(?:export[ \t]+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*"
    r"(?P<q>[\"']?)(?P<value>[^\s\"']+)(?P=q)[ \t]*(?:#.*)?$",
    re.MULTILINE,
)

_CODE_ASSIGN_RE = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_.\-]*(?:key|secret|token|passw(?:or)?d|credential)"
    r"[A-Za-z0-9_.\-]*)[\"']?\s*[=:]\s*[\"'](?P<value>[^\s\"']{16,})[\"']"
)


def _plausible_token(value: str, m: "re.Match") -> bool:
    v = value.lower()
    if "example" in v or "xxxx" in v:
        return False
    return shannon_entropy(value) >= 2.5


def _plausible_env_value(value: str, m: "re.Match") -> bool:
    if not _SECRETIVE_NAME_RE.search(m.group("name")):
        return False
    v = value.strip().strip("\"'")
    if len(v) < 8 or is_placeholder(v):
        return False
    if not any(c.isdigit() for c in v):
        return False  # header names, enum-ish values; real secrets have digits
    return shannon_entropy(v) >= 3.0


def _plausible_db_password(value: str, m: "re.Match") -> bool:
    # any real inline password in a connection URL is worth flagging, even a
    # weak one: the point is that no credential (strong or not) belongs
    # inline in a URL that might enter an AI's context. only obvious docs
    # placeholders (user:password@, user:pass@, ${VAR}) get a pass.
    if is_placeholder(value):
        return False
    return shannon_entropy(value) >= 2.0


def _plausible_azure_key(value: str, m: "re.Match") -> bool:
    if is_placeholder(value):
        return False
    return _plausible_token(value, m)


def _plausible_gcp_service_account(value: str, m: "re.Match") -> bool:
    # the bare service-account type marker alone also appears in docs and
    # example snippets; require a private key nearby, which every real GCP
    # service-account credential file has right next to it.
    text = m.string
    window = text[max(0, m.start() - 2000) : m.start() + 4000]
    return "private_key" in window


def _high_entropy_value(value: str, m: "re.Match") -> bool:
    v = value.strip()
    if len(v) < 16 or is_placeholder(v):
        return False
    ent = shannon_entropy(v)
    if re.fullmatch(r"[0-9a-fA-F]{24,}", v):
        return ent >= 3.4
    if re.fullmatch(r"[A-Za-z0-9+/=_\-]{24,}", v):
        return ent >= 4.2
    return ent >= 4.5


@dataclass(frozen=True)
class _Spec:
    name: str
    regex: Pattern[str]
    confidence: str
    group: object = 0  # int index or str group name
    validator: Optional[Callable[[str, "re.Match"], bool]] = None


_BUILTIN_SPECS = [
    _Spec(
        "aws_access_key_id",
        re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "aws_secret_access_key",
        re.compile(
            r"(?i)\baws[\w .\-]{0,25}?(?:secret|private)[\w .\-]{0,25}?[=:][ \t]*"
            r"[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "github_fine_grained_pat",
        re.compile(r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "github_pat",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "slack_token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "stripe_secret_key",
        re.compile(r"\b([sr]k_(?:live|test)_[A-Za-z0-9]{24,})\b"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "gcp_api_key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "gcp_service_account",
        re.compile(r"[\"']type[\"']\s*:\s*[\"']service_account[\"']"),
        "high",
        0,
        _plausible_gcp_service_account,
    ),
    _Spec(
        "azure_storage_account_key",
        re.compile(r"(?i)\b(?:Account|SharedAccess)Key=([A-Za-z0-9+/]{40,}={0,2})"),
        "high",
        1,
        _plausible_azure_key,
    ),
    _Spec(
        "twilio_api_key",
        re.compile(r"\b(SK[0-9a-fA-F]{32})(?![0-9a-fA-F])"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "sendgrid_api_key",
        re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "anthropic_api_key",
        re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{32,})\b"),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "openai_api_key",
        re.compile(
            r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{32,}"
            r"|sk-[A-Za-z0-9]{48}(?![A-Za-z0-9]))"
        ),
        "high",
        1,
        _plausible_token,
    ),
    _Spec(
        "database_url_password",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql2?|mariadb|mongodb(?:\+srv)?|rediss?"
            r"|amqps?|mssql)(?:\+[a-z0-9_]+)?://[^\s:@/]*:([^\s:@/]{4,})@"
        ),
        "high",
        1,
        _plausible_db_password,
    ),
    _Spec(
        "private_key_block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"),
        "high",
        0,
        None,
    ),
    _Spec(
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
        ),
        "medium",
        1,
        None,
    ),
]

_GENERIC_SPECS = [
    _Spec("env_assignment", _ENV_ASSIGN_RE, "medium", "value", _plausible_env_value),
    _Spec(
        "high_entropy_secret", _CODE_ASSIGN_RE, "medium", "value", _high_entropy_value
    ),
]


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(text: str, config: Optional["Config"] = None) -> List[Finding]:
    """Scan a text blob. Returns findings sorted by line, deduped by span."""
    specs: List[_Spec] = list(_BUILTIN_SPECS)
    if config is not None and config.custom_patterns:
        specs.extend(config.custom_patterns)
    specs.extend(_GENERIC_SPECS)

    findings: List[Finding] = []
    taken: List[tuple] = []
    for spec in specs:
        for m in spec.regex.finditer(text):
            try:
                value = m.group(spec.group)  # type: ignore[arg-type]
                span = m.span(spec.group)  # type: ignore[arg-type]
            except (IndexError, re.error):
                value, span = m.group(0), m.span(0)
            if not value:
                continue
            if any(span[0] < e and s < span[1] for s, e in taken):
                continue  # a more specific detector already claimed this span
            if spec.validator is not None and not spec.validator(value, m):
                continue
            taken.append(span)
            findings.append(
                Finding(
                    spec.name,
                    mask_secret(value),
                    spec.confidence,
                    _line_of(text, span[0]),
                )
            )
    findings.sort(key=lambda f: f.line_number)
    return findings


# ---------------------------------------------------------------------------
# Filename-based sensitivity

_ENV_EXEMPT_SUFFIXES = {"example", "sample", "template", "dist"}
_SENSITIVE_EXACT = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials.json",
}
_SENSITIVE_GLOBS = ("*.pem", "*.pfx", "*.p12", "service-account*.json")


def sensitive_filename_reason(path: object) -> Optional[str]:
    """Reason string if the filename alone marks the file sensitive, else None."""
    name = Path(str(path)).name.lower()
    if not name:
        return None
    if name == ".env":
        return "dotenv file"
    if name.startswith(".env."):
        if name.rsplit(".", 1)[-1] in _ENV_EXEMPT_SUFFIXES:
            return None
        return "dotenv file"
    if name in _SENSITIVE_EXACT:
        return "well-known credential file"
    for pattern in _SENSITIVE_GLOBS:
        if fnmatch.fnmatchcase(name, pattern):
            return "key/certificate file type"
    return None


# ---------------------------------------------------------------------------
# Config (.ctxguard.toml)


@dataclass
class Config:
    mode: str = "block"  # "block" | "warn"
    allowlist: List[str] = field(default_factory=list)
    custom_patterns: List[_Spec] = field(default_factory=list)
    root: Optional[Path] = None


def find_config_file(start_dir: object) -> Optional[Path]:
    """Look for .ctxguard.toml from start_dir upward, stopping at the git root."""
    cur = Path(str(start_dir)).resolve()
    if cur.is_file():
        cur = cur.parent
    for _ in range(64):
        candidate = cur / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if (cur / ".git").exists() or cur.parent == cur:
            return None
        cur = cur.parent
    return None


def load_config(start_dir: object = ".") -> Config:
    cfg = Config(root=Path(str(start_dir)).resolve())
    if cfg.root.is_file():
        cfg.root = cfg.root.parent
    path = find_config_file(start_dir)
    if path is None or _toml is None:
        return cfg
    try:
        data = _toml.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return cfg  # malformed config never breaks a session
    cfg.root = path.parent
    mode = str(data.get("mode", "block")).lower()
    if mode in ("block", "warn"):
        cfg.mode = mode
    allow = data.get("allowlist", [])
    if isinstance(allow, list):
        cfg.allowlist = [str(entry) for entry in allow]
    patterns = data.get("custom_patterns", [])
    if isinstance(patterns, list):
        for entry in patterns:
            try:
                name = str(entry["name"])
                regex = re.compile(str(entry["regex"]))
            except Exception:
                continue  # skip invalid user patterns, fail open
            confidence = str(entry.get("confidence", "medium")).lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"
            cfg.custom_patterns.append(
                _Spec(f"custom:{name}", regex, confidence, 0, None)
            )
    return cfg


def is_allowlisted(path: object, config: Optional[Config]) -> bool:
    if config is None or not config.allowlist:
        return False
    p = Path(str(path))
    candidates = {p.name, str(p), p.as_posix()}
    if config.root is not None:
        try:
            candidates.add(p.resolve().relative_to(config.root.resolve()).as_posix())
        except (ValueError, OSError):
            pass
    return any(
        fnmatch.fnmatch(candidate, pattern)
        for candidate in candidates
        for pattern in config.allowlist
    )


# ---------------------------------------------------------------------------
# File and tree scanning

_BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".tar",
    ".jar",
    ".war",
    ".pyc",
    ".pyo",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".class",
    ".o",
    ".a",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
    ".webm",
    ".sqlite",
    ".db",
    ".pfx",
    ".p12",
    ".jks",
    ".keystore",
    ".der",
}

DEFAULT_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".cache",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    ".terraform",
    ".gradle",
    ".eggs",
}


def _looks_binary(path: Path) -> bool:
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return True
    return b"\x00" in chunk


def scan_file(
    path: object, config: Optional[Config] = None, display: Optional[str] = None
) -> List[Finding]:
    """Scan one file: filename rules first, then content when safely readable."""
    p = Path(str(path))
    label = display if display is not None else str(p)
    if is_allowlisted(p, config):
        return []
    findings: List[Finding] = []
    reason = sensitive_filename_reason(p)
    if reason is not None:
        findings.append(
            Finding("sensitive_filename", f"{p.name} ({reason})", "high", 0, label)
        )
    if p.is_file():
        try:
            too_large = p.stat().st_size > MAX_SCAN_BYTES
        except OSError:
            too_large = True
        if not too_large and not _looks_binary(p):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for finding in scan_text(text, config):
                finding.file = label
                findings.append(finding)
    findings.sort(key=lambda f: f.line_number)
    return findings


def _git_listed_files(root: Path) -> Optional[List[Path]]:
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
            capture_output=True,
            timeout=5,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [root / rel for rel in out.decode("utf-8", "replace").split("\0") if rel]


def _walk_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
        for filename in filenames:
            yield Path(dirpath) / filename


def iter_scannable_files(
    root: object, max_bytes: int = MAX_SCAN_BYTES
) -> Iterator[Path]:
    """Yield files worth scanning under root: honors gitignore when possible,
    always skips well-known junk directories and oversized files."""
    rootp = Path(str(root))
    listed = _git_listed_files(rootp)
    files = listed if listed is not None else _walk_files(rootp)
    for p in files:
        try:
            if any(
                part in DEFAULT_SKIP_DIRS for part in p.relative_to(rootp).parts[:-1]
            ):
                continue
            if p.is_file() and p.stat().st_size <= max_bytes:
                yield p
        except (OSError, ValueError):
            continue


def scan_path(
    root: object,
    config: Optional[Config] = None,
    max_files: Optional[int] = None,
    time_budget: Optional[float] = None,
):
    """Scan a file or tree. Returns (findings, files_scanned, truncated)."""
    rootp = Path(str(root))
    if rootp.is_file():
        return scan_file(rootp, config, display=str(rootp)), 1, False
    findings: List[Finding] = []
    scanned = 0
    truncated = False
    deadline = (time.monotonic() + time_budget) if time_budget else None
    for p in iter_scannable_files(rootp):
        if (max_files is not None and scanned >= max_files) or (
            deadline is not None and time.monotonic() > deadline
        ):
            truncated = True
            break
        scanned += 1
        try:
            rel = p.relative_to(rootp).as_posix()
        except ValueError:
            rel = str(p)
        findings.extend(scan_file(p, config, display=rel))
    return findings, scanned, truncated


# ---------------------------------------------------------------------------
# Bash command analysis

_READER_COMMANDS = {
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "awk",
    "sed",
    "strings",
    "xxd",
    "hexdump",
    "od",
    "base64",
    "nl",
    "bat",
    "cut",
    "paste",
    "sort",
    "uniq",
    "tee",
    "view",
    "vi",
    "vim",
    "nvim",
    "nano",
    "emacs",
    "code",
    "open",
    "source",
    ".",
}

_ENV_DUMP_RE = re.compile(
    r"(?:^|[|;&(`]|\$\()\s*(?:sudo\s+)?(?:printenv|env)\s*(?:$|[|;&)>])"
)
_PRINTENV_TARGETED_RE = re.compile(
    r"\bprintenv\s+[\"']?\w*(?:secret|token|key|pass|cred)\w*", re.IGNORECASE
)
_ECHO_SECRET_RE = re.compile(
    r"\b(?:echo|printf)\b[^|;&\n]*\$\{?\w*(?:secret|token|key|passw|cred)\w*",
    re.IGNORECASE,
)


@dataclass
class BashAnalysis:
    inline_secrets: List[Finding] = field(default_factory=list)
    sensitive_reads: List[str] = field(default_factory=list)
    env_dump: bool = False

    @property
    def flagged(self) -> bool:
        return bool(self.inline_secrets or self.sensitive_reads or self.env_dump)


def analyze_bash_command(command: str, config: Optional[Config] = None) -> BashAnalysis:
    """Flag commands that would pull secrets into context.

    Three checks: high-confidence secret literals inline in the command,
    read-style commands targeting sensitive files, and environment dumps.
    """
    analysis = BashAnalysis()
    analysis.inline_secrets = [
        f for f in scan_text(command, config) if f.confidence == "high"
    ]

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    stripped = [t.strip("<>()|;&'\"`$") for t in tokens]
    has_reader = any(t.rsplit("/", 1)[-1] in _READER_COMMANDS for t in stripped if t)
    targets = []
    for token in stripped:
        if not token:
            continue
        for part in {token, token.split("=")[-1]}:
            if sensitive_filename_reason(part) and not is_allowlisted(part, config):
                targets.append(Path(part).name)
                break
    if has_reader and targets:
        analysis.sensitive_reads = sorted(set(targets))

    analysis.env_dump = bool(
        _ENV_DUMP_RE.search(command)
        or _PRINTENV_TARGETED_RE.search(command)
        or _ECHO_SECRET_RE.search(command)
    )
    return analysis


# ---------------------------------------------------------------------------
# Glob / grep pattern analysis

_SENSITIVE_NAME_PROBES = [
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "server.pem",
    "cert.pfx",
    "keystore.p12",
    "credentials.json",
    "service-account-prod.json",
]

_BENIGN_NAME_PROBES = [
    "main.py",
    "README.md",
    "src/index.ts",
    "docs/notes.txt",
    "package.json",
    "tsconfig.json",
]


def pattern_targets_sensitive(pattern: object) -> Optional[str]:
    """If a glob pattern specifically targets sensitive files, return an example
    filename it would match. Broad patterns (e.g. "*", "**/*") are not flagged."""
    if not pattern:
        return None
    pat = str(pattern).strip()
    hit = None
    for probe in _SENSITIVE_NAME_PROBES:
        for candidate in (probe, f"src/{probe}", f"a/b/{probe}"):
            if fnmatch.fnmatchcase(candidate, pat):
                hit = probe
                break
        if hit:
            break
    if hit is None:
        return None
    for benign in _BENIGN_NAME_PROBES:
        if fnmatch.fnmatchcase(benign, pat) or fnmatch.fnmatchcase(f"x/{benign}", pat):
            return None  # pattern is broad, not specifically hunting secrets
    return hit
