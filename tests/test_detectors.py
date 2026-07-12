"""Unit tests for the shared detection module."""

import pytest

from conftest import (
    ANTHROPIC_VAL,
    AWS_ID,
    AWS_SECRET,
    AZURE_ACCOUNT_VAL,
    CLEAN_DIR,
    DB_PASSWORD_VAL,
    ENTROPY_VAL,
    EXPECTED_SECRET_FINDINGS,
    GCP_API_VAL,
    GH_PAT,
    GHP,
    JWT,
    MONGO_URL_PW,
    OPENAI_VAL,
    PG_URL_PW,
    RAW_SECRETS,
    SECRETS_DIR,
    SENDGRID_VAL,
    SLACK,
    STRIPE_LIVE,
    STRIPE_TEST,
    TWILIO_VAL,
)
from ctxguard import detectors as det


def names(findings):
    return [f.pattern_name for f in findings]


# ---------------------------------------------------------------------------
# Pattern detectors: positive and negative per detector


class TestAws:
    def test_access_key_id_positive(self):
        findings = det.scan_text(f"id {AWS_ID}\n")
        assert names(findings) == ["aws_access_key_id"]
        assert findings[0].confidence == "high"
        assert findings[0].line_number == 1

    def test_access_key_id_docs_example_negative(self):
        assert det.scan_text("AKIAIOSFODNN7" + "EXAMPLE") == []

    def test_access_key_id_too_short_negative(self):
        assert det.scan_text("AKIA1234") == []

    def test_secret_key_positive(self):
        findings = det.scan_text(f"aws_secret_access_key = {AWS_SECRET}\n")
        assert names(findings) == ["aws_secret_access_key"]

    def test_secret_key_docs_example_negative(self):
        text = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
        assert det.scan_text(text) == []

    def test_secret_key_requires_aws_context(self):
        # a 40-char base64ish string with no aws-ish variable around it
        assert det.scan_text(f"blob {AWS_SECRET}\n") == []


class TestGitHub:
    def test_classic_pat_positive(self):
        findings = det.scan_text(f"token: {GHP}\n")
        assert names(findings) == ["github_pat"]

    def test_fine_grained_pat_positive(self):
        findings = det.scan_text(f"{GH_PAT}\n")
        assert names(findings) == ["github_fine_grained_pat"]

    def test_placeholder_negative(self):
        assert det.scan_text("ghp_" + "x" * 36) == []

    def test_too_short_negative(self):
        assert det.scan_text("ghp_abc123") == []


class TestSlack:
    def test_positive(self):
        findings = det.scan_text(f"SLACK_BOT_TOKEN={SLACK}\n")
        assert names(findings) == ["slack_token"]

    def test_too_short_negative(self):
        assert det.scan_text("xoxb-123") == []


class TestStripe:
    def test_live_positive(self):
        assert names(det.scan_text(STRIPE_LIVE)) == ["stripe_secret_key"]

    def test_test_positive(self):
        assert names(det.scan_text(STRIPE_TEST)) == ["stripe_secret_key"]

    def test_placeholder_negative(self):
        assert det.scan_text("sk_live_" + "X" * 24) == []


class TestPrivateKey:
    def test_positive(self):
        # assembled at runtime so this test file itself never contains a key header
        header = "-----BEGIN RSA " + "PRIVATE KEY-----"
        footer = "-----END RSA " + "PRIVATE KEY-----"
        findings = det.scan_text(f"{header}\nMIIEfixture\n{footer}\n")
        assert names(findings) == ["private_key_block"]

    def test_openssh_positive(self):
        header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
        assert names(det.scan_text(header)) == ["private_key_block"]

    def test_public_key_negative(self):
        assert det.scan_text("-----BEGIN PUBLIC KEY-----") == []


class TestJwt:
    def test_positive(self):
        findings = det.scan_text(f"auth: {JWT}\n")
        assert names(findings) == ["jwt"]

    def test_header_only_negative(self):
        assert det.scan_text("eyJhbGciOiJIUzI1NiJ9") == []


class TestGcp:
    def test_api_key_positive(self):
        findings = det.scan_text(f"maps key {GCP_API_VAL}\n")
        assert names(findings) == ["gcp_api_key"]

    def test_api_key_placeholder_negative(self):
        assert det.scan_text("AIza" + "X" * 35) == []

    def test_service_account_marker_positive(self):
        marker = '"type": ' + '"service_account"'
        assert names(det.scan_text(marker)) == ["gcp_service_account"]

    def test_service_account_other_type_negative(self):
        assert det.scan_text('"type": "authorized_user_config"') == []


class TestAzure:
    def test_connection_string_positive(self):
        text = f"DefaultEndpointsProtocol=https;AccountKey={AZURE_ACCOUNT_VAL};x=y"
        findings = det.scan_text(text)
        assert names(findings) == ["azure_storage_account_key"]
        assert AZURE_ACCOUNT_VAL not in str(findings[0])

    def test_low_entropy_negative(self):
        assert det.scan_text("AccountKey=" + "A" * 70) == []


class TestTwilio:
    def test_positive(self):
        assert names(det.scan_text(f"sid {TWILIO_VAL}\n")) == ["twilio_api_key"]

    def test_zeroed_negative(self):
        assert det.scan_text("SK" + "0" * 32) == []

    def test_too_short_negative(self):
        assert det.scan_text("SKa1b2c3") == []


class TestSendGrid:
    def test_positive(self):
        assert names(det.scan_text(SENDGRID_VAL)) == ["sendgrid_api_key"]

    def test_placeholder_negative(self):
        fake = "SG." + "X" * 22 + "." + "X" * 43
        assert det.scan_text(fake) == []

    def test_wrong_shape_negative(self):
        assert det.scan_text("SG.short.token") == []


class TestOpenAiStyle:
    def test_classic_positive(self):
        assert names(det.scan_text(OPENAI_VAL)) == ["openai_api_key"]

    def test_project_key_positive(self):
        proj = "sk-proj-" + OPENAI_VAL[3:]
        assert names(det.scan_text(proj)) == ["openai_api_key"]

    def test_anthropic_positive(self):
        assert names(det.scan_text(ANTHROPIC_VAL)) == ["anthropic_api_key"]

    def test_placeholder_negative(self):
        assert det.scan_text("sk-" + "x" * 48) == []

    def test_too_short_negative(self):
        assert det.scan_text("sk-abc123") == []


class TestDatabaseUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "postgres://svc:{pw}@db.internal:5432/app",
            "postgresql://svc:{pw}@db/app",
            "mysql://app:{pw}@10.0.0.5/x",
            "mongodb+srv://appuser:{pw}@cluster0.example.net/prod",
            "redis://default:{pw}@cache:6379/0",
            "amqp://worker:{pw}@mq:5672/vhost",
        ],
    )
    def test_inline_password_positive(self, url):
        findings = det.scan_text(url.format(pw=PG_URL_PW))
        assert names(findings) == ["database_url_password"]
        assert PG_URL_PW not in str(findings[0])

    def test_mongo_positive(self):
        url = f"mongodb://svc:{MONGO_URL_PW}@db/x"
        assert names(det.scan_text(url)) == ["database_url_password"]

    @pytest.mark.parametrize(
        "url",
        [
            "postgres://user:password@localhost:5432/dev",
            "mysql://root:pass@127.0.0.1/x",
            "postgresql://u:${DB_PASSWORD}@h/db",
            "postgres://u:{password}@h/db",
            "postgres://u:$PGPASSWORD@h/db",
            "postgres://user@localhost/db",
            "postgres://localhost:5432/db",
            "https://example.com/path",
        ],
    )
    def test_placeholder_or_no_password_negative(self, url):
        assert det.scan_text(url) == []


class TestEnvAssignment:
    def test_positive(self):
        findings = det.scan_text(f"DB_PASSWORD={DB_PASSWORD_VAL}\n")
        assert names(findings) == ["env_assignment"]

    def test_export_and_quotes_positive(self):
        findings = det.scan_text(f'export API_TOKEN="{DB_PASSWORD_VAL}"\n')
        assert names(findings) == ["env_assignment"]

    @pytest.mark.parametrize(
        "line",
        [
            "TOKEN=your-key-here",
            "PASSWORD=changeme",
            "SECRET=xxx",
            "API_KEY=<insert-your-key>",
            "SESSION_SECRET=${SESSION_SECRET}",
            "DB_PASSWORD=abc12",
            "PORT=8080",
            "NODE_ENV=production",
            'api_key_header = "X-Api-Key"',
            "PASSWORD=aaaaaaaaaaaa",
        ],
    )
    def test_negatives(self, line):
        assert det.scan_text(line + "\n") == []


class TestHighEntropyFallback:
    def test_dict_style_positive(self):
        findings = det.scan_text(f'CONFIG = {{"signing_key": "{ENTROPY_VAL}"}}\n')
        assert names(findings) == ["high_entropy_secret"]

    def test_hex_positive(self):
        hexval = "deadbeef12345678" + "90abcdef"  # 24 hex chars
        findings = det.scan_text(f'db_secret: "{hexval}"\n')
        assert names(findings) == ["high_entropy_secret"]

    def test_low_entropy_negative(self):
        assert det.scan_text('"signing_key": "aaaaaaaaaaaaaaaaaaaaaaaa"\n') == []

    def test_non_secret_name_negative(self):
        assert det.scan_text(f'"config_path": "{ENTROPY_VAL}"\n') == []


# ---------------------------------------------------------------------------
# Masking


class TestMasking:
    def test_shows_first4_last2_only(self):
        raw = "abcdefghij1234567890"
        masked = det.mask_secret(raw)
        assert masked.startswith("abcd")
        assert masked.endswith("90")
        assert raw not in masked
        assert "efghij" not in masked

    def test_short_values_fully_masked(self):
        assert set(det.mask_secret("abcd")) == {"*"}
        assert set(det.mask_secret("abcdef")) == {"*"}

    def test_mask_does_not_reveal_length(self):
        long = det.mask_secret("a" * 500)
        assert len(long) <= 4 + 12 + 2

    def test_no_finding_ever_contains_raw_secret(self):
        findings, _, _ = det.scan_path(SECRETS_DIR)
        assert findings, "expected fixture findings"
        for finding in findings:
            rendered = str(finding) + repr(finding.to_dict())
            for raw in RAW_SECRETS:
                assert raw not in rendered
                # inner 60% of the secret must not survive either
                inner = raw[4:-2]
                assert inner not in rendered


class TestEntropy:
    def test_empty_and_uniform(self):
        assert det.shannon_entropy("") == 0.0
        assert det.shannon_entropy("aaaa") == 0.0

    def test_high_for_random_like(self):
        assert det.shannon_entropy(ENTROPY_VAL) > 4.0


# ---------------------------------------------------------------------------
# Filename rules


@pytest.mark.parametrize(
    ("name", "sensitive"),
    [
        (".env", True),
        (".env.local", True),
        (".env.production", True),
        (".env.example", False),
        (".env.sample", False),
        (".env.template", False),
        ("id_rsa", True),
        ("id_ed25519", True),
        ("id_rsa.pub", False),
        ("server.pem", True),
        ("cert.pfx", True),
        ("keystore.p12", True),
        ("credentials.json", True),
        ("service-account-prod.json", True),
        ("main.py", False),
        ("placeholders.env", False),
        ("README.md", False),
    ],
)
def test_sensitive_filename(name, sensitive):
    assert (det.sensitive_filename_reason(name) is not None) is sensitive


def test_scan_file_dotenv_fixture():
    findings = det.scan_file(SECRETS_DIR / "dotenv" / ".env")
    assert names(findings) == [
        "sensitive_filename",
        "env_assignment",
        "env_assignment",
        "env_assignment",
    ]
    assert [f.line_number for f in findings] == [0, 2, 3, 4]


def test_scan_path_fixture_totals():
    findings, scanned, truncated = det.scan_path(SECRETS_DIR)
    assert len(findings) == EXPECTED_SECRET_FINDINGS
    assert not truncated
    assert scanned >= 11

    clean_findings, _, _ = det.scan_path(CLEAN_DIR)
    assert clean_findings == []


# ---------------------------------------------------------------------------
# Config: mode, allowlist, custom patterns


def _write_config(tmp_path, body):
    (tmp_path / det.CONFIG_FILENAME).write_text(body, encoding="utf-8")
    return det.load_config(tmp_path)


def test_load_config_defaults(tmp_path):
    cfg = det.load_config(tmp_path)
    assert cfg.mode == "block"
    assert cfg.allowlist == []
    assert cfg.custom_patterns == []


def test_load_config_full(tmp_path):
    cfg = _write_config(
        tmp_path,
        'mode = "warn"\n'
        'allowlist = ["fixtures/*", "docs/**"]\n'
        "[[custom_patterns]]\n"
        'name = "acme_token"\n'
        'regex = "acme_[A-Za-z0-9]{32}"\n'
        'confidence = "high"\n',
    )
    assert cfg.mode == "warn"
    assert cfg.allowlist == ["fixtures/*", "docs/**"]
    assert len(cfg.custom_patterns) == 1
    assert cfg.custom_patterns[0].name == "custom:acme_token"
    assert cfg.custom_patterns[0].confidence == "high"


def test_custom_pattern_detection(tmp_path):
    cfg = _write_config(
        tmp_path,
        '[[custom_patterns]]\nname = "acme_token"\nregex = "acme_[A-Za-z0-9]{32}"\n',
    )
    token = "acme_a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6"
    findings = det.scan_text(f"x = {token}", cfg)
    assert names(findings) == ["custom:acme_token"]
    assert token not in str(findings[0])


def test_invalid_custom_pattern_skipped(tmp_path):
    cfg = _write_config(
        tmp_path, '[[custom_patterns]]\nname = "broken"\nregex = "([unclosed"\n'
    )
    assert cfg.custom_patterns == []


def test_malformed_config_falls_back_to_defaults(tmp_path):
    cfg = _write_config(tmp_path, "mode = [not toml")
    assert cfg.mode == "block"


def test_allowlist_by_relative_path(tmp_path):
    cfg = _write_config(tmp_path, 'allowlist = ["fixtures/*"]\n')
    target = tmp_path / "fixtures" / ".env"
    target.parent.mkdir()
    target.write_text(f"DB_PASSWORD={DB_PASSWORD_VAL}\n", encoding="utf-8")
    assert det.is_allowlisted(target, cfg)
    assert det.scan_file(target, cfg) == []
    # a sibling outside the allowlist still gets flagged
    other = tmp_path / ".env"
    other.write_text(f"DB_PASSWORD={DB_PASSWORD_VAL}\n", encoding="utf-8")
    assert det.scan_file(other, cfg) != []


def test_find_config_stops_at_git_root(tmp_path):
    (tmp_path / det.CONFIG_FILENAME).write_text('mode = "warn"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    sub = repo / "src"
    sub.mkdir()
    # config above the git root must not leak into the repo
    assert det.find_config_file(sub) is None
    # but a config inside the repo is found from a subdirectory
    (repo / det.CONFIG_FILENAME).write_text('mode = "warn"\n', encoding="utf-8")
    assert det.find_config_file(sub) == repo / det.CONFIG_FILENAME


# ---------------------------------------------------------------------------
# Bash command analysis


@pytest.mark.parametrize(
    ("command", "flagged"),
    [
        ("cat .env", True),
        ("cat /some/project/.env", True),
        ("head -n 5 id_rsa", True),
        ("grep TOKEN .env", True),
        ("tail -f server.pem", True),
        ("env | grep AWS", True),
        ("printenv", True),
        ("printenv AWS_SECRET_ACCESS_KEY", True),
        ("echo $DB_PASSWORD", True),
        ("ls -la", False),
        ("printenv PATH", False),
        ("env FOO=1 python script.py", False),
        ("cat .env.example", False),
        ("git add .env", False),
        ("grep -r pattern src/", False),
        ("cat README.md", False),
    ],
)
def test_bash_analysis(command, flagged):
    assert det.analyze_bash_command(command).flagged is flagged


def test_bash_inline_secret_detected_and_masked():
    command = f"curl -H 'Authorization: Bearer {STRIPE_LIVE}' https://api.stripe.com"
    analysis = det.analyze_bash_command(command)
    assert analysis.flagged
    assert [f.pattern_name for f in analysis.inline_secrets] == ["stripe_secret_key"]
    assert STRIPE_LIVE not in str(analysis.inline_secrets[0])


def test_bash_respects_allowlist(tmp_path):
    cfg = _write_config(tmp_path, 'allowlist = ["*.pem"]\n')
    assert det.analyze_bash_command("cat server.pem", cfg).flagged is False


# ---------------------------------------------------------------------------
# Glob / grep pattern targeting


@pytest.mark.parametrize(
    ("pattern", "targeted"),
    [
        ("*.pem", True),
        ("**/.env", True),
        (".env*", True),
        ("**/id_rsa", True),
        ("credentials*.json", True),
        ("*", False),
        ("**/*", False),
        ("**/*.py", False),
        ("*.json", False),
        ("src/**/*.ts", False),
        ("", False),
    ],
)
def test_pattern_targets_sensitive(pattern, targeted):
    assert (det.pattern_targets_sensitive(pattern) is not None) is targeted
