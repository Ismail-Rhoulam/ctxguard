"""Shared test constants.

The raw secret values mirror the fixture files but are assembled by
concatenation so this file never contains a format-valid secret itself
(keeps ctxguard's own scan of the test suite quiet and keeps the values
out of any single greppable string).
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
SECRETS_DIR = FIXTURES_DIR / "secrets"
CLEAN_DIR = FIXTURES_DIR / "clean"

PRETOOLUSE_SCRIPT = REPO_ROOT / "scripts" / "pretooluse_guard.py"
SESSION_START_SCRIPT = REPO_ROOT / "scripts" / "session_start_scan.py"

AWS_ID = "AKIAQ3ZX7Y2W" + "9V4U8T1M"
AWS_SECRET = "9f2Kl7pQ4rS8tU3vW6xY" + "1zA5bC0dE9fG2hJ4kL7m"
GHP = "ghp_A7bC9dE2fG4hJ6kL" + "8mN0pQ1rS3tU5vW7xY9z"
GH_PAT = (
    "github_pat_11ABCDEFG0123456789abc_"
    + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D"
)
SLACK = "xox" + "b-2912345678-3187654321-AbCdEfGhIjKlMnOpQrSt"
STRIPE_LIVE = "sk_live_a1B2c3D4e5F6" + "g7H8i9J0k1L2"
STRIPE_TEST = "sk_test_m3N4o5P6q7R8" + "s9T0u1V2w3X4"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
ENTROPY_VAL = "c9X2mK8pQ4vR7tZ1" + "nL5wY3bD6fH0jS9a"
DB_PASSWORD_VAL = "q8Gz7p2X" + "v9rLw4Nt"
API_TOKEN_VAL = "8fk2mZpQ7wR4" + "xV1bN6cY3sD5"
STRIPE_KEY_VAL = "whsec_F8kL2mP9" + "qR4sT7vX1yZ3bC6d"

RAW_SECRETS = [
    AWS_ID,
    AWS_SECRET,
    GHP,
    GH_PAT,
    SLACK,
    STRIPE_LIVE,
    STRIPE_TEST,
    JWT,
    ENTROPY_VAL,
    DB_PASSWORD_VAL,
    API_TOKEN_VAL,
    STRIPE_KEY_VAL,
]

# Expected totals when scanning tests/fixtures/secrets:
#   aws.txt 2, github.txt 2, slack.txt 1, stripe.txt 2, keys.txt 1, jwt.txt 1,
#   dotenv/.env 4 (1 filename + 3 env), settings.py 1,
#   dummy.pem 1, credentials.json 1, id_rsa 1 (filename-only)
EXPECTED_SECRET_FINDINGS = 17
EXPECTED_FLAGGED_FILES = 11
