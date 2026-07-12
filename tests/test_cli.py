"""Tests for the ctxguard CLI: scan, init, --version, exit codes, masking."""

import json

import pytest

from conftest import (
    CLEAN_DIR,
    EXPECTED_FLAGGED_FILES,
    EXPECTED_SECRET_FINDINGS,
    RAW_SECRETS,
    SECRETS_DIR,
)
from ctxguard import __version__
from ctxguard.cli import main


def run_json_scan(capsys, path):
    code = main(["scan", str(path), "--json"])
    report = json.loads(capsys.readouterr().out)
    return code, report


# ---------------------------------------------------------------------------
# scan


class TestScan:
    def test_fixtures_exit_code_and_counts(self, capsys):
        code, report = run_json_scan(capsys, SECRETS_DIR)
        assert code == 1
        assert report["findings_count"] == EXPECTED_SECRET_FINDINGS
        assert report["files_flagged"] == EXPECTED_FLAGGED_FILES
        assert report["version"] == __version__
        for finding in report["findings"]:
            assert set(finding) >= {
                "pattern_name",
                "matched_snippet_masked",
                "confidence",
                "line_number",
                "file",
            }

    def test_clean_dir_exits_zero(self, capsys):
        code, report = run_json_scan(capsys, CLEAN_DIR)
        assert code == 0
        assert report["findings_count"] == 0
        assert report["findings"] == []

    def test_single_file_scan(self, capsys):
        code, report = run_json_scan(capsys, SECRETS_DIR / "slack.txt")
        assert code == 1
        assert report["findings_count"] == 1
        assert report["findings"][0]["pattern_name"] == "slack_token"

    def test_missing_path_exits_two(self, capsys):
        assert main(["scan", "/nonexistent/definitely/not/here"]) == 2

    def test_rich_report_lists_files_and_masks(self, capsys):
        code = main(["scan", str(SECRETS_DIR)])
        out = capsys.readouterr().out
        assert code == 1
        assert "potential secret" in out
        assert "slack.txt" in out

    def test_no_output_path_ever_leaks_a_secret(self, capsys):
        main(["scan", str(SECRETS_DIR)])
        rich_out = capsys.readouterr().out
        main(["scan", str(SECRETS_DIR), "--json"])
        json_out = capsys.readouterr().out
        for raw in RAW_SECRETS:
            assert raw not in rich_out
            assert raw not in json_out
            assert raw[4:-2] not in rich_out
            assert raw[4:-2] not in json_out


# ---------------------------------------------------------------------------
# --version and help


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "scan" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# init


class TestInit:
    def test_creates_config_and_settings(self, tmp_path, capsys):
        assert main(["init", str(tmp_path)]) == 0
        assert (tmp_path / ".ctxguard.toml").is_file()
        settings = json.loads(
            (tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8")
        )
        pre = settings["hooks"]["PreToolUse"]
        assert len(pre) == 1
        assert pre[0]["matcher"] == "Read|Edit|Write|Bash|Grep|Glob"
        assert "ctxguard hook pretooluse" in pre[0]["hooks"][0]["command"]
        assert (
            "ctxguard hook session-start"
            in (settings["hooks"]["SessionStart"][0]["hooks"][0]["command"])
        )

    def test_idempotent(self, tmp_path, capsys):
        assert main(["init", str(tmp_path)]) == 0
        assert main(["init", str(tmp_path)]) == 0
        settings = json.loads(
            (tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8")
        )
        assert len(settings["hooks"]["PreToolUse"]) == 1
        assert len(settings["hooks"]["SessionStart"]) == 1

    def test_existing_settings_untouched_without_confirmation(self, tmp_path, capsys):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        original = {"permissions": {"allow": ["Bash(ls:*)"]}}
        settings_path.write_text(json.dumps(original), encoding="utf-8")
        # non-interactive without --yes: must not modify, must explain
        assert main(["init", str(tmp_path)]) == 0
        assert json.loads(settings_path.read_text(encoding="utf-8")) == original
        assert "--yes" in capsys.readouterr().out

    def test_existing_settings_merged_with_yes(self, tmp_path, capsys):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(
            json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}}), encoding="utf-8"
        )
        assert main(["init", str(tmp_path), "--yes"]) == 0
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        assert settings["permissions"] == {"allow": ["Bash(ls:*)"]}
        assert len(settings["hooks"]["PreToolUse"]) == 1

    def test_init_on_missing_dir_exits_two(self, capsys):
        assert main(["init", "/nonexistent/definitely/not/here"]) == 2
