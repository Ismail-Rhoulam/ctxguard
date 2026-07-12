"""Tests for the ctxguard CLI: scan, init, doctor, --version, exit codes, masking."""

import json
import os
import sys
from pathlib import Path

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


def run_json_doctor(capsys, path):
    code = main(["doctor", str(path), "--json"])
    report = json.loads(capsys.readouterr().out)
    return code, report


def checks_by_name(report):
    return {c["name"]: c for c in report["checks"]}


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


# ---------------------------------------------------------------------------
# doctor


class TestDoctor:
    def test_missing_dir_exits_two(self, capsys):
        assert main(["doctor", "/nonexistent/definitely/not/here"]) == 2

    def test_nothing_set_up_reports_failures(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))  # no ctxguard resolvable
        code, report = run_json_doctor(capsys, tmp_path)
        assert code == 1
        assert report["healthy"] is False
        checks = checks_by_name(report)
        assert checks["path_resolution"]["status"] == "fail"
        assert checks["settings_file"]["status"] == "fail"
        assert checks["pretooluse_hook"]["status"] == "fail"
        assert checks["sessionstart_hook"]["status"] == "fail"
        assert checks["config_file"]["status"] == "warn"  # missing config is not fatal
        # can't run a subprocess smoke test or version check without a resolvable binary
        assert "version_match" not in checks
        assert "hook_smoke_test" not in checks

    def test_healthy_project_end_to_end(self, tmp_path, capsys, monkeypatch):
        # prepend the dir containing the currently-running interpreter, which
        # for a `pip install -e .` venv also contains the `ctxguard` console
        # script, so this exercises the real PATH-resolved binary end to end
        venv_bin = str(Path(sys.executable).parent)
        monkeypatch.setenv("PATH", venv_bin + os.pathsep + os.defpath)
        assert main(["init", str(tmp_path)]) == 0
        capsys.readouterr()  # drain init's own stdout before capturing doctor's JSON

        code, report = run_json_doctor(capsys, tmp_path)
        assert code == 0
        assert report["healthy"] is True
        checks = checks_by_name(report)
        assert checks["python_version"]["status"] == "ok"
        assert checks["path_resolution"]["status"] == "ok"
        assert checks["version_match"]["status"] == "ok"
        assert checks["settings_file"]["status"] == "ok"
        assert checks["pretooluse_hook"]["status"] == "ok"
        assert checks["sessionstart_hook"]["status"] == "ok"
        assert checks["config_file"]["status"] == "ok"
        assert checks["hook_smoke_test"]["status"] == "ok"

    def test_narrow_matcher_warns_but_not_fails(self, tmp_path, capsys, monkeypatch):
        # resolvable PATH so path_resolution/version_match/smoke_test don't
        # also fail and confound the "warn alone doesn't fail health" check
        venv_bin = str(Path(sys.executable).parent)
        monkeypatch.setenv("PATH", venv_bin + os.pathsep + os.defpath)
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": "ctxguard hook pretooluse",
                                    }
                                ],
                            }
                        ],
                        "SessionStart": [
                            {
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": "ctxguard hook session-start",
                                    }
                                ]
                            }
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )
        code, report = run_json_doctor(capsys, tmp_path)
        checks = checks_by_name(report)
        assert checks["pretooluse_hook"]["status"] == "warn"
        assert "Bash" in checks["pretooluse_hook"]["detail"]
        assert checks["sessionstart_hook"]["status"] == "ok"
        # a warning alone does not fail the overall health check
        assert report["healthy"] is True
        assert code == 0

    def test_malformed_config_fails(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))
        (tmp_path / ".ctxguard.toml").write_text("mode = [broken", encoding="utf-8")
        code, report = run_json_doctor(capsys, tmp_path)
        checks = checks_by_name(report)
        assert checks["config_file"]["status"] == "fail"
        assert report["healthy"] is False
        assert code == 1

    def test_rich_report_renders(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))
        code = main(["doctor", str(tmp_path)])
        out = capsys.readouterr().out
        assert code == 1
        assert "ctxguard doctor" in out
        assert "not fully set up" in out
