"""Tests for ftp_logs/scripts/ftp_analyzer.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# conftest.py wires up IIS_logs/scripts and orchestrator/scripts; we also
# need ftp_logs/scripts on sys.path for direct import.
_REPO = Path(__file__).resolve().parents[2]
_FTP_SCRIPTS = _REPO / "ftp_logs" / "scripts"
if str(_FTP_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_FTP_SCRIPTS))

import ftp_analyzer as fa  # noqa: E402


@pytest.fixture(scope="module")
def sample_ftp_log(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample_ftp.log"


def _entries(path: Path):
    return [fa.normalise(r) for r in fa.parse_ftp_log(path)]


def test_parse_yields_rows(sample_ftp_log: Path):
    entries = _entries(sample_ftp_log)
    assert len(entries) >= 20
    cmds = {e["method"] for e in entries}
    assert {"USER", "PASS", "STOR", "QUIT"} <= cmds


def test_reconstruct_sessions_groups_by_x_session(sample_ftp_log: Path):
    entries = _entries(sample_ftp_log)
    sessions = fa.reconstruct_sessions(entries)
    keys = {s["key"] for s in sessions}
    # Each distinct x-session in the fixture becomes one session.
    assert "sid:sess-A" in keys
    assert "sid:sess-B" in keys
    # alice's session terminates cleanly with QUIT
    alice = next(s for s in sessions if s["username"] == "alice")
    assert alice["terminated_cleanly"]
    assert alice["bytes_up"] >= 2048
    assert alice["bytes_down"] >= 2048


def test_reconstruct_sessions_falls_back_to_ip_heuristic(tmp_path: Path):
    # No x-session column at all.
    p = tmp_path / "no_session.log"
    p.write_text(
        "#Software: Microsoft FTP Service\n"
        "#Fields: date time c-ip cs-username cs-method cs-uri-stem "
        "sc-status sc-win32-status sc-substatus sc-bytes cs-bytes time-taken\n"
        "2026-05-26 10:00:00 10.0.0.1 - USER - 331 0 0 0 0 5\n"
        "2026-05-26 10:00:01 10.0.0.1 alice PASS - 230 0 0 0 0 5\n"
        "2026-05-26 10:00:02 10.0.0.1 alice QUIT - 221 0 0 0 0 5\n"
        "2026-05-26 10:01:00 10.0.0.1 - USER - 331 0 0 0 0 5\n"
        "2026-05-26 10:01:01 10.0.0.1 bob PASS - 230 0 0 0 0 5\n"
        "2026-05-26 10:01:02 10.0.0.1 bob QUIT - 221 0 0 0 0 5\n",
        encoding="utf-8",
    )
    sessions = fa.reconstruct_sessions(_entries(p))
    # The same IP with two USERs should yield two sessions via heuristic.
    assert len(sessions) == 2
    users = sorted(s["username"] for s in sessions)
    assert users == ["alice", "bob"]


def test_classify_problems_detects_brute_force_and_upload_error(sample_ftp_log: Path):
    entries = _entries(sample_ftp_log)
    sessions = fa.reconstruct_sessions(entries)
    problems = fa.classify_problems(entries, sessions)
    types = {p["type"] for p in problems}
    assert "ftp_brute_force" in types
    assert "ftp_upload_error" in types


def test_cli_emits_contract_envelope(sample_ftp_log: Path, capsys):
    rc = fa.main([str(sample_ftp_log)])
    out = capsys.readouterr().out
    assert rc == 0, out
    payload = json.loads(out)
    assert payload["skill"] == "ftp_logs"
    assert payload["ok"] is True
    raw = payload["raw"]
    for key in ("sessions", "session_stats", "problems",
                "skills_to_trigger", "timeseries", "detected_other_logs"):
        assert key in raw, f"missing raw.{key}"
    assert raw["session_stats"]["total_sessions"] >= 5


def test_cli_filter_and_around(sample_ftp_log: Path, capsys):
    rc = fa.main([
        str(sample_ftp_log),
        "--filter", "cmd=PASS,status=500-599,ip=10.0.0.0/24",
        "--around", "2026-05-26 09:01:05",
        "--window", "30s",
    ])
    out = capsys.readouterr().out
    assert rc == 0, out
    payload = json.loads(out)
    assert payload["raw"]["search"]["summary"]["count"] >= 5
    around = payload["raw"]["around"]
    assert "2026-05-26 09:01:05" in around


def test_cli_html_report(sample_ftp_log: Path, tmp_path: Path, capsys):
    report = tmp_path / "ftp.html"
    rc = fa.main([str(sample_ftp_log), "--bucket", "10s",
                  "--report", str(report)])
    capsys.readouterr()
    assert rc == 0
    text = report.read_text(encoding="utf-8")
    assert "FTP log analysis report" in text
    assert "<svg" in text
