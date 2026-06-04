"""Tests for the v2.1 enhancements to iis_analyzer.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import iis_analyzer as ia


def _run(args: list[str], capsys) -> dict:
    rc = ia.main(args)
    out = capsys.readouterr().out
    assert rc == 0, out
    return json.loads(out)


def test_contract_envelope_preserved(sample_iis_log: Path, capsys):
    payload = _run([str(sample_iis_log)], capsys)
    raw = payload["raw"]
    # Old fields still present
    for key in ("metrics", "problems", "skills_to_trigger", "log_files_parsed"):
        assert key in raw
    # New fields present
    assert "timeseries" in raw
    assert "detected_other_logs" in raw
    # Skill envelope untouched
    for key in ("skill", "ok", "findings", "root_cause",
                "confidence", "recommendations", "generated_at"):
        assert key in payload


def test_filter_search_returns_only_5xx(sample_iis_log: Path, capsys):
    payload = _run([str(sample_iis_log), "--filter", "status=500-599"], capsys)
    search = payload["raw"]["search"]
    assert search["filter"] == "status=500-599"
    assert search["summary"]["count"] > 0
    for entry in search["results"]:
        assert 500 <= int(entry["status"]) <= 599


def test_around_window_filters_by_time(sample_iis_log: Path, capsys):
    # The fixture starts at 2025-01-15 10:00:00 — anchor near the start with
    # a tight 5-second window and ensure only a few entries match.
    payload = _run(
        [str(sample_iis_log),
         "--around", "2025-01-15 10:00:05",
         "--window", "5s"],
        capsys,
    )
    around = payload["raw"]["around"]
    assert "2025-01-15 10:00:05" in around
    matched = around["2025-01-15 10:00:05"]["summary"]["count"]
    assert 1 <= matched <= 20  # bounded by the 10s window


def test_html_report_written(sample_iis_log: Path, tmp_path: Path, capsys):
    report = tmp_path / "out.html"
    payload = _run(
        [str(sample_iis_log), "--bucket", "10s",
         "--report", str(report)],
        capsys,
    )
    assert payload["raw"]["report_html_path"].endswith("out.html")
    text = report.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "<svg" in text
    assert "IIS log analysis report" in text


def test_folder_recursive_classification(fixtures_dir: Path, tmp_path: Path, capsys):
    import shutil
    # Drop one IIS + one FTP + one HTTPERR into a directory tree.
    sub = tmp_path / "W3SVC1"
    sub.mkdir()
    shutil.copy(fixtures_dir / "sample_iis.log", sub / "u_ex260526.log")
    (tmp_path / "FTPSVC1").mkdir()
    shutil.copy(fixtures_dir / "sample_ftp.log",
                tmp_path / "FTPSVC1" / "ftp.log")
    (tmp_path / "HTTPERR").mkdir()
    shutil.copy(fixtures_dir / "httperr1.log",
                tmp_path / "HTTPERR" / "httperr1.log")

    payload = _run([str(tmp_path)], capsys)
    other = payload["raw"]["detected_other_logs"]
    assert "ftp_w3c" in other and len(other["ftp_w3c"]) == 1
    assert "httperr" in other and len(other["httperr"]) == 1
    # The recommendation mentions FTP.
    recs = " | ".join(payload["recommendations"])
    assert "ftp_logs" in recs


def test_invalid_filter_key_returns_error_envelope(sample_iis_log: Path, capsys):
    rc = ia.main([str(sample_iis_log), "--filter", "foo=bar"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 2
    assert payload["ok"] is False
    assert "filter" in payload["error"]


def test_invalid_bucket_returns_error_envelope(sample_iis_log: Path, capsys):
    rc = ia.main([str(sample_iis_log), "--bucket", "oops"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 2
    assert payload["ok"] is False
