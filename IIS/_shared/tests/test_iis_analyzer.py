"""Tests for IIS_logs/scripts/iis_analyzer.py against the fixture log."""
from __future__ import annotations

from pathlib import Path

import iis_analyzer as ia


def _entries(log: Path):
    return [ia.normalise(row) for row in ia.parse_w3c_log(log)]


def test_parse_w3c_log_yields_122_rows(sample_iis_log: Path):
    assert len(_entries(sample_iis_log)) == 122


def test_compute_metrics_match_expected(sample_iis_log: Path):
    entries = _entries(sample_iis_log)
    m = ia.compute_metrics(entries)
    assert m["total_requests"] == 122
    assert m["error_5xx_count"] == 60
    assert m["error_4xx_count"] == 60
    assert m["p99_response_time_ms"] >= 5000


def test_classify_problems_finds_expected_types(sample_iis_log: Path):
    entries = _entries(sample_iis_log)
    metrics = ia.compute_metrics(entries)
    types = {p["type"] for p in ia.classify_problems(entries, metrics)}
    assert {"5xx_error", "high_latency", "auth_error", "suspicious_traffic"} <= types


def test_skills_to_trigger_includes_all_expected(sample_iis_log: Path):
    entries = _entries(sample_iis_log)
    metrics = ia.compute_metrics(entries)
    problems = ia.classify_problems(entries, metrics)
    skills = sorted({s for p in problems for s in p.get("follow_ups", [])})
    for required in ("httperror", "event_log", "security_audit",
                     "firewall", "resource_monitor", "app_crash"):
        assert required in skills, f"missing follow-up: {required}"
