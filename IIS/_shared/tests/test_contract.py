"""Unit tests for _shared/contract.py."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta

import pytest

import contract


def test_load_context_inline_json():
    ctx = contract.load_context(['{"problem_type":"5xx_error"}'])
    assert ctx["problem_type"] == "5xx_error"


def test_load_context_at_file(tmp_path):
    f = tmp_path / "ctx.json"
    f.write_text('{"problem_type":"high_latency"}', encoding="utf-8")
    ctx = contract.load_context([f"@{f}"])
    assert ctx["problem_type"] == "high_latency"


def test_load_context_empty():
    assert contract.load_context([]) == {}


def test_parse_time_iso_z_suffix():
    t = contract.parse_time("2025-01-15T10:00:00Z")
    assert t.year == 2025 and t.minute == 0


def test_time_range_returns_two():
    start, end = contract.time_range(
        {"time_range": {"start": "2025-01-15T10:00:00", "end": "2025-01-15T11:00:00"}}
    )
    assert (end - start) == timedelta(hours=1)


def test_in_window_tolerance():
    s = datetime(2025, 1, 15, 10, 0, 0)
    e = datetime(2025, 1, 15, 11, 0, 0)
    assert contract.in_window(s - timedelta(minutes=1), s, e, tolerance_minutes=2)
    assert not contract.in_window(s - timedelta(minutes=5), s, e, tolerance_minutes=2)


def test_skill_result_envelope_keys():
    d = asdict(contract.SkillResult(skill="iis_logs", ok=True))
    for key in ("skill", "ok", "findings", "root_cause", "confidence",
                "recommendations", "raw", "error", "generated_at"):
        assert key in d


def test_skill_result_to_json_round_trip():
    import json
    parsed = json.loads(contract.SkillResult(skill="iis_logs").to_json())
    assert parsed["skill"] == "iis_logs"


def test_registry_has_iis_logs_and_skill_entry_returns_path():
    reg = contract.registry()
    assert "iis_logs" in reg["skills"]
    p_py = contract.skill_entry("iis_logs", runtime="python")
    assert p_py.suffix == ".py"
    p_ps = contract.skill_entry("event_log", runtime="pwsh")
    assert p_ps.suffix == ".ps1"


def test_skill_entry_unknown_raises():
    with pytest.raises(KeyError):
        contract.skill_entry("does_not_exist")
