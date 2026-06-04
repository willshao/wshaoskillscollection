"""Tests for _shared/playbook.py: registry coverage, severity inheritance, dedup."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from _shared import playbook
from _shared.contract import (
    Finding, SkillResult, Solution, NextStep, LogRequest,
)

PLAYBOOK_JSON = Path(__file__).resolve().parents[1] / "playbook.json"
REGISTRY_JSON = Path(__file__).resolve().parents[1] / "registry.json"


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def test_every_registry_problem_type_has_entries():
    reg = _load_json(REGISTRY_JSON)
    pb = _load_json(PLAYBOOK_JSON)
    reg_types = set(reg.get("problem_types", {}).keys())
    pb_types = set(pb.get("problem_types", {}).keys())
    missing = reg_types - pb_types
    assert not missing, f"playbook.json is missing entries for: {missing}"


def test_problem_types_helper_matches_json():
    pb = _load_json(PLAYBOOK_JSON)
    assert set(playbook.problem_types()) == set(pb["problem_types"].keys())


def test_solutions_for_returns_dataclasses():
    sols = playbook.solutions_for("5xx_error")
    assert sols, "expected at least one solution for 5xx_error"
    assert all(isinstance(s, Solution) for s in sols)
    assert any(s.severity == "critical" for s in sols)
    # problem_ref auto-stamped
    assert all(s.problem_ref == "5xx_error" for s in sols)


def test_next_steps_and_logs_return_dataclasses():
    nxts = playbook.next_steps_for("5xx_error")
    logs = playbook.logs_for("5xx_error")
    assert nxts and all(isinstance(n, NextStep) for n in nxts)
    assert logs and all(isinstance(l, LogRequest) for l in logs)


def test_unknown_problem_type_returns_empty():
    assert playbook.solutions_for("does_not_exist") == []
    assert playbook.next_steps_for("does_not_exist") == []
    assert playbook.logs_for("does_not_exist") == []
    assert playbook.solutions_for(None) == []


def test_dedup_solutions_by_problem_ref_and_title():
    a = Solution(title="t1", problem_ref="5xx_error")
    b = Solution(title="t1", problem_ref="5xx_error", steps=["x"])  # duplicate key
    c = Solution(title="t1", problem_ref="auth_error")              # diff ref
    d = Solution(title="t2", problem_ref="5xx_error")               # diff title
    out = playbook._dedup_solutions([a, b, c, d])
    assert len(out) == 3
    # first occurrence wins
    assert out[0] is a


def test_dedup_next_steps_by_action_and_skill():
    a = NextStep(action="run x", skill="s1")
    b = NextStep(action="run x", skill="s1")  # duplicate
    c = NextStep(action="run x", skill="s2")  # diff skill
    out = playbook._dedup_next_steps([a, b, c])
    assert len(out) == 2


def test_dedup_log_requests_by_kind_and_skill():
    a = LogRequest(log_kind="evtx", why="...", skill="event_log")
    b = LogRequest(log_kind="evtx", why="...", skill="event_log")  # dup
    c = LogRequest(log_kind="evtx", why="...", skill=None)          # diff skill
    out = playbook._dedup_log_requests([a, b, c])
    assert len(out) == 2


def test_merge_into_result_populates_three_fields():
    r = SkillResult(skill="probe")
    playbook.merge_into_result(r, ["5xx_error"])
    assert r.solutions and r.next_steps and r.additional_logs_needed


def test_merge_into_result_empty_list_is_noop():
    r = SkillResult(skill="probe")
    playbook.merge_into_result(r, [])
    assert r.solutions == []
    assert r.next_steps == []
    assert r.additional_logs_needed == []


def test_severity_inheritance_from_findings():
    r = SkillResult(
        skill="probe",
        findings=[Finding(summary="x", severity="critical",
                          evidence={"problem_type": "5xx_error"})],
    )
    playbook.merge_into_result(r, ["5xx_error"])
    # at least one solution still 'critical' (declared) — and any 'info'
    # solution for the same problem_ref should have inherited 'critical'.
    for s in r.solutions:
        if s.problem_ref == "5xx_error":
            assert s.severity in ("critical", "warning")  # never plain info


def test_merge_dedupes_across_repeated_problem_types():
    r = SkillResult(skill="probe")
    playbook.merge_into_result(r, ["5xx_error", "5xx_error"])
    once = SkillResult(skill="probe")
    playbook.merge_into_result(once, ["5xx_error"])
    assert len(r.solutions) == len(once.solutions)
    assert len(r.next_steps) == len(once.next_steps)
    assert len(r.additional_logs_needed) == len(once.additional_logs_needed)
