"""Tests for Edge/_shared/playbook.py: registry coverage + merge behavior."""
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


def test_registry_problem_types_covered_by_playbook():
    reg = json.loads(REGISTRY_JSON.read_text(encoding="utf-8"))
    pb = json.loads(PLAYBOOK_JSON.read_text(encoding="utf-8"))
    reg_types = set(reg.get("problem_types", {}).keys())
    pb_types = set(pb.get("problem_types", {}).keys())
    missing = reg_types - pb_types
    assert not missing, f"playbook.json missing entries: {missing}"


def test_problem_types_helper_matches_json():
    pb = json.loads(PLAYBOOK_JSON.read_text(encoding="utf-8"))
    assert set(playbook.problem_types()) == set(pb["problem_types"].keys())


def test_solutions_for_crash_returns_dataclasses():
    sols = playbook.solutions_for("crash")
    assert sols
    assert all(isinstance(s, Solution) for s in sols)
    assert all(s.problem_ref == "crash" for s in sols)


def test_merge_into_result_populates_three_fields():
    r = SkillResult(skill="probe")
    playbook.merge_into_result(r, ["crash"])
    assert r.solutions and r.next_steps and r.additional_logs_needed


def test_merge_empty_problem_types_is_noop():
    r = SkillResult(skill="probe")
    playbook.merge_into_result(r, [])
    assert r.solutions == []
    assert r.next_steps == []
    assert r.additional_logs_needed == []


def test_severity_inheritance_from_finding():
    r = SkillResult(
        skill="probe",
        findings=[Finding(summary="x", severity="critical",
                          evidence={"problem_type": "crash"})],
    )
    playbook.merge_into_result(r, ["crash"])
    # Any solution whose declared severity was info should now be elevated.
    elevated = [s for s in r.solutions if s.problem_ref == "crash"]
    assert any(s.severity in ("critical", "warning") for s in elevated)


def test_dedup_helpers_use_canonical_keys():
    s_dup = [
        Solution(title="t", problem_ref="crash"),
        Solution(title="t", problem_ref="crash", steps=["x"]),
        Solution(title="t", problem_ref="other"),
    ]
    assert len(playbook._dedup_solutions(s_dup)) == 2

    n_dup = [
        NextStep(action="a", skill="s"),
        NextStep(action="a", skill="s"),
        NextStep(action="a", skill="other"),
    ]
    assert len(playbook._dedup_next_steps(n_dup)) == 2

    l_dup = [
        LogRequest(log_kind="crashpad", why="...", skill="edge_crash"),
        LogRequest(log_kind="crashpad", why="...", skill="edge_crash"),
        LogRequest(log_kind="crashpad", why="...", skill=None),
    ]
    assert len(playbook._dedup_log_requests(l_dup)) == 2


def test_unknown_problem_type_yields_empty():
    assert playbook.solutions_for("does_not_exist") == []
    assert playbook.next_steps_for("does_not_exist") == []
    assert playbook.logs_for("does_not_exist") == []
