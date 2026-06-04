"""Smoke tests for Edge contract envelope (v2.1)."""
from __future__ import annotations

import json

import pytest

from _shared.contract import (
    Finding, Solution, NextStep, LogRequest, SkillResult,
)


def test_envelope_has_v21_fields():
    r = SkillResult(skill="probe")
    d = json.loads(r.to_json())
    assert "solutions" in d
    assert "next_steps" in d
    assert "additional_logs_needed" in d
    assert d["solutions"] == []
    assert d["next_steps"] == []
    assert d["additional_logs_needed"] == []


def test_to_json_is_ascii_safe():
    """ensure_ascii=True so output never breaks Windows cp1252 consumers."""
    r = SkillResult(
        skill="probe",
        findings=[Finding(summary="contains arrow \u2192 and em-dash \u2014",
                          severity="critical")],
    )
    body = r.to_json()
    body.encode("ascii")  # must not raise


def test_recommendations_autoflatten_when_empty():
    r = SkillResult(
        skill="probe",
        solutions=[Solution(title="Reset profile", problem_ref="crash",
                            steps=["delete user data dir"])],
        next_steps=[NextStep(action="Check crashpad", skill="edge_crash")],
        additional_logs_needed=[LogRequest(log_kind="crashpad",
                                            why="need recent dumps")],
    )
    d = json.loads(r.to_json())
    recs = d["recommendations"]
    assert len(recs) == 3
    assert recs[0].startswith("[fix:crash]") and "Reset profile" in recs[0]
    assert recs[1].startswith("[next:edge_crash]")
    assert recs[2].startswith("[logs:crashpad]")


def test_recommendations_preserved_when_provided():
    r = SkillResult(
        skill="probe",
        recommendations=["explicit"],
        solutions=[Solution(title="x")],
    )
    d = json.loads(r.to_json())
    assert d["recommendations"] == ["explicit"]


def test_finding_severity_default():
    f = Finding(summary="x")
    assert f.severity == "info"
    assert f.evidence == {}
