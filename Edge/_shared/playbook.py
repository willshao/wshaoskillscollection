"""
_shared/playbook.py — Edge edition.

Same surface as IIS/_shared/playbook.py. Loads Edge/_shared/playbook.json
and merges standard solutions / next steps / log requests into a SkillResult.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from _shared.contract import ROOT, Solution, NextStep, LogRequest, SkillResult

_PLAYBOOK_PATH = ROOT / "_shared" / "playbook.json"

_SEV_RANK = {"info": 0, "warning": 1, "critical": 2}


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    with _PLAYBOOK_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def problem_types() -> list[str]:
    return sorted((_load().get("problem_types") or {}).keys())


def _entries_for(problem_type: str | None) -> dict[str, list[dict[str, Any]]]:
    if not problem_type:
        return {"solutions": [], "next_steps": [], "additional_logs_needed": []}
    return ((_load().get("problem_types") or {}).get(problem_type) or
            {"solutions": [], "next_steps": [], "additional_logs_needed": []})


def solutions_for(problem_type: str | None) -> list[Solution]:
    out: list[Solution] = []
    for s in _entries_for(problem_type).get("solutions") or []:
        out.append(Solution(
            title=s["title"],
            steps=list(s.get("steps") or []),
            problem_ref=problem_type,
            severity=s.get("severity", "info"),
            references=list(s.get("references") or []),
        ))
    return out


def next_steps_for(problem_type: str | None) -> list[NextStep]:
    out: list[NextStep] = []
    for n in _entries_for(problem_type).get("next_steps") or []:
        out.append(NextStep(
            action=n["action"],
            why=n.get("why"),
            skill=n.get("skill"),
        ))
    return out


def logs_for(problem_type: str | None) -> list[LogRequest]:
    out: list[LogRequest] = []
    for l in _entries_for(problem_type).get("additional_logs_needed") or []:
        out.append(LogRequest(
            log_kind=l["log_kind"],
            why=l["why"],
            how_to_collect=l.get("how_to_collect"),
            skill=l.get("skill"),
        ))
    return out


def _highest_finding_severity(result: SkillResult, problem_ref: str | None) -> str | None:
    if not problem_ref:
        return None
    best: str | None = None
    best_rank = -1
    for f in result.findings:
        ev = f.evidence or {}
        if ev.get("type") != problem_ref:
            continue
        rank = _SEV_RANK.get(f.severity, 0)
        if rank > best_rank:
            best, best_rank = f.severity, rank
    return best


def _dedup_solutions(items: Iterable[Solution]) -> list[Solution]:
    seen: dict[tuple[str | None, str], Solution] = {}
    for s in items:
        key = (s.problem_ref, s.title)
        if key not in seen:
            seen[key] = s
    return list(seen.values())


def _dedup_next_steps(items: Iterable[NextStep]) -> list[NextStep]:
    seen: dict[tuple[str, str | None], NextStep] = {}
    for n in items:
        key = (n.action, n.skill)
        if key not in seen:
            seen[key] = n
    return list(seen.values())


def _dedup_log_requests(items: Iterable[LogRequest]) -> list[LogRequest]:
    seen: dict[tuple[str, str | None], LogRequest] = {}
    for l in items:
        key = (l.log_kind, l.skill)
        if key not in seen:
            seen[key] = l
    return list(seen.values())


def merge_into_result(result: SkillResult,
                      problem_types: Iterable[str] | None = None,
                      *,
                      extra_solutions: Iterable[Solution] = (),
                      extra_next_steps: Iterable[NextStep] = (),
                      extra_logs: Iterable[LogRequest] = ()) -> SkillResult:
    sols: list[Solution] = list(result.solutions)
    nxts: list[NextStep] = list(result.next_steps)
    logs: list[LogRequest] = list(result.additional_logs_needed)

    for pt in problem_types or ():
        sols.extend(solutions_for(pt))
        nxts.extend(next_steps_for(pt))
        logs.extend(logs_for(pt))

    sols.extend(extra_solutions)
    nxts.extend(extra_next_steps)
    logs.extend(extra_logs)

    for s in sols:
        if s.severity == "info":
            inherited = _highest_finding_severity(result, s.problem_ref)
            if inherited:
                s.severity = inherited

    result.solutions = _dedup_solutions(sols)
    result.next_steps = _dedup_next_steps(nxts)
    result.additional_logs_needed = _dedup_log_requests(logs)
    return result


__all__ = [
    "problem_types",
    "solutions_for", "next_steps_for", "logs_for",
    "merge_into_result",
]
