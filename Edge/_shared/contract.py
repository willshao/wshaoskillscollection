"""
_shared/contract.py — Edge Diagnostics Skill Collection

Dependency-free helpers used by every Edge skill. Mirrors the IIS contract
so an agent that already understands the IIS collection can use these skills
with no additional learning.

Python 3.10+, standard library only.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT: Path = Path(__file__).resolve().parent.parent


def registry() -> dict[str, Any]:
    with (ROOT / "_shared" / "registry.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


def skill_entry(skill_id: str, runtime: str = "python") -> Path:
    reg = registry()
    if skill_id not in reg["skills"]:
        raise KeyError(f"Unknown skill: {skill_id}")
    rel = reg["skills"][skill_id]["entry"].get(runtime)
    if not rel:
        raise KeyError(f"Skill {skill_id} has no {runtime} entry")
    return (ROOT / rel).resolve()


def load_context(argv: list[str] | None = None) -> dict[str, Any]:
    """
    Read the first positional argument as a context object.
    Accepts:
      * '{...json...}'       — inline JSON
      * '@path/to/file.json' — read from file
      * (missing)            — return {}
    """
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        return {}
    raw = args[0]
    if raw.startswith("@"):
        with open(raw[1:], "r", encoding="utf-8") as fh:
            return json.load(fh)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        p = Path(raw)
        if p.exists():
            with p.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        raise


@dataclass
class Finding:
    summary: str
    severity: str = "info"            # critical | warning | info
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Solution:
    """A concrete fix proposal for a key problem."""
    title: str
    steps: list[str] = field(default_factory=list)
    problem_ref: str | None = None
    severity: str = "info"
    references: list[str] = field(default_factory=list)


@dataclass
class NextStep:
    """A recommended follow-up investigation action."""
    action: str
    why: str | None = None
    skill: str | None = None


@dataclass
class LogRequest:
    """An additional log/data source needed to deepen the analysis."""
    log_kind: str
    why: str
    how_to_collect: str | None = None
    skill: str | None = None


@dataclass
class SkillResult:
    skill: str
    ok: bool = True
    findings: list[Finding] = field(default_factory=list)
    root_cause: str | None = None
    confidence: str = "low"           # high | medium | low
    recommendations: list[str] = field(default_factory=list)
    # v2.1 structured advisory sections (auto-flattened into recommendations
    # by emit() when caller leaves recommendations empty).
    solutions: list[Solution] = field(default_factory=list)
    next_steps: list[NextStep] = field(default_factory=list)
    additional_logs_needed: list[LogRequest] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def _flatten_recommendations(self) -> list[str]:
        out: list[str] = []
        for s in self.solutions:
            head = f"[fix:{s.problem_ref}] {s.title}" if s.problem_ref else f"[fix] {s.title}"
            if s.steps:
                head += f" — {s.steps[0]}"
            out.append(head)
        for n in self.next_steps:
            tag = f"[next:{n.skill}]" if n.skill else "[next]"
            out.append(f"{tag} {n.action}")
        for l in self.additional_logs_needed:
            out.append(f"[logs:{l.log_kind}] {l.why}")
        return out

    def to_json(self) -> str:
        if not self.recommendations and (self.solutions or self.next_steps
                                          or self.additional_logs_needed):
            self.recommendations = self._flatten_recommendations()
        return json.dumps(asdict(self), indent=2, ensure_ascii=True, default=str)

    def emit(self) -> None:
        print(self.to_json())


def fail(skill: str, message: str, exit_code: int = 1) -> None:
    SkillResult(skill=skill, ok=False, error=message, confidence="low").emit()
    sys.exit(exit_code)


def parse_time(value: str) -> datetime:
    s = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def time_range(ctx: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    tr = ctx.get("time_range") or {}
    start = parse_time(tr["start"]) if tr.get("start") else None
    end = parse_time(tr["end"]) if tr.get("end") else None
    return start, end


def in_window(ts: datetime, start: datetime | None, end: datetime | None,
              tolerance_minutes: float = 0) -> bool:
    from datetime import timedelta
    tol = timedelta(minutes=tolerance_minutes)
    if start and ts < start - tol:
        return False
    if end and ts > end + tol:
        return False
    return True


__all__ = [
    "ROOT", "registry", "skill_entry",
    "load_context",
    "Finding", "Solution", "NextStep", "LogRequest",
    "SkillResult", "fail",
    "parse_time", "time_range", "in_window",
]
