"""
_shared/contract.py

Lightweight, dependency-free helpers that every skill in this collection uses.

Goals:
  * One place to load the skill registry
  * One way to read input context (positional JSON string OR @path/to/file.json)
  * One way to emit a contract-compliant result on stdout
  * Robust path resolution (skills work from any cwd)

Python 3.10+, stdlib only.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

#: Repository root (the folder that contains AGENTS.md and _shared/).
ROOT: Path = Path(__file__).resolve().parent.parent


def registry() -> dict[str, Any]:
    """Load the canonical skill registry."""
    with (ROOT / "_shared" / "registry.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


def skill_entry(skill_id: str, runtime: str = "python") -> Path:
    """Resolve a skill's entry script to an absolute path."""
    reg = registry()
    if skill_id not in reg["skills"]:
        raise KeyError(f"Unknown skill: {skill_id}")
    rel = reg["skills"][skill_id]["entry"].get(runtime)
    if not rel:
        raise KeyError(f"Skill {skill_id} has no {runtime} entry")
    return (ROOT / rel).resolve()


# ---------------------------------------------------------------------------
# Context loading
# ---------------------------------------------------------------------------

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
        # Treat as a file path if it looks like one
        p = Path(raw)
        if p.exists():
            with p.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        raise


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------

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
    problem_ref: str | None = None     # e.g. "5xx_error", "crash"
    severity: str = "info"             # critical | warning | info
    references: list[str] = field(default_factory=list)


@dataclass
class NextStep:
    """A recommended follow-up investigation action."""
    action: str
    why: str | None = None
    skill: str | None = None           # optional skill_id to invoke next


@dataclass
class LogRequest:
    """An additional log/data source needed to deepen the analysis."""
    log_kind: str                      # e.g. "evtx", "http_err", "iis_log", "crashpad"
    why: str
    how_to_collect: str | None = None
    skill: str | None = None           # optional skill_id that would consume it


@dataclass
class SkillResult:
    skill: str
    ok: bool = True
    findings: list[Finding] = field(default_factory=list)
    root_cause: str | None = None
    confidence: str = "low"           # high | medium | low
    recommendations: list[str] = field(default_factory=list)
    # v2.1 — structured advisory sections. Backward-compatible: when these are
    # populated and `recommendations` is empty, `emit()` auto-derives flat
    # `recommendations` strings so legacy consumers keep working.
    solutions: list[Solution] = field(default_factory=list)
    next_steps: list[NextStep] = field(default_factory=list)
    additional_logs_needed: list[LogRequest] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def _flatten_recommendations(self) -> list[str]:
        """Build legacy `recommendations` strings from the new structured fields."""
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
        # Auto-fill legacy recommendations when caller left them empty but
        # provided structured advisory entries.
        if not self.recommendations and (self.solutions or self.next_steps
                                          or self.additional_logs_needed):
            self.recommendations = self._flatten_recommendations()
        return json.dumps(asdict(self), indent=2, ensure_ascii=True, default=str)

    def emit(self) -> None:
        """Write to stdout. Use this as the last line of every skill."""
        print(self.to_json())


def fail(skill: str, message: str, exit_code: int = 1) -> None:
    """Emit a failure envelope and exit."""
    SkillResult(skill=skill, ok=False, error=message, confidence="low").emit()
    sys.exit(exit_code)


# ---------------------------------------------------------------------------
# Time helpers (the #1 thing every skill needs)
# ---------------------------------------------------------------------------

def parse_time(value: str) -> datetime:
    """Parse ISO 8601 with or without timezone; tolerant to 'Z' suffix."""
    s = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def time_range(ctx: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    """Pull (start, end) from a context. Either may be None."""
    tr = ctx.get("time_range") or {}
    start = parse_time(tr["start"]) if tr.get("start") else None
    end   = parse_time(tr["end"])   if tr.get("end")   else None
    return start, end


def _normalize_tz(a: datetime, b: datetime) -> tuple[datetime, datetime]:
    """Ensure both datetimes are tz-aware or both naive so they can be compared."""
    from datetime import timezone
    a_aware = a.tzinfo is not None and a.tzinfo.utcoffset(a) is not None
    b_aware = b.tzinfo is not None and b.tzinfo.utcoffset(b) is not None
    if a_aware and not b_aware:
        b = b.replace(tzinfo=a.tzinfo)
    elif b_aware and not a_aware:
        a = a.replace(tzinfo=b.tzinfo)
    return a, b


def in_window(ts: datetime, start: datetime | None, end: datetime | None,
              tolerance_minutes: float = 0) -> bool:
    """Whether ts falls in [start, end] expanded by ±tolerance."""
    from datetime import timedelta
    tol = timedelta(minutes=tolerance_minutes)
    if start:
        ts_s, start_s = _normalize_tz(ts, start)
        if ts_s < start_s - tol:
            return False
    if end:
        ts_e, end_e = _normalize_tz(ts, end)
        if ts_e > end_e + tol:
            return False
    return True


__all__ = [
    "ROOT", "registry", "skill_entry",
    "load_context",
    "Finding", "Solution", "NextStep", "LogRequest",
    "SkillResult", "fail",
    "parse_time", "time_range", "in_window",
]
