#!/usr/bin/env python3
"""
edge_orchestrator.py — fan-out coordinator for the Edge skill collection.

Input: a payload with at minimum `skills_to_trigger` (list[str]) and
optionally `problems`, `time_range`, `extra`. Accepts either the raw
edge_diagnostics envelope or just its `raw` block.

Runs each follow-up in parallel via _shared.contract.skill_entry().
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, load_context, registry, skill_entry,
    Solution, NextStep, LogRequest,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "orchestrator"
DEFAULT_PER_SKILL_TIMEOUT = 60
DEFAULT_TOTAL_TIMEOUT = 240
MAX_WORKERS = 3

# Map each child skill_id → the data-source kinds it actually exercises when
# it succeeds. Used by the missing-log gate to subtract "provided" from
# "expected" log_kinds.
SKILL_PRODUCES_KINDS: dict[str, tuple[str, ...]] = {
    "edge_crash":       ("crashpad",),
    "edge_diagnostics": ("crashpad", "registry", "user_data", "processes"),
    "edge_extensions":  ("user_data",),
    "edge_network":     ("registry",),
    "edge_netlog":      ("netlog",),
    "edge_performance": ("processes",),
    "edge_policy":      ("registry",),
    "edge_qa":          (),
}


def _unwrap_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Accept either an edge_diagnostics envelope or its inner raw block."""
    if "skills_to_trigger" in raw or "problems" in raw:
        return raw
    inner = raw.get("raw")
    if isinstance(inner, dict) and ("skills_to_trigger" in inner or "problems" in inner):
        return inner
    return raw


def _build_subcontext(payload: dict[str, Any], problem_type: str | None) -> dict[str, Any]:
    return {
        "time_range": payload.get("time_range") or {},
        "problem_type": problem_type,
        "extra": payload.get("extra") or {},
    }


def _problem_type_for_skill(skill_id: str, problems: list[dict[str, Any]]) -> str | None:
    reg = registry()["skills"]
    triggers = set(reg.get(skill_id, {}).get("triggers_for", []))
    for p in problems:
        if p.get("type") in triggers:
            return p["type"]
    return problems[0]["type"] if problems else None


def _run_one(skill_id: str, ctx: dict[str, Any], timeout: int) -> dict[str, Any]:
    try:
        entry = skill_entry(skill_id, "python")
    except KeyError as e:
        return {"skill": skill_id, "ok": False, "error": str(e)}
    try:
        proc = subprocess.run(
            [sys.executable, str(entry), json.dumps(ctx)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"skill": skill_id, "ok": False, "error": f"timeout after {timeout}s"}
    if proc.returncode != 0:
        return {"skill": skill_id, "ok": False,
                "error": proc.stderr.strip() or f"exit {proc.returncode}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"skill": skill_id, "ok": False,
                "error": f"non-JSON output: {e}", "raw_stdout": proc.stdout[:500]}


CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _aggregate_advisories(sub_results: dict[str, dict[str, Any]]
                          ) -> tuple[list[Solution], list[NextStep], list[LogRequest]]:
    sols: list[Solution] = []
    nxts: list[NextStep] = []
    logs: list[LogRequest] = []
    for res in sub_results.values():
        if not isinstance(res, dict):
            continue
        for s in res.get("solutions") or []:
            if isinstance(s, dict):
                sols.append(Solution(
                    title=str(s.get("title", "")),
                    steps=list(s.get("steps") or []),
                    problem_ref=s.get("problem_ref"),
                    severity=str(s.get("severity") or "info"),
                    references=list(s.get("references") or []),
                ))
        for n in res.get("next_steps") or []:
            if isinstance(n, dict):
                nxts.append(NextStep(
                    action=str(n.get("action", "")),
                    why=n.get("why"),
                    skill=n.get("skill"),
                ))
        for l in res.get("additional_logs_needed") or []:
            if isinstance(l, dict):
                logs.append(LogRequest(
                    log_kind=str(l.get("log_kind", "")),
                    why=str(l.get("why", "")),
                    how_to_collect=l.get("how_to_collect"),
                    skill=l.get("skill"),
                ))
    return (
        playbook._dedup_solutions(sols),
        playbook._dedup_next_steps(nxts),
        playbook._dedup_log_requests(logs),
    )


def _cross_source_context(payload: dict[str, Any],
                          children: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Summarise which Edge data sources were exercised and which problems
    surfaced across more than one skill (basic correlation hint)."""
    sources_used: set[str] = set()
    for sid, env in children.items():
        if not isinstance(env, dict) or not env.get("ok"):
            continue
        for kind in SKILL_PRODUCES_KINDS.get(sid, ()):
            sources_used.add(kind)

    pt_to_skills: dict[str, list[str]] = {}
    for sid, env in children.items():
        if not isinstance(env, dict) or not env.get("ok"):
            continue
        raw = env.get("raw") or {}
        for p in raw.get("problems") or []:
            t = p.get("type") if isinstance(p, dict) else None
            if t:
                pt_to_skills.setdefault(t, []).append(sid)
    shared = {t: sorted(set(sks)) for t, sks in pt_to_skills.items() if len(set(sks)) > 1}

    return {
        "sources_used": sorted(sources_used),
        "shared_problem_types": shared,
        "skills_run": sorted(children.keys()),
        "had_input_problems": bool(payload.get("problems")),
    }


# ---------------------------------------------------------------------------
# Missing-log gate
# ---------------------------------------------------------------------------

# Subset of `extra.*` keys that indicate a log/data source the caller already
# supplied. Used to mark a log_kind as "provided" without running its
# consumer skill.
EXTRA_KEY_TO_KIND: dict[str, str] = {
    "netlog_paths":   "netlog",
    "netlog_folder":  "netlog",
    "crashpad_path":  "crashpad",
    "evtx_paths":     "evtx",
    "evtx_folder":    "evtx",
}


def _expected_log_kinds(payload: dict[str, Any],
                        children: dict[str, dict[str, Any]]) -> dict[str, LogRequest]:
    """Build a {log_kind -> LogRequest} map of every log kind the playbook
    (via input problems) or any child skill said it needed.

    Returning the LogRequest preserves actionable metadata (why /
    how_to_collect) when we have to flag the kind as missing.
    """
    out: dict[str, LogRequest] = {}

    def _add(req: LogRequest) -> None:
        if req.log_kind and req.log_kind not in out:
            out[req.log_kind] = req

    for p in payload.get("problems") or []:
        t = p.get("type") if isinstance(p, dict) else None
        if t:
            for req in playbook.logs_for(t):
                _add(req)

    for env in children.values():
        if not isinstance(env, dict):
            continue
        for l in env.get("additional_logs_needed") or []:
            if not isinstance(l, dict) or not l.get("log_kind"):
                continue
            _add(LogRequest(
                log_kind=str(l.get("log_kind")),
                why=str(l.get("why") or ""),
                how_to_collect=l.get("how_to_collect"),
                skill=l.get("skill"),
            ))

    return out


def _provided_log_kinds(payload: dict[str, Any],
                        children: dict[str, dict[str, Any]]) -> set[str]:
    """Log kinds the caller already supplied (via extra) OR that a child skill
    successfully exercised on this host."""
    provided: set[str] = set()
    extra = payload.get("extra") or {}
    for key, kind in EXTRA_KEY_TO_KIND.items():
        if extra.get(key):
            provided.add(kind)
    for sid, env in children.items():
        if not isinstance(env, dict) or not env.get("ok"):
            continue
        for kind in SKILL_PRODUCES_KINDS.get(sid, ()):
            provided.add(kind)
    return provided


def _compute_missing_logs(payload: dict[str, Any],
                           children: dict[str, dict[str, Any]]
                           ) -> list[dict[str, Any]]:
    """Return a list of `additional_logs_needed`-shaped dicts for every log
    kind that was expected but not provided. Entries are sorted by log_kind
    for stable output."""
    expected = _expected_log_kinds(payload, children)
    provided = _provided_log_kinds(payload, children)
    missing = sorted(k for k in expected if k not in provided)
    out: list[dict[str, Any]] = []
    for kind in missing:
        req = expected[kind]
        out.append({
            "log_kind": kind,
            "why": req.why,
            "how_to_collect": req.how_to_collect,
            "skill": req.skill,
        })
    return out


def _operator_summary_md(*, payload: dict[str, Any],
                          assignments: dict[str, str | None],
                          children: dict[str, dict[str, Any]],
                          findings: list[Finding],
                          root_cause: str | None,
                          confidence: str,
                          solutions: list[Solution],
                          next_steps: list[NextStep],
                          additional_logs_needed: list[LogRequest],
                          cross_source_context: dict[str, Any],
                          missing_logs: list[dict[str, Any]] | None = None) -> str:
    lines: list[str] = []
    lines.append("# Edge orchestrator summary")
    lines.append("")
    lines.append(f"- Skills run: {', '.join(sorted(children.keys())) or '_none_'}")
    lines.append(f"- Confidence: **{confidence}**")
    if root_cause:
        lines.append(f"- Root cause: {root_cause}")
    avail = cross_source_context.get("sources_used") or []
    lines.append(f"- Data sources exercised: {', '.join(f'`{s}`' for s in avail) or '_none_'}")
    if missing_logs:
        kinds = ", ".join(f"`{m['log_kind']}`" for m in missing_logs)
        lines.append(f"- Missing log kinds: {kinds}")
    shared = cross_source_context.get("shared_problem_types") or {}
    if shared:
        lines.append("- Problem types confirmed by multiple skills:")
        for pt, sks in sorted(shared.items()):
            lines.append(f"  - `{pt}` (from {', '.join(sks)})")

    if findings:
        lines.append("")
        lines.append("## Top findings")
        for f in findings[:10]:
            sev = f.severity if isinstance(f, Finding) else (f.get("severity") if isinstance(f, dict) else "info")
            summ = f.summary if isinstance(f, Finding) else (f.get("summary") if isinstance(f, dict) else str(f))
            lines.append(f"- **{sev}** — {summ}")

    if missing_logs:
        lines.append("")
        lines.append("## Missing required logs")
        lines.append("These log kinds were needed for the requested investigation but were not provided.")
        for m in missing_logs:
            tail = f" (`{m['skill']}`)" if m.get("skill") else ""
            lines.append(f"- `{m['log_kind']}` — {m.get('why') or 'required for full analysis'}{tail}")
            if m.get("how_to_collect"):
                lines.append(f"  - _how:_ {m['how_to_collect']}")

    if solutions:
        lines.append("")
        lines.append("## Solutions")
        for s in solutions:
            ref = f" _(for `{s.problem_ref}`)_" if s.problem_ref else ""
            lines.append(f"- **{s.severity}** — {s.title}{ref}")
            for step in s.steps:
                lines.append(f"  - {step}")

    if next_steps:
        lines.append("")
        lines.append("## Next steps")
        for n in next_steps:
            tail = f" (`{n.skill}`)" if n.skill else ""
            lines.append(f"- {n.action}{tail}")
            if n.why:
                lines.append(f"  - _why:_ {n.why}")

    if additional_logs_needed:
        lines.append("")
        lines.append("## Additional logs needed")
        for l in additional_logs_needed:
            tail = f" (`{l.skill}`)" if l.skill else ""
            lines.append(f"- `{l.log_kind}` — {l.why}{tail}")
            if l.how_to_collect:
                lines.append(f"  - _how:_ {l.how_to_collect}")

    return "\n".join(lines)


def orchestrate(payload: dict[str, Any],
                per_skill_timeout: int = DEFAULT_PER_SKILL_TIMEOUT,
                total_timeout: int = DEFAULT_TOTAL_TIMEOUT) -> SkillResult:
    payload = _unwrap_payload(payload)
    follow_ups: list[str] = list(payload.get("skills_to_trigger") or [])
    problems: list[dict[str, Any]] = payload.get("problems") or []

    if not follow_ups:
        return SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(summary="Nothing to orchestrate.", severity="info")],
            recommendations=["No follow-up skills were requested."],
            confidence="low",
        )

    assignments: dict[str, str | None] = {}
    children: dict[str, dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        for sid in follow_ups:
            ptype = _problem_type_for_skill(sid, problems)
            assignments[sid] = ptype
            ctx = _build_subcontext(payload, ptype)
            futures[ex.submit(_run_one, sid, ctx, per_skill_timeout)] = sid
        try:
            for fut in as_completed(futures, timeout=total_timeout):
                sid = futures[fut]
                children[sid] = fut.result()
        except TimeoutError:
            for fut, sid in futures.items():
                if sid not in children:
                    children[sid] = {"skill": sid, "ok": False, "error": "total budget exceeded"}

    # Fuse
    all_findings: list[Finding] = []
    root_causes: list[str] = []
    best_conf = "low"
    for sid, env in children.items():
        if not env.get("ok"):
            all_findings.append(Finding(
                summary=f"{sid} failed: {env.get('error')}",
                severity="warning",
                evidence={"skill": sid},
            ))
            continue
        for f in env.get("findings") or []:
            all_findings.append(Finding(
                summary=f"[{sid}] {f.get('summary')}",
                severity=f.get("severity", "info"),
                evidence={**(f.get("evidence") or {}), "_from": sid},
            ))
        rc = env.get("root_cause")
        conf = env.get("confidence", "low")
        if rc and CONFIDENCE_RANK.get(conf, 0) >= 1:
            root_causes.append(f"{sid}: {rc}")
        if CONFIDENCE_RANK.get(conf, 0) > CONFIDENCE_RANK.get(best_conf, 0):
            best_conf = conf

    recommendations: list[str] = []
    for sid, env in children.items():
        for rec in env.get("recommendations") or []:
            recommendations.append(f"[{sid}] {rec}")

    agg_sols, agg_nxts, agg_logs = _aggregate_advisories(children)
    cross_ctx = _cross_source_context(payload, children)
    missing_logs = _compute_missing_logs(payload, children)

    # Surface missing logs as warning findings so they show up in the
    # interactive interface without requiring the operator to inspect raw.
    for m in missing_logs:
        all_findings.append(Finding(
            summary=(f"Required log '{m['log_kind']}' is missing — "
                     f"analysis may be incomplete."),
            severity="warning",
            evidence={
                "log_kind": m["log_kind"],
                "why": m.get("why"),
                "how_to_collect": m.get("how_to_collect"),
                "consumer_skill": m.get("skill"),
            },
        ))

    root_cause = " | ".join(root_causes) if root_causes else None
    summary_md = _operator_summary_md(
        payload=payload, assignments=assignments, children=children,
        findings=all_findings, root_cause=root_cause, confidence=best_conf,
        solutions=agg_sols, next_steps=agg_nxts,
        additional_logs_needed=agg_logs, cross_source_context=cross_ctx,
        missing_logs=missing_logs,
    )

    return SkillResult(
        skill=SKILL_ID, ok=True,
        findings=all_findings,
        root_cause=root_cause,
        confidence=best_conf,
        recommendations=recommendations or ["No actionable recommendations from follow-up skills."],
        solutions=agg_sols,
        next_steps=agg_nxts,
        additional_logs_needed=agg_logs,
        raw={
            "problem_assignments": assignments,
            "children": children,
            "skills_run": list(children.keys()),
            "cross_source_context": cross_ctx,
            "missing_logs": missing_logs,
            "operator_summary": summary_md,
        },
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge skill orchestrator")
    ap.add_argument("context", nargs="?", default=None)
    ap.add_argument("--per-skill-timeout", type=int, default=DEFAULT_PER_SKILL_TIMEOUT)
    ap.add_argument("--total-timeout", type=int, default=DEFAULT_TOTAL_TIMEOUT)
    args = ap.parse_args(argv)

    if args.context is None and not sys.stdin.isatty():
        try:
            payload = json.loads(sys.stdin.read())
        except json.JSONDecodeError as e:
            print(f"orchestrator: failed to parse stdin: {e}", file=sys.stderr)
            return 2
    else:
        payload = load_context([args.context] if args.context else [])

    result = orchestrate(payload, args.per_skill_timeout, args.total_timeout)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
