#!/usr/bin/env python3
"""
skill_orchestrator.py — folder-first entry point + fan-out coordinator (v3)

Two operating modes, picked automatically from the first positional argument:

1. **Folder mode** (NEW)  — argument is an existing directory.
   * Discovers IIS / FTP / HTTPERR / EVTX logs underneath.
   * Optionally runs an error-pattern locator (`--error REGEX`) to derive
     anchor timestamps from arbitrary log lines.
   * Dispatches the relevant entry skills (iis_logs, ftp_logs, httperror,
     event_log) against the folder, passing `--around` anchors and a
     `time_range`.
   * Performs a secondary fan-out: every entry-skill payload that emits
     `raw.skills_to_trigger` feeds the existing `orchestrate()` helper.
   * Optionally writes an HTML summary via `--report`.

2. **Legacy pipe mode** (UNCHANGED) — argument is JSON, `@file`, a `.json`
   path, or stdin contains JSON. Behaves exactly like v2.

Skill paths are resolved from _shared/registry.json — never hard-coded.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from html import escape as html_escape
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    SkillResult, Finding, registry, skill_entry, load_context,
    Solution, NextStep, LogRequest,
)
from _shared.log_discovery import (  # noqa: E402
    discover_logs, IIS_KIND, FTP_KIND, HTTPERR_KIND, EVTX_KIND, NETLOG_KIND, UNKNOWN_KIND,
)
from _shared.error_locator import (  # noqa: E402
    find_error_anchors, dedup_anchors,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "orchestrator"
DEFAULT_PER_SKILL_TIMEOUT = 60
DEFAULT_TOTAL_TIMEOUT = 180
DEFAULT_WINDOW = "5m"
DEFAULT_ERROR_MAX_HITS = 50
MAX_WORKERS = 3

# Module-level verbosity flag. When True the orchestrator prints a
# human-readable progress trace + final summary to stderr (stdout is
# always reserved for the JSON envelope). Toggled via --quiet / --verbose
# in main(); defaults to ON for folder mode so the user can see which
# skills ran and what they found without having to grep the JSON.
_VERBOSE = True


def _log(msg: str = "") -> None:
    """Print a progress/summary line to stderr (never stdout)."""
    if _VERBOSE:
        print(msg, file=sys.stderr, flush=True)


def _sev_tag(sev: str) -> str:
    return {
        "critical": "[CRIT]",
        "warning":  "[WARN]",
        "info":     "[INFO]",
    }.get(sev, f"[{sev.upper()}]")


def _print_skill_block(skill_id: str, res: dict[str, Any]) -> None:
    """Render one child skill's result as a compact text block on stderr."""
    if not _VERBOSE:
        return
    sep = "-" * 72
    _log(sep)
    if not isinstance(res, dict):
        _log(f"  skill={skill_id}  <invalid result type {type(res).__name__}>")
        return
    ok = res.get("ok")
    status = "OK" if ok else "FAIL"
    conf = res.get("confidence", "?")
    _log(f"  skill={skill_id:<12}  status={status:<4}  confidence={conf}")
    if not ok:
        err = res.get("error") or "unknown error"
        _log(f"    error: {err}")
        return
    rc = res.get("root_cause")
    if rc:
        _log(f"    root_cause: {rc}")
    findings = res.get("findings") or []
    if findings:
        _log(f"    findings ({len(findings)}):")
        for f in findings[:8]:
            sev = f.get("severity", "info")
            _log(f"      {_sev_tag(sev)} {f.get('summary', '')}")
        if len(findings) > 8:
            _log(f"      ... ({len(findings) - 8} more)")
    sols = res.get("solutions") or []
    if sols:
        _log(f"    solutions ({len(sols)}):")
        for s in sols[:5]:
            _log(f"      - [{s.get('severity','info')}] {s.get('title','')}")
        if len(sols) > 5:
            _log(f"      ... ({len(sols) - 5} more)")
    nxts = res.get("next_steps") or []
    if nxts:
        _log(f"    next_steps ({len(nxts)}):")
        for n in nxts[:5]:
            action = n.get("action", "")
            why = n.get("why", "")
            tag = f" ({n.get('skill')})" if n.get("skill") else ""
            line = f"      -> {action}{tag}"
            if why:
                line += f"  :: {why}"
            _log(line)
        if len(nxts) > 5:
            _log(f"      ... ({len(nxts) - 5} more)")

# Discovery LogKind ↔ shorthand surfaced in cross_log_context.available.
KIND_LABEL = {
    IIS_KIND: "iis_w3c", FTP_KIND: "ftp_w3c",
    HTTPERR_KIND: "http_err", EVTX_KIND: "evtx",
    NETLOG_KIND: "netlog",
}

# Map each entry-skill ↔ the log_kind it exercises when it succeeds.
SKILL_PRODUCES_KIND: dict[str, tuple[str, ...]] = {
    "iis_logs":   ("iis_w3c",),
    "ftp_logs":   ("ftp_w3c",),
    "httperror":  ("http_err",),
    "event_log":  ("evtx",),
    "netlog":     ("netlog",),
}


def _build_subcontext(iis_payload: dict[str, Any], problem_type: str | None) -> dict[str, Any]:
    metrics = iis_payload.get("metrics", {})
    return {
        "time_range": metrics.get("time_range", {}),
        "problem_type": problem_type,
        "metrics": metrics,
    }


def _run_one(skill_id: str, ctx: dict[str, Any], timeout: int) -> dict[str, Any]:
    try:
        entry = skill_entry(skill_id, "python")
    except KeyError as e:
        return {"skill": skill_id, "ok": False, "error": str(e)}
    proc = subprocess.run(
        [sys.executable, str(entry), json.dumps(ctx)],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        return {"skill": skill_id, "ok": False,
                "error": proc.stderr.strip() or f"exit {proc.returncode}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"skill": skill_id, "ok": False,
                "error": f"non-JSON output: {e}", "raw_stdout": proc.stdout[:500]}


def _problem_type_for_skill(skill_id: str, problems: list[dict[str, Any]]) -> str | None:
    """Pick the most relevant problem_type for this skill (first match wins)."""
    reg = registry()["skills"]
    triggers = set(reg.get(skill_id, {}).get("triggers_for", []))
    for p in problems:
        if p.get("type") in triggers:
            return p["type"]
    return problems[0]["type"] if problems else None


def _aggregate_advisories(sub_results: dict[str, dict[str, Any]]
                          ) -> tuple[list[Solution], list[NextStep], list[LogRequest]]:
    """Collect `solutions` / `next_steps` / `additional_logs_needed` from every
    child result (dicts from JSON), dedup with playbook helpers, return
    canonical dataclass lists."""
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


def _cross_log_context(discovery: dict[str, list[str]] | None,
                       time_range: dict[str, str] | None,
                       results: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    """Summarise which log kinds were present together so the operator can
    correlate IIS W3C entries with Event Log entries inside the same window."""
    discovery = discovery or {}
    results = results or {}
    has_iis = bool(discovery.get(IIS_KIND) or (results.get("iis_logs") or {}).get("ok"))
    has_evtx = bool(discovery.get(EVTX_KIND) or (results.get("event_log") or {}).get("ok"))
    has_httperr = bool(discovery.get(HTTPERR_KIND) or (results.get("httperror") or {}).get("ok"))
    has_ftp = bool(discovery.get(FTP_KIND) or (results.get("ftp_logs") or {}).get("ok"))
    has_netlog = bool(discovery.get(NETLOG_KIND) or (results.get("netlog") or {}).get("ok"))
    available = sorted(k for k, v in {
        "iis_w3c": has_iis, "evtx": has_evtx,
        "http_err": has_httperr, "ftp_w3c": has_ftp,
        "netlog": has_netlog,
    }.items() if v)
    return {
        "available": available,
        "time_range": time_range or {},
        "correlatable": has_iis and has_evtx,
        "note": ("IIS W3C and Event Log both present; correlate by time window."
                  if has_iis and has_evtx else None),
    }


# ---------------------------------------------------------------------------
# Missing-log gate
# ---------------------------------------------------------------------------

# Subset of `extra.*` / context keys that count as "log already supplied".
EXTRA_KEY_TO_KIND: dict[str, str] = {
    "netlog_paths":  "netlog",
    "netlog_folder": "netlog",
    "evtx_paths":    "evtx",
    "evtx_folder":   "evtx",
}


def _expected_log_kinds_for_folder(payload_problems: list[dict[str, Any]],
                                    results: dict[str, dict[str, Any]]
                                    ) -> dict[str, LogRequest]:
    """Build {log_kind -> LogRequest} from playbook (via observed problem
    types) and from every successful child skill's additional_logs_needed."""
    out: dict[str, LogRequest] = {}

    def _add(req: LogRequest) -> None:
        if req.log_kind and req.log_kind not in out:
            out[req.log_kind] = req

    for p in payload_problems or []:
        t = p.get("type") if isinstance(p, dict) else None
        if t:
            for req in playbook.logs_for(t):
                _add(req)

    for env in results.values():
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


def _provided_log_kinds_for_folder(discovery: dict[str, list[str]],
                                    results: dict[str, dict[str, Any]],
                                    extra: dict[str, Any] | None = None
                                    ) -> set[str]:
    """Discovery hits + child-skill exercises + caller-supplied extras."""
    provided: set[str] = set()
    for kind, paths in (discovery or {}).items():
        if not paths:
            continue
        label = KIND_LABEL.get(kind)
        if label:
            provided.add(label)
    for sid, env in (results or {}).items():
        if not isinstance(env, dict) or not env.get("ok"):
            continue
        for kind in SKILL_PRODUCES_KIND.get(sid, ()):
            provided.add(kind)
    for key, kind in EXTRA_KEY_TO_KIND.items():
        if (extra or {}).get(key):
            provided.add(kind)
    return provided


def _compute_missing_logs_folder(payload_problems: list[dict[str, Any]],
                                  discovery: dict[str, list[str]],
                                  results: dict[str, dict[str, Any]],
                                  extra: dict[str, Any] | None = None
                                  ) -> list[dict[str, Any]]:
    expected = _expected_log_kinds_for_folder(payload_problems, results)
    provided = _provided_log_kinds_for_folder(discovery, results, extra)
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


def orchestrate(iis_payload: dict[str, Any],
                per_skill_timeout: int = DEFAULT_PER_SKILL_TIMEOUT,
                total_timeout: int = DEFAULT_TOTAL_TIMEOUT) -> SkillResult:
    follow_ups: list[str] = list(iis_payload.get("skills_to_trigger", []))
    problems: list[dict[str, Any]] = iis_payload.get("problems", [])

    if not follow_ups:
        return SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(summary="Nothing to orchestrate", severity="info")],
            recommendations=["No follow-up skills were requested."],
            raw={"executed": []},
        )

    sub_results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(_run_one, skill,
                        _build_subcontext(iis_payload,
                                          _problem_type_for_skill(skill, problems)),
                        per_skill_timeout): skill
            for skill in follow_ups
        }
        for fut in as_completed(futures, timeout=total_timeout):
            skill = futures[fut]
            try:
                sub_results[skill] = fut.result()
            except Exception as exc:
                sub_results[skill] = {"skill": skill, "ok": False, "error": str(exc)}

    successes = [s for s, r in sub_results.items() if r.get("ok")]
    failures = [s for s, r in sub_results.items() if not r.get("ok")]

    # Build a fused finding list
    findings: list[Finding] = []
    root_chain: list[dict[str, str]] = []
    for skill, res in sub_results.items():
        if not res.get("ok"):
            continue
        for f in res.get("findings", []):
            findings.append(Finding(
                summary=f"[{skill}] {f.get('summary', '')}",
                severity=f.get("severity", "info"),
                evidence=f.get("evidence", {}),
            ))
        if res.get("root_cause"):
            root_chain.append({"skill": skill, "finding": res["root_cause"]})

    success_rate = len(successes) / max(1, len(follow_ups))
    confidence = "high" if success_rate >= 0.8 else "medium" if success_rate >= 0.5 else "low"

    agg_sols, agg_nxts, agg_logs = _aggregate_advisories(sub_results)

    return SkillResult(
        skill=SKILL_ID,
        ok=len(failures) == 0,
        findings=findings,
        root_cause=" → ".join(item["finding"] for item in root_chain) or None,
        confidence=confidence,
        recommendations=[
            f"Run rate: {len(successes)}/{len(follow_ups)} skills succeeded.",
            *([f"Re-run failed skills: {', '.join(failures)}"] if failures else []),
        ],
        solutions=agg_sols,
        next_steps=agg_nxts,
        additional_logs_needed=agg_logs,
        raw={
            "executed": follow_ups,
            "results": sub_results,
            "root_cause_chain": root_chain,
            "cross_log_context": _cross_log_context(None, iis_payload.get("metrics", {}).get("time_range"), sub_results),
        },
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Multi-skill orchestrator (folder-first)")
    ap.add_argument("context", nargs="?", default=None,
                    help="Folder path, JSON string, @file, .json path, or omit for stdin")
    ap.add_argument("--per-skill-timeout", type=int, default=DEFAULT_PER_SKILL_TIMEOUT)
    ap.add_argument("--total-timeout", type=int, default=DEFAULT_TOTAL_TIMEOUT)
    # Folder-mode-only switches (ignored in legacy mode).
    ap.add_argument("--around", action="append", default=[], metavar="TIMESTAMP",
                    help="Anchor timestamp passed through to iis_logs/ftp_logs. Repeatable.")
    ap.add_argument("--window", default=DEFAULT_WINDOW,
                    help="Window around each anchor (e.g. 30s, 5m, 1h). Default 5m.")
    ap.add_argument("--error", default=None, metavar="REGEX",
                    help="Search every text log under the folder for REGEX. "
                         "Matching lines' timestamps become extra --around anchors.")
    ap.add_argument("--no-recursive", action="store_true",
                    help="Folder mode: do not descend into subdirectories.")
    ap.add_argument("--report", default=None, metavar="HTML_PATH",
                    help="Folder mode: write an HTML summary to this path.")
    ap.add_argument("--agent-summary", default=None, metavar="PATH",
                    help=("Folder mode: read a Markdown or HTML file holding the "
                          "agent's (Copilot CLI) consolidated diagnosis / solution "
                          "and embed it as a featured section at the top of the "
                          "HTML report."))
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="Suppress the human-readable progress trace on stderr.")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Force the progress trace on stderr (default in folder mode).")
    args = ap.parse_args(argv)

    global _VERBOSE
    if args.quiet:
        _VERBOSE = False
    elif args.verbose:
        _VERBOSE = True

    # --- Mode arbitration -------------------------------------------------
    arg = args.context
    if arg and not arg.startswith("{") and not arg.startswith("@") \
            and not arg.lower().endswith(".json"):
        candidate = Path(arg)
        if candidate.exists() and candidate.is_dir():
            result = orchestrate_folder(
                folder=candidate,
                around=list(args.around),
                window=args.window,
                error_pattern=args.error,
                recursive=not args.no_recursive,
                per_skill_timeout=args.per_skill_timeout,
                total_timeout=args.total_timeout,
                report_path=Path(args.report) if args.report else None,
                agent_summary_path=(Path(args.agent_summary)
                                    if args.agent_summary else None),
            )
            result.emit()
            return 0 if result.ok else 1

    # --- Legacy pipe mode (unchanged) -------------------------------------
    if args.context is None and not sys.stdin.isatty():
        payload = json.loads(sys.stdin.read())
    else:
        payload = load_context([args.context] if args.context else [])

    # Accept both the IIS analyzer's full envelope and its `raw` sub-block
    if isinstance(payload, dict) and "raw" in payload and "skills_to_trigger" in payload.get("raw", {}):
        payload = payload["raw"]

    result = orchestrate(payload, args.per_skill_timeout, args.total_timeout)
    result.emit()
    return 0 if result.ok else 1


# =========================================================================
# Folder-mode helpers
# =========================================================================

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(s|sec|m|min|h|hr)?\s*$",
                          re.IGNORECASE)


def _parse_duration_seconds(text: str) -> int:
    m = _DURATION_RE.match(text or "")
    if not m:
        raise ValueError(f"invalid duration: {text!r}")
    n = float(m.group(1))
    unit = (m.group(2) or "s").lower()
    if unit.startswith("s"):
        return int(n)
    if unit.startswith("m"):
        return int(n * 60)
    if unit.startswith("h"):
        return int(n * 3600)
    raise ValueError(f"invalid duration: {text!r}")


def _parse_anchor(text: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        s = text.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s).replace(tzinfo=None)
    except ValueError:
        return None


def _run_cli_skill(skill_id: str, cli_args: list[str], timeout: int) -> dict[str, Any]:
    """Invoke a skill via its CLI (positional file/folder), capture JSON."""
    try:
        entry = skill_entry(skill_id, "python")
    except KeyError as exc:
        return {"skill": skill_id, "ok": False, "error": str(exc)}
    cmd = [sys.executable, str(entry), *cli_args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"skill": skill_id, "ok": False,
                "error": f"timed out after {timeout}s", "cmd": cmd}
    if proc.returncode != 0 and not proc.stdout.strip():
        return {"skill": skill_id, "ok": False,
                "error": proc.stderr.strip() or f"exit {proc.returncode}",
                "cmd": cmd}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"skill": skill_id, "ok": False,
                "error": f"non-JSON output: {exc}",
                "raw_stdout": proc.stdout[:500], "cmd": cmd}


def _run_json_skill(skill_id: str, ctx: dict[str, Any], timeout: int) -> dict[str, Any]:
    """Invoke a skill with a JSON context as its first positional arg."""
    return _run_one(skill_id, ctx, timeout)


def _bounding_time_range(anchors: list[datetime], window_seconds: int
                          ) -> dict[str, str] | None:
    if not anchors:
        return None
    half = timedelta(seconds=window_seconds)
    lo = min(anchors) - half
    hi = max(anchors) + half
    return {"start": lo.strftime("%Y-%m-%dT%H:%M:%S"),
            "end":   hi.strftime("%Y-%m-%dT%H:%M:%S")}


def orchestrate_folder(folder: Path,
                       around: list[str],
                       window: str,
                       error_pattern: str | None,
                       recursive: bool,
                       per_skill_timeout: int,
                       total_timeout: int,
                       report_path: Path | None,
                       agent_summary_path: Path | None = None) -> SkillResult:
    """Folder-first entry point. See module docstring for the high-level flow."""
    # --- Parse anchors and window ----------------------------------------
    try:
        window_seconds = _parse_duration_seconds(window)
    except ValueError as exc:
        return SkillResult(skill=SKILL_ID, ok=False,
                           error=f"--window: {exc}", confidence="low")

    user_anchors: list[datetime] = []
    bad_anchors: list[str] = []
    for raw in around:
        ts = _parse_anchor(raw)
        if ts:
            user_anchors.append(ts)
        else:
            bad_anchors.append(raw)

    # --- Discover logs ---------------------------------------------------
    disc = discover_logs(folder, recursive=recursive)
    discovery_summary: dict[str, list[str]] = {
        kind: [str(p) for p in files]
        for kind, files in disc.by_kind.items()
    }

    iis_files     = disc.by_kind.get(IIS_KIND, [])
    ftp_files     = disc.by_kind.get(FTP_KIND, [])
    httperr_files = disc.by_kind.get(HTTPERR_KIND, [])
    evtx_files    = disc.by_kind.get(EVTX_KIND, [])
    netlog_files  = disc.by_kind.get(NETLOG_KIND, [])
    text_files    = [p for kind, lst in disc.by_kind.items()
                     if kind not in (EVTX_KIND, NETLOG_KIND) for p in lst]

    _log("=" * 72)
    _log(f"IIS Orchestrator — folder mode")
    _log(f"  folder    : {folder}")
    _log(f"  recursive : {recursive}")
    _log(f"  window    : {window}  ({window_seconds}s)")
    if user_anchors:
        _log(f"  anchors   : {len(user_anchors)} user-supplied")
    _log("")
    _log("Discovered logs:")
    if discovery_summary:
        for kind, paths in discovery_summary.items():
            label = KIND_LABEL.get(kind, kind)
            _log(f"  - {label:<10} ({len(paths)} file(s))")
            for p in paths[:5]:
                _log(f"      {p}")
            if len(paths) > 5:
                _log(f"      ... ({len(paths) - 5} more)")
    else:
        _log("  (none)")

    # --- Error locator ---------------------------------------------------
    error_block: dict[str, Any] = {}
    error_anchors: list[datetime] = []
    if error_pattern:
        try:
            hits = find_error_anchors(text_files, error_pattern,
                                      max_hits=DEFAULT_ERROR_MAX_HITS)
        except ValueError as exc:
            return SkillResult(skill=SKILL_ID, ok=False,
                               error=str(exc), confidence="low")
        error_anchors = dedup_anchors(hits, min_gap_seconds=60)
        error_block = {
            "pattern": error_pattern,
            "hits": [h.to_dict() for h in hits],
            "derived_anchors": [a.strftime("%Y-%m-%d %H:%M:%S") for a in error_anchors],
        }

    all_anchors = sorted(set(user_anchors) | set(error_anchors))
    time_range = _bounding_time_range(all_anchors, window_seconds)
    around_cli = [a.strftime("%Y-%m-%d %H:%M:%S") for a in all_anchors]

    # --- Dispatch entry skills ------------------------------------------
    executed: list[str] = []
    results: dict[str, dict[str, Any]] = {}

    _log("")
    if error_block:
        _log(f"Error locator: pattern={error_pattern!r}  "
             f"hits={len(error_block.get('hits', []))}  "
             f"derived_anchors={len(error_anchors)}")
    if time_range:
        _log(f"Effective time_range: {time_range['start']} .. {time_range['end']}")
    _log("")
    _log("Dispatching entry skills...")

    def _maybe_add_around(args_list: list[str]) -> list[str]:
        out = list(args_list)
        for a in around_cli:
            out.extend(["--around", a])
        if all_anchors:
            out.extend(["--window", window])
        if not recursive:
            out.append("--no-recursive")
        return out

    if iis_files:
        _log(f">>> running skill: iis_logs ({len(iis_files)} IIS log file(s))")
        executed.append("iis_logs")
        results["iis_logs"] = _run_cli_skill(
            "iis_logs", _maybe_add_around([str(folder)]),
            timeout=per_skill_timeout,
        )
        _print_skill_block("iis_logs", results["iis_logs"])

    if ftp_files:
        _log(f">>> running skill: ftp_logs ({len(ftp_files)} FTP log file(s))")
        executed.append("ftp_logs")
        results["ftp_logs"] = _run_cli_skill(
            "ftp_logs", _maybe_add_around([str(folder)]),
            timeout=per_skill_timeout,
        )
        _print_skill_block("ftp_logs", results["ftp_logs"])

    if httperr_files:
        ctx: dict[str, Any] = {
            "problem_type": None,
            "extra": {"folder": str(folder), "no_recursive": not recursive},
        }
        if time_range:
            ctx["time_range"] = time_range
        _log(f">>> running skill: httperror ({len(httperr_files)} HTTPERR file(s))")
        executed.append("httperror")
        results["httperror"] = _run_json_skill("httperror", ctx, per_skill_timeout)
        _print_skill_block("httperror", results["httperror"])

    # event_log: run if we have evtx files (offline) OR a time_range
    # (live mode is only meaningful when a time window is known).
    if evtx_files or time_range:
        ctx = {"problem_type": None, "extra": {}}
        if evtx_files:
            ctx["extra"]["evtx_paths"] = [str(p) for p in evtx_files]
        if time_range:
            ctx["time_range"] = time_range
        mode_desc = (f"{len(evtx_files)} evtx file(s)" if evtx_files
                     else "live mode (time_range)")
        _log(f">>> running skill: event_log ({mode_desc})")
        executed.append("event_log")
        results["event_log"] = _run_json_skill("event_log", ctx, per_skill_timeout)
        _print_skill_block("event_log", results["event_log"])

    # netlog: run if any net-export JSON files were discovered.
    if netlog_files:
        ctx = {
            "problem_type": None,
            "extra": {"netlog_paths": [str(p) for p in netlog_files]},
        }
        if time_range:
            ctx["time_range"] = time_range
        _log(f">>> running skill: netlog ({len(netlog_files)} net-export file(s))")
        executed.append("netlog")
        results["netlog"] = _run_json_skill("netlog", ctx, per_skill_timeout)
        _print_skill_block("netlog", results["netlog"])

    # --- Secondary fan-out (re-use legacy orchestrate) -------------------
    fanout_calls: list[str] = []
    seen: set[str] = set(executed)
    for res in results.values():
        if not isinstance(res, dict) or not res.get("ok"):
            continue
        raw = res.get("raw") or {}
        for s in raw.get("skills_to_trigger", []) or []:
            if s in seen:
                continue
            seen.add(s)
            fanout_calls.append(s)

    secondary: dict[str, Any] | None = None
    if fanout_calls:
        _log("")
        _log(f"Secondary fan-out: {', '.join(fanout_calls)}")
        synthetic_payload = {
            "metrics": {"time_range": time_range or {}},
            "problems": _aggregate_problems(results),
            "skills_to_trigger": fanout_calls,
        }
        secondary_result = orchestrate(synthetic_payload,
                                        per_skill_timeout=per_skill_timeout,
                                        total_timeout=total_timeout)
        secondary = json.loads(secondary_result.to_json())
        _print_skill_block("secondary", secondary)

    # --- Fuse findings ---------------------------------------------------
    findings: list[Finding] = []
    root_chain: list[dict[str, str]] = []
    failures: list[str] = []

    for skill, res in results.items():
        if not isinstance(res, dict) or not res.get("ok"):
            failures.append(skill)
            findings.append(Finding(
                summary=f"[{skill}] skill failed: {res.get('error', 'unknown error')}"
                        if isinstance(res, dict) else f"[{skill}] invalid result",
                severity="warning",
            ))
            continue
        for f in res.get("findings", [])[:5]:
            findings.append(Finding(
                summary=f"[{skill}] {f.get('summary', '')}",
                severity=f.get("severity", "info"),
                evidence=f.get("evidence", {}),
            ))
        if res.get("root_cause"):
            root_chain.append({"skill": skill, "finding": res["root_cause"]})

    if secondary and secondary.get("ok"):
        for f in secondary.get("findings", [])[:5]:
            findings.append(Finding(
                summary=f"[secondary:{f.get('summary', '')}]",
                severity=f.get("severity", "info"),
                evidence=f.get("evidence", {}),
            ))
        for item in (secondary.get("raw") or {}).get("root_cause_chain", []):
            root_chain.append(item)

    if not executed:
        findings.insert(0, Finding(
            summary=f"No recognisable IIS/FTP/HTTPERR/EVTX logs found under {folder}",
            severity="info",
            evidence={"discovery": discovery_summary},
        ))

    if bad_anchors:
        findings.append(Finding(
            summary=f"Ignored {len(bad_anchors)} unparseable --around value(s)",
            severity="warning",
            evidence={"unparseable": bad_anchors},
        ))

    # --- Confidence ------------------------------------------------------
    if not executed:
        confidence = "low"
    else:
        ok_count = sum(1 for s in executed if isinstance(results.get(s), dict)
                       and results[s].get("ok"))
        rate = ok_count / len(executed)
        confidence = "high" if rate >= 0.8 else "medium" if rate >= 0.5 else "low"

    # --- Optional HTML report -------------------------------------------
    # Aggregate advisories from every child result (entry + secondary).
    combined_results: dict[str, dict[str, Any]] = dict(results)
    if secondary:
        combined_results["_secondary"] = secondary
    agg_sols, agg_nxts, agg_logs = _aggregate_advisories(combined_results)
    cross_ctx = _cross_log_context(discovery_summary, time_range, results)

    # --- Missing-log gate ----------------------------------------------
    # Compute required log_kinds (from playbook via observed problems, plus
    # every child skill's additional_logs_needed) minus the kinds we
    # actually have (discovery + successful child runs).
    aggregated_problems = _aggregate_problems(results)
    if secondary and secondary.get("ok"):
        for p in (secondary.get("raw") or {}).get("problems", []) or []:
            if isinstance(p, dict):
                aggregated_problems.append(p)
    missing_logs = _compute_missing_logs_folder(
        payload_problems=aggregated_problems,
        discovery=discovery_summary,
        results=combined_results,
        extra=None,  # folder-mode does not yet carry caller-supplied extras
    )
    for m in missing_logs:
        findings.append(Finding(
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

    report_written: str | None = None
    if report_path:
        try:
            _write_report(report_path, folder=folder, recursive=recursive,
                          discovery=discovery_summary, anchors=all_anchors,
                          window_seconds=window_seconds,
                          error_block=error_block,
                          executed=executed, results=results,
                          secondary=secondary, root_chain=root_chain,
                          solutions=agg_sols, next_steps=agg_nxts,
                          additional_logs_needed=agg_logs,
                          cross_log_context=cross_ctx,
                          missing_logs=missing_logs,
                          agent_summary_path=agent_summary_path)
            report_written = str(report_path)
        except OSError as exc:
            findings.append(Finding(
                summary=f"Failed to write HTML report: {exc}",
                severity="warning",
            ))

    # --- Human-readable consolidated diagnosis on stderr ----------------
    _log("")
    _log("=" * 72)
    _log("CONSOLIDATED DIAGNOSIS")
    _log("=" * 72)
    _log(f"  entry skills run : {len(executed)}  ({', '.join(executed) or 'none'})")
    if fanout_calls:
        _log(f"  secondary fan-out: {', '.join(fanout_calls)}")
    if failures:
        _log(f"  failed skills    : {', '.join(failures)}")
    _log(f"  confidence       : {confidence}")
    if root_chain:
        _log("")
        _log("Root-cause chain:")
        for item in root_chain:
            _log(f"  * [{item.get('skill','?')}] {item.get('finding','')}")
    crit = [f for f in findings if f.severity == "critical"]
    warn = [f for f in findings if f.severity == "warning"]
    if crit:
        _log("")
        _log(f"Critical findings ({len(crit)}):")
        for f in crit:
            _log(f"  {_sev_tag('critical')} {f.summary}")
    if warn:
        _log("")
        _log(f"Warning findings ({len(warn)}):")
        for f in warn[:10]:
            _log(f"  {_sev_tag('warning')} {f.summary}")
        if len(warn) > 10:
            _log(f"  ... ({len(warn) - 10} more)")
    if agg_sols:
        _log("")
        _log(f"Recommended solutions ({len(agg_sols)}):")
        for s in agg_sols:
            sev = getattr(s, "severity", None) or (s.get("severity", "info") if isinstance(s, dict) else "info")
            title = getattr(s, "title", None) or (s.get("title", "") if isinstance(s, dict) else "")
            steps = getattr(s, "steps", None) or (s.get("steps", []) if isinstance(s, dict) else [])
            _log(f"  - [{sev}] {title}")
            for step in (steps or [])[:3]:
                _log(f"      . {step}")
    if agg_nxts:
        _log("")
        _log(f"Next steps ({len(agg_nxts)}):")
        for n in agg_nxts:
            action = getattr(n, "action", None) or (n.get("action", "") if isinstance(n, dict) else "")
            why = getattr(n, "why", None) or (n.get("why", "") if isinstance(n, dict) else "")
            skill_id = getattr(n, "skill", None) or (n.get("skill") if isinstance(n, dict) else None)
            tag = f" ({skill_id})" if skill_id else ""
            _log(f"  -> {action}{tag}" + (f"  :: {why}" if why else ""))
    if missing_logs:
        _log("")
        _log(f"Missing required logs ({len(missing_logs)}):")
        for m in missing_logs:
            _log(f"  ! {m.get('log_kind')}  — {m.get('why','')}")
    if report_written:
        _log("")
        _log(f"HTML report: {report_written}")
    _log("=" * 72)

    return SkillResult(
        skill=SKILL_ID,
        ok=not failures,
        findings=findings,
        root_cause=" \u2192 ".join(item["finding"] for item in root_chain) or None,
        confidence=confidence,
        recommendations=[
            f"Entry skills run: {len(executed)} ({', '.join(executed) or 'none'}).",
            *([f"Secondary fan-out: {', '.join(fanout_calls)}"] if fanout_calls else []),
            *([f"Failed skills: {', '.join(failures)}"] if failures else []),
            *(["Open the HTML report for a visual summary."] if report_written else []),
        ],
        solutions=agg_sols,
        next_steps=agg_nxts,
        additional_logs_needed=agg_logs,
        raw={
            "mode": "folder",
            "input": {
                "folder": str(folder),
                "recursive": recursive,
                "anchors": [a.strftime("%Y-%m-%d %H:%M:%S") for a in all_anchors],
                "window": window,
                "window_seconds": window_seconds,
                "error_pattern": error_pattern,
                "time_range": time_range,
            },
            "discovery": discovery_summary,
            "error_locator": error_block,
            "executed": executed,
            "results": results,
            "secondary": secondary,
            "root_cause_chain": root_chain,
            "cross_log_context": cross_ctx,
            "missing_logs": missing_logs,
            "report_html_path": report_written,
        },
    )


def _aggregate_problems(results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Collect every `raw.problems` from successful entry skills (best-effort)."""
    out: list[dict[str, Any]] = []
    for res in results.values():
        if not isinstance(res, dict) or not res.get("ok"):
            continue
        for p in (res.get("raw") or {}).get("problems", []) or []:
            if isinstance(p, dict):
                out.append(p)
    return out


def _render_agent_summary(path: Path) -> str:
    """Load `path` and turn it into an HTML fragment.

    Accepts:
      * `.html` / `.htm`  — embedded verbatim (caller's responsibility to sanitise)
      * anything else      — treated as Markdown; converted via a small
                              stdlib-only converter that supports headings,
                              ordered/unordered lists, bold/italic, inline code,
                              fenced code blocks, and paragraphs.

    Errors are not raised — the resulting fragment falls back to a `<pre>` of
    the raw text so the report always renders.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return (f"<p class=\"warn\">Could not read agent summary "
                f"<code>{html_escape(str(path))}</code>: "
                f"{html_escape(str(exc))}</p>")
    if path.suffix.lower() in (".html", ".htm"):
        return raw
    try:
        return _md_to_html(raw)
    except Exception as exc:  # pragma: no cover — defensive
        return (f"<p class=\"warn\">Failed to render Markdown "
                f"({html_escape(str(exc))}); raw text below.</p>"
                f"<pre>{html_escape(raw)}</pre>")


# Tiny, deterministic Markdown → HTML converter (stdlib-only).
# Supports headings, fenced/inline code, bold, italic, list items, links.
_MD_INLINE_CODE_RE = re.compile(r"`([^`]+?)`")
_MD_BOLD_RE        = re.compile(r"\*\*([^*]+?)\*\*")
_MD_ITALIC_RE      = re.compile(r"(?<![\w*])\*([^*\n]+?)\*(?!\w)")
_MD_LINK_RE        = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_MD_FENCE_OPEN_RE  = re.compile(r"^```([a-zA-Z0-9_+\-]*)\s*$")
_MD_HEADING_RE     = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_MD_OL_RE          = re.compile(r"^\s*\d+\.\s+(.*)$")
_MD_UL_RE          = re.compile(r"^\s*[-*+]\s+(.*)$")
_MD_TABLE_SEP_RE   = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")


def _md_inline(text: str) -> str:
    """Escape & apply inline transforms (code → bold → italic → links)."""
    out: list[str] = []
    # Pull out inline `code` segments first so other transforms skip them.
    i = 0
    for m in _MD_INLINE_CODE_RE.finditer(text):
        out.append(_md_inline_after_code(text[i:m.start()]))
        out.append(f"<code>{html_escape(m.group(1))}</code>")
        i = m.end()
    out.append(_md_inline_after_code(text[i:]))
    return "".join(out)


def _md_inline_after_code(text: str) -> str:
    s = html_escape(text)
    s = _MD_BOLD_RE.sub(r"<strong>\1</strong>", s)
    s = _MD_ITALIC_RE.sub(r"<em>\1</em>", s)
    s = _MD_LINK_RE.sub(
        lambda m: (f"<a href=\"{html_escape(m.group(2), quote=True)}\" "
                   f"target=\"_blank\" rel=\"noopener\">{m.group(1)}</a>"),
        s)
    return s


def _md_to_html(text: str) -> str:
    """Convert a Markdown fragment to HTML. Best-effort; no nested lists."""
    lines = text.splitlines()
    out: list[str] = []
    in_code = False
    code_buf: list[str] = []
    list_open: str | None = None        # 'ul' | 'ol' | None
    para_buf: list[str] = []
    table_buf: list[str] = []           # collected raw rows for current table

    def _flush_para() -> None:
        nonlocal para_buf
        if para_buf:
            joined = " ".join(line.strip() for line in para_buf)
            if joined:
                out.append(f"<p>{_md_inline(joined)}</p>")
            para_buf = []

    def _close_list() -> None:
        nonlocal list_open
        if list_open:
            out.append(f"</{list_open}>")
            list_open = None

    def _flush_table() -> None:
        nonlocal table_buf
        if not table_buf:
            return
        # Split header | separator | body
        rows = [r for r in table_buf]
        if len(rows) < 2 or not _MD_TABLE_SEP_RE.match(rows[1]):
            # not a valid table — render as paragraphs
            for r in rows:
                out.append(f"<p>{_md_inline(r)}</p>")
            table_buf = []
            return
        header_cells = [c.strip() for c in rows[0].strip().strip("|").split("|")]
        body_rows = rows[2:]
        thead = "".join(f"<th>{_md_inline(c)}</th>" for c in header_cells)
        tbody = "".join(
            "<tr>" + "".join(
                f"<td>{_md_inline(c.strip())}</td>"
                for c in row.strip().strip("|").split("|")
            ) + "</tr>"
            for row in body_rows
        )
        out.append(f"<table><thead><tr>{thead}</tr></thead>"
                   f"<tbody>{tbody}</tbody></table>")
        table_buf = []

    for raw_line in lines:
        if in_code:
            if raw_line.strip().startswith("```"):
                out.append(f"<pre><code>"
                           f"{html_escape(chr(10).join(code_buf))}"
                           f"</code></pre>")
                code_buf = []
                in_code = False
            else:
                code_buf.append(raw_line)
            continue
        # Table rows: any line starting with '|' and containing another '|'
        if raw_line.lstrip().startswith("|") and raw_line.count("|") >= 2:
            _flush_para(); _close_list()
            table_buf.append(raw_line)
            continue
        else:
            _flush_table()
        m = _MD_FENCE_OPEN_RE.match(raw_line)
        if m:
            _flush_para(); _close_list()
            in_code = True
            continue
        if not raw_line.strip():
            _flush_para(); _close_list()
            continue
        h = _MD_HEADING_RE.match(raw_line)
        if h:
            _flush_para(); _close_list()
            level = min(len(h.group(1)) + 1, 6)  # offset by +1 so the agent's
                                                   # top-level # becomes <h2>
            out.append(f"<h{level}>{_md_inline(h.group(2))}</h{level}>")
            continue
        ol = _MD_OL_RE.match(raw_line)
        ul = _MD_UL_RE.match(raw_line)
        if ol:
            _flush_para()
            if list_open != "ol":
                _close_list()
                out.append("<ol>")
                list_open = "ol"
            out.append(f"<li>{_md_inline(ol.group(1))}</li>")
            continue
        if ul:
            _flush_para()
            if list_open != "ul":
                _close_list()
                out.append("<ul>")
                list_open = "ul"
            out.append(f"<li>{_md_inline(ul.group(1))}</li>")
            continue
        para_buf.append(raw_line)
    if in_code:
        out.append(f"<pre><code>{html_escape(chr(10).join(code_buf))}</code></pre>")
    _flush_table()
    _flush_para()
    _close_list()
    return "\n".join(out)


def _write_report(path: Path, *, folder: Path, recursive: bool,
                  discovery: dict[str, list[str]], anchors: list[datetime],
                  window_seconds: int, error_block: dict[str, Any],
                  executed: list[str], results: dict[str, dict[str, Any]],
                  secondary: dict[str, Any] | None,
                  root_chain: list[dict[str, str]],
                  solutions: list[Solution] | None = None,
                  next_steps: list[NextStep] | None = None,
                  additional_logs_needed: list[LogRequest] | None = None,
                  cross_log_context: dict[str, Any] | None = None,
                  missing_logs: list[dict[str, Any]] | None = None,
                  agent_summary_path: Path | None = None) -> None:
    from _shared import html_report  # late import: optional dep
    def esc(x: Any) -> str:
        return html_escape(str(x), quote=True)

    rows_disc = "".join(
        f"<tr><td>{esc(k)}</td><td>{len(v)}</td>"
        f"<td><ul>{''.join(f'<li><code>{esc(p)}</code></li>' for p in v)}</ul></td></tr>"
        for k, v in discovery.items()
    ) or "<tr><td colspan=3><em>no logs discovered</em></td></tr>"

    rows_anchors = "".join(
        f"<li><code>{esc(a.strftime('%Y-%m-%d %H:%M:%S'))}</code> "
        f"(\u00b1{window_seconds}s)</li>"
        for a in anchors
    ) or "<li><em>no anchors</em></li>"

    rows_err = ""
    if error_block:
        hits_html = "".join(
            f"<tr><td><code>{esc(h.get('file',''))}</code></td>"
            f"<td>{esc(h.get('lineno',''))}</td>"
            f"<td>{esc(h.get('timestamp') or '—')}</td>"
            f"<td><code>{esc((h.get('excerpt') or '')[:160])}</code></td></tr>"
            for h in error_block.get("hits", [])[:30]
        ) or "<tr><td colspan=4><em>no matches</em></td></tr>"
        rows_err = (
            f"<h2>Error locator</h2>"
            f"<p>Pattern: <code>{esc(error_block.get('pattern'))}</code> &middot; "
            f"derived anchors: {len(error_block.get('derived_anchors', []))}</p>"
            f"<table><thead><tr><th>file</th><th>line</th><th>ts</th><th>excerpt</th></tr></thead>"
            f"<tbody>{hits_html}</tbody></table>"
        )

    rows_results = ""
    for skill in executed:
        res = results.get(skill, {})
        ok = bool(res.get("ok"))
        badge = "OK" if ok else "FAIL"
        rc = esc(res.get("root_cause") or "—")
        findings = res.get("findings") or []
        f_html = "".join(
            f"<li><b>{esc(f.get('severity',''))}</b>: {esc(f.get('summary',''))}</li>"
            for f in findings[:5]
        ) or "<li><em>no findings</em></li>"
        rows_results += (
            f"<section><h3>{esc(skill)} <small>[{badge}]</small></h3>"
            f"<p><b>root_cause:</b> {rc}</p>"
            f"<ul>{f_html}</ul></section>"
        )

    chain_html = " &rarr; ".join(esc(f"{c.get('skill','?')}: {c.get('finding','')}")
                                  for c in root_chain) or "<em>none</em>"

    secondary_html = ""
    if secondary:
        sec_findings = (secondary or {}).get("findings", []) or []
        sec_items = "".join(
            f"<li><b>{esc(f.get('severity',''))}</b>: {esc(f.get('summary',''))}</li>"
            for f in sec_findings[:10]
        )
        secondary_html = (
            f"<h2>Secondary fan-out</h2>"
            f"<p>ok={esc(secondary.get('ok'))}, "
            f"confidence={esc(secondary.get('confidence'))}</p>"
            f"<ul>{sec_items}</ul>"
        )

    # --- Advisory sections (Solutions / Next steps / Additional logs needed)
    advisory_html = ""
    if solutions or next_steps or additional_logs_needed:
        sections = html_report.advisory_sections(
            solutions=solutions or [],
            next_steps=next_steps or [],
            additional_logs_needed=additional_logs_needed or [],
            level=2,
        )
        advisory_html = "".join(
            f"<h{sec.level}>{esc(sec.heading)}</h{sec.level}>{sec.html}"
            for sec in sections
        )

    cross_html = ""
    if cross_log_context:
        avail = cross_log_context.get("available") or []
        tr = cross_log_context.get("time_range") or {}
        note = cross_log_context.get("note")
        cross_html = (
            "<h2>Cross-log context</h2>"
            f"<p>Available log kinds: {', '.join(f'<code>{esc(k)}</code>' for k in avail) or '<em>none</em>'}</p>"
            f"<p>Time range: <code>{esc(tr.get('start') or '—')}</code> &rarr; "
            f"<code>{esc(tr.get('end') or '—')}</code></p>"
            f"<p>Correlatable: <b>{esc(cross_log_context.get('correlatable'))}</b></p>"
            + (f"<p><em>{esc(note)}</em></p>" if note else "")
        )

    missing_html = ""
    if missing_logs:
        rows_missing = "".join(
            f"<tr><td><code>{esc(m.get('log_kind',''))}</code></td>"
            f"<td>{esc(m.get('why') or '—')}</td>"
            f"<td>{esc(m.get('how_to_collect') or '—')}</td>"
            f"<td><code>{esc(m.get('skill') or '—')}</code></td></tr>"
            for m in missing_logs
        )
        missing_html = (
            "<h2>Missing required logs</h2>"
            "<p class=\"warn\">The investigation referenced log kinds that were not "
            "provided. Findings may be incomplete until they are collected.</p>"
            "<table><thead><tr><th>log_kind</th><th>why</th>"
            "<th>how to collect</th><th>consumer skill</th></tr></thead>"
            f"<tbody>{rows_missing}</tbody></table>"
        )

    agent_summary_html = ""
    if agent_summary_path:
        body = _render_agent_summary(agent_summary_path)
        agent_summary_html = (
            "<section class=\"agent-summary\">"
            "<h2>Consolidated diagnosis (GitHub Copilot CLI)</h2>"
            f"<p class=\"meta\">Authored by the Copilot CLI agent based on the "
            f"skill outputs below &middot; source: "
            f"<code>{esc(agent_summary_path)}</code></p>"
            f"<div class=\"agent-summary-body\">{body}</div>"
            "</section>"
        )

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>orchestrator report \u2014 {esc(folder)}</title>
<style>
 body{{font:14px/1.4 -apple-system,Segoe UI,Arial;margin:24px;max-width:1100px}}
 h1{{margin:0 0 4px}} h2{{margin-top:24px;border-bottom:1px solid #ddd;padding-bottom:4px}}
 h3{{margin:18px 0 4px}}
 table{{border-collapse:collapse;width:100%;margin:8px 0}}
 th,td{{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}}
 th{{background:#f5f5f5}}
 code{{background:#f4f4f4;padding:1px 4px;border-radius:3px}}
 pre{{background:#f4f4f4;padding:8px 12px;border-radius:4px;overflow:auto}}
 pre code{{background:transparent;padding:0}}
 section{{background:#fafafa;border:1px solid #eee;padding:8px 12px;margin:8px 0;border-radius:4px}}
 section.agent-summary{{background:#f1f7ff;border-color:#bcd9ff;padding:12px 18px;margin:16px 0}}
 section.agent-summary h2{{margin-top:0;border-bottom-color:#bcd9ff;color:#0a4f99}}
 .agent-summary-body p{{margin:6px 0}}
 .agent-summary-body li{{margin:2px 0}}
 .meta{{color:#666;font-size:12px}}
 small{{color:#888}}
 .warn{{color:#a00}}
</style></head><body>
<h1>orchestrator report</h1>
<p><b>folder:</b> <code>{esc(folder)}</code> &middot; recursive={esc(recursive)} &middot;
 entry skills run: {len(executed)}</p>

{agent_summary_html}

<h2>Discovery</h2>
<table><thead><tr><th>kind</th><th>count</th><th>files</th></tr></thead>
<tbody>{rows_disc}</tbody></table>

<h2>Anchors</h2>
<ul>{rows_anchors}</ul>

{rows_err}

<h2>Per-skill results</h2>
{rows_results or '<p><em>no entry skills executed</em></p>'}

<h2>Root cause chain</h2>
<p>{chain_html}</p>

{cross_html}

{missing_html}

{advisory_html}

{secondary_html}
</body></html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
