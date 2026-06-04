#!/usr/bin/env python3
"""
edge_netlog.py — Chromium net-export (edge://net-export) analyser.

Consumes the `netlog` log_kind referenced by the playbook for the
`page_load_failure`, `cert_error`, `proxy_issue`, and `dns_issue` problem
types. Uses _shared/sources/netlog.py for the low-level read; this skill
adds the diagnostic interpretation layer (ERR_* codes, slow requests,
proxy fallback, TLS handshake failures).

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, LogRequest, SkillResult, load_context,
)
from _shared import playbook  # noqa: E402
from _shared.sources import netlog as netlog_src  # noqa: E402

SKILL_ID = "edge_netlog"
SLOW_REQUEST_THRESHOLD_MS = 5000
MAX_TOP_REQUESTS = 5
MAX_FINDINGS_PER_KIND = 3


# ---------------------------------------------------------------------------
# Source resolution
# ---------------------------------------------------------------------------

def _resolve_sources(extra: dict[str, Any]) -> list[Path]:
    """Resolve net-export files from extra.netlog_paths and/or extra.folder."""
    out: list[Path] = []
    for raw in extra.get("netlog_paths") or []:
        p = Path(raw)
        if p.is_file():
            out.append(p)
    folder = extra.get("folder")
    if folder:
        out.extend(_discover_netlogs_in_folder(Path(folder),
                                               recursive=not extra.get("no_recursive")))
    # Dedup, keep order
    seen: set[Path] = set()
    uniq: list[Path] = []
    for p in out:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def _looks_like_netlog(path: Path, peek_bytes: int = 4096) -> bool:
    """Cheap structural check: top-level JSON has both 'events' and 'constants'."""
    try:
        with path.open("rb") as fh:
            head = fh.read(peek_bytes).decode("utf-8", errors="replace")
    except OSError:
        return False
    # Net-export files are large but the constants block is near the top.
    # A substring probe is enough to reject random JSON files cheaply.
    return '"constants"' in head and '"logSourceType"' in head


def _discover_netlogs_in_folder(folder: Path, recursive: bool = True) -> list[Path]:
    if not folder.is_dir():
        return []
    pattern = "**/*.json" if recursive else "*.json"
    return [p for p in sorted(folder.glob(pattern)) if _looks_like_netlog(p)]


# ---------------------------------------------------------------------------
# Interpretation
# ---------------------------------------------------------------------------

def _extract_net_error(params: Any) -> str | None:
    """Return the ERR_* string from a netlog event's params, if any."""
    if not isinstance(params, dict):
        return None
    # net_error can appear as integer code or as a string.
    for key in ("net_error", "error", "result"):
        v = params.get(key)
        if isinstance(v, str) and v.startswith("ERR_"):
            return v
    # Embedded errors in nested objects
    for v in params.values():
        if isinstance(v, str) and v.startswith("ERR_"):
            return v
    return None


def _classify_request_span(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Given all events for one URL_REQUEST source_id, return a request row."""
    url = None
    method = None
    net_error: str | None = None
    t_begin = None
    t_end = None
    for ev in events:
        params = ev.get("params") or {}
        if url is None and isinstance(params, dict) and params.get("url"):
            url = params.get("url")
            method = params.get("method") or method
        err = _extract_net_error(params)
        if err and err != "ERR_IO_PENDING":
            net_error = err
        try:
            t = int(ev.get("time")) if ev.get("time") is not None else None
        except (TypeError, ValueError):
            t = None
        if t is not None:
            if t_begin is None or t < t_begin:
                t_begin = t
            if t_end is None or t > t_end:
                t_end = t
    duration_ms = (t_end - t_begin) if (t_begin is not None and t_end is not None) else None
    return {
        "url": url,
        "method": method,
        "net_error": net_error,
        "duration_ms": duration_ms,
        "event_count": len(events),
    }


def _analyse_one(path: Path) -> dict[str, Any]:
    entries = list(netlog_src.iter_entries(path))
    summary = netlog_src.summarise(entries)

    # Per-source-id grouping for URL_REQUEST spans.
    by_source: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for e in entries:
        if e.get("source_type") == "URL_REQUEST":
            by_source[e.get("source_id")].append(e)
    requests = [_classify_request_span(evs) for evs in by_source.values()]

    failed = [r for r in requests if r["net_error"]]
    slow = [r for r in requests if (r["duration_ms"] or 0) >= SLOW_REQUEST_THRESHOLD_MS]
    slow.sort(key=lambda r: r["duration_ms"] or 0, reverse=True)
    error_counts = Counter(r["net_error"] for r in failed)

    # DNS failures: HOST_RESOLVER_IMPL events whose params include net_error.
    dns_failures = [
        e for e in entries
        if e.get("source_type") in ("HOST_RESOLVER_IMPL", "HOST_RESOLVER_IMPL_JOB",
                                    "HOST_RESOLVER_IMPL_REQUEST")
        and _extract_net_error(e.get("params"))
    ]

    # TLS / cert failures: ERR_CERT_* anywhere
    cert_failures = [r for r in failed if (r["net_error"] or "").startswith("ERR_CERT")]

    # Proxy fallback events: PROXY_RESOLVER or anything mentioning "proxy"
    # with a phase==1 (end) and a net_error.
    proxy_issues = [
        e for e in entries
        if (e.get("source_type") or "").startswith("PROXY")
        and _extract_net_error(e.get("params"))
    ]

    return {
        "file": str(path),
        "summary": summary,
        "requests_total": len(requests),
        "requests_failed": len(failed),
        "requests_slow": len(slow),
        "error_breakdown": dict(error_counts.most_common(10)),
        "top_slow_requests": slow[:MAX_TOP_REQUESTS],
        "dns_failures": len(dns_failures),
        "cert_failures": len(cert_failures),
        "proxy_issues": len(proxy_issues),
        "sample_failures": failed[:MAX_TOP_REQUESTS],
    }


# ---------------------------------------------------------------------------
# Build envelope
# ---------------------------------------------------------------------------

def _findings_from_files(per_file: list[dict[str, Any]]) -> tuple[list[Finding], list[str]]:
    """Return (findings, observed_problem_types)."""
    findings: list[Finding] = []
    problem_types: list[str] = []

    total_req = sum(f["requests_total"] for f in per_file)
    total_fail = sum(f["requests_failed"] for f in per_file)
    total_slow = sum(f["requests_slow"] for f in per_file)
    total_dns = sum(f["dns_failures"] for f in per_file)
    total_cert = sum(f["cert_failures"] for f in per_file)
    total_proxy = sum(f["proxy_issues"] for f in per_file)

    findings.append(Finding(
        summary=(f"Parsed {len(per_file)} net-export file(s): "
                 f"{total_req} URL requests, {total_fail} failed, {total_slow} slow."),
        severity="info",
        evidence={
            "files": [f["file"] for f in per_file],
            "total_requests": total_req,
            "total_failed": total_fail,
            "total_slow": total_slow,
        },
    ))

    if total_cert:
        problem_types.append("cert_error")
        findings.append(Finding(
            summary=f"TLS/cert errors observed in {total_cert} URL request(s).",
            severity="critical",
            evidence={"sample": [r for f in per_file for r in f["sample_failures"]
                                 if (r["net_error"] or "").startswith("ERR_CERT")
                                 ][:MAX_FINDINGS_PER_KIND]},
        ))
    if total_dns:
        problem_types.append("dns_issue")
        findings.append(Finding(
            summary=f"DNS resolution failures observed: {total_dns} event(s).",
            severity="warning",
            evidence={"by_file": [{"file": f["file"], "dns_failures": f["dns_failures"]}
                                  for f in per_file if f["dns_failures"]]},
        ))
    if total_proxy:
        problem_types.append("proxy_issue")
        findings.append(Finding(
            summary=f"Proxy-related failures observed: {total_proxy} event(s).",
            severity="warning",
            evidence={"by_file": [{"file": f["file"], "proxy_issues": f["proxy_issues"]}
                                  for f in per_file if f["proxy_issues"]]},
        ))
    if total_fail and not (total_cert or total_dns or total_proxy):
        problem_types.append("page_load_failure")
        findings.append(Finding(
            summary=f"{total_fail} URL request(s) failed with non-cert/dns errors.",
            severity="warning",
            evidence={"error_breakdown": _merge_counts(per_file)},
        ))
    if total_slow:
        problem_types.append("page_slow")
        findings.append(Finding(
            summary=f"{total_slow} URL request(s) slower than {SLOW_REQUEST_THRESHOLD_MS} ms.",
            severity="warning",
            evidence={"top_slow": _merge_top_slow(per_file)},
        ))

    return findings, problem_types


def _merge_counts(per_file: list[dict[str, Any]]) -> dict[str, int]:
    out: Counter[str] = Counter()
    for f in per_file:
        for k, v in (f.get("error_breakdown") or {}).items():
            out[k] += int(v)
    return dict(out.most_common(10))


def _merge_top_slow(per_file: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flat = []
    for f in per_file:
        for r in f.get("top_slow_requests") or []:
            flat.append({**r, "_file": f["file"]})
    flat.sort(key=lambda r: r.get("duration_ms") or 0, reverse=True)
    return flat[:MAX_TOP_REQUESTS]


def _root_cause(problem_types: Iterable[str]) -> str | None:
    pts = list(problem_types)
    if "cert_error" in pts:
        return "TLS/cert error chain in net-export"
    if "dns_issue" in pts:
        return "DNS resolution failures in net-export"
    if "proxy_issue" in pts:
        return "Proxy resolution / fallback failures in net-export"
    if "page_load_failure" in pts:
        return "URL request failures in net-export"
    if "page_slow" in pts:
        return "Slow URL requests in net-export"
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyse(ctx: dict[str, Any]) -> SkillResult:
    extra = ctx.get("extra") or {}
    sources = _resolve_sources(extra)

    if not sources:
        # Soft success: tell the operator how to collect it.
        result = SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(
                summary="No net-export files provided. Use edge://net-export "
                        "to capture a session, then pass extra.netlog_paths or extra.folder.",
                severity="info",
            )],
            confidence="low",
            additional_logs_needed=[LogRequest(
                log_kind="netlog",
                why="Required to diagnose proxy, cert, and DNS failures from the browser side.",
                how_to_collect=("Open edge://net-export, click Start Logging To Disk, "
                                "reproduce the issue, then Stop. Provide the resulting .json file."),
                skill=SKILL_ID,
            )],
            raw={"sources": []},
        )
        return result

    per_file: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    for src in sources:
        try:
            per_file.append(_analyse_one(src))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parse_errors.append({"file": str(src), "error": str(exc)})

    findings, problem_types = _findings_from_files(per_file)
    for pe in parse_errors:
        findings.append(Finding(
            summary=f"Failed to parse {pe['file']}: {pe['error']}",
            severity="warning",
            evidence=pe,
        ))

    rc = _root_cause(problem_types)
    confidence = "high" if rc else "medium" if per_file else "low"

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        root_cause=rc,
        confidence=confidence,
        raw={
            "sources": [str(p) for p in sources],
            "per_file": per_file,
            "parse_errors": parse_errors,
            "observed_problem_types": problem_types,
        },
    )
    # Seed playbook entries for every observed problem type. Always include
    # the caller-supplied problem_type if one was given.
    pb_types = list(problem_types)
    ctx_pt = ctx.get("problem_type")
    if ctx_pt and ctx_pt not in pb_types:
        pb_types.append(ctx_pt)
    playbook.merge_into_result(result, pb_types)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge net-export (netlog) analyser")
    ap.add_argument("context", nargs="?", default=None,
                    help="JSON context string, @file, or path to JSON file. Use extra.netlog_paths or extra.folder.")
    args = ap.parse_args(argv)
    ctx = load_context([args.context] if args.context else [])
    analyse(ctx).emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
