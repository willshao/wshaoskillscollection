#!/usr/bin/env python3
"""
iis_analyzer.py — IIS W3C log analyzer (entry-point skill, v2)

Robust changes vs v1:
  * Dynamic W3C field parsing driven by the `#Fields:` header (no more
    hard-coded indices that break on real IIS logs)
  * Tolerant to quoted user-agents, missing fields, multiple log files
  * Uses _shared.contract for I/O envelope and skill discovery
  * Path resolution works from any cwd
"""
from __future__ import annotations

import argparse
import shlex
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

# Make _shared importable regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import Finding, SkillResult, registry  # noqa: E402
from _shared import log_discovery, log_filters, timeseries, svg_charts, html_report, playbook  # noqa: E402
from _shared.logs import iis_w3c  # noqa: E402

# Re-export shared parser primitives so legacy imports continue to work.
parse_w3c_log = iis_w3c.parse_w3c_log
normalise     = iis_w3c.normalise
apply_filter  = iis_w3c.apply_filter
around_window = iis_w3c.around_window
summarise     = iis_w3c.summarise
_parse_entry_ts = iis_w3c._parse_entry_ts  # used by --around timestamp parsing

SKILL_ID = "iis_logs"

# Thresholds (kept identical to the documented contract)
TH_P99_LATENCY_MS = 5_000
TH_5XX_RATE_PCT   = 1.0
TH_5XX_ABSOLUTE   = 100
TH_AUTH_ERRORS    = 10
TH_NOT_FOUND_PCT  = 10.0
TH_SUSPICIOUS_PCT = 30.0

# Time-series defaults
DEFAULT_BUCKET_SECONDS = 60       # 1-minute buckets
DEFAULT_WINDOW_SECONDS = 5 * 60   # ±5 minutes around a timestamp
SEARCH_RESULT_HARD_CAP = 1000     # cap embedded search results in JSON


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
# (parse_w3c_log / normalise / _to_int / _shlex_split live in _shared.logs.iis_w3c)


# ---------------------------------------------------------------------------
# Metrics + classification
# ---------------------------------------------------------------------------

def _percentile(sorted_values: list[int], pct: float) -> int:
    if not sorted_values:
        return 0
    idx = min(len(sorted_values) - 1, max(0, int(len(sorted_values) * pct) - 1))
    return sorted_values[idx]


def compute_metrics(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"total_requests": 0}
    times = sorted(e["time_taken"] for e in entries)
    statuses = [e["status"] for e in entries]
    timestamps = [e["timestamp"] for e in entries if e["timestamp"]]
    err_4xx = sum(1 for s in statuses if 400 <= s < 500)
    err_5xx = sum(1 for s in statuses if 500 <= s < 600)
    total = len(entries)
    return {
        "total_requests": total,
        "avg_response_time_ms": sum(times) / total,
        "min_response_time_ms": times[0],
        "max_response_time_ms": times[-1],
        "p95_response_time_ms": _percentile(times, 0.95),
        "p99_response_time_ms": _percentile(times, 0.99),
        "status_code_distribution": dict(Counter(statuses)),
        "error_4xx_count": err_4xx,
        "error_5xx_count": err_5xx,
        "error_rate_percent": (err_4xx + err_5xx) / total * 100,
        "time_range": {
            "start": min(timestamps) if timestamps else None,
            "end":   max(timestamps) if timestamps else None,
        },
    }


def classify_problems(entries: list[dict[str, Any]],
                      metrics: dict[str, Any]) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    if not entries:
        return problems
    total = metrics["total_requests"]
    reg = registry()["problem_types"]

    # 5xx
    err5 = metrics["error_5xx_count"]
    if err5 > 0:
        rate = err5 / total * 100
        if rate > TH_5XX_RATE_PCT or err5 > TH_5XX_ABSOLUTE:
            problems.append({
                "type": "5xx_error",
                "severity": "critical",
                "description": f"{err5} 5xx errors ({rate:.2f}%)",
                "follow_ups": reg["5xx_error"]["follow_ups"],
            })

    # latency
    p99 = metrics["p99_response_time_ms"]
    if p99 > TH_P99_LATENCY_MS:
        problems.append({
            "type": "high_latency",
            "severity": "critical" if p99 > 2 * TH_P99_LATENCY_MS else "warning",
            "description": f"p99 response time {p99} ms",
            "follow_ups": reg["high_latency"]["follow_ups"],
        })

    # auth
    auth_errs = sum(1 for e in entries if e["status"] in (401, 403))
    if auth_errs > TH_AUTH_ERRORS:
        # Drill into the 401 population to distinguish bad creds from
        # broken handshake (401.2 with empty cs-username = NTLM/Negotiate
        # second leg never carried Authorization).
        s401 = [e for e in entries if e["status"] == 401]
        sub2 = sum(1 for e in s401 if e.get("substatus") == 2)
        anon = sum(1 for e in s401 if not e.get("is_authenticated", False))
        ips_with_both = set()
        succeed_ips = {e["client_ip"] for e in entries
                       if e["status"] < 400 and e.get("is_authenticated")}
        fail_ips    = {e["client_ip"] for e in s401}
        ips_with_both = succeed_ips & fail_ips
        evidence: dict[str, Any] = {
            "total_401": len(s401),
            "substatus_2": sub2,
            "anonymous_401": anon,
            "ips_failing_then_succeeding": sorted(ips_with_both)[:10],
        }
        problems.append({
            "type": "auth_error",
            "severity": "warning",
            "description": f"{auth_errs} auth/permission failures",
            "follow_ups": reg["auth_error"]["follow_ups"],
            "evidence": evidence,
        })
        # Handshake-loop pattern: dominant 401.2 with no Authorization on any
        # request. Strongly suggests Kerberos SPN mismatch or the site is
        # outside the browser's Local Intranet zone. Emit a second, more
        # specific problem_type so the playbook contributes Kerberos / GPO
        # remediation alongside the generic auth_error solutions.
        if s401 and sub2 / len(s401) >= 0.8 and anon == len(s401):
            problems.append({
                "type": "auth_handshake_loop",
                "severity": "warning",
                "description": (
                    f"All {len(s401)} 401 responses are sub-status .2 with "
                    f"empty cs-username — the client never sent Authorization "
                    f"on the second leg of the Negotiate/NTLM handshake."
                ),
                "follow_ups": ["netlog", "security_audit"],
                "evidence": evidence,
            })
            if ips_with_both:
                # Intermittent success from the same IPs strongly hints at
                # a Kerberos SPN issue (Negotiate falls back to NTLM
                # sometimes, succeeds; sometimes Kerberos SEC_E_WRONG_PRINCIPAL
                # before NTLM fallback can take over → 401).
                problems.append({
                    "type": "kerberos_spn_mismatch",
                    "severity": "warning",
                    "description": (
                        f"{len(ips_with_both)} client IP(s) intermittently "
                        f"succeed and fail Windows-auth — consistent with a "
                        f"Kerberos SPN problem; correlate with the netlog skill."
                    ),
                    "follow_ups": ["netlog", "security_audit", "event_log"],
                    "evidence": evidence,
                })

    # 404
    nf = sum(1 for e in entries if e["status"] == 404)
    if nf > total * (TH_NOT_FOUND_PCT / 100):
        problems.append({
            "type": "not_found",
            "severity": "info",
            "description": f"{nf} 404 responses",
            "follow_ups": reg["not_found"]["follow_ups"],
        })

    # suspicious traffic
    if total:
        top_ip, top_n = Counter(e["client_ip"] for e in entries).most_common(1)[0]
        if top_n / total * 100 > TH_SUSPICIOUS_PCT:
            problems.append({
                "type": "suspicious_traffic",
                "severity": "warning",
                "description": f"single IP {top_ip} = {top_n/total*100:.1f}% of traffic",
                "follow_ups": reg["suspicious_traffic"]["follow_ups"],
                "evidence": {"client_ip": top_ip, "count": top_n},
            })

    return problems


# ---------------------------------------------------------------------------
# Time-series + spike detection
# ---------------------------------------------------------------------------

def build_timeseries(entries: list[dict[str, Any]],
                     bucket_seconds: int) -> dict[str, Any]:
    """Wrap _shared.timeseries.bucketize into the report payload shape."""
    buckets = timeseries.bucketize(entries, bucket_seconds=bucket_seconds)
    spike = timeseries.detect_spike(buckets)
    return {
        "bucket_seconds": bucket_seconds,
        "buckets": [b.to_dict() for b in buckets],
        "peak_bucket": spike.to_dict() if spike else None,
    }


def classify_traffic_spike(ts: dict[str, Any]) -> dict[str, Any] | None:
    peak = ts.get("peak_bucket")
    if not peak:
        return None
    reg = registry().get("problem_types", {})
    follow_ups = reg.get("traffic_spike", {}).get("follow_ups", [])
    return {
        "type": "traffic_spike",
        "severity": "warning",
        "description": (
            f"Traffic spike at {peak['start']}: {peak['count']} requests in "
            f"{ts['bucket_seconds']}s bucket"
        ),
        "follow_ups": follow_ups,
        "evidence": {"bucket": peak},
    }


# ---------------------------------------------------------------------------
# Search + time-window helpers
# ---------------------------------------------------------------------------
# (apply_filter / around_window / summarise / _parse_entry_ts live in _shared.logs.iis_w3c)

_percentile = iis_w3c._percentile  # back-compat for tests


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _kpi_block(metrics: dict[str, Any]) -> str:
    kpi = html_report.kpi_card
    parts = [
        kpi("Total requests", str(metrics.get("total_requests", 0))),
        kpi("5xx errors", str(metrics.get("error_5xx_count", 0))),
        kpi("4xx errors", str(metrics.get("error_4xx_count", 0))),
        kpi("Error rate", f"{metrics.get('error_rate_percent', 0):.2f}%"),
        kpi("Avg ms", f"{metrics.get('avg_response_time_ms', 0):.0f}"),
        kpi("p95 ms", str(metrics.get("p95_response_time_ms", 0))),
        kpi("p99 ms", str(metrics.get("p99_response_time_ms", 0))),
        kpi("Max ms", str(metrics.get("max_response_time_ms", 0))),
    ]
    return "".join(parts)


def _problems_table(problems: list[dict[str, Any]]) -> str:
    if not problems:
        return '<div class="note">No problems detected.</div>'
    rows = [
        (
            f'<span class="badge {p["severity"]}">{p["severity"]}</span> {p["type"]}',
            p["description"],
            ", ".join(p.get("follow_ups", [])) or "-",
        )
        for p in problems
    ]
    # render_table escapes everything; embed raw badge by post-processing.
    table = html_report.render_table(["Problem", "Description", "Follow-up skills"], rows)
    # Un-escape only the badge spans we generated.
    table = table.replace("&lt;span class=&quot;badge ", '<span class="badge ')
    table = table.replace("&quot;&gt;", '">').replace("&lt;/span&gt;", "</span>")
    return table


def _bucket_labels(buckets: list[dict[str, Any]]) -> list[str]:
    return [b["start"].split(" ")[1] if " " in b["start"] else b["start"]
            for b in buckets]


def build_report_html(target_label: str,
                      metrics: dict[str, Any],
                      problems: list[dict[str, Any]],
                      ts_payload: dict[str, Any],
                      around_payload: dict[str, Any] | None,
                      search_payload: dict[str, Any] | None,
                      detected_other: dict[str, list[str]] | None,
                      advisory: tuple[list, list, list] | None = None) -> str:
    Section = html_report.Section
    sections: list[html_report.Section] = []

    sections.append(Section("Summary", _kpi_block(metrics)))
    sections.append(Section("Detected problems", _problems_table(problems)))

    # Status code distribution
    sd = metrics.get("status_code_distribution", {})
    if sd:
        items = sorted(sd.items(), key=lambda kv: -kv[1])[:12]
        labels = [str(k) for k, _ in items]
        values = [v for _, v in items]
        sections.append(Section(
            "Status code distribution",
            svg_charts.bar_chart(labels, values,
                                 title="Top status codes", ylabel="requests"),
        ))

    buckets = ts_payload.get("buckets", [])
    if buckets:
        labels = _bucket_labels(buckets)
        counts = [b["count"] for b in buckets]
        sections.append(Section(
            f"Requests per {ts_payload['bucket_seconds']}s bucket",
            svg_charts.bar_chart(labels, counts,
                                 title="Requests over time", ylabel="requests"),
        ))
        sections.append(Section(
            "Response time distribution over time",
            svg_charts.line_chart(labels, {
                "p50": [b["p50_time_ms"] for b in buckets],
                "p95": [b["p95_time_ms"] for b in buckets],
                "p99": [b["p99_time_ms"] for b in buckets],
            }, title="Latency percentiles", ylabel="ms"),
        ))
        sections.append(Section(
            "Throughput vs. p95 latency",
            svg_charts.dual_axis_chart(labels, counts,
                                       [b["p95_time_ms"] for b in buckets],
                                       title="Throughput + p95 latency",
                                       left_label="requests",
                                       right_label="p95 ms"),
        ))

    if around_payload:
        for anchor_ts, payload in around_payload.items():
            heading = f"Requests around {anchor_ts} (±{payload['window_seconds']}s)"
            summary = payload.get("summary", {})
            top_uris = summary.get("top_uris") or []
            kpis = (
                html_report.kpi_card("Matched", str(summary.get("count", 0))) +
                html_report.kpi_card("Avg ms", f"{summary.get('avg_time_ms', 0):.0f}") +
                html_report.kpi_card("p95 ms", str(summary.get("p95_time_ms", 0))) +
                html_report.kpi_card("Max ms", str(summary.get("max_time_ms", 0)))
            )
            rows = [
                (e.get("timestamp"), e.get("client_ip"), e.get("method"),
                 e.get("uri"), e.get("status"), e.get("time_taken"))
                for e in payload.get("entries", [])
            ]
            table = html_report.render_table(
                ["Timestamp", "Client IP", "Method", "URI", "Status", "Time (ms)"],
                rows, max_rows=200,
            )
            top_table = html_report.render_table(
                ["URI", "Count"], top_uris, max_rows=10,
            ) if top_uris else ""
            sections.append(Section(heading, kpis + top_table + table))

    if search_payload:
        summary = search_payload.get("summary", {})
        kpis = (
            html_report.kpi_card("Matched", str(summary.get("count", 0))) +
            html_report.kpi_card("Avg ms", f"{summary.get('avg_time_ms', 0):.0f}") +
            html_report.kpi_card("p95 ms", str(summary.get("p95_time_ms", 0))) +
            html_report.kpi_card("Max ms", str(summary.get("max_time_ms", 0)))
        )
        rows = [
            (e.get("timestamp"), e.get("client_ip"), e.get("method"),
             e.get("uri"), e.get("status"), e.get("time_taken"))
            for e in search_payload.get("results", [])
        ]
        table = html_report.render_table(
            ["Timestamp", "Client IP", "Method", "URI", "Status", "Time (ms)"],
            rows, max_rows=200,
        )
        sections.append(Section(
            f"Search results (filter: {search_payload.get('filter', '')})",
            kpis + table,
        ))

    if detected_other:
        rows = [(kind, p) for kind, paths in detected_other.items() for p in paths]
        if rows:
            sections.append(Section(
                "Other log files detected in folder",
                html_report.render_table(["Kind", "Path"], rows, max_rows=50)
                + '<div class="note">Run the matching skill on these files.</div>',
            ))

    if advisory:
        sols, nxts, logs = advisory
        sections.extend(html_report.advisory_sections(
            solutions=sols, next_steps=nxts, additional_logs_needed=logs,
        ))

    return html_report.render(
        title="IIS log analysis report",
        subtitle=f"Source: {target_label}",
        sections=sections,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def collect_log_files(target: Path, recursive: bool = True
                      ) -> tuple[list[Path], dict[str, list[Path]]]:
    """
    Return (iis_files, other_files_by_kind).

    Recursively discovers .log files under `target`. Only files classified as
    IIS W3C are returned in the first list; everything else (httperr, ftp,
    unknown) is grouped by kind in the second.
    """
    disc = log_discovery.discover_logs(target, recursive=recursive)
    iis = list(disc.get(log_discovery.IIS_KIND))
    others: dict[str, list[Path]] = {
        kind: paths for kind, paths in disc.by_kind.items()
        if kind != log_discovery.IIS_KIND and paths
    }
    # Back-compat: if user passed a single file and it wasn't classified as IIS,
    # still try to parse it as W3C (older callers may rely on the old behaviour).
    if not iis and target.is_file():
        iis = [target]
        others.pop(log_discovery.classify_file(target), None)
    return iis, others


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="IIS W3C log analyzer")
    ap.add_argument("log", help="Path to a .log file or a directory of logs")
    ap.add_argument("--auto-trigger", action="store_true",
                    help="Run follow-up skills via the orchestrator after analysis")
    ap.add_argument("--no-recursive", action="store_true",
                    help="Do not recurse into subdirectories")
    ap.add_argument("--bucket", default="1m",
                    help="Bucket size for the time series (e.g. 30s, 1m, 5m). Default 1m.")
    ap.add_argument("--around", action="append", default=[],
                    metavar="TIMESTAMP",
                    help="Anchor timestamp (e.g. '2026-05-26 10:15:30'). Repeatable.")
    ap.add_argument("--window", default="5m",
                    help="Window around each --around anchor (e.g. 30s, 5m). Default 5m.")
    ap.add_argument("--filter", dest="filter_text", default=None,
                    help=("Filter expression, e.g. "
                          "'method=GET,uri=^/api/,status=500-599,ip=10.0.0.0/24,"
                          "min-time=2000,ua=bot,q=token'"))
    ap.add_argument("--report", default=None, metavar="PATH",
                    help="Write an HTML report to PATH (no report by default).")
    args = ap.parse_args(argv)

    target = Path(args.log)
    if not target.exists():
        SkillResult(skill=SKILL_ID, ok=False, error=f"Path not found: {target}").emit()
        return 2

    # ---- Discover + parse -------------------------------------------------
    iis_files, other_files = collect_log_files(target, recursive=not args.no_recursive)
    entries: list[dict[str, Any]] = []
    for path in iis_files:
        for row in parse_w3c_log(path):
            entries.append(normalise(row))

    metrics = compute_metrics(entries)
    problems = classify_problems(entries, metrics)

    # ---- Time series ------------------------------------------------------
    try:
        bucket_seconds = log_filters.parse_duration_seconds(args.bucket)
    except ValueError as exc:
        SkillResult(skill=SKILL_ID, ok=False, error=str(exc)).emit()
        return 2
    ts_payload = build_timeseries(entries, bucket_seconds)
    spike_problem = classify_traffic_spike(ts_payload)
    if spike_problem:
        problems.append(spike_problem)

    # ---- Filter / search --------------------------------------------------
    try:
        filter_spec = log_filters.parse_filter(args.filter_text)
    except ValueError as exc:
        SkillResult(skill=SKILL_ID, ok=False, error=f"--filter: {exc}").emit()
        return 2

    search_payload: dict[str, Any] | None = None
    if not filter_spec.is_empty():
        matched = apply_filter(entries, filter_spec)
        search_payload = {
            "filter": filter_spec.raw_text,
            "summary": summarise(matched),
            "results": matched[:SEARCH_RESULT_HARD_CAP],
            "truncated": len(matched) > SEARCH_RESULT_HARD_CAP,
        }

    # ---- Around <ts> ------------------------------------------------------
    around_payload: dict[str, Any] | None = None
    if args.around:
        try:
            window_seconds = log_filters.parse_duration_seconds(args.window)
        except ValueError as exc:
            SkillResult(skill=SKILL_ID, ok=False, error=f"--window: {exc}").emit()
            return 2
        around_payload = {}
        for raw_ts in args.around:
            anchor = _parse_entry_ts(raw_ts)
            if anchor is None:
                SkillResult(skill=SKILL_ID, ok=False,
                            error=f"--around: invalid timestamp {raw_ts!r}").emit()
                return 2
            window_entries = around_window(entries, anchor, window_seconds)
            if not filter_spec.is_empty():
                window_entries = apply_filter(window_entries, filter_spec)
            around_payload[raw_ts] = {
                "window_seconds": window_seconds,
                "filter": filter_spec.raw_text if not filter_spec.is_empty() else None,
                "summary": summarise(window_entries),
                "entries": window_entries[:SEARCH_RESULT_HARD_CAP],
                "truncated": len(window_entries) > SEARCH_RESULT_HARD_CAP,
            }

    # ---- Assemble contract envelope ---------------------------------------
    follow_ups = sorted({s for p in problems for s in p.get("follow_ups", [])})

    findings = [
        Finding(summary=p["description"], severity=p["severity"],
                evidence={"type": p["type"], "follow_ups": p.get("follow_ups", [])})
        for p in problems
    ]

    detected_other_str = {kind: [str(p) for p in paths]
                          for kind, paths in other_files.items()}
    recs: list[str] = []
    if follow_ups:
        recs.append(f"Run follow-up skills: {', '.join(follow_ups)}")
    if detected_other_str.get(log_discovery.FTP_KIND):
        recs.append(
            f"Detected {len(detected_other_str[log_discovery.FTP_KIND])} FTP "
            f"log file(s); run the ftp_logs skill on the same folder."
        )
    if detected_other_str.get(log_discovery.HTTPERR_KIND):
        recs.append(
            f"Detected {len(detected_other_str[log_discovery.HTTPERR_KIND])} "
            f"HTTPERR file(s); run the httperror skill."
        )
    if not recs:
        recs.append("No problems detected; no further action needed.")

    # ---- Compute a headline root_cause from problems --------------------
    # Priority: most actionable / specific first. Lets the orchestrator
    # build a sensible root_cause_chain across skills.
    _RC_PRIORITY = (
        "kerberos_spn_mismatch",
        "auth_handshake_loop",
        "5xx_error",
        "auth_error",
        "high_latency",
        "suspicious_traffic",
        "traffic_spike",
        "not_found",
    )
    rc: str | None = None
    by_type = {p["type"]: p for p in problems if p.get("type")}
    for t in _RC_PRIORITY:
        if t in by_type:
            rc = f"[iis_logs] {by_type[t]['description']}"
            break

    result = SkillResult(
        skill=SKILL_ID,
        ok=True,
        findings=findings,
        root_cause=rc,
        confidence="medium" if problems else "low",
        recommendations=recs,
        raw={
            "log_files_parsed": len(iis_files),
            "metrics": metrics,
            "problems": problems,
            "skills_to_trigger": follow_ups,
            "timeseries": ts_payload,
            "detected_other_logs": detected_other_str,
        },
    )

    # ---- Merge playbook entries into the structured envelope ------------
    problem_types_seen = sorted({p["type"] for p in problems if p.get("type")})
    playbook.merge_into_result(result, problem_types_seen)

    if search_payload is not None:
        result.raw["search"] = search_payload
    if around_payload is not None:
        result.raw["around"] = around_payload

    # ---- Optional HTML report --------------------------------------------
    if args.report:
        try:
            report_path = Path(args.report)
            html = build_report_html(
                target_label=str(target),
                metrics=metrics,
                problems=problems,
                ts_payload=ts_payload,
                around_payload=around_payload,
                search_payload=search_payload,
                detected_other=detected_other_str,
                advisory=(result.solutions, result.next_steps, result.additional_logs_needed),
            )
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(html, encoding="utf-8")
            result.raw["report_html_path"] = str(report_path.resolve())
        except OSError as exc:
            result.raw["report_error"] = str(exc)

    # ---- Optional orchestrator hand-off ----------------------------------
    if args.auto_trigger and follow_ups:
        import json, subprocess
        orch = (Path(__file__).resolve().parents[2]
                / "orchestrator" / "scripts" / "skill_orchestrator.py")
        proc = subprocess.run(
            [sys.executable, str(orch), json.dumps(result.raw)],
            capture_output=True, text=True, timeout=180,
        )
        if proc.returncode == 0:
            try:
                result.raw["orchestrated"] = json.loads(proc.stdout)
            except json.JSONDecodeError:
                result.raw["orchestrated_raw_stdout"] = proc.stdout
        else:
            result.raw["orchestrator_error"] = proc.stderr.strip()

    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
