#!/usr/bin/env python3
"""
ftp_analyzer.py — Microsoft FTP Service (W3C) log analyzer

Reconstructs FTP sessions from W3C-formatted FTP logs:
    connect -> USER -> PASS -> [CWD/LIST/RETR/STOR ...] -> QUIT/timeout
and classifies four problem types:
    * ftp_auth_failure
    * ftp_upload_error
    * ftp_brute_force
    * ftp_incomplete_session

Same envelope as iis_logs (see _shared/contract.py). Supports the same
--around / --filter / --bucket / --report CLI surface so the two skills feel
identical.
"""
from __future__ import annotations

import argparse
import shlex
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import Finding, SkillResult, registry  # noqa: E402
from _shared import log_discovery, log_filters, timeseries, svg_charts, html_report, playbook  # noqa: E402
from _shared.logs import ftp_w3c  # noqa: E402

# Re-export shared parser/normalise so the rest of the file is unchanged
parse_ftp_log = ftp_w3c.parse_ftp_log
normalise     = ftp_w3c.normalise

SKILL_ID = "ftp_logs"

# ---- thresholds ------------------------------------------------------------
TH_AUTH_FAILURES_PER_IP   = 10   # 530s from one IP
TH_UPLOAD_ERROR_PCT       = 5.0  # 5xx/4xx during STOR/RETR
TH_BRUTE_FORCE_USER_COUNT = 5    # distinct usernames failed by one IP
TH_INCOMPLETE_PCT         = 20.0 # sessions without QUIT

SEARCH_RESULT_HARD_CAP = 1000

# ---- FTP command groupings ------------------------------------------------
_AUTH_CMDS     = {"USER", "PASS"}
_TRANSFER_CMDS = {"STOR", "STOU", "APPE", "RETR"}
_CONTROL_CMDS  = {"QUIT", "ABOR", "REIN"}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
# parse_ftp_log / normalise live in _shared.logs.ftp_w3c (re-exported above).


# ---------------------------------------------------------------------------
# Session reconstruction
# ---------------------------------------------------------------------------

def _session_key(entry: dict[str, Any], heuristic_counter: dict[str, int]) -> str:
    """
    Prefer the x-session id if present; otherwise group by client_ip and
    bump a counter whenever we see a new USER command from that IP.
    """
    sid = entry.get("session_id", "-")
    if sid and sid != "-":
        return f"sid:{sid}"
    ip = entry.get("client_ip", "-")
    if entry.get("method") == "USER":
        heuristic_counter[ip] = heuristic_counter.get(ip, 0) + 1
    return f"ip:{ip}#{heuristic_counter.get(ip, 1)}"


def _ts(entry: dict[str, Any]) -> datetime | None:
    raw = str(entry.get("timestamp", ""))
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def reconstruct_sessions(entries: list[dict[str, Any]]
                         ) -> list[dict[str, Any]]:
    """Group entries into ordered per-session event chains."""
    # Sort once by parsed timestamp so heuristic grouping is deterministic.
    entries_sorted = sorted(
        entries, key=lambda e: (_ts(e) or datetime.min, e.get("client_ip", ""))
    )

    counter: dict[str, int] = {}
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in entries_sorted:
        by_key[_session_key(e, counter)].append(e)

    sessions: list[dict[str, Any]] = []
    for key, evs in by_key.items():
        first_ts = _ts(evs[0])
        last_ts = _ts(evs[-1])
        duration_ms = (
            int((last_ts - first_ts).total_seconds() * 1000)
            if first_ts and last_ts else 0
        )
        username = next((e["user"] for e in evs
                         if e.get("user") and e["user"] != "-"), "-")
        client_ip = evs[0].get("client_ip", "-")
        pass_events = [e for e in evs if e["method"] == "PASS"]
        auth_ok = any(int(e["status"]) == 230 for e in pass_events)
        auth_failed = sum(1 for e in pass_events if int(e["status"]) >= 500)
        transfer_events = [e for e in evs if e["method"] in _TRANSFER_CMDS]
        errors = [e for e in evs if int(e["status"]) >= 400]
        terminated_cleanly = any(e["method"] == "QUIT" for e in evs)
        sessions.append({
            "key": key,
            "client_ip": client_ip,
            "username": username,
            "start": evs[0].get("timestamp"),
            "end":   evs[-1].get("timestamp"),
            "duration_ms": duration_ms,
            "auth_ok": auth_ok,
            "auth_failed_attempts": auth_failed,
            "commands_count": len(evs),
            "transfers": len(transfer_events),
            "bytes_up":   sum(e["bytes_received"] for e in transfer_events),
            "bytes_down": sum(e["bytes_sent"]     for e in transfer_events),
            "errors":     len(errors),
            "terminated_cleanly": terminated_cleanly,
            "events": [
                {
                    "ts": e.get("timestamp"),
                    "cmd": e["method"],
                    "uri": e.get("uri"),
                    "status": e["status"],
                    "bytes_up": e["bytes_received"],
                    "bytes_down": e["bytes_sent"],
                }
                for e in evs
            ],
        })
    sessions.sort(key=lambda s: (s["start"] or ""))
    return sessions


# ---------------------------------------------------------------------------
# Metrics / classification
# ---------------------------------------------------------------------------

def _percentile(sorted_values: list[int], pct: float) -> int:
    if not sorted_values:
        return 0
    idx = min(len(sorted_values) - 1,
              max(0, int(len(sorted_values) * pct) - 1))
    return sorted_values[idx]


def compute_stats(entries: list[dict[str, Any]],
                  sessions: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"total_commands": 0, "total_sessions": 0}
    statuses = [e["status"] for e in entries]
    times = sorted(e["time_taken"] for e in entries)
    timestamps = [e["timestamp"] for e in entries if e.get("timestamp")]
    return {
        "total_commands":  len(entries),
        "total_sessions":  len(sessions),
        "unique_ips":      len({e["client_ip"] for e in entries}),
        "unique_users":    len({e["user"] for e in entries
                                if e["user"] and e["user"] != "-"}),
        "status_distribution": dict(Counter(statuses)),
        "command_distribution": dict(Counter(e["method"] for e in entries)),
        "avg_time_taken_ms": sum(times) / len(times),
        "p95_time_taken_ms": _percentile(times, 0.95),
        "max_time_taken_ms": times[-1],
        "bytes_up":   sum(e["bytes_received"] for e in entries),
        "bytes_down": sum(e["bytes_sent"]     for e in entries),
        "time_range": {
            "start": min(timestamps) if timestamps else None,
            "end":   max(timestamps) if timestamps else None,
        },
    }


def classify_problems(entries: list[dict[str, Any]],
                      sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    problems: list[dict[str, Any]] = []
    if not entries:
        return problems
    reg = registry().get("problem_types", {})

    # --- auth failures by IP --------------------------------------------
    auth_fail_by_ip: Counter = Counter()
    for e in entries:
        if e["method"] == "PASS" and e["status"] >= 500:
            auth_fail_by_ip[e["client_ip"]] += 1
    for ip, n in auth_fail_by_ip.items():
        if n > TH_AUTH_FAILURES_PER_IP:
            problems.append({
                "type": "ftp_auth_failure",
                "severity": "warning",
                "description": f"{n} FTP auth failures from {ip}",
                "follow_ups": reg.get("ftp_auth_failure", {}).get("follow_ups", []),
                "evidence": {"client_ip": ip, "count": n},
            })

    # --- transfer errors -------------------------------------------------
    transfer_total = sum(1 for e in entries if e["method"] in _TRANSFER_CMDS)
    transfer_err = sum(1 for e in entries
                       if e["method"] in _TRANSFER_CMDS and e["status"] >= 400)
    if transfer_total > 0:
        pct = transfer_err / transfer_total * 100
        if pct > TH_UPLOAD_ERROR_PCT:
            problems.append({
                "type": "ftp_upload_error",
                "severity": "warning",
                "description": (
                    f"{transfer_err}/{transfer_total} FTP transfer commands "
                    f"failed ({pct:.1f}%)"
                ),
                "follow_ups": reg.get("ftp_upload_error", {}).get("follow_ups", []),
                "evidence": {"failed": transfer_err, "total": transfer_total},
            })

    # --- brute-force (one IP, many user names) --------------------------
    failed_users_by_ip: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        if e["method"] == "PASS" and e["status"] >= 500 and e["user"] and e["user"] != "-":
            failed_users_by_ip[e["client_ip"]].add(e["user"])
    for ip, users in failed_users_by_ip.items():
        if len(users) >= TH_BRUTE_FORCE_USER_COUNT:
            problems.append({
                "type": "ftp_brute_force",
                "severity": "critical",
                "description": (
                    f"FTP brute-force suspected: {ip} tried "
                    f"{len(users)} distinct usernames"
                ),
                "follow_ups": reg.get("ftp_brute_force", {}).get("follow_ups", []),
                "evidence": {"client_ip": ip, "users": sorted(users)},
            })

    # --- incomplete sessions --------------------------------------------
    if sessions:
        incomplete = sum(1 for s in sessions if not s["terminated_cleanly"])
        pct = incomplete / len(sessions) * 100
        if pct > TH_INCOMPLETE_PCT:
            problems.append({
                "type": "ftp_incomplete_session",
                "severity": "info",
                "description": (
                    f"{incomplete}/{len(sessions)} FTP sessions ended without "
                    f"QUIT ({pct:.1f}%)"
                ),
                "follow_ups": reg.get("ftp_incomplete_session", {}).get("follow_ups", []),
                "evidence": {"incomplete": incomplete, "total": len(sessions)},
            })

    return problems


# ---------------------------------------------------------------------------
# Time-series + search helpers (mirroring iis_analyzer for symmetry)
# ---------------------------------------------------------------------------

def build_timeseries(entries: list[dict[str, Any]],
                     bucket_seconds: int) -> dict[str, Any]:
    buckets = timeseries.bucketize(entries, bucket_seconds=bucket_seconds)
    spike = timeseries.detect_spike(buckets)
    return {
        "bucket_seconds": bucket_seconds,
        "buckets": [b.to_dict() for b in buckets],
        "peak_bucket": spike.to_dict() if spike else None,
    }


def apply_filter(entries: list[dict[str, Any]],
                 spec: log_filters.FilterSpec) -> list[dict[str, Any]]:
    if spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def around_window(entries: list[dict[str, Any]],
                  anchor: datetime, window_seconds: int
                  ) -> list[dict[str, Any]]:
    lo = anchor - timedelta(seconds=window_seconds)
    hi = anchor + timedelta(seconds=window_seconds)
    out: list[dict[str, Any]] = []
    for e in entries:
        ts = _ts(e)
        if ts is None:
            continue
        if lo <= ts <= hi:
            out.append(e)
    return out


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    statuses = [e["status"] for e in entries]
    return {
        "count": len(entries),
        "status_distribution": dict(Counter(statuses)),
        "top_users": Counter(e["user"] for e in entries
                             if e["user"] and e["user"] != "-").most_common(10),
        "top_ips": Counter(e["client_ip"] for e in entries).most_common(10),
        "top_cmds": Counter(e["method"] for e in entries).most_common(10),
    }


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _bucket_labels(buckets: list[dict[str, Any]]) -> list[str]:
    return [b["start"].split(" ")[1] if " " in b["start"] else b["start"]
            for b in buckets]


def build_report_html(target_label: str,
                      stats: dict[str, Any],
                      sessions: list[dict[str, Any]],
                      problems: list[dict[str, Any]],
                      ts_payload: dict[str, Any],
                      around_payload: dict[str, Any] | None,
                      search_payload: dict[str, Any] | None,
                      advisory: tuple[list, list, list] | None = None) -> str:
    Section = html_report.Section
    kpi = html_report.kpi_card
    sections: list[html_report.Section] = []

    summary_kpis = (
        kpi("Commands", str(stats.get("total_commands", 0))) +
        kpi("Sessions", str(stats.get("total_sessions", 0))) +
        kpi("Unique IPs", str(stats.get("unique_ips", 0))) +
        kpi("Unique users", str(stats.get("unique_users", 0))) +
        kpi("Bytes up", f"{stats.get('bytes_up', 0):,}") +
        kpi("Bytes down", f"{stats.get('bytes_down', 0):,}")
    )
    sections.append(Section("Summary", summary_kpis))

    # Problems table
    if problems:
        rows = [
            (
                f'<span class="badge {p["severity"]}">{p["severity"]}</span> {p["type"]}',
                p["description"],
                ", ".join(p.get("follow_ups", [])) or "-",
            )
            for p in problems
        ]
        table = html_report.render_table(
            ["Problem", "Description", "Follow-up skills"], rows,
        )
        table = table.replace("&lt;span class=&quot;badge ", '<span class="badge ')
        table = table.replace("&quot;&gt;", '">').replace("&lt;/span&gt;", "</span>")
        sections.append(Section("Detected problems", table))
    else:
        sections.append(Section(
            "Detected problems",
            '<div class="note">No FTP problems detected.</div>',
        ))

    # Command distribution
    cmd = stats.get("command_distribution") or {}
    if cmd:
        items = sorted(cmd.items(), key=lambda kv: -kv[1])[:12]
        sections.append(Section(
            "Command distribution",
            svg_charts.bar_chart([k for k, _ in items], [v for _, v in items],
                                 title="FTP command counts", ylabel="commands"),
        ))

    # Time series
    buckets = ts_payload.get("buckets", [])
    if buckets:
        labels = _bucket_labels(buckets)
        counts = [b["count"] for b in buckets]
        errors = [b["error_4xx"] + b["error_5xx"] for b in buckets]
        sections.append(Section(
            f"Commands per {ts_payload['bucket_seconds']}s bucket",
            svg_charts.bar_chart(labels, counts,
                                 title="FTP commands over time",
                                 ylabel="commands"),
        ))
        sections.append(Section(
            "Errors over time",
            svg_charts.line_chart(labels, {"4xx+5xx": errors},
                                  title="FTP error rate", ylabel="errors"),
        ))

    # Sessions table (top 100)
    if sessions:
        rows = [
            (s["start"], s["client_ip"], s["username"],
             s["duration_ms"], s["commands_count"], s["transfers"],
             s["bytes_up"], s["bytes_down"], s["errors"],
             "yes" if s["terminated_cleanly"] else "no")
            for s in sessions
        ]
        sections.append(Section(
            f"Sessions ({len(sessions)})",
            html_report.render_table(
                ["Start", "Client IP", "User", "Duration ms", "Cmds",
                 "Transfers", "Bytes up", "Bytes down", "Errors",
                 "Quit cleanly"],
                rows, max_rows=100,
            ),
        ))

    if around_payload:
        for anchor_ts, payload in around_payload.items():
            heading = f"Commands around {anchor_ts} (±{payload['window_seconds']}s)"
            summary = payload.get("summary", {})
            kpis = (
                kpi("Matched", str(summary.get("count", 0))) +
                kpi("Top cmd", str((summary.get("top_cmds") or [(None, 0)])[0][0]))
            )
            rows = [
                (e.get("timestamp"), e.get("client_ip"), e.get("user"),
                 e.get("method"), e.get("uri"), e.get("status"))
                for e in payload.get("entries", [])
            ]
            sections.append(Section(
                heading,
                kpis + html_report.render_table(
                    ["Timestamp", "Client IP", "User", "Cmd", "URI", "Status"],
                    rows, max_rows=200,
                ),
            ))

    if search_payload:
        summary = search_payload.get("summary", {})
        kpis = kpi("Matched", str(summary.get("count", 0)))
        rows = [
            (e.get("timestamp"), e.get("client_ip"), e.get("user"),
             e.get("method"), e.get("uri"), e.get("status"))
            for e in search_payload.get("results", [])
        ]
        sections.append(Section(
            f"Search results (filter: {search_payload.get('filter', '')})",
            kpis + html_report.render_table(
                ["Timestamp", "Client IP", "User", "Cmd", "URI", "Status"],
                rows, max_rows=200,
            ),
        ))

    if advisory:
        sols, nxts, logs = advisory
        sections.extend(html_report.advisory_sections(
            solutions=sols, next_steps=nxts, additional_logs_needed=logs,
        ))

    return html_report.render(
        title="FTP log analysis report",
        subtitle=f"Source: {target_label}",
        sections=sections,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def collect_log_files(target: Path, recursive: bool = True
                      ) -> tuple[list[Path], dict[str, list[Path]]]:
    disc = log_discovery.discover_logs(target, recursive=recursive)
    ftp = list(disc.get(log_discovery.FTP_KIND))
    others: dict[str, list[Path]] = {
        kind: paths for kind, paths in disc.by_kind.items()
        if kind != log_discovery.FTP_KIND and paths
    }
    if not ftp and target.is_file():
        ftp = [target]
        others.pop(log_discovery.classify_file(target), None)
    return ftp, others


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="FTP W3C log analyzer")
    ap.add_argument("log", help="Path to a .log file or a directory of logs")
    ap.add_argument("--no-recursive", action="store_true",
                    help="Do not recurse into subdirectories")
    ap.add_argument("--bucket", default="1m",
                    help="Bucket size for the time series (e.g. 30s, 1m). Default 1m.")
    ap.add_argument("--around", action="append", default=[],
                    metavar="TIMESTAMP",
                    help="Anchor timestamp (e.g. '2026-05-26 10:15:30'). Repeatable.")
    ap.add_argument("--window", default="5m",
                    help="Window around each --around anchor. Default 5m.")
    ap.add_argument("--filter", dest="filter_text", default=None,
                    help=("Filter expression, e.g. "
                          "'user=alice,cmd=STOR,status=500-599,ip=10.0.0.0/24,"
                          "path=^/uploads/,min-bytes=1024'"))
    ap.add_argument("--report", default=None, metavar="PATH",
                    help="Write an HTML report to PATH (no report by default).")
    args = ap.parse_args(argv)

    target = Path(args.log)
    if not target.exists():
        SkillResult(skill=SKILL_ID, ok=False, error=f"Path not found: {target}").emit()
        return 2

    ftp_files, other_files = collect_log_files(target, recursive=not args.no_recursive)
    entries: list[dict[str, Any]] = []
    for path in ftp_files:
        for row in parse_ftp_log(path):
            entries.append(normalise(row))

    sessions = reconstruct_sessions(entries)
    stats = compute_stats(entries, sessions)
    problems = classify_problems(entries, sessions)

    try:
        bucket_seconds = log_filters.parse_duration_seconds(args.bucket)
    except ValueError as exc:
        SkillResult(skill=SKILL_ID, ok=False, error=str(exc)).emit()
        return 2
    ts_payload = build_timeseries(entries, bucket_seconds)

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

    around_payload: dict[str, Any] | None = None
    if args.around:
        try:
            window_seconds = log_filters.parse_duration_seconds(args.window)
        except ValueError as exc:
            SkillResult(skill=SKILL_ID, ok=False, error=f"--window: {exc}").emit()
            return 2
        around_payload = {}
        for raw_ts in args.around:
            anchor = _ts({"timestamp": raw_ts})
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
    if detected_other_str.get(log_discovery.IIS_KIND):
        recs.append(
            f"Detected {len(detected_other_str[log_discovery.IIS_KIND])} IIS "
            f"log file(s) in the same folder; run the iis_logs skill on them."
        )
    if not recs:
        recs.append("No FTP problems detected; no further action needed.")

    result = SkillResult(
        skill=SKILL_ID,
        ok=True,
        findings=findings,
        root_cause=None,
        confidence="medium" if problems else "low",
        recommendations=recs,
        raw={
            "log_files_parsed": len(ftp_files),
            "session_stats": stats,
            "sessions": sessions,
            "problems": problems,
            "skills_to_trigger": follow_ups,
            "timeseries": ts_payload,
            "detected_other_logs": detected_other_str,
        },
    )

    # Merge playbook (FTP problem types: ftp_auth_failure, ftp_upload_error, ftp_brute_force, ftp_incomplete_session)
    problem_types_seen = sorted({p["type"] for p in problems if p.get("type")})
    playbook.merge_into_result(result, problem_types_seen)

    if search_payload is not None:
        result.raw["search"] = search_payload
    if around_payload is not None:
        result.raw["around"] = around_payload

    if args.report:
        try:
            report_path = Path(args.report)
            html = build_report_html(
                target_label=str(target),
                stats=stats,
                sessions=sessions,
                problems=problems,
                ts_payload=ts_payload,
                around_payload=around_payload,
                search_payload=search_payload,
                advisory=(result.solutions, result.next_steps, result.additional_logs_needed),
            )
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(html, encoding="utf-8")
            result.raw["report_html_path"] = str(report_path.resolve())
        except OSError as exc:
            result.raw["report_error"] = str(exc)

    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
