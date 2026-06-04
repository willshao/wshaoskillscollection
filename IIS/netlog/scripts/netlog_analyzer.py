#!/usr/bin/env python3
"""
netlog_analyzer.py — Chromium net-export (edge://net-export, chrome://net-export)
analyser for the IIS skill collection.

Client-side network capture is often the only place where a failing IIS
request can be inspected end-to-end: TLS handshake, redirect chain, proxy
fallback, **HTTP authentication (Negotiate/NTLM/Kerberos) round-trip**.

This skill consumes net-export `.json` files and produces the standard
envelope. The HTTP-auth pipeline is its single biggest value-add — it
decodes SSPI `security_status` codes (SEC_E_*), Chromium `net_error`
codes (ERR_*), extracts the Kerberos SPN that the browser tried, and
detects two very common Windows-Auth incident patterns:

  * `kerberos_spn_mismatch` — Kerberos failed with SEC_E_WRONG_PRINCIPAL
    (0x80090322), i.e. the SPN the client requested is not registered
    against the IIS app-pool identity (or is duplicated in AD).
  * `auth_handshake_loop` — the same URL receives repeated 401s with
    HTTP_TRANSACTION_DRAIN_BODY_FOR_AUTH_RESTART entries but the second
    leg never carries credentials (typically: site not in Intranet zone,
    proxy strips Authorization, ERR_MISSING_AUTH_CREDENTIALS).

Stdlib only. Self-contained (does not depend on the Edge collection).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, LogRequest, SkillResult, load_context,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "netlog"
SLOW_REQUEST_THRESHOLD_MS = 5000
MAX_TOP_REQUESTS = 5
# Modern Edge net-export prepends ~80 KB of activeFieldTrialGroups before
# logSourceType, so 4 KB is far too small for the structural sniff.
NETLOG_PEEK_BYTES = 1_048_576

# ---------------------------------------------------------------------------
# SSPI / Chromium auth code tables
# ---------------------------------------------------------------------------
# SSPI security_status values are signed 32-bit (Python stores them as
# negative). We normalise by masking to 32-bit unsigned for lookup.
def _sspi_u32(val: int) -> int:
    return val & 0xFFFFFFFF

SSPI_STATUS_NAMES = {
    0x00000000: ("SEC_E_OK",                   "success"),
    0x00090312: ("SEC_I_CONTINUE_NEEDED",      "handshake continues — normal"),
    0x00090313: ("SEC_I_COMPLETE_NEEDED",      "complete the token — normal"),
    0x00090314: ("SEC_I_COMPLETE_AND_CONTINUE","complete & continue — normal"),
    0x8009030C: ("SEC_E_LOGON_DENIED",         "bad username/password or account disabled"),
    0x8009030E: ("SEC_E_NO_CREDENTIALS",       "no credentials available for the target"),
    0x80090308: ("SEC_E_INVALID_TOKEN",        "token corrupted by a middlebox or codec"),
    0x80090322: ("SEC_E_WRONG_PRINCIPAL",      "SPN does not match the service account (Kerberos)"),
    0x80090303: ("SEC_E_TARGET_UNKNOWN",       "KDC could not find the target principal"),
    0x80090311: ("SEC_E_NO_AUTHENTICATING_AUTHORITY", "no DC contactable for the domain"),
    0x80090304: ("SEC_E_INTERNAL_ERROR",       "SSPI internal error"),
    0x80090300: ("SEC_E_INSUFFICIENT_MEMORY",  "SSPI out of memory"),
    0x80090301: ("SEC_E_INVALID_HANDLE",       "stale SSPI handle"),
    0x80090305: ("SEC_E_SECPKG_NOT_FOUND",     "Negotiate/NTLM package not installed"),
    0x80090331: ("SEC_E_UNSUPPORTED_PREAUTH",  "unsupported pre-auth (Kerberos)"),
    0x80090346: ("SEC_E_BAD_BINDINGS",         "channel binding mismatch (Extended Protection)"),
    0x80090351: ("SEC_E_SMARTCARD_LOGON_REQUIRED", "smart-card required by policy"),
}

# Chromium net_error codes we care about for auth flows.
NET_ERROR_NAMES = {
    -101: "ERR_CONNECTION_RESET",
    -102: "ERR_CONNECTION_REFUSED",
    -105: "ERR_NAME_NOT_RESOLVED",
    -118: "ERR_CONNECTION_TIMED_OUT",
    -200: "ERR_CERT_COMMON_NAME_INVALID",
    -201: "ERR_CERT_DATE_INVALID",
    -202: "ERR_CERT_AUTHORITY_INVALID",
    -337: "ERR_INVALID_AUTH_CREDENTIALS",
    -338: "ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS",
    -339: "ERR_MISSING_AUTH_CREDENTIALS",
    -340: "ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS",
    -341: "ERR_MISCONFIGURED_AUTH_ENVIRONMENT",
    -342: "ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS",
}


def _decode_sspi(security_status: Any) -> tuple[str | None, str | None]:
    """Return (name, description) for an SSPI security_status int, or (None, None)."""
    try:
        code = int(security_status)
    except (TypeError, ValueError):
        return None, None
    info = SSPI_STATUS_NAMES.get(_sspi_u32(code))
    return info if info else (f"0x{_sspi_u32(code):08X}", None)


def _decode_net_error(net_error: Any) -> str | None:
    try:
        code = int(net_error)
    except (TypeError, ValueError):
        return None
    return NET_ERROR_NAMES.get(code, f"net_error={code}")


# ---------------------------------------------------------------------------
# Reader (mirror of Edge/_shared/sources/netlog.py; kept self-contained so
# the IIS collection has zero cross-collection dependencies).
# ---------------------------------------------------------------------------

def _looks_like_netlog(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(NETLOG_PEEK_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return False
    if '"constants"' not in head[:256]:
        return False
    return ('"logSourceType"' in head
            or '"logEventTypes"' in head
            or '"clientInfo"' in head)


def _load_netlog(path: Path) -> tuple[dict[str, Any], dict[int, str], dict[int, str]]:
    """Return (raw_blob, event_type_name_map, source_type_name_map)."""
    blob = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(blob, dict):
        raise ValueError("net-export root is not a JSON object")
    consts = blob.get("constants") or {}
    et = {int(v): k for k, v in (consts.get("logEventTypes") or {}).items()
          if isinstance(v, int)}
    st = {int(v): k for k, v in (consts.get("logSourceType") or {}).items()
          if isinstance(v, int)}
    return blob, et, st


def _iter_entries(blob: dict[str, Any], et_map: dict[int, str],
                  st_map: dict[int, str]) -> Iterator[dict[str, Any]]:
    events = blob.get("events")
    if not isinstance(events, list):
        return
    for ev in events:
        if not isinstance(ev, dict):
            continue
        src = ev.get("source") or {}
        st = src.get("type")
        try:
            type_id = int(ev.get("type")) if ev.get("type") is not None else None
        except (TypeError, ValueError):
            type_id = None
        yield {
            "time": ev.get("time"),
            "phase": ev.get("phase"),
            "source_id": src.get("id"),
            "source_type_id": st,
            "source_type": st_map.get(int(st), str(st)) if st is not None else None,
            "type_id": type_id,
            "type": et_map.get(type_id, str(type_id)) if type_id is not None else None,
            "params": ev.get("params"),
        }


def _summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    by_src = Counter(e.get("source_type", "?") for e in entries)
    by_phase = Counter(e.get("phase", -1) for e in entries)
    return {
        "count": len(entries),
        "top_source_types": by_src.most_common(10),
        "phase_distribution": dict(by_phase),
    }


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
        out.extend(_discover_netlogs_in_folder(
            Path(folder), recursive=not extra.get("no_recursive")
        ))
    # Dedup, preserve order
    seen: set[Path] = set()
    uniq: list[Path] = []
    for p in out:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def _discover_netlogs_in_folder(folder: Path, recursive: bool = True) -> list[Path]:
    if not folder.is_dir():
        return []
    pattern = "**/*.json" if recursive else "*.json"
    return [p for p in sorted(folder.glob(pattern)) if _looks_like_netlog(p)]


# ---------------------------------------------------------------------------
# Per-request span interpretation
# ---------------------------------------------------------------------------

def _extract_net_error(params: Any) -> str | None:
    if not isinstance(params, dict):
        return None
    for key in ("net_error", "error", "result"):
        v = params.get(key)
        if isinstance(v, str) and v.startswith("ERR_"):
            return v
        if isinstance(v, int) and v < 0:
            return _decode_net_error(v)
    for v in params.values():
        if isinstance(v, str) and v.startswith("ERR_"):
            return v
    return None


def _classify_request_span(events: list[dict[str, Any]]) -> dict[str, Any]:
    url = None
    method = None
    net_error: str | None = None
    auth_restarts = 0
    response_codes: list[int] = []
    t_begin = None
    t_end = None
    for ev in events:
        params = ev.get("params") or {}
        if url is None and isinstance(params, dict) and params.get("url"):
            url = params.get("url")
            method = params.get("method") or method
        if isinstance(params, dict):
            rc = params.get("http_status_code") or params.get("response_code")
            if isinstance(rc, int):
                response_codes.append(rc)
        if ev.get("type") == "HTTP_TRANSACTION_DRAIN_BODY_FOR_AUTH_RESTART":
            auth_restarts += 1
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
        "auth_restarts": auth_restarts,
        "response_codes": response_codes,
    }


# ---------------------------------------------------------------------------
# HTTP-auth (Windows / Negotiate / NTLM / Kerberos) analysis
# ---------------------------------------------------------------------------

def _analyse_auth(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode every AUTH_* event the browser emitted.

    Produces a structured picture of every auth attempt: which scheme was
    used (Negotiate / NTLM / Basic / Digest), which SPN the SSPI layer
    asked for, what security_status it got back, and which Chromium
    net_error the controller surfaced. Used by `_findings_from_files`
    to emit `kerberos_spn_mismatch` / `auth_handshake_loop` etc.

    AUTH_LIBRARY_INIT_SEC_CTX is emitted as a BEGIN event carrying the
    SPN, then an END event carrying the SSPI status. We pair them by
    source_id so the failure record reports the SPN that actually failed.
    """
    spn_attempts: list[dict[str, Any]] = []         # AUTH_LIBRARY_INIT_SEC_CTX
    handler_results: list[dict[str, Any]] = []      # AUTH_HANDLER_CREATE_RESULT
    generate_token_errors: list[dict[str, Any]] = [] # AUTH_GENERATE_TOKEN with net_error
    schemes_seen: Counter = Counter()
    origins_seen: Counter = Counter()
    sspi_status_counter: Counter = Counter()
    net_error_counter: Counter = Counter()

    # Pending BEGIN frames per source_id for AUTH_LIBRARY_INIT_SEC_CTX,
    # so the matching END frame can be enriched with its SPN.
    pending_init: dict[Any, dict[str, Any]] = {}

    for e in entries:
        nm = e.get("type") or ""
        if not nm.startswith(("AUTH_", "HTTP_TRANSACTION_DRAIN")):
            continue
        params = e.get("params") or {}
        if not isinstance(params, dict):
            continue
        phase = e.get("phase")
        sid = e.get("source_id")

        # SSPI status often lives inside params["status"] (END events).
        status = params.get("status") if isinstance(params.get("status"), dict) else None
        ne_val = (status or {}).get("net_error") if status else params.get("net_error")
        ss_val = (status or {}).get("security_status") if status else params.get("security_status")

        if ne_val is not None:
            net_name = _decode_net_error(ne_val)
            if net_name:
                net_error_counter[net_name] += 1
        if ss_val is not None:
            ss_name, ss_desc = _decode_sspi(ss_val)
            if ss_name:
                sspi_status_counter[ss_name] += 1

        if nm == "AUTH_LIBRARY_INIT_SEC_CTX":
            # Pair BEGIN (carries `spn`) with END (carries `status`).
            # Chromium netlog phases: NONE=0, BEGIN=1, END=2.
            if phase == 1:  # PHASE_BEGIN
                pending_init[sid] = {
                    "spn": params.get("spn"),
                    "flags": params.get("flags"),
                }
                continue  # wait for END to record a result
            # END or NONE → emit a record, enriched with the pending BEGIN.
            begin = pending_init.pop(sid, {})
            ss_name, ss_desc = (_decode_sspi(ss_val) if ss_val is not None
                                else (None, None))
            spn_attempts.append({
                "spn": (params.get("spn") or begin.get("spn")),
                "mechanism": (params.get("context") or {}).get("mechanism"),
                "net_error": (_decode_net_error(ne_val)
                              if ne_val is not None else None),
                "security_status": ss_name,
                "security_status_desc": ss_desc,
                "flags": (params.get("flags")
                          or (params.get("context") or {}).get("flags")
                          or begin.get("flags")),
            })
        elif nm == "AUTH_HANDLER_CREATE_RESULT":
            scheme = params.get("scheme")
            origin = params.get("origin")
            if scheme:
                schemes_seen[scheme] += 1
            if origin:
                origins_seen[origin] += 1
            handler_results.append({
                "scheme": scheme,
                "challenge": params.get("challenge"),
                "origin": origin,
                "allows_default_credentials": params.get("allows_default_credentials"),
                "net_error": _decode_net_error(ne_val) if ne_val is not None else None,
            })
        elif nm == "AUTH_GENERATE_TOKEN" and ne_val is not None:
            decoded = _decode_net_error(ne_val)
            if decoded and decoded != "net_error=0":
                generate_token_errors.append({
                    "net_error": decoded,
                })

    return {
        "spn_attempts": spn_attempts,
        "handler_results": handler_results,
        "generate_token_errors": generate_token_errors,
        "schemes_seen": dict(schemes_seen),
        "origins_seen": dict(origins_seen),
        "sspi_status_counts": dict(sspi_status_counter),
        "net_error_counts": dict(net_error_counter),
    }


def _detect_auth_problems(auth: dict[str, Any],
                          requests: list[dict[str, Any]]
                          ) -> list[dict[str, Any]]:
    """Turn raw auth analysis into discrete problem records."""
    problems: list[dict[str, Any]] = []

    spn_failures = [a for a in auth["spn_attempts"]
                    if a.get("security_status") == "SEC_E_WRONG_PRINCIPAL"]
    if spn_failures:
        # Pick the most-attempted SPN for the headline.
        spns = Counter(a.get("spn") for a in spn_failures if a.get("spn"))
        top_spn, top_n = (spns.most_common(1)[0] if spns else (None, 0))
        # Figure out which URL origin the browser was driving when this happened.
        origins = Counter(a.get("origin") for a in auth["handler_results"] if a.get("origin"))
        top_origin = origins.most_common(1)[0][0] if origins else None
        host_in_url = urlparse(top_origin).hostname if top_origin else None
        spn_host = None
        if top_spn and "/" in top_spn:
            spn_host = top_spn.split("/", 1)[1].split(":")[0].lower()
        mismatch = bool(host_in_url and spn_host and host_in_url.lower() != spn_host)
        problems.append({
            "type": "kerberos_spn_mismatch",
            "severity": "critical",
            "description": (
                f"Kerberos returned SEC_E_WRONG_PRINCIPAL {len(spn_failures)} time(s) "
                f"for SPN {top_spn!r}" + (
                    f" while the browser was on origin {top_origin}"
                    f" (URL host {host_in_url} != SPN host {spn_host})"
                    if mismatch else ""
                )
            ),
            "evidence": {
                "failed_spn": top_spn,
                "failed_spn_count": top_n,
                "origin": top_origin,
                "url_host": host_in_url,
                "spn_host": spn_host,
                "host_mismatch": mismatch,
                "sample_attempts": spn_failures[:3],
            },
        })

    # Detect handshake loop: requests with >= 3 auth_restarts and ending in 401
    # or in ERR_MISSING_AUTH_CREDENTIALS.
    loops = [r for r in requests
             if r.get("auth_restarts", 0) >= 3
             and (
                 (r.get("response_codes") or [None])[-1] == 401
                 or r.get("net_error") in ("ERR_MISSING_AUTH_CREDENTIALS",
                                            "ERR_INVALID_AUTH_CREDENTIALS")
             )]
    missing_creds = auth["net_error_counts"].get("ERR_MISSING_AUTH_CREDENTIALS", 0)
    if loops or missing_creds:
        sample = loops[:3] if loops else []
        problems.append({
            "type": "auth_handshake_loop",
            "severity": "warning",
            "description": (
                f"{len(loops)} URL request(s) looped through repeated 401 "
                f"challenges; ERR_MISSING_AUTH_CREDENTIALS seen "
                f"{missing_creds} time(s) — the browser is not (or cannot) "
                f"send credentials silently."
            ),
            "evidence": {
                "looping_requests_sample": sample,
                "missing_credentials_count": missing_creds,
            },
        })

    # Plain auth_error if we saw any Negotiate/NTLM challenge at all but
    # neither of the more specific patterns fired — keeps cross-correlation
    # with iis_logs.auth_error sound even on light captures.
    saw_challenge = any(
        s in ("negotiate", "ntlm") for s in (auth["schemes_seen"] or {}).keys()
    )
    if saw_challenge and not problems:
        problems.append({
            "type": "auth_error",
            "severity": "info",
            "description": (
                f"Browser saw {sum(auth['schemes_seen'].values())} Windows-auth "
                f"challenges (schemes: {sorted(auth['schemes_seen'])}); "
                f"no SSPI failure recorded."
            ),
            "evidence": {"schemes_seen": auth["schemes_seen"]},
        })

    # TLS handshake failure — surface as its own problem_type.
    tls_failures = [r for r in requests
                    if (r.get("net_error") or "").startswith(
                        ("ERR_SSL_", "ERR_BAD_SSL_", "ERR_CERT_AUTHORITY_INVALID"))]
    if tls_failures:
        problems.append({
            "type": "tls_handshake_failure",
            "severity": "critical",
            "description": f"{len(tls_failures)} TLS handshake failure(s) observed.",
            "evidence": {"sample": tls_failures[:3]},
        })

    return problems


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def _analyse_one(path: Path) -> dict[str, Any]:
    blob, et_map, st_map = _load_netlog(path)
    entries = list(_iter_entries(blob, et_map, st_map))
    summary = _summarise(entries)

    by_source: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for e in entries:
        if e.get("source_type") == "URL_REQUEST":
            by_source[e.get("source_id")].append(e)
    requests = [_classify_request_span(evs) for evs in by_source.values()]

    failed = [r for r in requests if r["net_error"]]
    slow = [r for r in requests if (r["duration_ms"] or 0) >= SLOW_REQUEST_THRESHOLD_MS]
    slow.sort(key=lambda r: r["duration_ms"] or 0, reverse=True)
    error_counts = Counter(r["net_error"] for r in failed)

    dns_failures = [
        e for e in entries
        if (e.get("source_type") or "").startswith("HOST_RESOLVER_IMPL")
        and _extract_net_error(e.get("params"))
    ]
    cert_failures = [r for r in failed if (r["net_error"] or "").startswith("ERR_CERT")]
    proxy_issues = [
        e for e in entries
        if (e.get("source_type") or "").startswith("PROXY")
        and _extract_net_error(e.get("params"))
    ]

    auth = _analyse_auth(entries)
    auth_problems = _detect_auth_problems(auth, requests)

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
        "auth": auth,
        "auth_problems": auth_problems,
    }


# ---------------------------------------------------------------------------
# Envelope assembly
# ---------------------------------------------------------------------------

def _findings_from_files(per_file: list[dict[str, Any]]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    problem_types: list[str] = []

    total_req = sum(f["requests_total"] for f in per_file)
    total_fail = sum(f["requests_failed"] for f in per_file)
    total_slow = sum(f["requests_slow"] for f in per_file)
    total_dns = sum(f["dns_failures"] for f in per_file)
    total_cert = sum(f["cert_failures"] for f in per_file)
    total_proxy = sum(f["proxy_issues"] for f in per_file)

    # Aggregate auth view across files.
    agg_schemes: Counter = Counter()
    agg_sspi: Counter = Counter()
    agg_net: Counter = Counter()
    all_auth_problems: list[dict[str, Any]] = []
    for f in per_file:
        agg_schemes.update((f.get("auth") or {}).get("schemes_seen") or {})
        agg_sspi.update((f.get("auth") or {}).get("sspi_status_counts") or {})
        agg_net.update((f.get("auth") or {}).get("net_error_counts") or {})
        all_auth_problems.extend(f.get("auth_problems") or [])

    findings.append(Finding(
        summary=(f"Parsed {len(per_file)} net-export file(s): "
                 f"{total_req} URL requests, {total_fail} failed, {total_slow} slow."),
        severity="info",
        evidence={
            "files": [f["file"] for f in per_file],
            "total_requests": total_req,
            "total_failed": total_fail,
            "total_slow": total_slow,
            "auth_schemes_seen": dict(agg_schemes),
            "sspi_status_counts": dict(agg_sspi),
            "auth_net_error_counts": dict(agg_net),
        },
    ))

    # Surface auth findings *first* — they are usually the headline.
    seen_types: set[str] = set()
    for prob in all_auth_problems:
        ptype = prob.get("type")
        if not ptype or ptype in seen_types:
            continue
        seen_types.add(ptype)
        problem_types.append(ptype)
        findings.append(Finding(
            summary=prob.get("description") or ptype,
            severity=prob.get("severity", "warning"),
            evidence=prob.get("evidence") or {},
        ))

    if total_cert:
        problem_types.append("cert_error")
        findings.append(Finding(
            summary=f"TLS/cert errors observed in {total_cert} URL request(s).",
            severity="critical",
            evidence={"sample": [r for f in per_file for r in f["sample_failures"]
                                 if (r["net_error"] or "").startswith("ERR_CERT")
                                 ][:MAX_TOP_REQUESTS]},
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
        problem_types.append("client_request_failure")
        findings.append(Finding(
            summary=f"{total_fail} URL request(s) failed with non-cert/dns errors.",
            severity="warning",
            evidence={"error_breakdown": _merge_counts(per_file)},
        ))
    if total_slow:
        problem_types.append("high_latency")
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
    # Auth findings dominate when present — they map directly to actionable
    # remediation in the playbook.
    if "kerberos_spn_mismatch" in pts:
        return "Kerberos SPN mismatch (SEC_E_WRONG_PRINCIPAL) in net-export"
    if "auth_handshake_loop" in pts:
        return "Windows-auth handshake loop in net-export (ERR_MISSING_AUTH_CREDENTIALS)"
    if "tls_handshake_failure" in pts:
        return "TLS handshake failure in net-export"
    if "cert_error" in pts:
        return "TLS/cert error chain in net-export"
    if "dns_issue" in pts:
        return "DNS resolution failures in net-export"
    if "proxy_issue" in pts:
        return "Proxy resolution / fallback failures in net-export"
    if "client_request_failure" in pts:
        return "Client URL request failures in net-export"
    if "high_latency" in pts:
        return "Slow URL requests in net-export"
    if "auth_error" in pts:
        return "Windows-auth challenges observed in net-export"
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def analyse(ctx: dict[str, Any]) -> SkillResult:
    extra = ctx.get("extra") or {}
    sources = _resolve_sources(extra)

    if not sources:
        return SkillResult(
            skill=SKILL_ID, ok=True,
            findings=[Finding(
                summary=("No net-export files provided. Capture one with "
                          "edge://net-export and pass extra.netlog_paths or extra.folder."),
                severity="info",
            )],
            confidence="low",
            additional_logs_needed=[LogRequest(
                log_kind="netlog",
                why=("Client-side view is required to diagnose proxy / TLS / DNS / "
                     "Windows-auth issues for IIS-served requests."),
                how_to_collect=("Open edge://net-export, click Start Logging To Disk, "
                                "reproduce the issue, then Stop."),
                skill=SKILL_ID,
            )],
            raw={"sources": []},
        )

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
            "problems": [{"type": t, "severity": "warning"} for t in problem_types],
        },
    )
    # Only merge playbook entries whose problem_type exists in this collection.
    known = set(playbook.problem_types())
    relevant = [t for t in problem_types if t in known]
    if relevant:
        playbook.merge_into_result(result, relevant)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="net-export (netlog) analyser for IIS collection")
    ap.add_argument("context", nargs="?", default=None,
                    help="JSON context, @file, or path to JSON file. Use extra.netlog_paths or extra.folder.")
    args = ap.parse_args(argv)
    ctx = load_context([args.context] if args.context else [])
    analyse(ctx).emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
