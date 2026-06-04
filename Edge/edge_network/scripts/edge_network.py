#!/usr/bin/env python3
"""
edge_network.py — DNS / proxy / TLS sanity checks for Microsoft Edge.

For each target host:
  * Resolve DNS (Resolve-DnsName on Windows, socket.getaddrinfo elsewhere)
  * TCP connect to :443 with 3s timeout
  * TLS handshake via system trust; extract cert subject/issuer/notAfter

Also reports:
  * System WinHTTP proxy
  * Internet Settings (HKCU) proxy
  * Edge proxy policy (HKLM/HKCU\\Software\\Policies\\Microsoft\\Edge)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, load_context,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "edge_network"
DEFAULT_TARGETS = [
    "edge.microsoft.com",
    "config.edge.skype.com",
    "login.microsoftonline.com",
    "www.microsoft.com",
]


def _ps(cmd: str, timeout: int = 15) -> str:
    if os.name != "nt":
        return ""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return (proc.stdout or "").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _system_proxy() -> dict[str, Any]:
    winhttp = _ps("netsh winhttp show proxy")
    inet = _ps(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'"
        " | Select-Object ProxyEnable, ProxyServer, AutoConfigURL"
        " | ConvertTo-Json -Compress"
    )
    parsed: dict[str, Any] = {"winhttp": winhttp}
    try:
        parsed["internet_settings"] = json.loads(inet) if inet else {}
    except json.JSONDecodeError:
        parsed["internet_settings"] = {}
    return parsed


def _edge_proxy_policy() -> dict[str, Any]:
    ps = (
        "$out=@{};"
        "foreach($root in 'HKLM:\\Software\\Policies\\Microsoft\\Edge',"
        "'HKCU:\\Software\\Policies\\Microsoft\\Edge'){"
        " if(Test-Path $root){"
        "  $v=Get-ItemProperty $root;"
        "  foreach($k in 'ProxyMode','ProxyServer','ProxyPacUrl','ProxySettings'){"
        "   if($v.PSObject.Properties.Name -contains $k){$out[$root + '\\' + $k]=$v.$k}"
        "  }"
        " }"
        "}"
        "$out | ConvertTo-Json -Compress"
    )
    raw = _ps(ps)
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}


def _resolve_dns(host: str) -> dict[str, Any]:
    if os.name == "nt":
        raw = _ps(
            f"Resolve-DnsName -Name '{host}' -Type A -ErrorAction SilentlyContinue"
            " | Select-Object Name, IPAddress, TTL"
            " | ConvertTo-Json -Compress"
        )
        try:
            data = json.loads(raw) if raw else None
            return {"ok": bool(data), "records": data or []}
        except json.JSONDecodeError:
            pass
    try:
        infos = socket.getaddrinfo(host, 443)
        ips = sorted({i[4][0] for i in infos})
        return {"ok": True, "records": [{"Name": host, "IPAddress": ip} for ip in ips]}
    except socket.gaierror as e:
        return {"ok": False, "error": str(e)}


def _tcp_connect(host: str, port: int = 443, timeout: float = 3.0) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"ok": False, "error": str(e)}


def _tls(host: str, timeout: float = 5.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ts:
                cert = ts.getpeercert()
                return {
                    "ok": True,
                    "tls_version": ts.version(),
                    "cipher": ts.cipher()[0] if ts.cipher() else None,
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "not_after": cert.get("notAfter"),
                }
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"cert_verify: {e.reason}",
                "verify_message": str(e)}
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        return {"ok": False, "error": str(e)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge network diagnostics")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    ctx = load_context([args.context] if args.context else [])
    extra = ctx.get("extra") or {}
    targets: list[str] = extra.get("targets") or DEFAULT_TARGETS
    skip_inet: bool = bool(extra.get("skip_internet"))

    sys_proxy = _system_proxy()
    edge_proxy = _edge_proxy_policy()

    per_target: list[dict[str, Any]] = []
    if not skip_inet:
        for host in targets:
            dns = _resolve_dns(host)
            tcp = _tcp_connect(host) if dns["ok"] else {"ok": False, "skipped": "dns_failed"}
            tls = _tls(host) if tcp.get("ok") else {"ok": False, "skipped": "tcp_failed"}
            per_target.append({"host": host, "dns": dns, "tcp": tcp, "tls": tls})

    findings: list[Finding] = []
    root_cause: str | None = None
    confidence = "low"

    if sys_proxy.get("internet_settings", {}).get("ProxyEnable"):
        ps = sys_proxy["internet_settings"].get("ProxyServer")
        findings.append(Finding(
            summary=f"System proxy is enabled: {ps}",
            severity="info",
            evidence=sys_proxy["internet_settings"],
        ))
    if edge_proxy:
        findings.append(Finding(
            summary="Edge proxy policy is set by management.",
            severity="info",
            evidence=edge_proxy,
        ))

    if not skip_inet:
        dns_failures = [t for t in per_target if not t["dns"]["ok"]]
        tls_failures = [t for t in per_target if t["tls"].get("ok") is False
                        and "cert_verify" in (t["tls"].get("error") or "")]
        tcp_failures = [t for t in per_target if t["tcp"].get("ok") is False
                        and t["tcp"].get("skipped") != "dns_failed"]

        if len(dns_failures) == len(per_target):
            root_cause = "All DNS lookups failed — check DNS server / VPN."
            confidence = "high"
            findings.append(Finding(summary=root_cause, severity="critical",
                                    evidence={"failed": [t["host"] for t in dns_failures]}))
        elif tls_failures:
            root_cause = "TLS certificate verification failed for one or more Edge-critical endpoints."
            confidence = "high"
            findings.append(Finding(
                summary=root_cause, severity="critical",
                evidence={"failed": [{"host": t["host"], "error": t["tls"].get("error")}
                                     for t in tls_failures]},
            ))
        elif tcp_failures:
            findings.append(Finding(
                summary=f"TCP/443 failed for {len(tcp_failures)} target(s).",
                severity="warning",
                evidence={"failed": [t["host"] for t in tcp_failures]},
            ))
        else:
            findings.append(Finding(
                summary="DNS, TCP/443, and TLS all OK for the probed targets.",
                severity="info",
                evidence={"targets": [t["host"] for t in per_target]},
            ))
            confidence = "high"

    recommendations: list[str] = []
    if edge_proxy:
        recommendations.append("Edge proxy is policy-managed. To change it, modify the corresponding Group Policy / MDM setting, not edge://settings.")
    if not skip_inet and per_target:
        if any(not t["dns"]["ok"] for t in per_target):
            recommendations.append("Validate DNS: `ipconfig /flushdns`, try `Resolve-DnsName <host>` against `8.8.8.8`.")
        if any(t["tls"].get("error", "").startswith("cert_verify") for t in per_target):
            recommendations.append("A man-in-the-middle proxy may be re-signing TLS. Ensure its root CA is installed in `Trusted Root Certification Authorities`.")
    if not recommendations:
        recommendations.append("Network plumbing looks healthy from this host.")

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings, root_cause=root_cause, confidence=confidence,
        recommendations=recommendations,
        raw={
            "system_proxy": sys_proxy,
            "edge_proxy_policy": edge_proxy,
            "targets": per_target,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
        },
    )
    # Map observed failures to playbook problem_types
    pts: list[str] = []
    if not skip_inet:
        if any(not t["dns"]["ok"] for t in per_target):
            pts.append("dns_issue")
        if any("cert_verify" in (t["tls"].get("error") or "") for t in per_target):
            pts.append("cert_error")
        if any(t["tcp"].get("ok") is False and t["tcp"].get("skipped") != "dns_failed"
               for t in per_target):
            pts.append("page_load_failure")
    if sys_proxy.get("internet_settings", {}).get("ProxyEnable") or edge_proxy:
        pts.append("proxy_issue")
    playbook.merge_into_result(result, pts)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
