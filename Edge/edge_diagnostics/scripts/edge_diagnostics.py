#!/usr/bin/env python3
"""
edge_diagnostics.py — Edge troubleshooting entry point.

Detects:
  * Whether Edge is installed (Stable / Beta / Dev / Canary)
  * Version (from the binary's VS_VERSION_INFO via PowerShell)
  * User Data directory and available profiles
  * Whether msedge.exe is currently running (and how many child processes)
  * Whether the install is managed (HKLM/HKCU\Software\Policies\Microsoft\Edge)
  * Recent Crashpad reports (count in the last 24h)

Then classifies problem types (from user-supplied symptoms + observed state)
and recommends which follow-up skills to invoke.

Stdlib only; runs from any cwd. Windows-first, degrades on other OSes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, SkillResult, fail, load_context, registry,
)
from _shared import playbook  # noqa: E402
from _shared.sources import user_data as ud_src, processes as proc_src, edge_registry, crashpad as crashpad_src  # noqa: E402

SKILL_ID = "edge_diagnostics"

EDGE_EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge Beta\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge Dev\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge SxS\Application\msedge.exe",
]

CHANNEL_FROM_PATH = {
    "Edge\\Application":      "Stable",
    "Edge Beta\\Application": "Beta",
    "Edge Dev\\Application":  "Dev",
    "Edge SxS\\Application":  "Canary",
}

SYMPTOM_KEYWORDS: list[tuple[str, list[str]]] = [
    ("crash",               ["crash", "crashes", "crashed", "aw snap", "aw, snap", "process gone"]),
    ("render_process_gone", ["render process gone", "renderer crashed", "tab crashed"]),
    ("hang",                ["hang", "freeze", "frozen", "not responding", "unresponsive"]),
    ("slow_startup",        ["slow startup", "takes forever to open", "cold start", "slow to launch"]),
    ("high_cpu",            ["high cpu", "100% cpu", "cpu spike", "cpu usage"]),
    ("high_memory",         ["high memory", "memory leak", "using all my ram", "huge ram"]),
    ("page_slow",           ["page slow", "pages load slowly", "slow website"]),
    ("page_load_failure",   ["err_connection", "this site can", "can't reach", "page won't load"]),
    ("cert_error",          ["cert", "certificate", "err_cert", "not secure", "your connection is not private"]),
    ("proxy_issue",         ["proxy", "pac file", "err_proxy", "err_tunnel"]),
    ("dns_issue",           ["dns", "err_name_not_resolved", "name not resolved"]),
    ("sync_error",          ["sync error", "sync paused", "signed out", "sync isn't working"]),
    ("update_blocked",      ["update blocked", "cannot update", "won't update", "update is managed"]),
    ("extension_issue",     ["extension", "add-on", "addon"]),
    ("extension_blocked",   ["extension blocked", "this extension is managed"]),
    ("managed_browser",     ["managed by your organization", "managed browser", "policies set"]),
    ("feature_blocked",     ["feature blocked", "this feature is managed"]),
    ("question",            ["how do i", "how to", "what is", "where is", "can i", "?"]),
]


# ---------------------------------------------------------------------------
# Environment probing
# ---------------------------------------------------------------------------

def _find_edge_exe() -> tuple[Path | None, str | None]:
    for cand in EDGE_EXE_CANDIDATES:
        p = Path(cand)
        if p.exists():
            for marker, channel in CHANNEL_FROM_PATH.items():
                if marker in cand:
                    return p, channel
            return p, "Stable"
    return None, None


def _edge_version(exe: Path) -> str | None:
    if os.name != "nt":
        return None
    ps = (
        f"(Get-Item -LiteralPath '{exe}').VersionInfo.ProductVersion"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        )
        v = proc.stdout.strip()
        return v or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _user_data_dir() -> Path | None:
    return ud_src.default_user_data_dir()


def _profiles(user_data_dir: Path | None) -> list[str]:
    return ud_src.list_profiles(user_data_dir) if user_data_dir else []


def _running_processes() -> int:
    return proc_src.count_msedge()


def _is_managed() -> bool:
    if os.name != "nt":
        return False
    # A single value or subkey under any Edge policy root means "managed".
    for entry in edge_registry._walk("HKLM", r"Software\Policies\Microsoft\Edge"):
        return True
    for entry in edge_registry._walk("HKCU", r"Software\Policies\Microsoft\Edge"):
        return True
    return False


def _recent_crash_count(user_data_dir: Path | None, hours: int = 24) -> int:
    if not user_data_dir:
        return 0
    crashpad = user_data_dir / "Crashpad" / "reports"
    if not crashpad.exists():
        return 0
    cutoff = datetime.now() - timedelta(hours=hours)
    n = 0
    for entry in crashpad_src.iter_entries(crashpad):
        try:
            if datetime.fromtimestamp(entry["mtime_epoch"]) >= cutoff:
                n += 1
        except (OSError, KeyError, TypeError):
            continue
    return n


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_problems(symptoms: str, env: dict[str, Any]) -> list[dict[str, Any]]:
    text = (symptoms or "").lower()
    problems: dict[str, dict[str, Any]] = {}

    for ptype, kws in SYMPTOM_KEYWORDS:
        if any(k in text for k in kws):
            problems[ptype] = {
                "type": ptype,
                "severity": registry()["problem_types"].get(ptype, {}).get("severity_default", "info"),
                "evidence": {"matched": [k for k in kws if k in text][:3]},
            }

    if env.get("recent_crash_count", 0) > 0 and "crash" not in problems:
        problems["crash"] = {
            "type": "crash",
            "severity": "critical",
            "evidence": {"recent_crash_count": env["recent_crash_count"]},
        }

    if env.get("is_managed") and "managed_browser" not in problems:
        problems["managed_browser"] = {
            "type": "managed_browser",
            "severity": "info",
            "evidence": {"hint": "Group Policy or MDM is configuring Edge"},
        }

    if env.get("running_processes", 0) >= 25:
        problems.setdefault("high_memory", {
            "type": "high_memory",
            "severity": "warning",
            "evidence": {"running_processes": env["running_processes"]},
        })

    return list(problems.values())


def skills_to_trigger(problems: list[dict[str, Any]]) -> list[str]:
    reg = registry()
    out: list[str] = []
    for p in problems:
        for sk in reg["problem_types"].get(p["type"], {}).get("follow_ups", []):
            if sk not in out:
                out.append(sk)
    return out


# ---------------------------------------------------------------------------
# Auto-trigger
# ---------------------------------------------------------------------------

def _auto_trigger(payload: dict[str, Any]) -> dict[str, Any]:
    """Pipe our payload to the orchestrator and return its parsed result."""
    try:
        from _shared.contract import skill_entry  # type: ignore
        entry = skill_entry("orchestrator", "python")
    except KeyError as e:
        return {"ok": False, "error": str(e)}
    proc = subprocess.run(
        [sys.executable, str(entry), json.dumps(payload)],
        capture_output=True, text=True, timeout=240,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip() or f"exit {proc.returncode}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"non-JSON output: {e}", "raw_stdout": proc.stdout[:500]}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Microsoft Edge diagnostics entry point")
    ap.add_argument("context", nargs="?", default=None,
                    help="JSON context (string, @file) or omit")
    ap.add_argument("--auto-trigger", action="store_true",
                    help="Pipe my output to the orchestrator and return its result")
    args = ap.parse_args(argv)

    ctx = load_context([args.context] if args.context else [])
    symptoms = (ctx.get("extra") or {}).get("symptoms", "")
    extra_in = ctx.get("extra") or {}

    exe, channel = _find_edge_exe()
    user_data = _user_data_dir()
    env = {
        "os": os.name,
        "installed": exe is not None,
        "channel": channel,
        "exe": str(exe) if exe else None,
        "version": _edge_version(exe) if exe else None,
        "user_data_dir": str(user_data) if user_data else None,
        "profiles": _profiles(user_data),
        "running_processes": _running_processes(),
        "is_running": _running_processes() > 0,
        "is_managed": _is_managed(),
        "recent_crash_count": _recent_crash_count(user_data),
    }

    problems = classify_problems(symptoms, env)
    triggers = skills_to_trigger(problems)

    # Net-export: if the caller provided netlog files (extra.netlog_paths or
    # extra.folder containing *.json), make edge_netlog a follow-up so the
    # orchestrator picks it up unconditionally — even when no network-shaped
    # problem was classified yet.
    netlog_paths_in = list(extra_in.get("netlog_paths") or [])
    if netlog_paths_in and "edge_netlog" not in triggers:
        triggers.append("edge_netlog")

    findings: list[Finding] = []
    if not env["installed"]:
        findings.append(Finding(
            summary="Microsoft Edge does not appear to be installed in the standard locations.",
            severity="warning",
            evidence={"searched": EDGE_EXE_CANDIDATES},
        ))
    else:
        findings.append(Finding(
            summary=f"Edge {env['channel']} {env['version']} installed at {env['exe']}",
            severity="info",
            evidence={"profiles": env["profiles"], "is_managed": env["is_managed"]},
        ))
    for p in problems:
        findings.append(Finding(
            summary=f"Classified problem: {p['type']}",
            severity=p["severity"],
            evidence=p["evidence"],
        ))
    if not problems:
        findings.append(Finding(
            summary="No specific problem classified. Provide more symptoms or ask via edge_qa.",
            severity="info",
        ))

    payload = {
        "environment": env,
        "problems": problems,
        "skills_to_trigger": triggers,
        "time_range": ctx.get("time_range") or {},
        "extra": {**extra_in},
    }

    if args.auto_trigger and triggers:
        payload["orchestrator_result"] = _auto_trigger(payload)

    result = SkillResult(
        skill=SKILL_ID,
        ok=True,
        findings=findings,
        root_cause=None,
        confidence="medium" if problems else "low",
        recommendations=(
            [f"Run follow-up skills: {', '.join(triggers)}"] if triggers else
            ["Ask the user for more details, or invoke edge_qa for a knowledge-base lookup."]
        ),
        raw=payload,
    )
    # Merge playbook from every classified problem_type so the report carries
    # actionable Solutions / Next steps / Additional logs needed.
    problem_types_seen = sorted({p["type"] for p in problems if p.get("type")})
    playbook.merge_into_result(result, problem_types_seen)
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
