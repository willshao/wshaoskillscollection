"""IIS orchestrator missing-log gate (folder mode)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _run_orch(project_root: Path, folder: Path) -> dict:
    orch = project_root / "orchestrator" / "scripts" / "skill_orchestrator.py"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, str(orch), str(folder)],
        capture_output=True, encoding="utf-8", env=env, timeout=180,
    )
    assert proc.returncode == 0, f"orchestrator crashed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_iis_folder_with_only_iis_log_flags_missing_logs(
    project_root: Path, tmp_path: Path, sample_iis_log: Path,
):
    """A folder containing only an IIS W3C log triggers iis_logs detection of
    5xx_error / high_latency, which both require additional logs not present.
    We expect those to show up in raw.missing_logs as warning findings."""
    folder = tmp_path / "incident"
    folder.mkdir()
    shutil.copy(sample_iis_log, folder / "u_ex.log")

    result = _run_orch(project_root, folder)
    raw = result["raw"]
    missing = raw.get("missing_logs") or []
    assert missing, "missing_logs should not be empty"
    kinds = {m["log_kind"] for m in missing}
    # iis_logs's playbook always asks for http_err and evtx for these problems.
    assert "evtx" in kinds or "http_err" in kinds, f"got {kinds}"
    # A warning Finding should mirror at least one missing kind.
    summaries = [f["summary"] for f in result["findings"]]
    assert any("Required log" in s for s in summaries)


def test_iis_folder_with_netlog_runs_skill(
    project_root: Path, tmp_path: Path,
):
    """When a net-export JSON is dropped into the folder the orchestrator
    runs the netlog skill and lists it as executed."""
    folder = tmp_path / "incident2"
    folder.mkdir()
    synth = {
        "constants": {
            "logSourceType": {"URL_REQUEST": 1, "SOCKET": 2,
                               "HOST_RESOLVER_IMPL_JOB": 3},
            "logEventTypes": {"URL_REQUEST_START_JOB": 100},
            "logEventPhase": {"PHASE_BEGIN": 1, "PHASE_END": 2, "PHASE_NONE": 0},
        },
        "events": [{"time": "1", "phase": 1, "source": {"id": 1, "type": 1},
                    "type": 100, "params": {"url": "https://x"}}],
    }
    (folder / "netlog.json").write_text(json.dumps(synth), encoding="utf-8")

    result = _run_orch(project_root, folder)
    raw = result["raw"]
    assert "netlog" in (raw.get("executed") or []), \
        f"executed={raw.get('executed')}"
    assert "netlog" in (raw.get("results") or {})
