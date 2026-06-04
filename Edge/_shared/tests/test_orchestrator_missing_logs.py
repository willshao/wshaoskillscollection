"""Edge orchestrator missing-log gate."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Reuse the synthetic netlog from test_edge_netlog.
from test_edge_netlog import SYNTH_NETLOG  # noqa: E402


def _run_orch(project_root: Path, ctx: dict) -> dict:
    orch = project_root / "orchestrator" / "scripts" / "edge_orchestrator.py"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, str(orch), json.dumps(ctx)],
        capture_output=True, encoding="utf-8", env=env, timeout=180,
    )
    assert proc.returncode == 0, f"orchestrator crashed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_missing_netlog_reported(project_root: Path):
    """A page_load_failure investigation that ships no netlog must surface
    netlog in raw.missing_logs and emit a warning finding."""
    ctx = {
        "skills_to_trigger": ["edge_policy"],
        "problems": [{"type": "page_load_failure", "severity": "warning",
                       "summary": "page failed to load"}],
    }
    result = _run_orch(project_root, ctx)
    raw = result["raw"]
    missing = raw.get("missing_logs") or []
    assert missing, "missing_logs should not be empty"
    kinds = [m.get("log_kind") for m in missing]
    assert "netlog" in kinds, f"expected netlog in missing kinds, got {kinds}"
    # And a warning Finding should call it out.
    summaries = [f["summary"] for f in result["findings"]]
    assert any("Required log" in s and "netlog" in s for s in summaries)


def test_missing_netlog_cleared_when_provided(project_root: Path, tmp_path: Path):
    """When the caller passes extra.netlog_paths the gap closes."""
    nl = tmp_path / "synth-netlog.json"
    nl.write_text(json.dumps(SYNTH_NETLOG), encoding="utf-8")
    ctx = {
        "skills_to_trigger": ["edge_policy"],
        "problems": [{"type": "page_load_failure", "severity": "warning",
                       "summary": "page failed to load"}],
        "extra": {"netlog_paths": [str(nl)]},
    }
    result = _run_orch(project_root, ctx)
    raw = result["raw"]
    missing = raw.get("missing_logs") or []
    kinds = [m.get("log_kind") for m in missing]
    assert "netlog" not in kinds, (
        f"netlog should not be missing after extra.netlog_paths; kinds={kinds}"
    )
