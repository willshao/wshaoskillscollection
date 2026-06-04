"""End-to-end smoke for Edge orchestrator: aggregation + cross_source_context."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Note: Edge orchestrator spawns child skills which probe the live system.
# These tests must not depend on Edge actually being installed; we use
# skills that work in degraded mode (edge_qa, edge_policy).


def _run_orch(project_root: Path, ctx: dict) -> dict:
    orch = project_root / "orchestrator" / "scripts" / "edge_orchestrator.py"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, str(orch), json.dumps(ctx)],
        capture_output=True, encoding="utf-8", env=env, timeout=180,
    )
    assert proc.returncode == 0, f"orchestrator crashed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_orchestrator_aggregates_advisories(project_root: Path):
    ctx = {
        "skills_to_trigger": ["edge_policy"],
        "problems": [{"type": "managed_browser", "severity": "info",
                       "summary": "Edge is managed by policy"}],
    }
    result = _run_orch(project_root, ctx)
    assert result["ok"] is True
    raw = result["raw"]
    assert "cross_source_context" in raw
    assert "operator_summary" in raw
    assert isinstance(raw["operator_summary"], str)
    assert raw["operator_summary"].startswith("# Edge orchestrator summary")

    # Aggregated advisories must be populated (or at minimum present as lists)
    assert isinstance(result["solutions"], list)
    assert isinstance(result["next_steps"], list)
    assert isinstance(result["additional_logs_needed"], list)


def test_orchestrator_no_follow_ups_returns_noop(project_root: Path):
    ctx = {"skills_to_trigger": [], "problems": []}
    result = _run_orch(project_root, ctx)
    assert result["ok"] is True
    assert any("Nothing to orchestrate" in f.get("summary", "")
                for f in result.get("findings", []))


def test_cross_source_context_tracks_sources(project_root: Path):
    ctx = {
        "skills_to_trigger": ["edge_policy"],
        "problems": [{"type": "managed_browser", "severity": "info"}],
    }
    result = _run_orch(project_root, ctx)
    cs = result["raw"]["cross_source_context"]
    assert "sources_used" in cs
    assert "skills_run" in cs
    assert "edge_policy" in cs["skills_run"]
    # edge_policy uses the registry source
    assert "registry" in cs["sources_used"]


def test_aggregated_advisories_have_no_duplicate_keys(project_root: Path):
    ctx = {
        "skills_to_trigger": ["edge_policy", "edge_extensions"],
        "problems": [
            {"type": "managed_browser", "severity": "info"},
            {"type": "extension_issue", "severity": "warning"},
        ],
    }
    result = _run_orch(project_root, ctx)
    sols = result["solutions"]
    keys = [(s.get("problem_ref"), s.get("title")) for s in sols]
    assert len(keys) == len(set(keys)), f"duplicate solutions: {keys}"
    nxts = result["next_steps"]
    nkeys = [(n.get("action"), n.get("skill")) for n in nxts]
    assert len(nkeys) == len(set(nkeys)), f"duplicate next_steps: {nkeys}"
