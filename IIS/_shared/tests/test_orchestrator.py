"""End-to-end test: pipe iis_analyzer output into the orchestrator via stdin."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_pipeline_iis_then_orchestrator(project_root: Path, sample_iis_log: Path):
    iis = project_root / "IIS_logs" / "scripts" / "iis_analyzer.py"
    orch = project_root / "orchestrator" / "scripts" / "skill_orchestrator.py"

    p1 = subprocess.run(
        [sys.executable, str(iis), str(sample_iis_log)],
        capture_output=True, text=True, check=True,
    )
    iis_result = json.loads(p1.stdout)
    assert iis_result["ok"] is True
    assert iis_result["skill"] == "iis_logs"
    triggered = iis_result["raw"]["skills_to_trigger"]
    assert triggered, "expected at least one follow-up skill"

    ctx = json.dumps(iis_result["raw"])
    p2 = subprocess.run(
        [sys.executable, str(orch)],
        input=ctx, capture_output=True, text=True,
    )
    assert p2.returncode in (0, 1), f"orchestrator crashed: {p2.stderr}"
    orch_result = json.loads(p2.stdout)
    assert orch_result["skill"] == "orchestrator"

    assert set(orch_result["raw"]["executed"]) == set(triggered)
    results = orch_result["raw"]["results"]
    assert set(results.keys()) == set(triggered)
    for skill_id, res in results.items():
        assert res.get("skill") == skill_id, f"{skill_id}: {res}"
