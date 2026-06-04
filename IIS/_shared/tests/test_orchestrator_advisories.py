"""Folder-mode orchestrator end-to-end: aggregated advisories + cross-log context."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run_orchestrator(project_root: Path, target: Path, *, report: Path | None = None,
                      ) -> dict:
    orch = project_root / "orchestrator" / "scripts" / "skill_orchestrator.py"
    cmd = [sys.executable, str(orch), str(target)]
    if report:
        cmd += ["--report", str(report)]
    env = {"PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(cmd, capture_output=True, encoding="utf-8",
                          env={**__import__("os").environ, **env})
    assert proc.returncode in (0, 1), f"orchestrator crashed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_folder_mode_aggregates_advisories(project_root: Path, fixtures_dir: Path):
    result = _run_orchestrator(project_root, fixtures_dir)
    assert result["ok"] is True
    # IIS + FTP + HTTPERR + EVTX fixtures present → all four entry skills run
    raw = result["raw"]
    assert raw["mode"] == "folder"
    assert set(raw["executed"]) >= {"iis_logs", "ftp_logs", "httperror", "event_log"}

    # Aggregated structured advisories must be populated
    assert isinstance(result["solutions"], list) and len(result["solutions"]) > 0
    assert isinstance(result["next_steps"], list) and len(result["next_steps"]) > 0
    assert isinstance(result["additional_logs_needed"], list)


def test_folder_mode_cross_log_context_is_populated(project_root: Path, fixtures_dir: Path):
    result = _run_orchestrator(project_root, fixtures_dir)
    ctx = result["raw"].get("cross_log_context")
    assert isinstance(ctx, dict)
    assert "available" in ctx and isinstance(ctx["available"], list)
    # Fixtures cover IIS + EVTX → correlatable=True
    assert ctx["correlatable"] is True
    assert ctx["note"] and "Event Log" in ctx["note"]


def test_aggregated_solutions_have_no_duplicate_keys(project_root: Path,
                                                     fixtures_dir: Path):
    result = _run_orchestrator(project_root, fixtures_dir)
    sols = result["solutions"]
    keys = [(s.get("problem_ref"), s.get("title")) for s in sols]
    assert len(keys) == len(set(keys)), f"duplicate solution keys: {keys}"

    nxts = result["next_steps"]
    nkeys = [(n.get("action"), n.get("skill")) for n in nxts]
    assert len(nkeys) == len(set(nkeys)), f"duplicate next_step keys: {nkeys}"


def test_html_report_contains_advisory_sections(project_root: Path,
                                                fixtures_dir: Path, tmp_path: Path):
    report = tmp_path / "orch.html"
    _run_orchestrator(project_root, fixtures_dir, report=report)
    assert report.exists()
    html = report.read_text(encoding="utf-8")
    for heading in ("<h2>Solutions</h2>",
                    "<h2>Next steps</h2>",
                    "<h2>Additional logs needed</h2>",
                    "<h2>Cross-log context</h2>"):
        assert heading in html, f"missing {heading}"
