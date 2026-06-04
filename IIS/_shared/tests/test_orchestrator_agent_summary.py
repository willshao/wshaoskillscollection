"""Smoke test for the orchestrator's --agent-summary plumbing."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_agent_summary_md_embeds_in_report(project_root: Path, tmp_path: Path):
    # Fabricate a minimal IIS log so the orchestrator has something to run.
    iis = tmp_path / "u_ex.log"
    iis.write_text(
        "#Software: Microsoft Internet Information Services 10.0\n"
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
        "cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus "
        "sc-win32-status time-taken\n"
        "2026-06-04 00:00:00 1.1.1.1 GET / - 80 - 2.2.2.2 UA - - 200 0 0 5\n",
        encoding="utf-8",
    )
    summary = tmp_path / "diagnosis.md"
    summary.write_text(
        "# Root cause\n\n"
        "**Kerberos SPN mismatch** for `HTTP/foo.example`.\n\n"
        "## Fix\n\n"
        "- Register the SPN with `setspn -S`\n"
        "- Recycle the app pool\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.html"
    script = project_root / "orchestrator" / "scripts" / "skill_orchestrator.py"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, str(script), str(tmp_path),
         "--report", str(report),
         "--agent-summary", str(summary)],
        capture_output=True, encoding="utf-8", env=env, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert report.exists()
    html = report.read_text(encoding="utf-8")
    # Headline section is present.
    assert "Consolidated diagnosis (GitHub Copilot CLI)" in html
    # Markdown was converted (bold, list, inline code, heading offset).
    assert "<strong>Kerberos SPN mismatch</strong>" in html
    assert "<code>HTTP/foo.example</code>" in html
    assert "<li>Register the SPN with <code>setspn -S</code></li>" in html
    # Top-level `#` headings are offset to <h2> so they don't conflict with <h1>.
    assert "<h2>Root cause</h2>" in html
