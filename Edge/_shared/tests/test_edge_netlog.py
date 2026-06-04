"""Edge netlog skill smoke tests using a synthetic net-export JSON."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


# Minimum shape that satisfies the netlog reader. We only need a handful of
# events of the right types; the reader keys off constants.logSourceType.
SYNTH_NETLOG = {
    "constants": {
        "logSourceType": {
            "URL_REQUEST": 1, "SOCKET": 2, "HOST_RESOLVER_IMPL_JOB": 3,
        },
        "logEventTypes": {
            "URL_REQUEST_START_JOB": 100,
            "URL_REQUEST_REDIRECT_JOB": 101,
            "REQUEST_ALIVE": 102,
            "SSL_CERTIFICATES_RECEIVED": 200,
            "SSL_HANDSHAKE_ERROR": 201,
            "HOST_RESOLVER_IMPL_JOB": 300,
            "PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST": 400,
        },
        "logEventPhase": {"PHASE_BEGIN": 1, "PHASE_END": 2, "PHASE_NONE": 0},
    },
    "events": [
        # A request that fails with a cert error
        {"time": "100", "phase": 1, "source": {"id": 1, "type": 1},
         "type": 100, "params": {"url": "https://bad.example/"}},
        {"time": "110", "phase": 0, "source": {"id": 1, "type": 1},
         "type": 201, "params": {"net_error": -202,
                                  "error_description": "CERT_AUTHORITY_INVALID"}},
        # A DNS failure
        {"time": "200", "phase": 1, "source": {"id": 2, "type": 3},
         "type": 300, "params": {"host": "nope.invalid"}},
        {"time": "210", "phase": 2, "source": {"id": 2, "type": 3},
         "type": 300, "params": {"net_error": -105}},  # ERR_NAME_NOT_RESOLVED
        # A slow request
        {"time": "300", "phase": 1, "source": {"id": 3, "type": 1},
         "type": 100, "params": {"url": "https://slow.example/"}},
        {"time": "15000", "phase": 2, "source": {"id": 3, "type": 1},
         "type": 102, "params": {}},
    ],
}


@pytest.fixture()
def synth_netlog_path(tmp_path: Path) -> Path:
    p = tmp_path / "synth-netlog.json"
    p.write_text(json.dumps(SYNTH_NETLOG), encoding="utf-8")
    return p


def _run(project_root: Path, ctx: dict) -> dict:
    script = project_root / "edge_netlog" / "scripts" / "edge_netlog.py"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, str(script), json.dumps(ctx)],
        capture_output=True, encoding="utf-8", env=env, timeout=60,
    )
    assert proc.returncode == 0, f"edge_netlog crashed: {proc.stderr}"
    return json.loads(proc.stdout)


def test_edge_netlog_no_input(project_root: Path):
    """Without any netlog files the skill returns a low-confidence info envelope
    plus an additional_logs_needed entry."""
    result = _run(project_root, {})
    assert result["ok"] is True
    assert result["confidence"] == "low"
    assert result["additional_logs_needed"], "should ask for the missing log"
    assert result["additional_logs_needed"][0]["log_kind"] == "netlog"


def test_edge_netlog_with_synthetic(project_root: Path, synth_netlog_path: Path):
    result = _run(project_root, {"extra": {"netlog_paths": [str(synth_netlog_path)]}})
    assert result["ok"] is True
    raw = result.get("raw") or {}
    assert raw.get("observed_problem_types"), "should classify at least one problem"
    # Findings should include something about the data we put in.
    summaries = " ".join(f.get("summary", "") for f in result.get("findings", []))
    # At least one of cert / dns / slow should be flagged.
    assert any(tok in summaries.lower()
               for tok in ("cert", "dns", "slow", "proxy", "failure"))
