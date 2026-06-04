"""Tests for edge_qa's MS Learn MCP suggestion block."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


EDGE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = EDGE_ROOT / "edge_qa" / "scripts" / "edge_qa.py"


def _run(ctx: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), json.dumps(ctx)],
        capture_output=True, text=True, cwd=str(EDGE_ROOT), check=True,
    )
    return json.loads(proc.stdout)


def test_mslearn_lookup_present_by_default_with_kb_match():
    """When the KB matches, the skill still publishes MCP suggestions."""
    out = _run({"question": "how do I enable IE mode?"})
    assert out["ok"] is True
    raw = out["raw"]
    assert "mslearn_lookup" in raw
    ml = raw["mslearn_lookup"]
    assert ml["enabled"] is True
    assert isinstance(ml["suggested_calls"], list)
    assert len(ml["suggested_calls"]) >= 1
    tools = {c["tool"] for c in ml["suggested_calls"]}
    assert "microsoft_docs_search" in tools
    # The agent contract is reflected in next_steps as a microsoft_docs_mcp call
    assert any(
        ns.get("skill") == "microsoft_docs_mcp"
        for ns in out["next_steps"]
    )
    # And surfaced in recommendations with an [mcp:...] tag
    assert any("[mcp:microsoft_docs_search]" in r for r in out["recommendations"])


def test_mslearn_lookup_present_when_no_kb_match():
    """When no KB entry scores, the MCP block becomes the primary answer."""
    out = _run({"question": "asdf qwerty zxcv obscure nonsense"})
    assert out["ok"] is True
    assert out["raw"]["matches"] == []
    assert out["confidence"] == "low"
    ml = out["raw"]["mslearn_lookup"]
    assert ml["enabled"] is True
    # At least the user-question search
    assert any(
        c["tool"] == "microsoft_docs_search" and "qwerty" in c["query"]
        for c in ml["suggested_calls"]
    )


def test_mslearn_can_be_disabled():
    """extra.use_mslearn=false keeps the skill fully offline."""
    out = _run({
        "question": "how do I enable IE mode?",
        "extra": {"use_mslearn": False},
    })
    assert out["ok"] is True
    assert "mslearn_lookup" not in out["raw"]
    # And no microsoft_docs_mcp NextStep was added
    assert all(
        ns.get("skill") != "microsoft_docs_mcp"
        for ns in out["next_steps"]
    )
