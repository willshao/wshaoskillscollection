"""Tests for edge_policy's MS Learn MCP suggestion block."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


EDGE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = EDGE_ROOT / "edge_policy" / "scripts" / "edge_policy.py"


def _run(ctx: dict | None = None) -> dict:
    args = [sys.executable, str(SCRIPT)]
    if ctx is not None:
        args.append(json.dumps(ctx))
    proc = subprocess.run(
        args, capture_output=True, text=True, cwd=str(EDGE_ROOT), check=True,
    )
    return json.loads(proc.stdout)


def test_mslearn_lookup_present_by_default():
    """edge_policy always emits an mslearn_lookup block (with the master
    reference fetch) regardless of whether policies are found."""
    out = _run({})
    assert out["ok"] is True
    raw = out["raw"]
    assert "mslearn_lookup" in raw
    ml = raw["mslearn_lookup"]
    assert ml["enabled"] is True
    assert isinstance(ml["suggested_calls"], list)
    assert len(ml["suggested_calls"]) >= 1
    # The very first call must always be the master policy reference fetch.
    first = ml["suggested_calls"][0]
    assert first["tool"] == "microsoft_docs_fetch"
    assert "microsoft-edge-policies" in first["query"]


def test_mslearn_recommendation_and_next_step():
    """[mcp:...] tag in recommendations and microsoft_docs_mcp NextStep."""
    out = _run({})
    assert any("[mcp:microsoft_docs_search]" in r for r in out["recommendations"])
    assert any(
        ns.get("skill") == "microsoft_docs_mcp"
        for ns in out["next_steps"]
    )


def test_mslearn_can_be_disabled():
    """extra.use_mslearn=false keeps the skill fully offline."""
    out = _run({"extra": {"use_mslearn": False}})
    assert out["ok"] is True
    assert "mslearn_lookup" not in out["raw"]
    assert all(
        ns.get("skill") != "microsoft_docs_mcp"
        for ns in out["next_steps"]
    )


def test_mslearn_no_numeric_value_names():
    """List-style policies store entries as numeric value-names ('1', '2'…).
    The MCP suggestions must use the parent subkey leaf (the real policy
    name), never the numeric value names themselves."""
    out = _run({})
    ml = out["raw"].get("mslearn_lookup", {})
    queries = [c["query"] for c in ml.get("suggested_calls", [])
               if c["tool"] == "microsoft_docs_search"]
    # No query should end with a pure digit policy name (e.g. "... policy 1").
    for q in queries:
        # Last token should not be a bare number
        last = q.split()[-1] if q.split() else ""
        assert not last.isdigit(), f"Numeric policy name leaked into MCP query: {q!r}"


def test_mslearn_suggestions_are_capped():
    """The per-policy suggestion list is bounded so machines with hundreds
    of values do not produce hundreds of MCP calls."""
    out = _run({})
    ml = out["raw"].get("mslearn_lookup", {})
    suggested = ml.get("suggested_calls", [])
    # 1 fetch + at most 8 per-policy searches + at most 3 category searches = 12
    assert len(suggested) <= 12
