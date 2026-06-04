#!/usr/bin/env python3
"""
edge_qa.py — answer common Edge questions from a local KB.

Scores each entry in kb/kb.json by counting keyword/alias hits in the
lowercased question, returns the top-K matches.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _shared.contract import (  # noqa: E402
    Finding, NextStep, SkillResult, fail, load_context,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "edge_qa"
KB_PATH = Path(__file__).resolve().parent.parent / "kb" / "kb.json"

WORD_RE = re.compile(r"[a-z0-9_+-]+")

# Hint scope: prefer Edge / deployedge docs over generic Microsoft content.
MSLEARN_SITE_FILTER = "site:learn.microsoft.com (microsoft-edge OR deployedge)"


def _tokens(text: str) -> set[str]:
    return set(WORD_RE.findall(text.lower()))


def _build_mslearn_suggestions(
    question: str, matches: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Build a structured block that tells the agent which MS Learn MCP calls to
    make in order to augment the local KB answer with the latest official docs.

    The Python skill never calls MCP tools directly (they are only available to
    the AI agent through Copilot CLI). It just *describes* the queries to run.
    """
    # The primary search is always the user question, scoped to Edge docs.
    queries: list[dict[str, str]] = [
        {
            "tool": "microsoft_docs_search",
            "query": f"Microsoft Edge {question}".strip(),
            "why": "Find current official documentation that answers the question.",
        }
    ]

    # Add a secondary search per matched KB entry (uses the entry title — usually
    # a sharper query than the raw user question).
    for m in matches[:2]:
        queries.append({
            "tool": "microsoft_docs_search",
            "query": f"Microsoft Edge {m['title']}",
            "why": f"Cross-check KB entry '{m['id']}' against the latest docs.",
        })

    # And recommend a fetch on the highest-ranked doc link if any exist.
    fetch_url: str | None = None
    for m in matches:
        for link in m.get("doc_links", []) or []:
            if "learn.microsoft.com" in link or "support.microsoft.com" in link:
                fetch_url = link
                break
        if fetch_url:
            break
    if fetch_url:
        queries.append({
            "tool": "microsoft_docs_fetch",
            "query": fetch_url,
            "why": "Retrieve the full, current page content for the top KB reference.",
        })

    return {
        "enabled": True,
        "rationale": (
            "edge_qa returns curated KB answers that may lag the latest Edge "
            "features. The agent should call the Microsoft Learn MCP tools "
            "listed below and merge the live results into the final reply, "
            "citing URLs. If the local KB had zero matches, the MCP results "
            "become the primary answer."
        ),
        "site_filter_hint": MSLEARN_SITE_FILTER,
        "suggested_calls": queries,
    }


def _score(question: str, entry: dict[str, Any]) -> int:
    q = question.lower()
    q_tokens = _tokens(q)
    score = 0
    for kw in entry.get("keywords", []):
        kw_l = kw.lower()
        if kw_l in q:
            score += 2 if " " in kw_l else 1
        elif kw_l in q_tokens:
            score += 1
    for al in entry.get("aliases", []):
        if al.lower() in q:
            score += 3
    title = entry.get("title", "").lower()
    for t in _tokens(title):
        if t in q_tokens and len(t) > 3:
            score += 1
    return score


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Edge Q&A knowledge base")
    ap.add_argument("context", nargs="?", default=None)
    args = ap.parse_args(argv)

    ctx = load_context([args.context] if args.context else [])
    question = (ctx.get("question") or "").strip()
    extra = ctx.get("extra") or {}
    top_k = int(extra.get("top_k", 3))
    use_mslearn = bool(extra.get("use_mslearn", True))
    if not question:
        fail(SKILL_ID, "Missing 'question' in context.")
        return 1  # unreachable

    if not KB_PATH.exists():
        fail(SKILL_ID, f"Knowledge base not found at {KB_PATH}")
        return 1

    kb = json.loads(KB_PATH.read_text(encoding="utf-8"))

    scored: list[tuple[int, int, dict[str, Any]]] = []
    for idx, entry in enumerate(kb):
        s = _score(question, entry)
        if s > 0:
            scored.append((s, idx, entry))
    scored.sort(key=lambda t: (-t[0], t[1]))
    top = scored[:top_k]

    findings: list[Finding] = []
    matches: list[dict[str, Any]] = []
    for s, _, e in top:
        matches.append({
            "id": e["id"],
            "title": e["title"],
            "score": s,
            "answer": e["answer"],
            "doc_links": e.get("doc_links", []),
        })
        findings.append(Finding(
            summary=e["title"],
            severity="info",
            evidence={"id": e["id"], "score": s, "doc_links": e.get("doc_links", [])},
        ))

    if not matches:
        findings.append(Finding(
            summary="No KB entry matched. Falling back to MS Learn MCP guidance.",
            severity="info",
        ))
        recommendations = [
            "Try rephrasing the question with more keywords.",
            "Browse the official docs: https://learn.microsoft.com/microsoft-edge/",
            "For consumer support: https://support.microsoft.com/microsoft-edge",
        ]
        confidence = "low"
    else:
        recommendations = [
            "Read the top match's answer block; consult `doc_links` for the authoritative procedure.",
        ]
        confidence = "high" if top[0][0] >= 3 else "medium"

    raw_block: dict[str, Any] = {
        "question": question,
        "kb_path": str(KB_PATH),
        "kb_size": len(kb),
        "matches": matches,
    }

    # MS Learn MCP integration: the Python skill cannot call MCP tools itself
    # (they are only available to the AI agent in Copilot CLI). Instead, it
    # publishes a `mslearn_lookup` block that *describes* the calls the agent
    # should make to augment the local answer with the latest official content.
    if use_mslearn:
        raw_block["mslearn_lookup"] = _build_mslearn_suggestions(question, matches)
        recommendations.append(
            "[mcp:microsoft_docs_search] Agent: run the queries in "
            "`raw.mslearn_lookup.suggested_calls` and merge live MS Learn "
            "results into the final reply, citing URLs."
        )

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        confidence=confidence,
        recommendations=recommendations,
        raw=raw_block,
    )

    # Augment next_steps so the agent sees this as an explicit follow-up action.
    if use_mslearn:
        result.next_steps.append(NextStep(
            action=(
                "Call microsoft_docs_search / microsoft_docs_fetch with the "
                "queries in raw.mslearn_lookup.suggested_calls and synthesise "
                "the live results into the final answer."
            ),
            why="Local KB may lag the latest Edge release / policy / feature.",
            skill="microsoft_docs_mcp",
        ))

    playbook.merge_into_result(result, ["question"])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
