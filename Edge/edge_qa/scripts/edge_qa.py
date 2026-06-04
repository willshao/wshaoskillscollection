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
    Finding, SkillResult, fail, load_context,
)
from _shared import playbook  # noqa: E402

SKILL_ID = "edge_qa"
KB_PATH = Path(__file__).resolve().parent.parent / "kb" / "kb.json"

WORD_RE = re.compile(r"[a-z0-9_+-]+")


def _tokens(text: str) -> set[str]:
    return set(WORD_RE.findall(text.lower()))


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
    top_k = int((ctx.get("extra") or {}).get("top_k", 3))
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
            summary="No KB entry matched. Falling back to general guidance.",
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

    result = SkillResult(
        skill=SKILL_ID, ok=True,
        findings=findings,
        confidence=confidence,
        recommendations=recommendations,
        raw={
            "question": question,
            "kb_path": str(KB_PATH),
            "kb_size": len(kb),
            "matches": matches,
        },
    )
    playbook.merge_into_result(result, ["question"])
    result.emit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
