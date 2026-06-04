"""Regression tests for _shared/logs/httperr.py header-driven parser.

The previous inline parser swapped `reason` and `queuename` for IIS 10
HTTPERR logs that include `s-queuename`. The shared reader uses the
`#Fields:` header so column order no longer matters.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from _shared.logs import httperr as httperr_reader


def _write(tmp: Path, body: str) -> Path:
    p = tmp / "httperr.log"
    p.write_text(body, encoding="utf-8")
    return p


def test_header_driven_parse_extracts_reason_and_pool(tmp_path: Path):
    body = (
        "#Software: Microsoft HTTP API 2.0\n"
        "#Version: 1.0\n"
        "#Date: 2026-05-26 10:00:00\n"
        "#Fields: date time c-ip c-port s-ip s-port cs-version cs-method "
        "cs-uri sc-status s-siteid s-reason s-queuename\n"
        "2026-05-26 10:00:01 10.0.0.5 51000 10.0.0.50 80 HTTP/1.1 GET / 503 1 "
        "Timer_ConnectionIdle Pool-A\n"
        "2026-05-26 10:00:02 10.0.0.5 51001 10.0.0.50 80 HTTP/1.1 GET / 503 1 "
        "ConnLimit Pool-B\n"
    )
    log = _write(tmp_path, body)
    res = httperr_reader.query([log])
    assert res["summary"]["count"] == 2
    reasons = dict(res["summary"]["top_reasons"])
    assert reasons.get("Timer_ConnectionIdle") == 1
    assert reasons.get("ConnLimit") == 1
    # No "Pool-A" leaking into reasons (the old bug)
    assert "Pool-A" not in reasons
    pools = dict(res["summary"]["top_app_pools"])
    assert pools.get("Pool-A") == 1
    assert pools.get("Pool-B") == 1


def test_parse_line_returns_dict_or_none(tmp_path: Path):
    body = (
        "#Fields: date time c-ip c-port s-ip s-port cs-version cs-method "
        "cs-uri sc-status s-siteid s-reason s-queuename\n"
        "2026-05-26 10:00:01 10.0.0.5 51000 10.0.0.50 80 HTTP/1.1 GET / 503 1 ConnLimit -\n"
    )
    log = _write(tmp_path, body)
    res = httperr_reader.query([log])
    e = res["entries"][0]
    assert e["reason"] == "ConnLimit"
    assert e["app_pool"] == "-"
    assert e["status"] == "503"
    assert e["client_ip"] == "10.0.0.5"


def test_apply_filter_by_reason(tmp_path: Path):
    body = (
        "#Fields: date time c-ip c-port s-ip s-port cs-version cs-method "
        "cs-uri sc-status s-siteid s-reason s-queuename\n"
        "2026-05-26 10:00:01 10.0.0.5 51000 10.0.0.50 80 HTTP/1.1 GET / 503 1 ConnLimit -\n"
        "2026-05-26 10:00:02 10.0.0.6 51001 10.0.0.50 80 HTTP/1.1 GET / 503 1 Timer_HeaderWait -\n"
    )
    log = _write(tmp_path, body)
    res = httperr_reader.query(
        [log],
        filter=httperr_reader.HttpErrFilter(reason="ConnLimit"),
    )
    assert res["summary"]["count"] == 1
    assert res["entries"][0]["reason"] == "ConnLimit"


def test_uniform_api_surface_present():
    for name in ("discover", "iter_entries", "summarise",
                 "apply_filter", "around_window", "query"):
        assert hasattr(httperr_reader, name), f"missing {name}"
