"""Tests for _shared.log_filters."""
from __future__ import annotations

import pytest

import log_filters


def _entry(**kwargs):
    base = {
        "method": "GET", "uri": "/api/users", "query": "id=1",
        "client_ip": "10.0.0.5", "status": 200, "time_taken": 100,
        "user_agent": "Mozilla/5.0",
    }
    base.update(kwargs)
    return base


def test_empty_filter_matches_everything():
    spec = log_filters.parse_filter("")
    assert spec.is_empty()
    assert spec.matches(_entry())


def test_method_filter_case_insensitive():
    spec = log_filters.parse_filter("method=get")
    assert spec.matches(_entry(method="GET"))
    assert not spec.matches(_entry(method="POST"))


def test_uri_regex():
    spec = log_filters.parse_filter("uri=^/api/")
    assert spec.matches(_entry(uri="/api/users"))
    assert not spec.matches(_entry(uri="/static/img.png"))


def test_status_single_and_range():
    s1 = log_filters.parse_filter("status=404")
    assert s1.matches(_entry(status=404))
    assert not s1.matches(_entry(status=403))

    s2 = log_filters.parse_filter("status=500-599")
    assert s2.matches(_entry(status=500))
    assert s2.matches(_entry(status=599))
    assert not s2.matches(_entry(status=499))


def test_inverted_range_raises():
    with pytest.raises(ValueError):
        log_filters.parse_filter("status=599-500")


def test_ip_exact_and_cidr():
    s_exact = log_filters.parse_filter("ip=10.0.0.5")
    assert s_exact.matches(_entry(client_ip="10.0.0.5"))
    assert not s_exact.matches(_entry(client_ip="10.0.0.6"))

    s_cidr = log_filters.parse_filter("ip=10.0.0.0/24")
    assert s_cidr.matches(_entry(client_ip="10.0.0.99"))
    assert not s_cidr.matches(_entry(client_ip="10.0.1.5"))


def test_min_time_and_ua_and_q():
    spec = log_filters.parse_filter("min-time=200,ua=bot,q=token")
    assert spec.matches(_entry(time_taken=500, user_agent="Googlebot",
                               query="auth&token=abc"))
    assert not spec.matches(_entry(time_taken=100, user_agent="Googlebot",
                                   query="auth&token=abc"))
    assert not spec.matches(_entry(time_taken=500, user_agent="Mozilla",
                                   query="auth&token=abc"))
    assert not spec.matches(_entry(time_taken=500, user_agent="Googlebot",
                                   query="auth=1"))


def test_unknown_key_raises():
    with pytest.raises(ValueError):
        log_filters.parse_filter("foo=bar")


def test_missing_equals_raises():
    with pytest.raises(ValueError):
        log_filters.parse_filter("methodGET")


def test_parse_duration_seconds():
    assert log_filters.parse_duration_seconds("30") == 30
    assert log_filters.parse_duration_seconds("45s") == 45
    assert log_filters.parse_duration_seconds("5m") == 300
    assert log_filters.parse_duration_seconds("2h") == 7200
    assert log_filters.parse_duration_seconds("1d") == 86400
    with pytest.raises(ValueError):
        log_filters.parse_duration_seconds("oops")
