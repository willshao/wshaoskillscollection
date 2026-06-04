"""
_shared/log_filters.py

Parse a compact filter expression into a callable predicate that matches
normalised log entries (IIS or FTP).

Syntax (comma-separated key=value pairs; commas inside values must be avoided):

    method=GET
    uri=^/api/                # regex (re.search)
    status=500                # single
    status=500-599            # inclusive range
    ip=10.0.0.1               # exact
    ip=10.0.0.0/24            # CIDR (IPv4/IPv6)
    min-time=2000             # time-taken >= 2000 ms
    ua=bot                    # regex (re.search), case-insensitive
    q=token                   # substring on the query string
    user=alice                # FTP: cs-username exact
    cmd=STOR                  # FTP: cs-method exact (case-insensitive)
    path=^/uploads/           # FTP: cs-uri-stem regex
    min-bytes=1024            # FTP: sc-bytes + cs-bytes >= 1024

Unknown keys raise ValueError so typos surface loudly.

The predicate consults whichever normalised keys exist on the entry, so an
IIS filter applied to FTP rows is harmless (the FTP-only keys just won't
match anything) and vice versa.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

_VALID_KEYS = {
    "method", "uri", "status", "ip", "min-time", "ua", "q",
    "user", "cmd", "path", "min-bytes",
}


@dataclass
class FilterSpec:
    """Parsed filter; call `matches(entry)` to test a normalised dict."""
    method: str | None = None
    uri_re: re.Pattern[str] | None = None
    status_range: tuple[int, int] | None = None
    ip_exact: str | None = None
    ip_network: ipaddress._BaseNetwork | None = None
    min_time_ms: int | None = None
    ua_re: re.Pattern[str] | None = None
    query_contains: str | None = None
    # FTP-flavoured
    user: str | None = None
    cmd: str | None = None
    path_re: re.Pattern[str] | None = None
    min_bytes: int | None = None
    # Audit trail
    raw_text: str = ""
    parsed: dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not self.parsed

    # ------------------------------------------------------------------
    def matches(self, entry: dict[str, Any]) -> bool:
        if self.method and str(entry.get("method", "")).upper() != self.method.upper():
            return False
        if self.uri_re and not self.uri_re.search(str(entry.get("uri", ""))):
            return False
        if self.status_range:
            try:
                s = int(entry.get("status", 0))
            except (TypeError, ValueError):
                return False
            lo, hi = self.status_range
            if not (lo <= s <= hi):
                return False
        if self.ip_exact and str(entry.get("client_ip", "")) != self.ip_exact:
            return False
        if self.ip_network is not None:
            try:
                addr = ipaddress.ip_address(str(entry.get("client_ip", "")))
            except ValueError:
                return False
            if addr not in self.ip_network:
                return False
        if self.min_time_ms is not None:
            try:
                t = int(entry.get("time_taken", 0))
            except (TypeError, ValueError):
                return False
            if t < self.min_time_ms:
                return False
        if self.ua_re and not self.ua_re.search(str(entry.get("user_agent", ""))):
            return False
        if self.query_contains and self.query_contains not in str(entry.get("query", "")):
            return False
        # FTP fields
        if self.user and str(entry.get("user", entry.get("username", ""))) != self.user:
            return False
        if self.cmd and str(entry.get("method", "")).upper() != self.cmd.upper():
            return False
        if self.path_re and not self.path_re.search(str(entry.get("uri", ""))):
            return False
        if self.min_bytes is not None:
            try:
                up = int(entry.get("bytes_received", entry.get("cs_bytes", 0)) or 0)
                dn = int(entry.get("bytes_sent", entry.get("sc_bytes", 0)) or 0)
            except (TypeError, ValueError):
                return False
            if (up + dn) < self.min_bytes:
                return False
        return True


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _parse_status(value: str) -> tuple[int, int]:
    if "-" in value:
        lo_s, hi_s = value.split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
    else:
        lo = hi = int(value)
    if lo > hi:
        raise ValueError(f"status range inverted: {value}")
    return (lo, hi)


def _parse_ip(value: str) -> tuple[str | None, ipaddress._BaseNetwork | None]:
    if "/" in value:
        return None, ipaddress.ip_network(value, strict=False)
    # Validate but keep exact-string match (faster, avoids zero-pad surprises).
    ipaddress.ip_address(value)
    return value, None


def parse_filter(text: str | None) -> FilterSpec:
    """Parse a key=value,key=value string into a FilterSpec."""
    spec = FilterSpec(raw_text=text or "")
    if not text:
        return spec

    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise ValueError(f"filter token missing '=': {chunk!r}")
        key, value = chunk.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key not in _VALID_KEYS:
            raise ValueError(f"unknown filter key: {key!r} "
                             f"(allowed: {sorted(_VALID_KEYS)})")
        spec.parsed[key] = value

        if key == "method":
            spec.method = value
        elif key == "uri":
            spec.uri_re = re.compile(value)
        elif key == "status":
            spec.status_range = _parse_status(value)
        elif key == "ip":
            spec.ip_exact, spec.ip_network = _parse_ip(value)
        elif key == "min-time":
            spec.min_time_ms = int(value)
        elif key == "ua":
            spec.ua_re = re.compile(value, re.IGNORECASE)
        elif key == "q":
            spec.query_contains = value
        elif key == "user":
            spec.user = value
        elif key == "cmd":
            spec.cmd = value
        elif key == "path":
            spec.path_re = re.compile(value)
        elif key == "min-bytes":
            spec.min_bytes = int(value)
    return spec


# ---------------------------------------------------------------------------
# Duration helper used by --window / --bucket
# ---------------------------------------------------------------------------

_DUR_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_DUR_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86_400}


def parse_duration_seconds(text: str) -> int:
    """Parse '30', '90s', '5m', '2h', '1d' into seconds."""
    m = _DUR_RE.match(text or "")
    if not m:
        raise ValueError(f"invalid duration: {text!r} (use e.g. 30s, 5m, 2h)")
    n, unit = m.group(1), m.group(2).lower()
    return int(n) * _DUR_UNIT_SECONDS[unit]


__all__ = ["FilterSpec", "parse_filter", "parse_duration_seconds"]
