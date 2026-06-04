"""
Edge/_shared/sources/edge_registry.py — read Edge group-policy registry.

Walks HKLM and HKCU under `Software\\Policies\\Microsoft\\Edge` (and
EdgeUpdate). Non-Windows callers get an empty list (the API stays stable).
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

__all__ = [
    "PolicyFilter",
    "POLICY_ROOTS",
    "discover", "iter_entries",
    "summarise", "apply_filter", "around_window", "query",
]

POLICY_ROOTS: list[tuple[str, str]] = [
    ("HKLM", r"Software\Policies\Microsoft\Edge"),
    ("HKCU", r"Software\Policies\Microsoft\Edge"),
    ("HKLM", r"Software\Policies\Microsoft\EdgeUpdate"),
]

CATEGORY_MAP = {
    "extension": "extension_management",
    "update": "update",
    "channel": "update",
    "smartscreen": "security",
    "ssl": "security",
    "tls": "security",
    "cipher": "security",
    "sync": "sync",
    "signin": "sync",
    "proxy": "network",
    "auth": "network",
    "homepage": "browser_features",
    "restoreonstartup": "browser_features",
    "defaultsearchprovider": "browser_features",
    "internetexplorerintegration": "browser_features",
    "newtabpage": "browser_features",
}


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------

@dataclass
class PolicyFilter:
    category: str | None = None      # exact match against categorise()
    name_contains: str | None = None  # substring on value name
    subkey_contains: str | None = None
    hive: str | None = None          # "HKLM" / "HKCU"

    def is_empty(self) -> bool:
        return not any((self.category, self.name_contains, self.subkey_contains, self.hive))

    def matches(self, e: dict[str, Any]) -> bool:
        if self.category and e.get("category") != self.category:
            return False
        if self.name_contains and self.name_contains.lower() not in str(e.get("name", "")).lower():
            return False
        if self.subkey_contains and self.subkey_contains.lower() not in str(e.get("subkey", "")).lower():
            return False
        if self.hive and e.get("hive") != self.hive:
            return False
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _categorise(name: str, subkey: str) -> str:
    blob = (subkey + " " + name).lower()
    for key, cat in CATEGORY_MAP.items():
        if key in blob:
            return cat
    return "other"


def _reg_type_name(t: int) -> str:
    try:
        import winreg  # type: ignore
    except ImportError:
        return str(t)
    return {
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_BINARY: "REG_BINARY",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_QWORD: "REG_QWORD",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    }.get(t, f"REG_{t}")


def _coerce(v: Any) -> Any:
    if isinstance(v, bytes):
        try:
            return v.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return v.hex()
    return v


def _walk(hive: str, base: str) -> list[dict[str, Any]]:
    """Recursively read a registry subtree (Windows only)."""
    if os.name != "nt":
        return []
    try:
        import winreg  # type: ignore
    except ImportError:
        return []
    hroot = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER

    rows: list[dict[str, Any]] = []

    def _read(key, subkey: str) -> None:
        i = 0
        while True:
            try:
                name, value, vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            rows.append({
                "hive": hive,
                "subkey": subkey,
                "name": name,
                "type": _reg_type_name(vtype),
                "value": _coerce(value),
                "category": _categorise(name, subkey),
            })
            i += 1
        i = 0
        while True:
            try:
                child_name = winreg.EnumKey(key, i)
            except OSError:
                break
            try:
                with winreg.OpenKey(key, child_name) as ck:
                    _read(ck, f"{subkey}\\{child_name}" if subkey else child_name)
            except OSError:
                pass
            i += 1

    try:
        with winreg.OpenKey(hroot, base) as root_key:
            _read(root_key, "")
    except (FileNotFoundError, OSError):
        return []
    return rows


# ---------------------------------------------------------------------------
# Uniform source API
# ---------------------------------------------------------------------------

def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[tuple[str, str]]:
    """Return the list of (hive, base) roots that will be walked."""
    return list(POLICY_ROOTS)


def iter_entries(root: tuple[str, str] | None = None) -> Iterator[dict[str, Any]]:
    """Yield rows for one (hive, base) tuple, or all default roots if None."""
    roots = [root] if root else POLICY_ROOTS
    for hive, base in roots:
        for row in _walk(hive, base):
            yield row


def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: PolicyFilter | None) -> list[dict[str, Any]]:
    if spec is None or spec.is_empty():
        return list(entries)
    return [e for e in entries if spec.matches(e)]


def around_window(entries: Iterable[dict[str, Any]], *_args, **_kwargs) -> list[dict[str, Any]]:
    return list(entries)


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {"count": 0}
    by_cat = Counter(e.get("category", "other") for e in entries)
    by_hive = Counter(e.get("hive", "?") for e in entries)
    by_type = Counter(e.get("type", "?") for e in entries)
    return {
        "count": len(entries),
        "by_category": dict(by_cat),
        "by_hive": dict(by_hive),
        "by_type": dict(by_type),
    }


def query(sources: Iterable[tuple[str, str]] | None = None,
          *,
          filter: PolicyFilter | None = None,
          time_range=None,
          around=None,
          window_seconds: int = 300,
          limit: int | None = None) -> dict[str, Any]:
    roots = list(sources) if sources else POLICY_ROOTS
    entries: list[dict[str, Any]] = []
    for r in roots:
        entries.extend(iter_entries(r))

    if filter is not None and not filter.is_empty():
        entries = apply_filter(entries, filter)

    truncated = False
    if limit is not None and len(entries) > limit:
        truncated = True
        entries = entries[:limit]

    return {
        "summary": summarise(entries),
        "entries": entries,
        "truncated": truncated,
        "policy_roots": [{"hive": h, "subkey": s} for h, s in roots],
    }
