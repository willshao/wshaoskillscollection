"""Tests for Edge/_shared/sources/edge_registry.py — Edge policy registry reader."""
from __future__ import annotations

import sys

import pytest

from _shared.sources import edge_registry


def test_uniform_api_surface_present():
    for name in ("discover", "iter_entries", "summarise",
                 "apply_filter", "around_window", "query"):
        assert hasattr(edge_registry, name), f"missing {name}"


def test_policy_roots_and_categories_exported():
    assert edge_registry.POLICY_ROOTS
    assert edge_registry.CATEGORY_MAP
    # Map keys are substrings categorised against name+subkey
    assert "extension" in edge_registry.CATEGORY_MAP
    assert edge_registry.CATEGORY_MAP["extension"] == "extension_management"


def test_categorise_known_keys():
    # signature is _categorise(name, subkey) — substring matched
    assert edge_registry._categorise("ExtensionInstallBlocklist", "") == "extension_management"
    assert edge_registry._categorise("SyncDisabled", "") == "sync"
    assert edge_registry._categorise("RandomUnknownKey", "") == "other"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Registry only available on Windows")
def test_query_returns_summary_structure():
    res = edge_registry.query()
    s = res["summary"]
    assert "count" in s
    assert "by_category" in s
    assert "by_hive" in s
    assert isinstance(s["count"], int)
    assert isinstance(s["by_category"], dict)


def test_reg_type_name_handles_common_types():
    # Windows-only winreg constants — we just call through.
    if sys.platform == "win32":
        import winreg
        assert edge_registry._reg_type_name(winreg.REG_SZ) == "REG_SZ"
        assert edge_registry._reg_type_name(winreg.REG_DWORD) == "REG_DWORD"


def test_filter_dataclass_has_is_empty():
    f = edge_registry.PolicyFilter()
    assert f.is_empty()
