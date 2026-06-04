"""
Edge/_shared/sources/user_data.py — locate Edge User Data directory and profiles.

Other source modules import `default_user_data_dir()` / `resolve_user_data_dir()`
instead of reimplementing the LOCALAPPDATA lookup.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "default_user_data_dir", "resolve_user_data_dir",
    "discover", "iter_entries", "summarise", "apply_filter",
    "around_window", "query",
    "list_profiles", "read_preferences",
]


def default_user_data_dir() -> Path | None:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    p = Path(local) / "Microsoft" / "Edge" / "User Data"
    return p if p.exists() else None


def resolve_user_data_dir(ctx: dict[str, Any] | None = None) -> Path | None:
    """Honour `extra.user_data_dir` override from the contract context."""
    if ctx:
        override = (ctx.get("extra") or {}).get("user_data_dir")
        if override:
            p = Path(override)
            return p if p.exists() else None
    return default_user_data_dir()


def list_profiles(udd: Path | None) -> list[str]:
    if not udd or not udd.exists():
        return []
    out: list[str] = []
    for ch in udd.iterdir():
        if not ch.is_dir():
            continue
        if (ch.name == "Default" or ch.name.startswith("Profile ")) and (ch / "Preferences").exists():
            out.append(ch.name)
    return sorted(out)


def read_preferences(udd: Path, profile: str) -> dict[str, Any]:
    p = udd / profile / "Preferences"
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# Uniform source API
# ---------------------------------------------------------------------------

def discover(folder: Path | str | None = None,
             recursive: bool = True) -> list[Path]:
    """Return profile directories under the chosen User Data dir."""
    udd = Path(folder) if folder else default_user_data_dir()
    if udd is None or not udd.exists():
        return []
    return [udd / name for name in list_profiles(udd)]


def iter_entries(path: Path) -> Iterable[dict[str, Any]]:
    """Yield one entry per profile describing its top-level prefs."""
    udd = Path(path).parent
    profile = Path(path).name
    prefs = read_preferences(udd, profile)
    yield {
        "profile": profile,
        "default_search_provider": ((prefs.get("default_search_provider_data") or {})
                                    .get("template_url_data") or {}).get("short_name"),
        "homepage": (prefs.get("homepage") or ""),
        "session_restore_on_startup": (prefs.get("session") or {}).get("restore_on_startup"),
        "browser_signin": (prefs.get("browser") or {}).get("signin_allowed_on_next_startup"),
        "preferences_file": str(udd / profile / "Preferences"),
    }


def apply_filter(entries: Iterable[dict[str, Any]],
                 spec: object | None) -> list[dict[str, Any]]:
    if spec is None:
        return list(entries)
    if hasattr(spec, "matches"):
        return [e for e in entries if spec.matches(e)]
    return list(entries)


def around_window(entries: Iterable[dict[str, Any]], *_args, **_kwargs) -> list[dict[str, Any]]:
    return list(entries)


def summarise(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "count": len(entries),
        "profiles": [e.get("profile") for e in entries],
    }


def query(sources: Iterable[Path | str] | None = None,
          *,
          filter: object | None = None,
          time_range=None,
          around=None,
          window_seconds: int = 300,
          limit: int | None = None,
          ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    udd = resolve_user_data_dir(ctx) if ctx else default_user_data_dir()
    src = list(sources) if sources else (discover(udd) if udd else [])
    entries: list[dict[str, Any]] = []
    for p in src:
        entries.extend(iter_entries(Path(p)))
    if filter is not None:
        entries = apply_filter(entries, filter)
    truncated = False
    if limit is not None and len(entries) > limit:
        truncated = True
        entries = entries[:limit]
    return {
        "summary": summarise(entries),
        "entries": entries,
        "truncated": truncated,
        "user_data_dir": str(udd) if udd else None,
    }
