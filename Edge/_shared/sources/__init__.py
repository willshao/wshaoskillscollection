"""
Edge/_shared/sources/ — canonical readers for Edge data sources.

Skills should import the relevant submodule here instead of duplicating
%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\... discovery, registry walking,
or Crashpad enumeration. Each submodule exposes the uniform surface:

    discover(...)                  -> list of source artefacts
    iter_entries(...)              -> iterable of dicts
    summarise(entries)             -> dict
    apply_filter(entries, filter)  -> list
    query(...)                     -> {summary, entries, truncated, ...}

Filter shapes are per-source (CrashpadFilter, ExtensionFilter, ...).
"""
