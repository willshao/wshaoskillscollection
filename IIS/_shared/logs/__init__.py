"""
_shared/logs/ — canonical readers for each log/data-source kind.

Skills should import the matching submodule instead of owning their own
parser/filter implementations. Every submodule exposes the same surface:

    discover(folder, recursive=True) -> list[Path]
    iter_entries(path) -> Iterator[dict]          # already normalised
    summarise(entries) -> dict
    apply_filter(entries, filter_spec) -> list
    query(sources, *,
          filter=None,
          time_range=None,
          around=None, window_seconds=300,
          limit=None) -> dict

The returned `query()` payload has a stable shape:

    {
      "summary": {...},
      "entries": [...],
      "truncated": bool,
      "source_files": [...],
    }

Filter shapes are per-kind (FilterSpec for W3C-style logs, HttpErrFilter,
EvtxFilter, ...) — no forced unification.
"""
