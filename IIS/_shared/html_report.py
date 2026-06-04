"""
_shared/html_report.py

Minimal single-file HTML report builder. Embeds inline SVG charts and
arbitrary HTML sections produced by skills. No external CSS/JS.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Iterable, Sequence

_CSS = """
:root { color-scheme: light dark; }
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px auto;
       max-width: 1024px; color: #222; line-height: 1.45; }
h1 { margin: 0 0 4px; font-size: 22px; }
h2 { margin: 28px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #ddd; font-size: 18px; }
h3 { margin: 16px 0 4px; font-size: 15px; color: #444; }
.meta { color: #666; font-size: 12px; margin-bottom: 12px; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px;
         margin-right: 4px; font-weight: 600; }
.badge.critical { background: #ffe0e0; color: #a00; }
.badge.warning  { background: #fff3cd; color: #946200; }
.badge.info     { background: #e1f0ff; color: #0a4f99; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 8px 0 16px; }
th, td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
th { background: #f8f8f8; font-weight: 600; }
tr:hover td { background: #fafbfc; }
code, pre { font-family: ui-monospace, Consolas, monospace; font-size: 12px;
            background: #f4f4f4; padding: 1px 4px; border-radius: 3px; }
.kpi { display: inline-block; min-width: 160px; padding: 8px 12px;
       border: 1px solid #e2e2e2; border-radius: 6px; margin: 4px 6px 4px 0;
       background: #fafafa; }
.kpi .label { display:block; color:#666; font-size:11px; }
.kpi .value { display:block; font-size:18px; font-weight:600; }
svg { display: block; margin: 8px 0 16px; max-width: 100%; height: auto; }
.note { color: #666; font-size: 12px; }
.advisory { margin: 6px 0 14px; padding: 8px 12px; border-left: 3px solid #ccc;
            background: #fafafa; border-radius: 0 4px 4px 0; }
.advisory.critical { border-left-color: #d33; background: #fff5f5; }
.advisory.warning  { border-left-color: #d9a200; background: #fffbeb; }
.advisory.info     { border-left-color: #2778c4; background: #f1f7ff; }
.advisory .title { font-weight: 600; }
.advisory ol, .advisory ul { margin: 4px 0 4px 18px; padding: 0; }
.advisory .refs { font-size: 12px; color: #555; margin-top: 4px; }
.advisory .meta { color: #666; font-size: 11px; }
"""


@dataclass
class Section:
    heading: str
    html: str          # arbitrary inner HTML (already escaped where needed)
    level: int = 2     # 2 = h2, 3 = h3, …


def kpi_card(label: str, value: str) -> str:
    return (
        f'<div class="kpi"><span class="label">{escape(label)}</span>'
        f'<span class="value">{escape(value)}</span></div>'
    )


def render_table(headers: Sequence[str],
                 rows: Iterable[Sequence[object]],
                 max_rows: int | None = None) -> str:
    """Render a basic HTML table; values are escaped automatically."""
    out = ["<table><thead><tr>"]
    for h in headers:
        out.append(f"<th>{escape(str(h))}</th>")
    out.append("</tr></thead><tbody>")
    count = 0
    for row in rows:
        if max_rows is not None and count >= max_rows:
            break
        out.append("<tr>")
        for cell in row:
            out.append(f"<td>{escape(str(cell)) if cell is not None else ''}</td>")
        out.append("</tr>")
        count += 1
    out.append("</tbody></table>")
    if max_rows is not None and count == max_rows:
        out.append(
            f'<div class="note">(truncated at {max_rows} rows — '
            f'see JSON for full results)</div>'
        )
    return "".join(out)


def render(title: str,
           sections: Iterable[Section],
           generated_at: datetime | None = None,
           subtitle: str = "") -> str:
    """Assemble sections into a single HTML document string."""
    when = generated_at or datetime.now()
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{escape(title)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>{escape(title)}</h1>",
    ]
    if subtitle:
        parts.append(f'<div class="meta">{escape(subtitle)}</div>')
    parts.append(
        f'<div class="meta">Generated {escape(when.strftime("%Y-%m-%d %H:%M:%S"))}</div>'
    )
    for sec in sections:
        tag = f"h{max(2, min(4, sec.level))}"
        parts.append(f"<{tag}>{escape(sec.heading)}</{tag}>")
        parts.append(sec.html)
    parts.append("</body></html>")
    return "\n".join(parts)


def write_report(path: Path, title: str, sections: Iterable[Section],
                 subtitle: str = "") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(title, sections, subtitle=subtitle),
                    encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Advisory section helpers (Solutions / Next steps / Additional logs)
# ---------------------------------------------------------------------------

def _adv_severity(item: object, default: str = "info") -> str:
    sev = getattr(item, "severity", None) or (item.get("severity") if isinstance(item, dict) else None)
    return sev if sev in ("critical", "warning", "info") else default


def _adv_field(item: object, name: str, default=None):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def render_solutions(items: Iterable[object]) -> str:
    """Render Solution items (dataclass or dict) into HTML."""
    items = list(items)
    if not items:
        return '<p class="note">No standardised solutions for the detected problems.</p>'
    out: list[str] = []
    for s in items:
        sev = _adv_severity(s)
        title = _adv_field(s, "title", "(no title)")
        problem_ref = _adv_field(s, "problem_ref")
        steps = list(_adv_field(s, "steps", []) or [])
        refs = list(_adv_field(s, "references", []) or [])
        head = (
            f'<div class="advisory {sev}">'
            f'<div><span class="badge {sev}">{escape(sev)}</span>'
            f'<span class="title">{escape(str(title))}</span>'
            + (f' <span class="meta">[{escape(str(problem_ref))}]</span>' if problem_ref else '')
            + '</div>'
        )
        if steps:
            head += "<ol>" + "".join(f"<li>{escape(str(st))}</li>" for st in steps) + "</ol>"
        if refs:
            head += '<div class="refs">References: ' + ", ".join(
                f'<a href="{escape(str(r))}">{escape(str(r))}</a>' if str(r).startswith(("http://", "https://"))
                else f'<code>{escape(str(r))}</code>'
                for r in refs
            ) + "</div>"
        head += "</div>"
        out.append(head)
    return "".join(out)


def render_next_steps(items: Iterable[object]) -> str:
    items = list(items)
    if not items:
        return '<p class="note">No additional next steps recommended.</p>'
    rows = []
    for n in items:
        action = _adv_field(n, "action", "")
        why = _adv_field(n, "why")
        skill = _adv_field(n, "skill")
        skill_html = f' <code>{escape(str(skill))}</code>' if skill else ""
        why_html = f'<div class="meta">{escape(str(why))}</div>' if why else ""
        rows.append(
            f'<div class="advisory info">'
            f'<div class="title">→ {escape(str(action))}{skill_html}</div>'
            f'{why_html}</div>'
        )
    return "".join(rows)


def render_log_requests(items: Iterable[object]) -> str:
    items = list(items)
    if not items:
        return '<p class="note">No additional log sources needed at this time.</p>'
    rows = ["<table><thead><tr><th>log kind</th><th>why</th><th>how to collect</th><th>consumer skill</th></tr></thead><tbody>"]
    for l in items:
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(_adv_field(l, 'log_kind', '')))}</code></td>"
            f"<td>{escape(str(_adv_field(l, 'why', '')))}</td>"
            f"<td>{escape(str(_adv_field(l, 'how_to_collect', '') or ''))}</td>"
            f"<td>{escape(str(_adv_field(l, 'skill', '') or ''))}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def advisory_sections(*,
                      solutions: Iterable[object] = (),
                      next_steps: Iterable[object] = (),
                      additional_logs_needed: Iterable[object] = (),
                      level: int = 2) -> list["Section"]:
    """Build the three standard advisory sections in a consistent order.

    Returns a list of Section objects ready to append to a report.
    """
    return [
        Section(heading="Solutions", html=render_solutions(solutions), level=level),
        Section(heading="Next steps", html=render_next_steps(next_steps), level=level),
        Section(heading="Additional logs needed",
                html=render_log_requests(additional_logs_needed), level=level),
    ]


__all__ = ["Section", "kpi_card", "render_table", "render", "write_report",
           "render_solutions", "render_next_steps", "render_log_requests",
           "advisory_sections"]
