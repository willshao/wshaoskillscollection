"""
_shared/svg_charts.py

Pure-stdlib SVG chart generators. Output is a self-contained <svg>…</svg>
string suitable for direct embedding into an HTML report.

Provided chart types:
  * bar_chart(labels, values, title, ylabel)             — vertical bars
  * line_chart(labels, series, title, ylabel)            — multi-series lines
  * dual_axis_chart(labels, left, right, title,          — bars + overlaid line
                    left_label, right_label)
"""
from __future__ import annotations

from html import escape
from typing import Iterable, Sequence

# Default canvas
_W = 900
_H = 320
_PAD_L = 60
_PAD_R = 20
_PAD_T = 40
_PAD_B = 60

# A small qualitative palette
_PALETTE = ["#1f77b4", "#d62728", "#2ca02c", "#ff7f0e",
            "#9467bd", "#8c564b", "#17becf", "#7f7f7f"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nice_max(value: float) -> float:
    """Round up to a 'nice' axis maximum so labels are readable."""
    if value <= 0:
        return 1.0
    import math
    mag = 10 ** math.floor(math.log10(value))
    for m in (1, 2, 2.5, 5, 10):
        if value <= m * mag:
            return m * mag
    return 10 * mag


def _fmt(v: float) -> str:
    if v >= 1000:
        return f"{v:,.0f}"
    if float(v).is_integer():
        return f"{int(v)}"
    return f"{v:.2f}"


def _x_labels(labels: Sequence[str], n_ticks: int = 8) -> list[tuple[int, str]]:
    if not labels:
        return []
    n = len(labels)
    step = max(1, n // n_ticks)
    out = [(i, labels[i]) for i in range(0, n, step)]
    if out[-1][0] != n - 1:
        out.append((n - 1, labels[-1]))
    return out


def _svg_open(title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{_W}" height="{_H}" viewBox="0 0 {_W} {_H}" '
        f'role="img" aria-label="{escape(title)}" '
        f'style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; font-size: 12px;">'
    )


def _frame(title: str, ylabel: str, y_max: float, y2_label: str = "",
           y2_max: float | None = None) -> list[str]:
    """Common chart frame (title, axes, gridlines, y labels)."""
    plot_w = _W - _PAD_L - _PAD_R
    plot_h = _H - _PAD_T - _PAD_B
    parts: list[str] = []
    # Title
    parts.append(
        f'<text x="{_W // 2}" y="20" text-anchor="middle" '
        f'font-weight="600" font-size="14">{escape(title)}</text>'
    )
    # Y label
    parts.append(
        f'<text x="14" y="{_PAD_T + plot_h // 2}" text-anchor="middle" '
        f'transform="rotate(-90, 14, {_PAD_T + plot_h // 2})" '
        f'fill="#555">{escape(ylabel)}</text>'
    )
    # Axes
    parts.append(
        f'<line x1="{_PAD_L}" y1="{_PAD_T}" x2="{_PAD_L}" y2="{_PAD_T + plot_h}" stroke="#888"/>'
        f'<line x1="{_PAD_L}" y1="{_PAD_T + plot_h}" x2="{_PAD_L + plot_w}" y2="{_PAD_T + plot_h}" stroke="#888"/>'
    )
    # Y gridlines + labels (5 ticks)
    for i in range(6):
        y = _PAD_T + plot_h - int(plot_h * i / 5)
        v = y_max * i / 5
        parts.append(
            f'<line x1="{_PAD_L}" y1="{y}" x2="{_PAD_L + plot_w}" y2="{y}" '
            f'stroke="#eee"/>'
            f'<text x="{_PAD_L - 6}" y="{y + 4}" text-anchor="end" fill="#555">{_fmt(v)}</text>'
        )
    # Right axis (optional)
    if y2_label and y2_max is not None:
        parts.append(
            f'<line x1="{_PAD_L + plot_w}" y1="{_PAD_T}" '
            f'x2="{_PAD_L + plot_w}" y2="{_PAD_T + plot_h}" stroke="#888"/>'
        )
        for i in range(6):
            y = _PAD_T + plot_h - int(plot_h * i / 5)
            v = y2_max * i / 5
            parts.append(
                f'<text x="{_PAD_L + plot_w + 6}" y="{y + 4}" '
                f'text-anchor="start" fill="#555">{_fmt(v)}</text>'
            )
        parts.append(
            f'<text x="{_W - 12}" y="{_PAD_T + plot_h // 2}" text-anchor="middle" '
            f'transform="rotate(90, {_W - 12}, {_PAD_T + plot_h // 2})" '
            f'fill="#555">{escape(y2_label)}</text>'
        )
    return parts


def _x_tick_labels(labels: Sequence[str]) -> list[str]:
    plot_w = _W - _PAD_L - _PAD_R
    plot_h = _H - _PAD_T - _PAD_B
    parts: list[str] = []
    n = len(labels)
    if n == 0:
        return parts
    for idx, lbl in _x_labels(labels):
        # Centre the label under its position.
        if n == 1:
            x = _PAD_L + plot_w // 2
        else:
            x = _PAD_L + int(plot_w * idx / (n - 1))
        y = _PAD_T + plot_h + 16
        parts.append(
            f'<text x="{x}" y="{y}" text-anchor="middle" fill="#555" '
            f'transform="rotate(-30 {x} {y})">{escape(lbl)}</text>'
        )
    return parts


# ---------------------------------------------------------------------------
# Bar chart
# ---------------------------------------------------------------------------

def bar_chart(labels: Sequence[str], values: Sequence[float],
              title: str = "", ylabel: str = "",
              color: str = _PALETTE[0]) -> str:
    """Vertical bar chart. labels and values must be the same length."""
    if len(labels) != len(values):
        raise ValueError("labels and values length mismatch")
    plot_w = _W - _PAD_L - _PAD_R
    plot_h = _H - _PAD_T - _PAD_B
    y_max = _nice_max(max(values) if values else 1)
    n = max(1, len(values))
    bar_w = plot_w / n * 0.8
    gap = plot_w / n * 0.2

    out = [_svg_open(title)]
    out.extend(_frame(title, ylabel, y_max))
    for i, v in enumerate(values):
        x = _PAD_L + i * (bar_w + gap) + gap / 2
        h = 0 if y_max == 0 else (v / y_max) * plot_h
        y = _PAD_T + plot_h - h
        out.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
            f'fill="{color}" opacity="0.85">'
            f'<title>{escape(str(labels[i]))}: {_fmt(v)}</title></rect>'
        )
    out.extend(_x_tick_labels(labels))
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Line chart
# ---------------------------------------------------------------------------

def line_chart(labels: Sequence[str],
               series: dict[str, Sequence[float]],
               title: str = "", ylabel: str = "") -> str:
    """Multi-series line chart. series: name -> values aligned with labels."""
    if not series:
        return bar_chart(labels, [0] * len(labels), title, ylabel)
    n = len(labels)
    for name, vals in series.items():
        if len(vals) != n:
            raise ValueError(f"series {name!r} length mismatch")
    plot_w = _W - _PAD_L - _PAD_R
    plot_h = _H - _PAD_T - _PAD_B
    flat = [v for vals in series.values() for v in vals]
    y_max = _nice_max(max(flat) if flat else 1)

    out = [_svg_open(title)]
    out.extend(_frame(title, ylabel, y_max))

    for s_idx, (name, vals) in enumerate(series.items()):
        color = _PALETTE[s_idx % len(_PALETTE)]
        pts = []
        for i, v in enumerate(vals):
            x = _PAD_L + (0 if n == 1 else int(plot_w * i / (n - 1)))
            y = _PAD_T + plot_h - (0 if y_max == 0 else (v / y_max) * plot_h)
            pts.append(f"{x:.1f},{y:.1f}")
        out.append(
            f'<polyline fill="none" stroke="{color}" stroke-width="2" '
            f'points="{" ".join(pts)}"/>'
        )
        # Legend entry
        lx = _PAD_L + 10 + s_idx * 120
        ly = _PAD_T - 8
        out.append(
            f'<rect x="{lx}" y="{ly - 8}" width="10" height="10" fill="{color}"/>'
            f'<text x="{lx + 14}" y="{ly}" fill="#333">{escape(name)}</text>'
        )

    out.extend(_x_tick_labels(labels))
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Dual-axis chart (bars left, line right)
# ---------------------------------------------------------------------------

def dual_axis_chart(labels: Sequence[str],
                    left_values: Sequence[float],
                    right_values: Sequence[float],
                    title: str = "",
                    left_label: str = "",
                    right_label: str = "") -> str:
    """Bars use left axis, line uses right axis."""
    n = len(labels)
    if len(left_values) != n or len(right_values) != n:
        raise ValueError("labels/left/right length mismatch")
    plot_w = _W - _PAD_L - _PAD_R
    plot_h = _H - _PAD_T - _PAD_B
    y_max_l = _nice_max(max(left_values) if left_values else 1)
    y_max_r = _nice_max(max(right_values) if right_values else 1)
    bar_w = plot_w / max(1, n) * 0.8
    gap = plot_w / max(1, n) * 0.2

    out = [_svg_open(title)]
    out.extend(_frame(title, left_label, y_max_l, right_label, y_max_r))

    # Bars (left axis)
    for i, v in enumerate(left_values):
        x = _PAD_L + i * (bar_w + gap) + gap / 2
        h = 0 if y_max_l == 0 else (v / y_max_l) * plot_h
        y = _PAD_T + plot_h - h
        out.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
            f'fill="{_PALETTE[0]}" opacity="0.75">'
            f'<title>{escape(str(labels[i]))}: {_fmt(v)} {escape(left_label)}</title>'
            f'</rect>'
        )
    # Line (right axis)
    pts = []
    for i, v in enumerate(right_values):
        x = _PAD_L + (0 if n == 1 else int(plot_w * i / (n - 1)))
        y = _PAD_T + plot_h - (0 if y_max_r == 0 else (v / y_max_r) * plot_h)
        pts.append(f"{x:.1f},{y:.1f}")
    out.append(
        f'<polyline fill="none" stroke="{_PALETTE[1]}" stroke-width="2.2" '
        f'points="{" ".join(pts)}"/>'
    )
    # Legend
    out.append(
        f'<rect x="{_PAD_L + 10}" y="{_PAD_T - 16}" width="10" height="10" fill="{_PALETTE[0]}"/>'
        f'<text x="{_PAD_L + 26}" y="{_PAD_T - 8}" fill="#333">{escape(left_label)}</text>'
        f'<rect x="{_PAD_L + 180}" y="{_PAD_T - 16}" width="10" height="10" fill="{_PALETTE[1]}"/>'
        f'<text x="{_PAD_L + 196}" y="{_PAD_T - 8}" fill="#333">{escape(right_label)}</text>'
    )

    out.extend(_x_tick_labels(labels))
    out.append("</svg>")
    return "".join(out)


__all__ = ["bar_chart", "line_chart", "dual_axis_chart"]
