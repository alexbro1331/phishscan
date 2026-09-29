"""Server-side chart geometry. Templates only draw what these functions compute (no chart library, no JS)."""
import math
from datetime import date

CLASSES = ("malicious", "suspicious", "safe")   # stacking order, bottom to top
DONUT_R = 40


def _step(max_total: int) -> int:
    for step in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000):
        if max_total / step <= 4:
            return step
    return 10000 * math.ceil(max_total / 40000)


def activity_chart(series, width=640, height=200):
    left, right, top, bottom = 34, 8, 10, 24
    plot_w, plot_h = width - left - right, height - top - bottom
    max_total = max([d["total"] for d in series] + [0])
    step = _step(max(max_total, 1))
    top_val = max(step, math.ceil(max(max_total, 1) / step) * step)
    unit = plot_h / top_val
    slot = plot_w / max(len(series), 1)
    bar_w = slot * 0.62
    bars = []
    for i, d in enumerate(series):
        segments, cum = [], 0
        for cls in CLASSES:
            n = d[cls]
            if n:
                h = n * unit
                segments.append({"cls": cls, "count": n, "y": round(plot_h - (cum * unit) - h, 2), "h": round(h, 2)})
                cum += n
        try:
            label = date.fromisoformat(d["date"]).strftime("%b %d").replace(" 0", " ")
        except ValueError:
            label = d["date"]
        bars.append({"x": round(i * slot + (slot - bar_w) / 2, 2), "w": round(bar_w, 2), "segments": segments,
                     "total": d["total"], "date": d["date"], "label": label,
                     "tip": f"{label}: {d['total']} analyzed ({d['malicious']} malicious, "
                            f"{d['suspicious']} suspicious, {d['safe']} safe)"})
    every = max(1, math.ceil(len(series) / 7))
    return {
        "width": width, "height": height, "left": left, "top": top, "plot_w": plot_w, "plot_h": plot_h,
        "max": top_val, "bars": bars,
        "gridlines": [{"y": round(plot_h - v * unit, 2), "label": str(v)} for v in range(0, top_val + 1, step)],
        "xlabels": [{"x": round(b["x"] + b["w"] / 2, 2), "label": b["label"]} for i, b in enumerate(bars)
                    if i % every == 0 or i == len(bars) - 1],
    }


def donut(counts: dict):
    circ = 2 * math.pi * DONUT_R
    total = sum(counts.get(c, 0) for c in CLASSES)
    segments, cum = [], 0.0
    if total:
        for cls in CLASSES:
            n = counts.get(cls, 0)
            if not n:
                continue
            dash = circ * n / total
            segments.append({"cls": cls, "count": n, "pct": round(100 * n / total), "dash": round(dash, 3),
                             "offset": round(-cum, 3)})
            cum += dash
    return {"r": DONUT_R, "circ": round(circ, 3), "total": total, "segments": segments}


def sparkline(values, width=90, height=28) -> str:
    if not values:
        return ""
    if len(values) == 1:
        values = [values[0], values[0]]
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    n = len(values)
    return " ".join(f"{1 + i * (width - 2) / (n - 1):.1f},{height - 1 - (v - lo) / span * (height - 2):.1f}"
                    for i, v in enumerate(values))
