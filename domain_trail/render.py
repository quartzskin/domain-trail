from datetime import datetime
from html import escape

LANES = ["lifecycle", "dns", "cert", "whois", "report"]
COLORS = {
    "lifecycle": "#6b7280",
    "dns": "#2563eb",
    "cert": "#16a34a",
    "whois": "#9333ea",
    "report": "#dc2626",
}
W, LEFT, RIGHT, TOP, LANE_H = 960, 90, 30, 30, 44


def _t(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _tip(e):
    conf = "unspecified" if e["confidence"] is None else f"{e['confidence']:.2f}"
    return (
        f"{e['ts']}  {e['type']}\n{e['summary']}\n"
        f"source: {e['source']}\nretrieved: {e['retrieved_at']}\nconfidence: {conf}"
    )


def _svg(events):
    lo, hi = _t(events[0]["ts"]), _t(events[-1]["ts"])
    span = (hi - lo) or 1
    height = TOP + LANE_H * len(LANES) + 30
    x = lambda ts: LEFT + (_t(ts) - lo) / span * (W - LEFT - RIGHT)  # noqa: E731
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height}" '
        f'width="100%" role="img">'
    ]
    for i, lane in enumerate(LANES):
        y = TOP + i * LANE_H + LANE_H / 2
        out.append(f'<line x1="{LEFT}" x2="{W - RIGHT}" y1="{y}" y2="{y}" stroke="#e5e7eb"/>')
        out.append(f'<text x="8" y="{y + 4}" font-size="12" fill="#374151">{lane}</text>')
    for tick in range(5):
        ts = lo + span * tick / 4
        tx = LEFT + (W - LEFT - RIGHT) * tick / 4
        label = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
        out.append(
            f'<text x="{tx:.1f}" y="{height - 8}" font-size="11" fill="#6b7280" '
            f'text-anchor="middle">{label}</text>'
        )
    for e in events:
        y = TOP + LANES.index(e["category"]) * LANE_H + LANE_H / 2
        conf = e["confidence"]
        opacity = 1 if conf is None else 0.35 + 0.65 * conf
        dash = ' stroke-dasharray="3 2"' if conf is not None and conf < 0.5 else ""
        out.append(
            f'<circle cx="{x(e["ts"]):.1f}" cy="{y}" r="7" fill="{COLORS[e["category"]]}" '
            f'fill-opacity="{opacity:.2f}" stroke="#111"{dash}><title>{escape(_tip(e))}</title>'
            f"</circle>"
        )
    out.append("</svg>")
    return "\n".join(out)


def render(domain, events):
    rows = "\n".join(
        f"<tr><td>{escape(e['ts'])}</td><td>{escape(e['type'])}</td>"
        f"<td>{escape(e['summary'])}</td><td>{escape(e['source'])}</td>"
        f"<td>{escape(e['retrieved_at'])}</td>"
        f"<td>{'' if e['confidence'] is None else f'{e["confidence"]:.2f}'}</td></tr>"
        for e in events
    )
    body = (
        _svg(events) + f"<table><tr><th>time</th><th>event</th><th>detail</th>"
        f"<th>source</th><th>retrieved</th><th>conf.</th></tr>{rows}</table>"
        if events
        else "<p>No observations stored for this domain.</p>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{escape(domain)} - domain timeline</title>
<style>
body {{ font: 14px system-ui, sans-serif; margin: 2rem auto; max-width: 1000px; color: #111; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1.5rem; }}
th, td {{ text-align: left; padding: 4px 8px; border-bottom: 1px solid #e5e7eb; }}
circle:hover {{ stroke-width: 3; }}
</style></head><body>
<h1>{escape(domain)}</h1>
<p>Marker opacity follows the stated confidence; dashed outline means below 0.5.
Hover a marker for its source and retrieval time.</p>
{body}
</body></html>
"""
