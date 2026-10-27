import json
from collections import defaultdict

CATEGORY = {
    "first_seen": "lifecycle",
    "last_seen": "lifecycle",
    "ip_changed": "dns",
    "ns_changed": "dns",
    "mx_changed": "dns",
    "txt_changed": "dns",
    "cname_changed": "dns",
    "cert_issued": "cert",
    "registered": "whois",
    "registrar_changed": "whois",
    "report_link": "report",
}
_DNS_EVENT = {
    "A": "ip_changed",
    "AAAA": "ip_changed",
    "NS": "ns_changed",
    "MX": "mx_changed",
    "TXT": "txt_changed",
    "CNAME": "cname_changed",
}


def _event(ts, type_, summary, row):
    return {
        "ts": ts,
        "type": type_,
        "category": CATEGORY[type_],
        "summary": summary,
        "source": row["source"],
        "retrieved_at": row["retrieved_at"],
        "confidence": row["confidence"],
    }


def _fmt(values):
    return ", ".join(sorted(values)) or "(none)"


def _dns_events(rows):
    series = defaultdict(lambda: defaultdict(set))
    first_row = {}
    for r in rows:
        if r["kind"] != "dns":
            continue
        k = (r["key"], r["source"])
        slot = series[k][r["retrieved_at"]]
        first_row.setdefault((k, r["retrieved_at"]), r)
        if r["value"]:
            slot.add(r["value"])
    for (rtype, source), snaps in sorted(series.items()):
        prev = None
        for when in sorted(snaps):
            cur = snaps[when]
            if prev is not None and cur != prev:
                added, removed = cur - prev, prev - cur
                parts = []
                if removed:
                    parts.append(f"removed {_fmt(removed)}")
                if added:
                    parts.append(f"added {_fmt(added)}")
                row = first_row[((rtype, source), when)]
                yield _event(when, _DNS_EVENT[rtype], f"{rtype} {'; '.join(parts)}", row)
            prev = cur


def _cert_events(rows):
    seen = {}
    for r in rows:
        if r["kind"] == "cert" and r["value"] not in seen:
            seen[r["value"]] = r
    for serial, r in seen.items():
        d = json.loads(r["detail"])
        ts = d["not_before"] or r["retrieved_at"]
        names = _fmt(d["names"]) if d["names"] else "unknown names"
        text = f"certificate {serial} issued by {d['issuer']} for {names}"
        if d["not_after"]:
            text += f", expires {d['not_after']}"
        if not d["not_before"]:
            text += " (issue time unknown, using first observation)"
        yield _event(ts, "cert_issued", text, r)


def _whois_events(rows):
    registrar = None
    created_seen = False
    for r in rows:
        if r["kind"] != "whois":
            continue
        created = json.loads(r["detail"])["created"]
        if created and not created_seen:
            created_seen = True
            yield _event(created, "registered", f"registered {created}", r)
        if r["value"] and r["value"] != registrar:
            if registrar is not None:
                yield _event(
                    r["retrieved_at"],
                    "registrar_changed",
                    f"registrar {registrar} -> {r['value']}",
                    r,
                )
            registrar = r["value"]


def _report_events(rows):
    seen = set()
    for r in rows:
        if r["kind"] == "report" and r["value"] not in seen:
            seen.add(r["value"])
            title = json.loads(r["detail"])["title"]
            yield _event(
                r["retrieved_at"],
                "report_link",
                f"report: {title + ' ' if title else ''}{r['value']}",
                r,
            )


def compute(rows):
    if not rows:
        return []
    rows = sorted(rows, key=lambda r: (r["retrieved_at"], r["id"]))
    first, last = rows[0], rows[-1]
    out = [_event(first["retrieved_at"], "first_seen", "first observation", first)]
    for gen in (_dns_events, _cert_events, _whois_events, _report_events):
        out.extend(gen(rows))
    out.append(_event(last["retrieved_at"], "last_seen", "latest observation", last))
    out.sort(key=lambda e: (e["ts"], e["type"] == "last_seen"))
    return out
