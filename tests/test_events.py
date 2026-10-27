from domain_trail import events, importer, store

D = "x.example"


def dns(t, typ, vals, source="s"):
    return {"domain": D, "kind": "dns", "source": source, "retrieved_at": t,
            "data": {"type": typ, "values": vals}}


def run(db, docs):
    store.add(db, importer.parse(docs))
    return events.compute(store.for_domain(db, D))


def types(evs):
    return [e["type"] for e in evs]


def test_no_rows_no_events():
    assert events.compute([]) == []


def test_ip_change_lists_added_and_removed(db):
    evs = run(db, [dns("2025-01-01T00:00:00Z", "A", ["192.0.2.1"]),
                   dns("2025-01-02T00:00:00Z", "A", ["192.0.2.1"]),
                   dns("2025-01-03T00:00:00Z", "A", ["192.0.2.2"])])
    [ch] = [e for e in evs if e["type"] == "ip_changed"]
    assert ch["ts"] == "2025-01-03T00:00:00Z"
    assert "removed 192.0.2.1" in ch["summary"] and "added 192.0.2.2" in ch["summary"]
    assert types(evs)[0] == "first_seen" and types(evs)[-1] == "last_seen"


def test_unchanged_set_gives_no_change(db):
    evs = run(db, [dns("2025-01-01T00:00:00Z", "NS", ["a.example", "b.example"]),
                   dns("2025-01-02T00:00:00Z", "NS", ["b.example", "a.example"])])
    assert "ns_changed" not in types(evs)


def test_sources_are_compared_separately(db):
    evs = run(db, [dns("2025-01-01T00:00:00Z", "A", ["192.0.2.1"], "one"),
                   dns("2025-01-02T00:00:00Z", "A", ["192.0.2.2"], "two"),
                   dns("2025-01-03T00:00:00Z", "A", ["192.0.2.1"], "one")])
    assert "ip_changed" not in types(evs)


def test_record_disappearing_is_a_change(db):
    evs = run(db, [dns("2025-01-01T00:00:00Z", "MX", ["10 m.example"]),
                   dns("2025-01-02T00:00:00Z", "MX", [])])
    [ch] = [e for e in evs if e["type"] == "mx_changed"]
    assert "removed 10 m.example" in ch["summary"]


def test_cert_issued_once_and_uses_not_before(db):
    cert = {"domain": D, "kind": "cert", "source": "ct", "confidence": 1,
            "data": {"serial": "AB", "issuer": "CA", "names": [D],
                     "not_before": "2024-12-30T00:00:00Z"}}
    evs = run(db, [dict(cert, retrieved_at="2025-01-05T00:00:00Z"),
                   dict(cert, retrieved_at="2025-01-06T00:00:00Z")])
    [c] = [e for e in evs if e["type"] == "cert_issued"]
    assert c["ts"] == "2024-12-30T00:00:00Z"
    assert c["retrieved_at"] == "2025-01-05T00:00:00Z"
    assert c["confidence"] == 1.0


def test_cert_without_not_before_falls_back(db):
    doc = {"domain": D, "kind": "cert", "source": "ct", "retrieved_at": "2025-01-05T00:00:00Z",
           "data": {"serial": "AB", "issuer": "CA"}}
    [c] = [e for e in run(db, [doc]) if e["type"] == "cert_issued"]
    assert c["ts"] == "2025-01-05T00:00:00Z"
    assert "unknown" in c["summary"]


def test_whois_registered_and_registrar_change(db):
    def w(t, **d):
        return {"domain": D, "kind": "whois", "source": "w", "retrieved_at": t, "data": d}
    evs = run(db, [w("2025-01-05T00:00:00Z", registrar="A Co", created="2025-01-01T00:00:00Z"),
                   w("2025-02-05T00:00:00Z", registrar="B Co")])
    assert types(evs).count("registered") == 1
    [ch] = [e for e in evs if e["type"] == "registrar_changed"]
    assert ch["summary"] == "registrar A Co -> B Co"


def test_report_link_deduplicated(db):
    r = {"domain": D, "kind": "report", "source": "n", "data": {"url": "https://r.example/1"}}
    evs = run(db, [dict(r, retrieved_at="2025-01-01T00:00:00Z"),
                   dict(r, retrieved_at="2025-01-02T00:00:00Z")])
    assert types(evs).count("report_link") == 1


def test_distinct_certs_each_get_an_event(db):
    def cert(serial, t):
        return {"domain": D, "kind": "cert", "source": "ct", "retrieved_at": t,
                "data": {"serial": serial, "issuer": "CA"}}
    evs = run(db, [cert("AA", "2025-01-01T00:00:00Z"), cert("BB", "2025-01-02T00:00:00Z")])
    got = [e["summary"] for e in evs if e["type"] == "cert_issued"]
    assert len(got) == 2 and "aa" in got[0] and "bb" in got[1]
