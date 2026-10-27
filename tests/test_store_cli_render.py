import json
from pathlib import Path

from domain_trail import doh, events, importer, store
from domain_trail.cli import main
from domain_trail.render import render

SAMPLE = Path(__file__).parent.parent / "samples" / "observations.json"


def test_import_is_idempotent(db):
    obs = importer.load(SAMPLE)
    assert store.add(db, obs) == len(obs)
    assert store.add(db, obs) == 0


def test_cli_roundtrip(tmp_path, capsys):
    db, out = str(tmp_path / "d.db"), tmp_path / "t.html"
    assert main(["--db", db, "import", str(SAMPLE)]) == 0
    assert main(["--db", db, "domains"]) == 0
    assert "login-update.example" in capsys.readouterr().out
    assert main(["--db", db, "events", "login-update.example", "--json"]) == 0
    evs = json.loads(capsys.readouterr().out)
    kinds = [e["type"] for e in evs]
    assert "first_seen" in kinds and kinds[-1] == "last_seen"
    assert {"ip_changed", "ns_changed", "cert_issued", "registrar_changed"} <= set(kinds)
    assert main(["--db", db, "timeline", "login-update.example", "-o", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    assert "<svg" in html and "ct-log-export" in html and "ns_changed" in html


def test_cli_bad_input_exits_1(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert main(["--db", str(tmp_path / "d.db"), "import", str(bad)]) == 1
    assert "error:" in capsys.readouterr().err


def test_cli_rejects_bad_domain_arg(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "d.db"), "events", "not a domain"]) == 1


def test_lookup_requires_online(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "d.db"), "lookup", "a.example"]) == 2
    assert "--online" in capsys.readouterr().err


def test_timeline_for_unknown_domain(tmp_path):
    out = tmp_path / "t.html"
    assert main(["--db", str(tmp_path / "d.db"), "timeline", "none.example", "-o", str(out)]) == 0
    assert "No observations" in out.read_text(encoding="utf-8")


def test_render_escapes_markup(db):
    store.add(
        db,
        importer.parse(
            [
                {
                    "domain": "x.example",
                    "kind": "report",
                    "source": "<script>alert(1)</script>",
                    "retrieved_at": "2025-01-01T00:00:00Z",
                    "data": {"url": "https://r.example/?a=1&b=<2>"},
                }
            ]
        ),
    )
    html = render("x.example", events.compute(store.for_domain(db, "x.example")))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_single_instant_does_not_divide_by_zero(db):
    store.add(
        db,
        importer.parse(
            [
                {
                    "domain": "x.example",
                    "kind": "dns",
                    "source": "s",
                    "retrieved_at": "2025-01-01T00:00:00Z",
                    "data": {"type": "A", "values": ["192.0.2.1"]},
                }
            ]
        ),
    )
    assert "<svg" in render("x.example", events.compute(store.for_domain(db, "x.example")))


def test_doh_lookup_parses_answers_without_network():
    seen = []

    def fake(url):
        seen.append(url)
        if "type=A&" in url or url.endswith("type=A"):
            return {
                "Status": 0,
                "Answer": [{"type": 1, "data": "192.0.2.4"}, {"type": 5, "data": "c.example."}],
            }
        if "type=MX" in url:
            return {"Status": 0, "Answer": [{"type": 15, "data": "10 Mail.Example."}]}
        return {"Status": 3}

    obs = doh.lookup("A.example", ("A", "MX", "TXT"), now="2025-01-01T00:00:00Z", fetch=fake)
    got = {(o.key, o.value) for o in obs}
    assert got == {("A", "192.0.2.4"), ("MX", "mail.example"), ("TXT", "")}
    assert all(o.source == "doh:cloudflare-dns.com" for o in obs)
    assert all("cloudflare-dns.com" in u and "a.example" in u for u in seen)


def test_doh_rejects_garbage_response():
    try:
        doh.lookup("a.example", ("A",), fetch=lambda u: ["x"])
    except ValueError:
        return
    raise AssertionError("expected ValueError")
