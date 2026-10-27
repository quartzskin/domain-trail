import json

import pytest

from domain_trail import importer
from domain_trail.importer import InputError, parse


def obs(**kw):
    base = {"domain": "a.example", "kind": "dns", "source": "s",
            "retrieved_at": "2025-01-01T00:00:00Z", "data": {"type": "A", "values": ["192.0.2.1"]}}
    base.update(kw)
    return base


def test_normalizes_domain_and_time():
    [o] = parse([obs(domain="A.Example.", retrieved_at="2025-01-01T02:00:00+02:00")])
    assert o.domain == "a.example"
    assert o.retrieved_at == "2025-01-01T00:00:00Z"


def test_dns_values_dedup_and_sorted():
    rows = parse([obs(data={"type": "ns", "values": ["B.example.", "a.example", "b.example"]})])
    assert [r.value for r in rows] == ["a.example", "b.example"]
    assert rows[0].key == "NS"


def test_empty_values_keeps_a_marker_row():
    [r] = parse([obs(data={"type": "A", "values": []})])
    assert r.value == ""


def test_wrapped_and_bare_lists_both_work():
    assert len(parse({"observations": [obs()]})) == len(parse([obs()])) == 1


@pytest.mark.parametrize("bad", [
    None, "text", 5, {"observations": "x"}, [1], [{}],
    [obs(kind="http")],
    [obs(domain="nodot")],
    [obs(domain="bad_domain!.example")],
    [obs(domain=7)],
    [obs(source="")],
    [obs(retrieved_at="yesterday")],
    [obs(retrieved_at=None)],
    [obs(confidence=1.5)],
    [obs(confidence=True)],
    [obs(data=[])],
    [obs(data={"type": "SRV", "values": []})],
    [obs(data={"type": "A", "values": "1.2.3.4"})],
    [obs(data={"type": "A", "values": [1]})],
    [obs(kind="cert", data={"issuer": "x"})],
    [obs(kind="cert", data={"serial": "1", "issuer": "x", "not_before": "nope"})],
    [obs(kind="report", data={"url": "javascript:alert(1)"})],
    [obs(kind="whois", data={})],
])
def test_rejects_malformed(bad):
    with pytest.raises(InputError):
        parse(bad)


def test_load_reports_bad_json_and_missing_file(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="not valid JSON"):
        importer.load(p)
    with pytest.raises(InputError, match="cannot read"):
        importer.load(tmp_path / "missing.json")
    p.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(InputError):
        importer.load(p)


def test_load_ok(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps([obs()]), encoding="utf-8")
    assert len(importer.load(p)) == 1
