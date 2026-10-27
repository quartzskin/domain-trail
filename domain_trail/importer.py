import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

DNS_TYPES = {"A", "AAAA", "NS", "MX", "TXT", "CNAME"}
KINDS = {"dns", "cert", "report", "whois"}
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Observation:
    domain: str
    kind: str
    key: str
    value: str
    detail: str
    source: str
    retrieved_at: str
    confidence: float | None


def normalize_domain(name):
    if not isinstance(name, str):
        raise InputError(f"domain must be a string, got {name!r}")
    name = name.strip().lower().rstrip(".")
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        raise InputError(f"invalid domain name: {name!r}")
    return name


def normalize_time(value):
    if not isinstance(value, str):
        raise InputError(f"timestamp must be an ISO 8601 string, got {value!r}")
    try:
        ts = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise InputError(f"bad timestamp: {value!r}") from None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(item, field, where):
    v = item.get(field)
    if not isinstance(v, str) or not v.strip():
        raise InputError(f"{where}: missing or empty {field!r}")
    return v.strip()


def _optional_time(data, field, where):
    if data.get(field) is None:
        return None
    try:
        return normalize_time(data[field])
    except InputError as e:
        raise InputError(f"{where}: {field}: {e}") from None


def _confidence(item, where):
    c = item.get("confidence")
    if c is None:
        return None
    if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0 <= c <= 1:
        raise InputError(f"{where}: confidence must be a number between 0 and 1")
    return float(c)


def _rows(kind, data, where):
    if not isinstance(data, dict):
        raise InputError(f"{where}: 'data' must be an object")
    if kind == "dns":
        rtype = str(data.get("type", "")).upper()
        if rtype not in DNS_TYPES:
            raise InputError(f"{where}: unsupported record type {data.get('type')!r}")
        values = data.get("values")
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise InputError(f"{where}: 'values' must be a list of strings")
        clean = sorted(
            {
                v.strip().rstrip(".").lower() if rtype != "TXT" else v.strip()
                for v in values
                if v.strip()
            }
        )
        return [(rtype, v, "{}") for v in clean] or [(rtype, "", "{}")]
    if kind == "cert":
        names = data.get("names", [])
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise InputError(f"{where}: 'names' must be a list of strings")
        detail = {
            "issuer": _text(data, "issuer", where),
            "names": sorted({n.strip().lower() for n in names}),
            "not_before": _optional_time(data, "not_before", where),
            "not_after": _optional_time(data, "not_after", where),
        }
        return [("cert", _text(data, "serial", where).lower(), json.dumps(detail))]
    if kind == "report":
        detail = {"title": str(data.get("title") or "")}
        url = _text(data, "url", where)
        if not re.match(r"^https?://", url):
            raise InputError(f"{where}: report url must be http(s)")
        return [("report", url, json.dumps(detail))]
    registrar = data.get("registrar")
    created = _optional_time(data, "created", where)
    if registrar is None and created is None:
        raise InputError(f"{where}: whois needs 'registrar' or 'created'")
    detail = {"created": created}
    return [("whois", str(registrar or "").strip(), json.dumps(detail))]


def parse(doc):
    if isinstance(doc, dict):
        doc = doc.get("observations")
    if not isinstance(doc, list):
        raise InputError("expected a list of observations or {'observations': [...]}")
    out = []
    for i, item in enumerate(doc):
        where = f"observation {i}"
        if not isinstance(item, dict):
            raise InputError(f"{where}: not an object")
        kind = item.get("kind")
        if kind not in KINDS:
            raise InputError(f"{where}: kind must be one of {sorted(KINDS)}")
        domain = normalize_domain(item.get("domain"))
        source = _text(item, "source", where)
        when = normalize_time(item.get("retrieved_at"))
        conf = _confidence(item, where)
        for key, value, detail in _rows(kind, item.get("data"), where):
            out.append(Observation(domain, kind, key, value, detail, source, when, conf))
    return out


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise InputError(f"cannot read {path}: {e.strerror}") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InputError(f"{path}: not valid JSON ({e})") from None
    return parse(doc)
