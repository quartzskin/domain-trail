import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime

from .importer import Observation, normalize_domain, normalize_time

RESOLVER = "https://cloudflare-dns.com/dns-query"
RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def _get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def _clean(rtype, data):
    data = data.strip()
    if rtype == "TXT":
        return data.strip('"')
    if rtype == "MX":
        data = data.split(None, 1)[-1]
    return data.rstrip(".").lower()


def lookup(domain, rtypes=("A", "AAAA", "NS", "MX", "TXT"), now=None, fetch=_get,
           resolver=RESOLVER):
    """Ask a DoH resolver about the domain. Nothing is sent to the domain's own servers."""
    domain = normalize_domain(domain)
    when = normalize_time(now) if now else datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    source = "doh:" + urllib.parse.urlparse(resolver).netloc
    out = []
    for rtype in rtypes:
        url = f"{resolver}?{urllib.parse.urlencode({'name': domain, 'type': rtype})}"
        resp = fetch(url)
        if not isinstance(resp, dict):
            raise ValueError(f"unexpected resolver response for {rtype}")
        want = RTYPES[rtype]
        answers = resp.get("Answer") or []
        values = sorted({
            _clean(rtype, a["data"]) for a in answers
            if isinstance(a, dict) and a.get("type") == want and isinstance(a.get("data"), str)
        })
        for v in values or [""]:
            out.append(Observation(domain, "dns", rtype, v, "{}", source, when, 0.8))
    return out
