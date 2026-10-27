# domain-trail

Keeps a history of what was observed about a domain (DNS records, certificates, whois-style
registrar data, links to public reports), works out what changed between observations, and
writes a single-file HTML timeline for it. Every marker carries where the data came from, when
it was retrieved, and how sure the source was.

Python standard library only (3.12+, developed on 3.14). Dev tools: pytest and ruff.

## Usage

    python -m domain_trail import samples/observations.json
    python -m domain_trail domains
    python -m domain_trail events login-update.example
    python -m domain_trail timeline login-update.example -o timeline.html

`--db` picks the SQLite file (default `domain-trail.db` in the current directory). Importing the
same file twice adds nothing.

Input is a JSON list (or `{"observations": [...]}`). Each item has `domain`, `kind`, `source`,
`retrieved_at` (ISO 8601), an optional `confidence` between 0 and 1, and a `data` object:

- `dns`: `{"type": "A", "values": [...]}`. An empty list means "no such record" at that time.
- `cert`: `serial`, `issuer`, and optionally `names`, `not_before`, `not_after`.
- `report`: `url`, optional `title`.
- `whois`: `registrar` and/or `created`.

See `samples/observations.json`; all names in it are made up (`.example` and `.test`, documentation
IP ranges). Bad input aborts the whole file with a message and stores nothing from it.

Events: first/last observation, A/AAAA/NS/MX/TXT/CNAME changes (added and removed values),
certificate issued, registered, registrar changed, report links. DNS sets are compared per
source, so two feeds that disagree do not look like a flapping record.

### Online lookup

    python -m domain_trail lookup suspicious.example --online

This asks a public DNS-over-HTTPS resolver (Cloudflare) for A, AAAA, NS, MX and TXT and stores the
answers as observations with source `doh:cloudflare-dns.com`. Nothing is sent to the domain's own
servers, and nothing is fetched from the domain. Without `--online` the command refuses to run.
The resolver sees the name you ask about.

## Limits

- The online lookup is not exercised by the tests against a real resolver, only against canned
  responses. Its output is the resolver's cached view, not necessarily what authoritative servers say.
- Only DNS has an online source; certificates, whois and reports must be imported.
- Confidence is whatever the importer supplies; it is shown, not combined or used for judgement.
- The timeline puts markers at event time on a linear scale, so dense clusters overlap.
  Hover or read the table below the chart.
- A record set that goes missing in one snapshot is reported as removed, even if the cause was a
  failed lookup. Check the source and confidence.
- Timestamps without a zone are read as UTC.

## Development

    pip install pytest ruff
    ruff check .
    pytest
