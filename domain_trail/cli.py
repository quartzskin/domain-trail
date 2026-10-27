import argparse
import json
import sys

from . import doh, events, importer, store
from .render import render


def _parser():
    p = argparse.ArgumentParser(prog="domain-trail")
    p.add_argument("--db", default="domain-trail.db", help="SQLite file (default: %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("import", help="load observations from JSON files")
    s.add_argument("files", nargs="+")
    sub.add_parser("domains", help="list stored domains")
    s = sub.add_parser("events", help="print change events for a domain")
    s.add_argument("domain")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("timeline", help="write an HTML timeline for a domain")
    s.add_argument("domain")
    s.add_argument("-o", "--output", default="timeline.html")
    s = sub.add_parser("lookup", help="query a DNS-over-HTTPS resolver and store the answers")
    s.add_argument("domain")
    s.add_argument("--online", action="store_true", help="required; allows network access")
    s.add_argument("--types", default="A,AAAA,NS,MX,TXT")
    return p


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except importer.InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _run(args):
    if args.cmd == "lookup" and not args.online:
        print(
            "error: lookup talks to a public resolver; pass --online to allow it", file=sys.stderr
        )
        return 2
    db = store.connect(args.db)
    if args.cmd == "import":
        total = added = 0
        for path in args.files:
            obs = importer.load(path)
            total += len(obs)
            added += store.add(db, obs)
        print(f"{added} new rows ({total - added} already stored)")
    elif args.cmd == "domains":
        for r in store.domains(db):
            print(f"{r['domain']}  {r['n']} rows  {r['first']} .. {r['last']}")
    elif args.cmd == "lookup":
        rtypes = [t.strip().upper() for t in args.types.split(",") if t.strip()]
        bad = [t for t in rtypes if t not in doh.RTYPES]
        if bad:
            raise importer.InputError(f"unsupported record types: {', '.join(bad)}")
        try:
            obs = doh.lookup(args.domain, rtypes)
        except (OSError, ValueError) as e:
            print(f"error: lookup failed: {e}", file=sys.stderr)
            return 1
        print(f"{store.add(db, obs)} new rows from {obs[0].source}")
    else:
        domain = importer.normalize_domain(args.domain)
        evs = events.compute(store.for_domain(db, domain))
        if args.cmd == "events":
            if args.json:
                print(json.dumps(evs, indent=2))
            for e in [] if args.json else evs:
                conf = "" if e["confidence"] is None else f" conf={e['confidence']:.2f}"
                print(f"{e['ts']}  {e['type']:<17} {e['summary']}  [{e['source']}{conf}]")
        else:
            with open(args.output, "w", encoding="utf-8", newline="\n") as f:
                f.write(render(domain, evs))
            print(f"wrote {args.output} ({len(evs)} events)")
    return 0
