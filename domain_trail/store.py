import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    detail TEXT NOT NULL,
    source TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    confidence REAL,
    UNIQUE (domain, kind, key, value, source, retrieved_at)
);
CREATE INDEX IF NOT EXISTS obs_domain ON observations (domain, retrieved_at);
"""


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


def add(db, observations):
    before = db.total_changes
    with db:
        db.executemany(
            "INSERT OR IGNORE INTO observations"
            " (domain, kind, key, value, detail, source, retrieved_at, confidence)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (o.domain, o.kind, o.key, o.value, o.detail, o.source, o.retrieved_at, o.confidence)
                for o in observations
            ],
        )
    return db.total_changes - before


def domains(db):
    return db.execute(
        "SELECT domain, COUNT(*) n, MIN(retrieved_at) first, MAX(retrieved_at) last"
        " FROM observations GROUP BY domain ORDER BY domain"
    ).fetchall()


def for_domain(db, domain):
    return db.execute(
        "SELECT * FROM observations WHERE domain = ? ORDER BY retrieved_at, id", (domain,)
    ).fetchall()
