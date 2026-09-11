"""SQLite setup for the Log Security Analyzer."""
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "logsec.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    user TEXT,
    event_type TEXT NOT NULL,
    status TEXT,
    host TEXT,
    raw_line TEXT NOT NULL,
    source_file TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user ON events (user);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    description TEXT NOT NULL,
    severity_weight REAL NOT NULL,
    matched_event_ids TEXT NOT NULL,          -- JSON list of event ids (evidence trail)
    entity TEXT,                              -- principal the rule fired on (user / ip / user@ip)
    first_seen TEXT,
    last_seen TEXT,
    incident_id TEXT                           -- set by app.correlate
);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections (rule_id);
CREATE INDEX IF NOT EXISTS idx_detections_entity ON detections (entity);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT UNIQUE NOT NULL,          -- INC-001, assigned by first_seen order
    entity TEXT NOT NULL,                      -- merged principal label
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    detection_ids TEXT NOT NULL,               -- JSON list of detection ids
    event_ids TEXT NOT NULL,                   -- JSON union of evidence event ids
    n_detections INTEGER NOT NULL,
    n_events INTEGER NOT NULL,
    risk_score REAL,                           -- 0..10, set by app.score
    risk_level TEXT,                           -- 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low
    risk_breakdown TEXT,                        -- JSON: per-component value + reason
    recommendation TEXT                        -- cached AI/plain-English remediation text
);
"""

def init_db(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(SCHEMA)
        # lightweight migration: older DBs predate risk columns
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
        for col_sql in (
            "ALTER TABLE incidents ADD COLUMN risk_score REAL",
            "ALTER TABLE incidents ADD COLUMN risk_level TEXT",
            "ALTER TABLE incidents ADD COLUMN risk_breakdown TEXT",
            "ALTER TABLE incidents ADD COLUMN recommendation TEXT",
        ):
            col = col_sql.split("ADD COLUMN ")[1].split()[0]
            if col not in cols:
                conn.execute(col_sql)
        conn.commit()

if __name__ == "__main__":
    init_db()
    print(f"DB ready at {DB_PATH}")
