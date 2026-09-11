"""Chunked log ingestion into SQLite.

Streams the file line-by-line, hands batches of CHUNK lines to the parser,
and bulk-inserts normalized rows into the events table. Malformed lines are
kept as event_type='malformed' rows (never dropped silently, never fatal).
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
import time
from pathlib import Path

import pandas as pd

from app.parsers import PARSERS, COLUMNS

CHUNK = 50_000

INSERT_SQL = """
INSERT INTO events (timestamp, source_ip, user, event_type, status, host, raw_line, source_file)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""


def _df_to_rows(df: pd.DataFrame):
    """DataFrame -> list of tuples with ISO timestamps (NaT -> NULL-safe)."""
    ts = df["timestamp"]
    iso = ts.dt.strftime("%Y-%m-%d %H:%M:%S").where(ts.notna(), None)
    zipped = zip(
        iso, df["source_ip"], df["user"], df["event_type"], df["status"],
        df["host"], df["raw_line"], df["source_file"],
    )
    return [tuple(None if v is pd.NA else v for v in row) for row in zipped]


def ingest_file(path: str | Path, conn: sqlite3.Connection,
                fmt: str = "auth", year: int = 2026,
                chunk_size: int = CHUNK) -> dict:
    """Ingest one log file. Returns stats dict."""
    path = Path(path)
    if fmt not in PARSERS:
        raise ValueError(f"unknown format {fmt!r}; supported: {list(PARSERS)}")

    parse = PARSERS[fmt]
    total = parsed = malformed = 0
    rejected: list[str] = []       # first N rejected lines, for diagnostics UI
    encoding_used = "utf-8"
    t0 = time.perf_counter()

    # idempotent: re-ingesting the same file replaces, not duplicates
    conn.execute("DELETE FROM events WHERE source_file = ?", (path.name,))

    def flush(lines: list[str]):
        nonlocal total, parsed, malformed
        if not lines:
            return
        df = parse(lines, source_file=path.name, **({"year": year} if fmt == "auth" else {}))
        # rows with no timestamp can't be queried usefully -> capture for diagnostics
        ts_bad = df["timestamp"].isna()
        n_bad = int(ts_bad.sum())
        if n_bad:
            rejected.extend(df.loc[ts_bad, "raw_line"].tolist()[:20 - len(rejected)])
        df = df.loc[~ts_bad]
        total += len(lines)
        if df.empty:
            return
        rows = _df_to_rows(df)
        conn.executemany(INSERT_SQL, rows)
        parsed += int((df["event_type"] != "malformed").sum())
        malformed += int((df["event_type"] == "malformed").sum())

    with open(path, encoding="utf-8", errors="replace") as f:
        buf: list[str] = []
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            buf.append(line)
            if len(buf) >= chunk_size:
                flush(buf)
                buf = []
        flush(buf)

    conn.commit()
    # count blank/whitespace-only lines too (they were filtered pre-chunking)
    blank = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                blank += 1
    return {
        "file": str(path),
        "format": fmt,
        "total_lines": total,
        "parsed": parsed,
        "malformed_kept": malformed,
        "rejected_lines": rejected,           # sample of unparseable lines (diagnostics)
        "n_rejected": total - parsed,          # every non-parsed line counts as rejected
        "n_blank": blank,
        "encoding": encoding_used,
        "seconds": round(time.perf_counter() - t0, 2),
        "lines_per_sec": int(total / max(time.perf_counter() - t0, 1e-9)),
    }


def ingest(files: list[tuple[str, str]] | None = None,
          db_path: str | Path = "db/logsec.db", year: int = 2026) -> dict:
    """Ingest multiple files: [(path, format), ...]. Defaults to synthetic auth.log."""
    from db.schema import init_db
    db = Path(db_path)
    init_db(db)

    if files is None:
        files = [("data/synthetic/auth.log", "auth")]

    stats = []
    with closing(sqlite3.connect(db)) as conn:
        for path, fmt in files:
            stats.append(ingest_file(path, conn, fmt, year))
    return {"db": str(db), "files": stats}


if __name__ == "__main__":
    import pprint
    pprint.pprint(ingest(), sort_dicts=False)
