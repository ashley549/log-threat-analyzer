"""Incident correlation (Phase 4).

Groups detections into incidents. Two detections belong to the same incident
when ANY of:
  1. ENTITY overlap — they share a principal key (user, ip, or user@ip):
     brute force on root@attacker-ip and the later root login are one story.
  2. TIME + ENTITY-GRAPH proximity — their windows are within LINK_WINDOW
     of each other AND they share at least one entity token (so an account
     compromise correlates with what the attacker then did with the account).
  3. EVIDENCE overlap — they cite the same raw event ids.

Merging is transitive (union-find): brute force -> successful login ->
backdoor user creation collapses into ONE incident even if each pair only
shares part of the chain.

Writes the `incidents` table and stamps detections.incident_id.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from collections import defaultdict

import pandas as pd

from db.schema import init_db, DB_PATH

LINK_WINDOW_MIN = 120   # detections within this gap can be linked if sharing an entity token


# ---------------------------------------------------------------------------
# entity tokenization: one detection -> a set of linkable principals
# ---------------------------------------------------------------------------

def entity_tokens(entity: str) -> set[str]:
    """'root@203.0.113.45' -> {'root@203.0.113.45', 'root', '203.0.113.45'}
    '198.51.100 (source)' -> {'198.51.100', '198.51.100 (source)'}
    '*' entities (ML source-level) keep the raw token only."""
    toks = {entity}
    if "@" in entity:
        user, ip = entity.split("@", 1)
        toks |= {user, ip, entity}
        if user != "*":
            toks.add(f"*@{ip}")          # user-anything-from-this-ip
    return {t for t in toks if t and t.strip()}


# ---------------------------------------------------------------------------
# union-find
# ---------------------------------------------------------------------------

class DSU:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------

def load_detections(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql("SELECT id, rule_id, description, severity_weight, matched_event_ids, entity, first_seen, last_seen FROM detections", conn)
    if df.empty:
        return df
    df["first_ts"] = pd.to_datetime(df["first_seen"])
    df["last_ts"] = pd.to_datetime(df["last_seen"])
    df["evidence"] = df["matched_event_ids"].apply(json.loads)
    df["tokens"] = df["entity"].apply(entity_tokens)
    return df.sort_values("first_ts").reset_index(drop=True)


def correlate(db_path=DB_PATH, link_window_min: int = LINK_WINDOW_MIN) -> dict:
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        dets = load_detections(conn)
        if dets.empty:
            print("No detections — run app.detect and app.detect_ml first.")
            return {"incidents": 0}
        conn.execute("DELETE FROM incidents")
        conn.execute("UPDATE detections SET incident_id = NULL")

        n = len(dets)
        dsu = DSU(n)
        link_delta = pd.Timedelta(minutes=link_window_min)

        # index: entity token -> detection row indices, for pairing through tokens
        by_token: dict[str, list[int]] = defaultdict(list)
        for i, toks in enumerate(dets["tokens"]):
            for t in toks:
                by_token[t].append(i)

        # 1) evidence overlap: same raw events -> same incident (cheap, exact)
        ev_owner: dict[int, int] = {}
        for i, evs in enumerate(dets["evidence"]):
            for e in evs:
                if e in ev_owner:
                    dsu.union(i, ev_owner[e])
                else:
                    ev_owner[e] = i

        # 2) entity-token + time proximity (and pure token overlap is enough
        #    when the same principal recurs, regardless of gap)
        for i in range(n):
            a_first, a_last = dets.at[i, "first_ts"], dets.at[i, "last_ts"]
            a_tokens = dets.at[i, "tokens"]
            for t in a_tokens:
                for j in by_token[t]:
                    if j <= i:
                        continue
                    b_first, b_last = dets.at[j, "first_ts"], dets.at[j, "last_ts"]
                    gap = max(b_first - a_last, a_first - b_last, pd.Timedelta(0))
                    # same principal token: link if windows within LINK_WINDOW of each other
                    if gap <= link_delta:
                        dsu.union(i, j)

        # assemble groups
        groups: dict[int, list[int]] = defaultdict(list)
        for i in range(n):
            groups[dsu.find(i)].append(i)

        # span discipline: a chain of detections sharing tokens can stretch over
        # months of recurring activity (e.g. every nightly off-hours login).
        # An incident is a BURST, not a recurring pattern — split any group
        # whose detections span more than MAX_INCIDENT_SPAN into time clusters
        # (gap-based: consecutive detections > LINK_WINDOW apart start a new one).
        max_gap = pd.Timedelta(minutes=link_window_min)
        final_groups: list[list[int]] = []
        for members in groups.values():
            if not members:
                continue
            members = sorted(members, key=lambda i: dets.at[i, "first_ts"])
            cluster = [members[0]]
            for i in members[1:]:
                gap = dets.at[i, "first_ts"] - dets.at[cluster[-1], "last_ts"]
                if gap > max_gap:
                    final_groups.append(cluster)
                    cluster = [i]
                else:
                    cluster.append(i)
            final_groups.append(cluster)

        # name + persist incidents in chronological order
        inc_rows, det_updates = [], []
        seq = 0
        for members in sorted(final_groups, key=lambda m: dets.at[m[0], "first_ts"]):
            if not members:
                continue
            seq += 1
            inc_id = f"INC-{seq:03d}"
            sub = dets.loc[members]
            first_ts = sub["first_ts"].min()
            last_ts = sub["last_ts"].max()
            # entity label: prefer the most informative token (user@ip with fewest '*')
            all_tokens = [t for toks in sub["tokens"] for t in toks]
            core_tokens = [t for t in all_tokens if "@" in t and not t.startswith("*")]
            label = sorted(set(core_tokens))[0] if core_tokens else sorted(set(all_tokens))[0]
            ev_ids = sorted({e for evs in sub["evidence"] for e in evs})
            inc_rows.append((
                inc_id, label,
                first_ts.strftime("%Y-%m-%d %H:%M:%S"),
                last_ts.strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(sorted(sub["id"].tolist())),
                json.dumps(ev_ids),
                len(sub), len(ev_ids),
            ))
            for det_id in sub["id"]:
                det_updates.append((inc_id, det_id))

        conn.executemany(
            "INSERT INTO incidents (incident_id, entity, first_seen, last_seen, detection_ids, event_ids, n_detections, n_events) VALUES (?,?,?,?,?,?,?,?)",
            inc_rows)
        conn.executemany("UPDATE detections SET incident_id=? WHERE id=?", det_updates)
        conn.commit()

    print(f"Correlated {n} detections -> {len(inc_rows)} incidents")
    for r in inc_rows:
        print(f"  {r[0]}  {r[1]:<28} {r[2]} -> {r[3]}  ({r[6]} detections, {r[7]} events)")
    return {"incidents": len(inc_rows)}


if __name__ == "__main__":
    correlate()
