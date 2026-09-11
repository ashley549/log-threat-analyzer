"""Phase 3 verification: ML anomalies vs ground truth + rule overlap."""
import json
import sqlite3

import pandas as pd

conn = sqlite3.connect("db/logsec.db")
gt = json.load(open("data/synthetic/ground_truth.json", encoding="utf-8"))

ml = pd.read_sql("SELECT * FROM detections WHERE rule_id='ML_ANOMALY'", conn)
rules = pd.read_sql("SELECT * FROM detections WHERE rule_id!='ML_ANOMALY'", conn)
events = pd.read_sql("SELECT id, timestamp, source_ip, user, event_type, status FROM events", conn)
events["timestamp"] = pd.to_datetime(events["timestamp"])

print("=== Phase 3: ML anomalies vs planted scenarios ===")
new_catches = []
for s in gt["scenarios"]:
    w0, w1 = pd.Timestamp(s["window"]["start"]), pd.Timestamp(s["window"]["end"])
    attack_ips = set(s["actors"]["source_ips"])
    attack_users = {u for u in s["actors"]["users"] if not u.startswith("~")}
    hits = []
    for _, m in ml.iterrows():
        ids = json.loads(m["matched_event_ids"])
        ev = events[events["id"].isin(ids)]
        in_win = ev[(ev["timestamp"] >= w0) & (ev["timestamp"] <= w1)]
        if in_win.empty:
            continue
        if in_win["source_ip"].isin(attack_ips).any() or in_win["user"].isin(attack_users).any():
            hits.append(m["entity"])
    uniq = sorted(set(hits))
    print(f"  {s['id']} {s['name']:<22} {len(uniq)} ML hit(s): {', '.join(uniq) if uniq else '-'}")

# entities the ML caught that NO rule caught (the phase-3 exit criterion)
print("\n=== ML-only catches (no rule fired on same entity) ===")
rule_entities = set(rules["entity"].str.split("@").str[-1]) | set(rules["entity"])
for _, m in ml.iterrows():
    ent_ip = m["entity"].split("@")[-1].replace(" (source)", "")
    ent_user = m["entity"].split("@")[0]
    rule_hit_same = ent_ip in rule_entities or m["entity"] in rule_entities
    # also check: did any rule's evidence overlap this ML evidence?
    ids = set(json.loads(m["matched_event_ids"]))
    overlap = False
    for _, r in rules.iterrows():
        if ids & set(json.loads(r["matched_event_ids"])):
            overlap = True
            break
    tag = "ML-ONLY" if (not rule_hit_same and not overlap) else "corroborates rules"
    print(f"  {m['entity']:<32} {tag}")

# false positives on clean background noise
print("\n=== FP check: ML anomalies on clean entities ===")
attack_ips = set()
for s in gt["scenarios"]:
    attack_ips |= set(s["actors"]["source_ips"])
fps = []
for _, m in ml.iterrows():
    ids = json.loads(m["matched_event_ids"])
    ev = events[events["id"].isin(ids)]
    if not ev["source_ip"].isin(attack_ips).any() and not (ev["user"] == "svc_bkp").any():
        fps.append(m["entity"])
print(f"  clean-noise FPs: {len(fps)} -> {fps if fps else 'none'}")
