"""Phase 4 verification: incidents vs ground truth + multi-stage collapse check."""
import json
import sqlite3

import pandas as pd

conn = sqlite3.connect("db/logsec.db")
gt = json.load(open("data/synthetic/ground_truth.json", encoding="utf-8"))

inc = pd.read_sql("SELECT * FROM incidents ORDER BY first_seen", conn)
dets = pd.read_sql("SELECT id, rule_id, entity, incident_id, matched_event_ids FROM detections", conn)
events = pd.read_sql("SELECT id, timestamp, source_ip, user, event_type, status FROM events", conn)
events["timestamp"] = pd.to_datetime(events["timestamp"])

EXPECT_INCIDENTS = {
    "S1": "INC-005",  # brute force + compromise: one incident, not two
    "S2": "INC-003",  # spray + both account compromises: one incident
    "S3": "INC-004",  # priv-esc chain
    "S4": "INC-001",  # impossible travel
}

print("=== Phase 4: incidents vs planted scenarios ===")
all_ok = True
for s in gt["scenarios"]:
    w0, w1 = pd.Timestamp(s["window"]["start"]), pd.Timestamp(s["window"]["end"])
    attack_ips = set(s["actors"]["source_ips"])
    attack_users = {u for u in s["actors"]["users"] if not u.startswith("~")}
    if s["id"] == "S3":
        attack_users.add("bob")
    # incidents overlapping this scenario's window with its actors
    hit = set()
    for _, i in inc.iterrows():
        ids = json.loads(i["event_ids"])
        ev = events[events["id"].isin(ids)]
        in_win = ev[(ev["timestamp"] >= w0) & (ev["timestamp"] <= w1)]
        if in_win.empty:
            continue
        if in_win["source_ip"].isin(attack_ips).any() or in_win["user"].isin(attack_users).any():
            hit.add(i["incident_id"])
    want = EXPECT_INCIDENTS[s["id"]]
    ok = hit == {want}
    all_ok &= ok
    print(f"  {s['id']} {s['name']:<22} -> incident(s) {sorted(hit)}  {'PASS (collapsed)' if ok else 'CHECK: expected ' + want}")

# multi-stage collapse: S1 chain check
print("\n=== Multi-stage collapse (exit criterion) ===")
i = inc[inc["incident_id"] == "INC-005"].iloc[0]
det_ids = json.loads(i["detection_ids"])
chain = dets[dets["id"].isin(det_ids)]
stages = sorted(chain["rule_id"].unique())
has_bf = "RULE_BRUTE_FORCE" in stages and "RULE_SUCCESS_AFTER_FAILS" in stages
print(f"  INC-005 stages: {stages}")
print(f"  brute force -> compromise in ONE incident: {'PASS' if has_bf else 'FAIL'}")

# every detection assigned to exactly one incident
assigned = dets["incident_id"].notna().sum()
print(f"\n  detections assigned: {assigned}/{len(dets)}")
print(f"  total incidents: {len(inc)} (expected 5: 4 attacks + 1 benign off-hours)")
print(f"\nALL {'PASS' if all_ok and has_bf and assigned == len(dets) else 'ISSUES FOUND'}")
