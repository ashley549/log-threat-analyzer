"""AI-assisted incident recommendations (Phase 6).

For every incident:
  1. Build a compact structured prompt (entity, detections, risk, evidence
     digest — never raw log lines).
  2. Call the Gemini API (free tier) for the write-up; if no key, no network,
     or a flaky/quota'd API, degrade gracefully to a deterministic playbook stub.
  3. Cache the generated text in incidents.recommendation (regenerated only
     when missing).

Everything is isolated behind generate_recommendation(incident) -> str.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
import time
from datetime import datetime, timezone

import pandas as pd

from db.schema import init_db, DB_PATH

# ---------------------------------------------------------------------------
# .env loading (no python-dotenv dependency) — lets GEMINI_API_KEY live in
# <project>/.env without a shell profile change. Runs at import time, before
# any generate_recommendation() call, and never overrides real env vars.
# ---------------------------------------------------------------------------


def _load_dotenv() -> None:
    p = Path(__file__).resolve().parent.parent / ".env"
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)
    except OSError:
        pass  # no .env file — fine


_load_dotenv()

MAX_EVIDENCE_ROWS = 12          # rows of digest in the prompt
REQUEST_TIMEOUT = 20            # seconds per LLM attempt
GEMINI_MODEL = "gemini-3.5-flash-lite"   # current free-tier model (2.5 is closed to new keys); see _try_gemini


# ---------------------------------------------------------------------------
# structured incident payload (prompt source — no raw logs)
# ---------------------------------------------------------------------------

def build_payload(inc: pd.Series, dets: pd.DataFrame, ev: pd.DataFrame) -> dict:
    """Compact, structured summary of the incident for the LLM."""
    logins = ev[ev["event_type"] == "ssh_login"] if not ev.empty else ev
    digest = {
        "n_failed_logins": int((logins["status"] == "fail").sum()) if not logins.empty else 0,
        "n_successful_logins": int((logins["status"] == "success").sum()) if not logins.empty else 0,
        "distinct_users_targeted": int(logins["user"].nunique()) if not logins.empty else 0,
        "distinct_source_ips": int(logins["source_ip"].nunique()) if not logins.empty else 0,
        "n_hosts_touched": int(ev["host"].nunique()) if not ev.empty else 0,
    }
    if not logins.empty:
        digest["off_hours"] = bool(((logins["timestamp"].dt.hour >= 22)
                                    | (logins["timestamp"].dt.hour < 5)).any())
    if not ev.empty:
        digest["new_accounts_created"] = sorted(
            ev.loc[ev["event_type"] == "user_added", "user"].dropna().unique().tolist())
        digest["account_modified"] = sorted(
            ev.loc[ev["event_type"] == "user_modified", "user"].dropna().unique().tolist())

    return {
        "incident_id": inc["incident_id"],
        "entity": inc["entity"],
        "risk_level": inc["risk_level"],
        "risk_score": inc["risk_score"],
        "time_range": {"start": inc["first_seen"], "end": inc["last_seen"]},
        "n_events": int(inc["n_events"]),
        "detections": [
            {"rule": d["rule_id"], "severity": d["severity_weight"],
             "summary": d["description"][:220]}
            for _, d in dets.iterrows()
        ],
        "risk_breakdown": [
            {"factor": c, "value": v["value"], "reason": v["reason"]}
            for c, v in (json.loads(inc["risk_breakdown"]) if inc["risk_breakdown"] else {}).items()
            if isinstance(v, dict)
        ],
        "evidence_digest": digest,
    }


def build_prompt(payload: dict) -> str:
    return (
        "You are a senior security analyst. Write an incident explanation and "
        "remediation recommendation for a SOC team.\n\n"
        "Output format (strict — do not use markdown headings or bold):\n"
        "SUMMARY:\n"
        "2-4 sentences of plain English explaining what happened and why it is risky.\n\n"
        "RECOMMENDED ACTIONS:\n"
        "- 2-4 concrete, immediately actionable steps, each on its own line starting "
        "with '- ' (specific commands/controls, not generic advice).\n\n"
        "Be factual; only use the incident data below.\n\n"
        f"INCIDENT DATA:\n{json.dumps(payload, indent=2, default=str)}\n"
    )


# ---------------------------------------------------------------------------
# provider chain: gemini -> deterministic template
# ---------------------------------------------------------------------------


def _try_gemini(prompt: str) -> str | None:
    """Google Gemini via plain REST (no SDK dep). Free-tier friendly: falls
    back through two flash-class models on 404s, single attempt per model
    (429 → deterministic fallback, never hangs a demo)."""
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return None
    try:
        import requests  # optional dep; fail soft if absent
    except ImportError:
        print("  [gemini] requests not installed — skipping")
        return None
    for model in (GEMINI_MODEL, "gemini-3.5-flash"):
        try:
            r = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                params={"key": key},
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"maxOutputTokens": 600, "temperature": 0.3}},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code == 404:
                continue          # model unavailable for this key → try next
            if r.status_code in (429, 403):
                print(f"  [gemini] {model}: rate-limited/forbidden — falling back")
                return None       # quota gone for today → don't burn attempts
            r.raise_for_status()
            data = r.json()
            parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts).strip()
            if text:
                return text
            # 200 but empty (safety block / MAX_TOKENS with no text) → try next model
            print(f"  [gemini] {model}: empty candidate — trying fallback model")
        except Exception as e:
            print(f"  [gemini] unavailable: {type(e).__name__}: {e}")
            return None
    return None


# rule-type -> targeted, concrete response playbook
_PLAYBOOK = {
    "RULE_BRUTE_FORCE": [
        "Block the source IP at the edge firewall and add it to fail2ban's deny list",
        "Disable password auth for SSH (public key only) in /etc/ssh/sshd_config",
    ],
    "RULE_SUCCESS_AFTER_FAILS": [
        "Assume the account is compromised: reset its password and revoke all active sessions (pkill -u, or terminate via IdP)",
        "Rotate any keys/credentials issued to this account and audit recent commands it ran",
    ],
    "RULE_CRED_STUFFING": [
        "Block the attacking subnet (all source IPs) and enable MFA on all exposed accounts",
        "Force a password reset for every account that saw a successful login in the incident window",
    ],
    "RULE_IMPOSSIBLE_TRAVEL": [
        "Kill the remote session for this user and reset their credentials",
        "Require step-up MFA verification for logins from new geolocations (IdP conditional access)",
    ],
    "RULE_BACKDOOR_USER": [
        f"Lock the backdoor account immediately: `usermod -L <account>`; then review /etc/sudoers and group memberships it gained",
        "Hunt for other persistence: check cron, systemd units, authorized_keys on all hosts",
    ],
    "RULE_OFFHOURS_LOGIN": [
        "Verify with the user whether this login was legitimate (could be on-call work)",
        "If unconfirmed, shorten session TTLs and alert on interactive logins outside business hours",
    ],
    "RULE_WEB_RECON": [
        "Block the scanning IP at the WAF/edge and rate-limit 404s per source IP",
        "Confirm none of the probed paths exist (admin panels, .env, .git) — if any do, restrict access and rotate any exposed secrets",
    ],
    "RULE_SQLI_ATTEMPT": [
        "Block the source IP and enable WAF SQL-injection rules (modsecurity or equivalent)",
        "Parameterize the queries behind the affected endpoint(s) and check logs for successful (2xx) injections",
    ],
    "ML_ANOMALY": [
        "Review the flagged windows below; confirm with the user whether the behavior was expected",
    ],
}


def _template_fallback(payload: dict) -> str:
    """Deterministic analyst-quality text when no LLM is reachable."""
    d = payload["evidence_digest"]
    rules = [x["rule"] for x in payload["detections"]]
    entity = payload["entity"]
    ip = entity.split("@")[-1]
    user = entity.split("@")[0]

    # ---- summary --------------------------------------------------------
    parts = []
    parts.append(
        f"Between {payload['time_range']['start']} and {payload['time_range']['end']}, "
        f"the system observed suspicious activity involving {entity} "
        f"({payload['n_events']} related events across {len(payload['detections'])} detection(s))."
    )
    if d["n_failed_logins"] or d["n_successful_logins"]:
        parts.append(
            f"Login activity: {d['n_failed_logins']} failed and {d['n_successful_logins']} "
            f"successful attempt(s) targeting {d['distinct_users_targeted']} user(s) "
            f"from {d['distinct_source_ips']} source IP(s)."
        )
    if d.get("new_accounts_created"):
        parts.append(f"New account(s) were created during the window: {', '.join(d['new_accounts_created'])}.")
    if d.get("off_hours"):
        parts.append("The activity occurred outside normal business hours.")
    why = "; ".join(f["reason"] for f in payload["risk_breakdown"]
                    if f["factor"] in ("rule_severity", "outcome", "ml_anomaly") and f["value"] > 0)
    if why:
        parts.append(f"Risk factors: {why}.")
    summary = " ".join(parts)

    # ---- recommended actions ---------------------------------------------
    actions: list[str] = []
    for r in rules:
        for a in _PLAYBOOK.get(r, []):
            a = a.replace("<account>", user).replace("<entity>", entity)
            if a not in actions:
                actions.append(a)
    if d.get("new_accounts_created"):
        for acc in d["new_accounts_created"]:
            act = f"Disable the new account '{acc}' immediately: `usermod -L {acc}`"
            if act not in actions:
                actions.insert(0, act)
    if not actions:
        actions.append("Investigate the raw events for this incident and validate with the account owner.")
    actions = actions[:4]

    note = ("\n\n[generated by built-in playbook template — no LLM API configured; "
            "set GEMINI_API_KEY for AI-written recommendations]")
    return (f"SUMMARY: {summary}\n\nRECOMMENDED ACTIONS:\n"
            + "\n".join(f"- {a}" for a in actions) + note)


def generate_recommendation(incident: pd.Series | dict, dets: pd.DataFrame | None = None,
                            ev: pd.DataFrame | None = None) -> str:
    """One-function interface (swappable/stubbable). Accepts an incident row
    plus its detections/evidence; returns explanation + recommended actions."""
    inc = incident if isinstance(incident, pd.Series) else pd.Series(incident)
    payload = build_payload(inc, dets if dets is not None else pd.DataFrame(),
                            ev if ev is not None else pd.DataFrame())
    prompt = build_prompt(payload)
    text = (_try_gemini(prompt)
            or _template_fallback(payload))
    return text


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def recommend_all(db_path=DB_PATH, force: bool = False) -> dict:
    init_db(db_path)
    with closing(sqlite3.connect(db_path)) as conn:
        inc = pd.read_sql("SELECT * FROM incidents", conn)
        if inc.empty:
            print("No incidents — run app.correlate + app.score first.")
            return {"recommended": 0}
        dets = pd.read_sql("SELECT id, rule_id, description, severity_weight, entity, incident_id FROM detections", conn)
        ev_all = pd.read_sql("SELECT id, timestamp, user, source_ip, event_type, status, host FROM events", conn)
        if not ev_all.empty:
            ev_all["timestamp"] = pd.to_datetime(ev_all["timestamp"])

        updates = []
        for _, i in inc.iterrows():
            if i["recommendation"] and not force:
                continue  # cache hit
            sub = dets[dets["incident_id"] == i["incident_id"]]
            ev = ev_all[ev_all["id"].isin(json.loads(i["event_ids"]))] if not ev_all.empty else ev_all
            t0 = time.perf_counter()
            text = generate_recommendation(i, sub, ev)
            ms = (time.perf_counter() - t0) * 1000
            updates.append((text, i["incident_id"]))
            print(f"  {i['incident_id']}: recommendation generated [{ms:.0f} ms, {len(text)} chars]")
        if updates:
            conn.executemany("UPDATE incidents SET recommendation=? WHERE incident_id=?", updates)
            conn.commit()

    print(f"Recommendations cached for {len(updates)}/{len(inc)} incident(s)")
    return {"recommended": len(updates), "total": len(inc)}


if __name__ == "__main__":
    recommend_all()
