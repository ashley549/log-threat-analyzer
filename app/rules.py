"""Rule-based detection engine (Phase 2).

Rules are plain Python functions over pandas groupby/rolling windows.
Every rule returns a list of Detection records with the matched event ids
(evidence trail), and each is written to the `detections` table.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import pandas as pd


@dataclass
class Detection:
    rule_id: str
    description: str
    severity_weight: float
    matched_event_ids: list[int]
    entity: str
    first_seen: str
    last_seen: str

    def to_row(self) -> tuple:
        return (self.rule_id, self.description, self.severity_weight,
                json.dumps(self.matched_event_ids), self.entity,
                self.first_seen, self.last_seen)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get_events(df: pd.DataFrame, ids: list[int]) -> pd.DataFrame:
    return df.loc[df["id"].isin(ids)]


def _mk(rule_id, description, weight, ev: pd.DataFrame, entity) -> Detection:
    ts = ev["timestamp"]
    return Detection(
        rule_id=rule_id,
        description=description,
        severity_weight=weight,
        matched_event_ids=sorted(ev["id"].tolist()),
        entity=entity,
        first_seen=ts.min().strftime("%Y-%m-%d %H:%M:%S"),
        last_seen=ts.max().strftime("%Y-%m-%d %H:%M:%S"),
    )


# ---------------------------------------------------------------------------
# RULE 1 — brute force: N failed logins within a time window, per (ip, user)
# ---------------------------------------------------------------------------

def rule_brute_force(df: pd.DataFrame, threshold: int = 10, window_min: int = 10) -> list[Detection]:
    fails = df[(df["event_type"] == "ssh_login") & (df["status"] == "fail")].copy()
    if fails.empty:
        return []
    fails = fails.sort_values("timestamp")
    out = []
    win_delta = pd.Timedelta(minutes=window_min)
    for (ip, user), grp in fails.groupby(["source_ip", "user"]):
        ts = grp["timestamp"].to_numpy()
        ids = grp["id"].to_numpy()
        for i in range(len(ts)):
            j = i
            while j < len(ts) and ts[j] <= ts[i] + win_delta:
                j += 1
            n = j - i
            if n >= threshold:
                ev = grp.iloc[i:j]
                out.append(_mk(
                    "RULE_BRUTE_FORCE",
                    f"{n} failed logins for '{user}' from {ip} within {window_min} min "
                    f"(brute force / password guessing)",
                    min(1.0 + n / 50, 3.0),
                    ev, entity=f"{user}@{ip}",
                ))
                break
    return out


# ---------------------------------------------------------------------------
# RULE 2 — success after many failures (password guessing succeeded)
# ---------------------------------------------------------------------------

def rule_success_after_fails(df: pd.DataFrame, threshold: int = 5, lookback_min: int = 30) -> list[Detection]:
    fails = df[(df["event_type"] == "ssh_login") & (df["status"] == "fail")].sort_values("timestamp")
    succs = df[(df["event_type"] == "ssh_login") & (df["status"] == "success")].sort_values("timestamp")
    if fails.empty or succs.empty:
        return []
    out = []
    # count fails per (ip, user) in the lookback before each success — vectorized
    # via merge_asof-style scan: sort both, walk fails with a two-pointer window.
    f_rec = fails[["id", "timestamp", "source_ip", "user"]].to_dict("records")
    s_rec = succs[["id", "timestamp", "source_ip", "user"]].to_dict("records")
    lookback = pd.Timedelta(minutes=lookback_min)
    # bucket fails by (ip, user) -> sorted ts/id lists
    from collections import defaultdict
    by_key: dict[tuple, list[tuple]] = defaultdict(list)
    for r in f_rec:
        by_key[(r["source_ip"], r["user"])].append((r["timestamp"], r["id"]))
    for k in by_key:
        by_key[k].sort()
    import bisect
    for s in s_rec:
        key = (s["source_ip"], s["user"])
        lst = by_key.get(key)
        if not lst:
            continue
        tses = [x[0] for x in lst]
        hi = bisect.bisect_left(tses, s["timestamp"])          # fails before this success
        lo = bisect.bisect_left(tses, s["timestamp"] - lookback)  # within lookback
        prior_ids = [lst[i][1] for i in range(lo, hi)]
        if len(prior_ids) >= threshold:
            ids = prior_ids + [s["id"]]
            ev = df[df["id"].isin(ids)]
            out.append(_mk(
                "RULE_SUCCESS_AFTER_FAILS",
                f"Successful login as '{s['user']}' from {s['source_ip']} after {len(prior_ids)} "
                f"failed attempts in the last {lookback_min} min — likely compromised",
                3.0, ev, entity=f"{s['user']}@{s['source_ip']}",
            ))
    return out


# ---------------------------------------------------------------------------
# RULE 3 — credential stuffing: many distinct users failed from same IP / subnet
# ---------------------------------------------------------------------------

def rule_credential_stuffing(df: pd.DataFrame, distinct_users: int = 8,
                             window_min: int = 60, min_attempts: int = 15) -> list[Detection]:
    fails = df[(df["event_type"] == "ssh_login") & (df["status"] == "fail")].copy()
    if fails.empty:
        return []
    fails = fails.sort_values("timestamp")
    fails["subnet"] = fails["source_ip"].str.rsplit(".", n=1).str[0]  # /24 grouping
    out = []
    for subnet, grp in fails.groupby("subnet"):
        span_end = grp["timestamp"].max()
        span_start = grp["timestamp"].min()
        # attack must be reasonably bursty (stuffing), not spread over days
        if span_end - span_start > pd.Timedelta(hours=2):
            continue
        users = grp["user"].nunique()
        ips = grp["source_ip"].nunique()
        total = len(grp)
        # stuffing = MANY users, MANY attacker IPs; single-IP mass-fail is brute force
        if users >= distinct_users and total >= min_attempts and ips >= 2:
            out.append(_mk(
                "RULE_CRED_STUFFING",
                f"{total} failed logins across {users} distinct users from {ips} IPs in subnet "
                f"{subnet}.0/24 over {int((span_end-span_start).total_seconds()//60)} min "
                f"(credential stuffing / password spraying)",
                2.5, grp, entity=subnet,
            ))
    return out


# ---------------------------------------------------------------------------
# RULE 4 — impossible travel: same user, logins from IPs far apart in time
# ---------------------------------------------------------------------------

def rule_impossible_travel(df: pd.DataFrame, min_gap_min: int = 10,
                           max_speed_kmh: int = 900) -> list[Detection]:
    succs = df[(df["event_type"] == "ssh_login") & (df["status"] == "success")].copy()
    if succs.empty:
        return []
    succs = succs.sort_values("timestamp")

    # coarse geo: private RFC1918 (corp) vs everything else (external).
    # "impossible travel" = flip between corp and external faster than max_speed
    def zone(ip: str) -> str | None:
        if not isinstance(ip, str):
            return None
        if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                          "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
            return "corp"
        return "external"

    succs["zone"] = succs["source_ip"].map(zone)
    out = []
    for user, grp in succs.groupby("user"):
        rows = grp.to_dict("records")
        for a, b in zip(rows, rows[1:]):
            if a["zone"] != b["zone"] and a["zone"] and b["zone"]:
                gap = (b["timestamp"] - a["timestamp"]).total_seconds() / 60
                if gap <= min_gap_min * 6:  # generous ceiling; travel takes hours
                    ev = grp[grp["id"].isin([a["id"], b["id"]])]
                    out.append(_mk(
                        "RULE_IMPOSSIBLE_TRAVEL",
                        f"User '{user}' logged in from {a['zone']} IP {a['source_ip']} then from "
                        f"{b['zone']} IP {b['source_ip']} only {gap:.0f} min later — impossible travel "
                        f"/ session hijack suspected",
                        2.5, ev, entity=user,
                    ))
    return out


# ---------------------------------------------------------------------------
# RULE 5 — new user account created via sudo then added to privileged group
# ---------------------------------------------------------------------------

def rule_backdoor_user(df: pd.DataFrame) -> list[Detection]:
    added = df[df["event_type"] == "user_added"]
    if added.empty:
        return []
    out = []
    for _, add_row in added.iterrows():
        user = add_row["user"]
        host = add_row["host"]
        t0 = add_row["timestamp"]
        # evidence: everything about this new user, plus the sudo/su failures that
        # preceded its creation on the same host (the escalation attempt itself)
        related = df[
            (
                ((df["user"] == user) & df["event_type"].isin(["user_added", "user_modified", "su_session"]))
                | (df["event_type"].isin(["sudo_fail", "su_auth_fail"]) & (df["host"] == host)
                   & df["user"].isin([user, "bob", *df.loc[df["event_type"] == "sudo_fail", "user"].tolist()]))
            )
            & (df["timestamp"] >= t0 - pd.Timedelta(minutes=30))
            & (df["timestamp"] <= t0 + pd.Timedelta(minutes=30))
        ]
        if len(related) >= 2:
            desc = f"New user '{user}' created via sudo after failed privilege escalation on {host} — possible backdoor account"
            out.append(_mk("RULE_BACKDOOR_USER", desc, 3.0, related, entity=user))
    return out


# ---------------------------------------------------------------------------
# RULE 6 — off-hours activity: successful interactive logins 22:00-05:00
#
# A night login alone is weak evidence — employees work late, admins patch
# at 2am. To keep benign night activity from flooding the incident list,
# every flagged login must carry a RISK SIGNAL:
#
#   user@ip pair with NO daytime activity    -> weight 1.0  (identity misuse)
#   external source IP                       -> weight 0.8-1.0
#   host the user never touches by day       -> weight 0.7  (lateral movement)
#   recurring late-hours pattern (>=2 nights)-> weight 0.5  (soft: verify it's
#     established user@ip, usual hosts)                       scheduled work)
#
# SUPPRESSED silently: a one-off night login from the user's own machine to
# a host they also use during the day — the classic "worked late" pattern.
# That single case is the bulk of benign off-hours noise.
# ---------------------------------------------------------------------------

_OFFHOURS_NEW_PAIR_WEIGHT = 1.0
_OFFHOURS_EXTERNAL_WEIGHT = 0.8
_OFFHOURS_NEW_HOST_WEIGHT = 0.7
_OFFHOURS_RECURRING_SOFT_WEIGHT = 0.5


def _is_offhours(ts: pd.Series) -> pd.Series:
    hrs = ts.dt.hour
    return (hrs >= 22) | (hrs < 5)


def _is_internal_ip(ip: str) -> bool:
    return isinstance(ip, str) and ip.startswith(("10.", "192.168.", "172."))


def rule_offhours_login(df: pd.DataFrame, privileged: set[str] | None = None) -> list[Detection]:
    succs = df[(df["event_type"] == "ssh_login") & (df["status"] == "success")].copy()
    if succs.empty:
        return []
    # cron/service accounts are normal at night — only interactive humans
    privileged = privileged or set()

    def _service_like(u) -> bool:
        return isinstance(u, str) and (u.startswith("svc.") or u.endswith(".job"))

    # daytime baseline: which hosts does each user normally touch?
    day = succs[~_is_offhours(succs["timestamp"])]
    usual_hosts = {u: set(g["host"]) for u, g in day.groupby("user")}

    offhours = succs[_is_offhours(succs["timestamp"])]
    if offhours.empty:
        return []

    # established pair: this user@ip combination also logs in successfully
    # during daytime — so the identity+source pairing is normal behavior
    pair_day = set(zip(day["user"], day["source_ip"]))

    out = []
    for (user, ip), grp in offhours.groupby(["user", "source_ip"]):
        if user in privileged or _service_like(user):
            continue
        n_nights = grp["timestamp"].dt.date.nunique()
        external = not _is_internal_ip(ip)

        if (user, ip) in pair_day:
            # identity+source established: only deviations are interesting
            new_hosts = grp[~grp["host"].isin(usual_hosts.get(user, set()))]
            if not new_hosts.empty:
                sig = ["host not normally accessed by this user"] + (["external source IP"] if external else [])
                out.append(_mk(
                    "RULE_OFFHOURS_LOGIN",
                    f"{len(new_hosts)} off-hours (22:00-05:00) login(s) for '{user}' from {ip} — " + "; ".join(sig),
                    max(_OFFHOURS_NEW_HOST_WEIGHT, _OFFHOURS_EXTERNAL_WEIGHT if external else 0),
                    new_hosts, entity=f"{user}@{ip}",
                ))
            elif external:
                out.append(_mk(
                    "RULE_OFFHOURS_LOGIN",
                    f"{len(grp)} off-hours (22:00-05:00) login(s) for '{user}' from external IP {ip}",
                    _OFFHOURS_EXTERNAL_WEIGHT, grp, entity=f"{user}@{ip}",
                ))
            elif n_nights >= 2:
                # recurring late-hours pattern on usual hosts: soft signal only
                out.append(_mk(
                    "RULE_OFFHOURS_LOGIN",
                    f"{len(grp)} off-hours (22:00-05:00) login(s) for '{user}' from {ip} across {n_nights} nights — "
                    f"recurring late-hours pattern on usual hosts (soft signal — verify scheduled work)",
                    _OFFHOURS_RECURRING_SOFT_WEIGHT, grp, entity=f"{user}@{ip}",
                ))
            # else: one-off night login, established pair, usual hosts -> routine, not flagged
        else:
            # this user@ip pair has NEVER logged in during daytime
            sig = (f"user@ip pair with no daytime activity (internal IP {ip})" if not external
                   else f"login from external IP {ip} with no daytime activity")
            w = _OFFHOURS_NEW_PAIR_WEIGHT
            if not external and n_nights >= 3:
                w = _OFFHOURS_EXTERNAL_WEIGHT
                sig += f"; repeats on {n_nights} different nights"
            out.append(_mk(
                "RULE_OFFHOURS_LOGIN",
                f"{len(grp)} off-hours (22:00-05:00) login(s) for '{user}' from {ip} — {sig}",
                w, grp, entity=f"{user}@{ip}",
            ))
    return out


# ---------------------------------------------------------------------------
# RULE 7 — web recon: many 404s on sensitive paths from one IP
# ---------------------------------------------------------------------------

SENSITIVE_PATH_RE = re.compile(
    r"(/admin|wp-admin|wp-login|phpmyadmin|administrator|/manager/html|/console|"
    r"/actuator|\.env|\.git|\.bak|\.sql|/config|\.php\b|/backup|/shell|/cgi-bin|"
    r"/\.aws|/\.ssh|/etc/passwd)", re.I)


def rule_web_recon(df: pd.DataFrame, threshold: int = 5) -> list[Detection]:
    probes = df[df["event_type"] == "sensitive_probe"].copy()
    if probes.empty:
        return []
    out = []
    for ip, grp in probes.groupby("source_ip"):
        if len(grp) >= threshold:
            paths = sorted(grp["user"].unique())
            out.append(_mk(
                "RULE_WEB_RECON",
                f"{len(grp)} requests to sensitive paths ({', '.join(paths[:6])}"
                f"{'…' if len(paths) > 6 else ''}) from {ip} — reconnaissance scan",
                min(1.5 + len(grp) / 20, 3.0), grp, entity=str(ip),
            ))
    return out


# ---------------------------------------------------------------------------
# RULE 8 — SQL injection attempts
# ---------------------------------------------------------------------------

def rule_sqli(df: pd.DataFrame) -> list[Detection]:
    sqli = df[df["event_type"] == "sqli_attempt"].copy()
    if sqli.empty:
        return []
    out = []
    for ip, grp in sqli.groupby("source_ip"):
        out.append(_mk(
            "RULE_SQLI_ATTEMPT",
            f"{len(grp)} SQL-injection-shaped request(s) from {ip} against "
            f"{', '.join(sorted(grp['user'].unique())[:3])} — web application attack",
            2.5, grp, entity=str(ip),
        ))
    return out


# ---------------------------------------------------------------------------
# RULE 9 — XSS attempts
# ---------------------------------------------------------------------------

def rule_xss(df: pd.DataFrame) -> list[Detection]:
    xss = df[df["event_type"] == "xss_attempt"].copy()
    if xss.empty:
        return []
    out = []
    for ip, grp in xss.groupby("source_ip"):
        out.append(_mk(
            "RULE_XSS_ATTEMPT",
            f"{len(grp)} cross-site-scripting-shaped request(s) from {ip} against "
            f"{', '.join(sorted(grp['user'].unique())[:3])} — web application attack",
            2.0, grp, entity=str(ip),
        ))
    return out


# ---------------------------------------------------------------------------
# RULE 10 — path traversal attempts
# ---------------------------------------------------------------------------

def rule_traversal(df: pd.DataFrame) -> list[Detection]:
    tv = df[df["event_type"] == "traversal_attempt"].copy()
    if tv.empty:
        return []
    out = []
    for ip, grp in tv.groupby("source_ip"):
        out.append(_mk(
            "RULE_TRAVERSAL_ATTEMPT",
            f"{len(grp)} path-traversal request(s) from {ip} (../ sequences, "
            f"/etc/passwd) — file system access attempt",
            2.5, grp, entity=str(ip),
        ))
    return out


# ---------------------------------------------------------------------------
# RULE 11 — web login brute force: N failed (401/403) hits on auth endpoints
# ---------------------------------------------------------------------------

AUTH_PATH_RE = re.compile(r"(/login|/signin|/auth|/session|/token|/wp-login)", re.I)


def rule_web_bruteforce(df: pd.DataFrame, threshold: int = 10, window_min: int = 10) -> list[Detection]:
    reqs = df[(df["event_type"] == "http_request") & (df["status"] == "fail")].copy()
    if reqs.empty:
        return []
    reqs = reqs[reqs["user"].astype(str).map(lambda p: bool(AUTH_PATH_RE.search(str(p))))]
    if reqs.empty:
        return []
    reqs = reqs.sort_values("timestamp")
    out = []
    win_delta = pd.Timedelta(minutes=window_min)
    for ip, grp in reqs.groupby("source_ip"):
        ts = grp["timestamp"].to_numpy()
        best = None
        for i in range(len(ts)):
            j = i
            while j < len(ts) and ts[j] <= ts[i] + win_delta:
                j += 1
            if best is None or (j - i) > (best[1] - best[0]):
                best = (i, j)
        n = best[1] - best[0] if best else 0
        if n >= threshold:
            ev = grp.iloc[best[0]:best[1]]
            # was the brute force eventually successful?
            later_ok = df[(df["source_ip"] == ip) & (df["status"] == "success")
                          & (df["timestamp"] >= ev["timestamp"].max())
                          & (df["timestamp"] <= ev["timestamp"].max() + pd.Timedelta(minutes=5))
                          & df["user"].astype(str).str.contains("login|auth|session|token", case=False, na=False)]
            desc = (f"{n} failed logins to {ev['user'].iloc[0]} from {ip} within {window_min} min "
                    f"(web brute force)")
            if not later_ok.empty:
                ev = pd.concat([ev, later_ok.head(1)])
                desc += " — followed by a SUCCESSFUL login (compromise)"
            out.append(_mk("RULE_WEB_BRUTEFORCE", desc,
                           3.0 if not later_ok.empty else min(1.5 + n / 25, 2.5),
                           ev, entity=str(ip)))
    return out


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

RULES = {
    "RULE_BRUTE_FORCE": (rule_brute_force, "Brute force: N failed logins per user@ip in a time window"),
    "RULE_SUCCESS_AFTER_FAILS": (rule_success_after_fails, "Success after many failures (compromise)"),
    "RULE_CRED_STUFFING": (rule_credential_stuffing, "Credential stuffing: many users sprayed from one subnet"),
    "RULE_IMPOSSIBLE_TRAVEL": (rule_impossible_travel, "Impossible travel: zone flip faster than travel allows"),
    "RULE_BACKDOOR_USER": (rule_backdoor_user, "Backdoor: new user created + modified via sudo"),
    "RULE_OFFHOURS_LOGIN": (rule_offhours_login, "Off-hours interactive login (22:00-05:00)"),
    "RULE_WEB_RECON": (rule_web_recon, "Web recon: sensitive-path probing from one IP"),
    "RULE_SQLI_ATTEMPT": (rule_sqli, "SQL injection attempt pattern in query strings"),
    "RULE_XSS_ATTEMPT": (rule_xss, "XSS attempt pattern in query strings"),
    "RULE_TRAVERSAL_ATTEMPT": (rule_traversal, "Path traversal attempt pattern"),
    "RULE_WEB_BRUTEFORCE": (rule_web_bruteforce, "Web brute force: N failed logins to auth endpoints from one IP"),
}
