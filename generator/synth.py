"""Synthetic auth.log generator with planted attack scenarios.

Emits a realistic Linux syslog-style auth.log plus a ground-truth answer key
(scenario -> line range / IPs / users) used ONLY for evaluating the detector,
never by the detector itself.

Usage (one command):
    python -m generator.synth
    python -m generator.synth --days 3 --seed 42 --out data/synthetic

Outputs (in --out):
    auth.log            synthetic syslog-style auth log
    ground_truth.json   answer key: scenario windows, actors, line numbers
"""
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

YEAR = 2026
START_DAY = 7  # June 7
HOSTS = ["srv-web01", "srv-db01", "srv-app01", "srv-bkp01"]

LEGIT_USERS = {
    "alice":      {"ip": "10.0.1.22",  "home": "/home/alice"},
    "bob":        {"ip": "10.0.2.8",   "home": "/home/bob"},
    "dev.jones":  {"ip": "10.0.3.44",  "home": "/home/dev.jones"},
    "m.chen":     {"ip": "10.0.3.51",  "home": "/home/m.chen"},
    "svc.deploy": {"ip": "10.0.4.10",  "home": "/home/svc.deploy"},
    "backup.job": {"ip": "10.0.4.12",  "home": "/home/backup.job"},
}

ATTACK_IPS = {
    "brute_force": "203.0.113.45",
    "cred_stuffing": [f"198.51.100.{n}" for n in range(10, 15)],
    "impossible_travel": "203.0.113.77",
}


@dataclass
class Ev:
    dt: datetime
    line: str
    tag: str | None = None  # scenario id, None = background noise


def syslog_ts(dt: datetime) -> str:
    return f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S}"


class Gen:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events: list[Ev] = []

    # -- primitive line builders -------------------------------------------------
    def add(self, dt, host, proc, msg, tag=None):
        self.events.append(Ev(dt, f"{syslog_ts(dt)} {host} {proc}: {msg}", tag))

    def sshd(self, dt, host, pid, msg, tag=None):
        self.add(dt, host, f"sshd[{pid}]", msg, tag)

    def accepted(self, dt, host, user, ip, tag=None, method="publickey"):
        pid, port = self.rng.randint(9000, 30000), self.rng.randint(40000, 60000)
        self.sshd(dt, host, pid, f"Accepted {method} for {user} from {ip} port {port} ssh2", tag)
        self.sshd(
            dt + timedelta(seconds=self.rng.randint(1, 3)), host, pid,
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)", tag,
        )
        return pid

    def failed(self, dt, host, user, ip, tag=None, invalid=False):
        pid, port = self.rng.randint(9000, 30000), self.rng.randint(40000, 60000)
        name = f"invalid user {user}" if invalid else user
        if invalid:
            self.sshd(dt - timedelta(seconds=1), host, pid, f"Invalid user {user} from {ip} port {port}", tag)
        self.sshd(dt, host, pid, f"Failed password for {name} from {ip} port {port} ssh2", tag)
        return pid

    def session_closed(self, dt, host, pid, user, tag=None):
        self.sshd(dt, host, pid, f"pam_unix(sshd:session): session closed for user {user}", tag)

    # -- background noise --------------------------------------------------------
    def background(self, days: int):
        rng = self.rng
        users = list(LEGIT_USERS)
        start = datetime(YEAR, 6, START_DAY)
        for d in range(days):
            day = start + timedelta(days=d)
            # hourly cron noise on two hosts
            for hour in range(24):
                for host in ("srv-web01", "srv-db01"):
                    t = day.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
                    pid = rng.randint(9000, 30000)
                    self.add(t, host, f"CRON[{pid}]", "(root) CMD (cd / && run-parts --report /etc/cron.hourly)")
                    self.add(t + timedelta(seconds=rng.randint(1, 4)), host, f"CRON[{pid}]",
                             "pam_unix(cron:session): session opened for user root by (uid=0)")
                    self.add(t + timedelta(seconds=rng.randint(30, 300)), host, f"CRON[{pid}]",
                             "pam_unix(cron:session): session closed for user root")
            # normal user sessions
            for user in users:
                info = LEGIT_USERS[user]
                for _ in range(rng.randint(2, 5)):
                    t = day + timedelta(hours=rng.randint(6, 22), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                    host = rng.choice(HOSTS)
                    method = rng.choice(["publickey", "publickey", "password"])
                    if rng.random() < 0.12:  # fat-finger typo
                        self.failed(t, host, user, info["ip"])
                        t += timedelta(seconds=rng.randint(5, 90))
                    pid = self.accepted(t, host, user, info["ip"], method=method)
                    dur = timedelta(minutes=rng.randint(3, 180))
                    self.session_closed(t + dur, host, pid, user)

    # -- scenario S1: ssh brute force --------------------------------------------
    def brute_force(self):
        rng, ip, host = self.rng, ATTACK_IPS["brute_force"], "srv-web01"
        t = datetime(YEAR, 6, START_DAY + 2, 14, 5, 0)  # Jun 9, 14:05
        targets = ["root"] * 70 + ["admin", "oracle", "test", "postgres", "ubuntu", "pi", "guest"]
        for user in targets:
            if user != "root":
                self.failed(t, host, user, ip, tag="S1", invalid=True)
            else:
                self.failed(t, host, "root", ip, tag="S1")
            t += timedelta(seconds=rng.randint(2, 14))
        # compromise: root password finally guessed
        t += timedelta(seconds=rng.randint(30, 90))
        pid = self.accepted(t, host, "root", ip, tag="S1", method="password")
        self.add(t + timedelta(seconds=45), host, f"sshd[{pid}]",
                 f"Received disconnect from {ip} port 44192:11: Bye Bye", tag="S1")
        self.session_closed(t + timedelta(minutes=3), host, pid, "root", tag="S1")

    # -- scenario S2: credential stuffing -----------------------------------------
    def credential_stuffing(self):
        rng = self.rng
        botnet = ATTACK_IPS["cred_stuffing"]
        t = datetime(YEAR, 6, START_DAY + 1, 2, 10, 0)  # Jun 8, 02:10 (overnight)
        stuffed = list(LEGIT_USERS) + ["admin", "test", "deploy", "jenkins", "git",
                                       "monitor", "guest", "oracle", "pi", "user",
                                       "backup", "sa", "sql", "nagios", "zabbix"]
        successes = {"alice", "m.chen"}  # accounts that got compromised
        for user in stuffed:
            ip = rng.choice(botnet)
            attempts = rng.randint(1, 3)
            for _ in range(attempts):
                self.failed(t, "srv-web01", user, ip, tag="S2")
                t += timedelta(seconds=rng.randint(2, 40))
            if user in successes:
                self.accepted(t, "srv-web01", user, ip, tag="S2", method="password")
                t += timedelta(seconds=rng.randint(30, 120))

    # -- scenario S3: privilege escalation ------------------------------------------
    def privilege_escalation(self):
        bob = LEGIT_USERS["bob"]
        host = "srv-db01"
        t = datetime(YEAR, 6, START_DAY + 2, 9, 30, 0)  # Jun 9, 09:30, after bob logged in for the day
        tag = "S3"
        self.accepted(t, host, "bob", bob["ip"], tag=tag)
        # 1. tries to read /etc/shadow via sudo -> denied
        self.add(t + timedelta(seconds=41), host, "sudo",
                 f"  bob : command not allowed ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                 tag)
        # 2. sudo auth failures
        self.add(t + timedelta(minutes=1, seconds=12), host, "sudo",
                 f"  bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/su -",
                 tag)
        # 3. su to root fails
        self.add(t + timedelta(minutes=2, seconds=5), host, f"su[{self.rng.randint(9000, 30000)}]",
                 "pam_unix(su:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost= ",
                 tag)
        # 4. finally a successful sudo: creates a backdoor user
        new_user = "svc_bkp"
        t2 = t + timedelta(minutes=5)
        self.add(t2, host, "sudo",
                 f"  bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash {new_user}",
                 tag)
        self.add(t2 + timedelta(seconds=1), host, f"useradd[{self.rng.randint(9000, 30000)}]",
                 f"new user: name={new_user}, UID=1002, GID=1002, home=/home/{new_user}, shell=/bin/bash, from=/dev/pts/0",
                 tag)
        # 5. adds it to the sudo group
        self.add(t2 + timedelta(seconds=23), host, "sudo",
                 f"  bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo {new_user}",
                 tag)
        self.add(t2 + timedelta(seconds=24), host, f"usermod[{self.rng.randint(9000, 30000)}]",
                 f"add '{new_user}' to group 'sudo'", tag)
        # 6. and the new user gets a root shell without a password prompt
        self.add(t2 + timedelta(seconds=70), host, f"su[{self.rng.randint(9000, 30000)}]",
                 f"pam_unix(su:session): session opened for user {new_user}(uid=0) by bob", tag)

    # -- scenario S4: impossible travel -----------------------------------------------
    def impossible_travel(self):
        host = "srv-app01"
        near, far = LEGIT_USERS["alice"]["ip"], ATTACK_IPS["impossible_travel"]
        t = datetime(YEAR, 6, START_DAY, 9, 0, 4)  # Jun 7, 09:00 from office
        self.accepted(t, host, "alice", near, tag="S4", method="password")
        # 12 minutes later, "alice" logs in from an IP on the other side of the planet
        self.accepted(t + timedelta(minutes=12, seconds=37), host, "alice", far, tag="S4", method="password")
        # and keeps working from there
        for mins in (18, 26, 41):
            self.accepted(t + timedelta(minutes=mins), host, "alice", far, tag="S4", method="password")

    # -- malformed lines (Phase 1 robustness fodder) -----------------------------------
    def malformed(self, days: int, total_lines: int):
        rng = self.rng
        junk = [
            "Jun  9 14:23:11 srv-web01 sshd[2",
            "????????????????",
            "Jun 32 99:99:99 srv-web01 sshd[12345]: something broke",
            "Jun  9 14:2 srv-web01 sshd[12345]: Failed password for root from 1.2.3 port 1 ssh2",
            "srv-web01 sshd[991]: Accepted password for nobody from 0.0.0.0",
            "Jun  9 14:24:01 srv-web01 sshd: no user no ip no port ssh2",
        ]
        for i, line in enumerate(junk):
            self.events.append(Ev(datetime(YEAR, 6, START_DAY + 1, 12, 30) + i * timedelta(minutes=17), line, "MALFORMED"))


def build(days: int, seed: int) -> tuple[list[Ev], list[dict]]:
    g = Gen(random.Random(seed))
    g.background(days)
    g.brute_force()
    g.credential_stuffing()
    g.privilege_escalation()
    g.impossible_travel()
    g.malformed(days, 0)

    g.events.sort(key=lambda e: e.dt)

    scenario_meta = {
        "S1": {
            "name": "ssh_brute_force",
            "description": "120+ failed SSH logins for root/invalid users from one attacker IP, ending in a successful root login (compromise).",
            "actors": {"source_ips": [ATTACK_IPS["brute_force"]], "users": ["root", "admin", "oracle", "test", "postgres", "ubuntu", "pi", "guest"], "hosts": ["srv-web01"]},
            "outcome": "compromised (root)",
        },
        "S2": {
            "name": "credential_stuffing",
            "description": "Sprayed 1-3 password attempts per user across ~22 accounts from a 5-IP botnet; two accounts (alice, m.chen) accepted.",
            "actors": {"source_ips": ATTACK_IPS["cred_stuffing"], "users": ["~22 sprayed accounts", "alice", "m.chen"], "hosts": ["srv-web01"]},
            "outcome": "2 accounts compromised",
        },
        "S3": {
            "name": "privilege_escalation",
            "description": "bob: sudo denials and su failures escalate to successful sudo useradd + usermod, creating backdoor user 'svc_bkp' with sudo group membership.",
            "actors": {"source_ips": [LEGIT_USERS["bob"]["ip"]], "users": ["bob", "svc_bkp"], "hosts": ["srv-db01"]},
            "outcome": "backdoor user with sudo rights",
        },
        "S4": {
            "name": "impossible_travel",
            "description": "alice logs in from the office, then again 12 minutes later from a foreign IP (203.0.113.77) and continues from there.",
            "actors": {"source_ips": [LEGIT_USERS["alice"]["ip"], ATTACK_IPS["impossible_travel"]], "users": ["alice"], "hosts": ["srv-app01"]},
            "outcome": "account takeover suspected",
        },
    }

    per_tag: dict[str, dict] = {}
    for i, ev in enumerate(g.events, 1):
        if ev.tag is None:
            continue
        d = per_tag.setdefault(ev.tag, {"start": i, "end": i, "count": 0, "first_dt": ev.dt, "last_dt": ev.dt})
        d["end"] = i
        d["count"] += 1
        d["last_dt"] = ev.dt

    scenarios = []
    for tag, meta in sorted(scenario_meta.items()):
        d = per_tag.get(tag, {})
        scenarios.append({
            "id": tag,
            **meta,
            "window": {"start": d.get("first_dt").isoformat(), "end": d.get("last_dt").isoformat()},
            "lines": {"start": d.get("start"), "end": d.get("end"), "count": d.get("count")},
        })
    return g.events, scenarios


def main() -> None:
    p = argparse.ArgumentParser(description="Generate synthetic auth.log + ground truth")
    p.add_argument("--out", default="data/synthetic", help="output directory")
    p.add_argument("--days", type=int, default=3, help="days of background noise")
    p.add_argument("--seed", type=int, default=42, help="RNG seed (reproducible output)")
    args = p.parse_args()

    events, scenarios = build(args.days, args.seed)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    log_path = out / "auth.log"
    log_path.write_text("\n".join(e.line for e in events) + "\n", encoding="utf-8")

    attack_lines = sum(s["lines"]["count"] for s in scenarios)
    gt = {
        "meta": {
            "format": "linux_auth_syslog",
            "year": YEAR,
            "note": "syslog timestamps carry no year; the parser must assume meta.year",
            "seed": args.seed,
            "total_lines": len(events),
            "attack_lines": attack_lines,
            "attack_free_lines": len(events) - attack_lines - sum(1 for e in events if e.tag == "MALFORMED"),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "scenarios": scenarios,
        "malformed_lines": [e.line for e in events if e.tag == "MALFORMED"],
    }
    gt_path = out / "ground_truth.json"
    gt_path.write_text(json.dumps(gt, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {log_path}  ({len(events)} lines)")
    print(f"Wrote {gt_path}  ({len(scenarios)} attack scenarios, {gt['meta']['attack_free_lines']} clean lines)")
    for s in scenarios:
        print(f"  {s['id']} {s['name']:<22} lines {s['lines']['start']:>5}-{s['lines']['end']:<5} "
              f"count={s['lines']['count']:<4} {s['window']['start']} -> {s['window']['end']}")


if __name__ == "__main__":
    main()
