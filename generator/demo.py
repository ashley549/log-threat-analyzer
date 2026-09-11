"""Demo dataset generator: a multi-format security demo in one command.

Produces data/demo/demo.log — an Apache combined-format log with:
  - normal browsing traffic (many internal IPs, realistic paths)
  - brute-force login attempts (POST /api/login 401 x N, then 200)
  - recon scan (sensitive paths, 404s)
  - SQL injection campaign
  - XSS probes
  - path traversal attempts
plus a ground-truth answer key.

This is the 'Run Security Demo' dataset — clearly labeled SAMPLE data.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)",
       "Mozilla/5.0 (X11; Linux x86_64)", "curl/8.0", "python-requests/2.28"]
PATHS = ["/", "/index.html", "/products", "/about", "/contact", "/css/style.css",
         "/api/health", "/cart", "/api/products"]
ATTACK_IPS = {"brute": "203.0.113.45", "recon": "193.106.191.88",
              "sqli": "198.51.100.66", "xss": "198.51.100.77", "trav": "203.0.113.99"}


def line(ip, dt, method, target, code, size, ua):
    return (f'{ip} - - [{dt:%d/%b/%Y:%H:%M:%S +0000}] "{method} {target} HTTP/1.1" '
            f'{code} {size} "-" "{ua}"')


def build(seed=7, n_normal=140):
    rng = random.Random(seed)
    t0 = datetime(2026, 9, 9, 9, 30, 0)
    out = []  # (dt, line, tag)

    # normal traffic over ~2 hours
    for i in range(n_normal):
        t = t0 + timedelta(seconds=rng.randint(0, 7200))
        ip = f"10.0.0.{rng.randint(2, 30)}"
        out.append((t, line(ip, t, "GET", rng.choice(PATHS), 200,
                            rng.randint(400, 5000), rng.choice(UAS[:3])), None))

    # brute force: 40 failed logins then success (scenario W1)
    t = t0.replace(hour=10, minute=21)
    for i in range(40):
        t = t + timedelta(seconds=rng.randint(1, 4))
        out.append((t, line(ATTACK_IPS["brute"], t, "POST", "/api/login", 401, 90,
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "W1"))
    t = t + timedelta(seconds=6)
    out.append((t, line(ATTACK_IPS["brute"], t, "POST", "/api/login", 200, 412,
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "W1"))

    # recon scan (W2)
    t = t0.replace(hour=10, minute=40)
    for p in ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git/config",
              "/config.php.bak", "/backup.sql", "/manager/html", "/console",
              "/actuator/env", "/administrator", "/wp-login.php"]:
        t = t + timedelta(seconds=2)
        out.append((t, line(ATTACK_IPS["recon"], t, "GET", p, 404, 210, "python-requests/2.28"), "W2"))

    # SQL injection (W3)
    t = t0.replace(hour=11, minute=2)
    for q in ["/search?q=1' OR '1'='1", "/search?q=1; DROP TABLE users;--",
              "/search?q=' UNION SELECT username,password FROM users--",
              "/product?id=1 OR 1=1", "/product?id=sleep(5)"]:
        t = t + timedelta(seconds=3)
        out.append((t, line(ATTACK_IPS["sqli"], t, "GET", q, 500, 180, "python-requests/2.28"), "W3"))

    # XSS (W4)
    t = t0.replace(hour=11, minute=15)
    for q in ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
              "/comment?text=<img src=x onerror=alert(1)>",
              "/profile?name=javascript:alert(document.cookie)",
              "/search?q=<svg onload=alert(2)>"]:
        t = t + timedelta(seconds=4)
        out.append((t, line(ATTACK_IPS["xss"], t, "GET", q, 200, 240, "curl/8.0"), "W4"))

    # path traversal (W5)
    t = t0.replace(hour=11, minute=30)
    for q in ["/files?path=../../etc/passwd", "/download?f=../../../etc/shadow",
              "/static?name=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/view?doc=....//....//boot.ini"]:
        t = t + timedelta(seconds=5)
        out.append((t, line(ATTACK_IPS["trav"], t, "GET", q, 403, 150, "curl/8.0"), "W5"))

    out.sort(key=lambda x: x[0])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/demo")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    events = build()
    (out / "demo.log").write_text("\n".join(l for _, l, _ in events) + "\n", encoding="utf-8")

    per = {}
    for i, (dt, l, tag) in enumerate(events, 1):
        if tag:
            d = per.setdefault(tag, {"start": i, "end": i, "count": 0})
            d["end"], d["count"] = i, d["count"] + 1
    meta = {"W1": ("web_brute_force", ATTACK_IPS["brute"]), "W2": ("recon_scan", ATTACK_IPS["recon"]),
            "W3": ("sql_injection", ATTACK_IPS["sqli"]), "W4": ("xss_campaign", ATTACK_IPS["xss"]),
            "W5": ("path_traversal", ATTACK_IPS["trav"])}
    scenarios = [{"id": k, "name": v[0], "attacker_ip": v[1], "lines": per[k]}
                 for k, v in meta.items()]
    (out / "ground_truth.json").write_text(json.dumps(
        {"meta": {"format": "apache_combined", "total_lines": len(events),
                  "sample_data": True}, "scenarios": scenarios}, indent=2), encoding="utf-8")
    print(f"Wrote {out/'demo.log'} ({len(events)} lines) + ground truth")
    for s in scenarios:
        print(f"  {s['id']} {s['name']:<18} {s['attacker_ip']:<16} lines {s['lines']['start']}-{s['lines']['end']}")


if __name__ == "__main__":
    main()
