#!/usr/bin/env python3
"""Run detection rules over JSON-lines logs and print alerts with severity and MITRE mapping.

Usage: python3 detections/detect.py sample_logs.jsonl
"""
import json
import sys
from collections import defaultdict
from datetime import datetime

WORK_START, WORK_END = 7, 17  # branch hours


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def ts(e):
    return datetime.fromisoformat(e["time"])


def credential_stuffing(events, min_users=10, min_fails=20):
    by_ip = defaultdict(list)
    for e in events:
        if e["type"] == "login" and e["result"] == "failure":
            by_ip[e["ip"]].append(e)
    for ip, es in by_ip.items():
        users = {x["user"] for x in es}
        if len(es) >= min_fails and len(users) >= min_users:
            yield dict(rule="Credential stuffing", severity="high", mitre="T1110.004", time=es[0]["time"],
                       detail=f"{len(es)} failed logins across {len(users)} accounts from {ip} ({es[0]['country']})")


def account_takeover(events):
    known = defaultdict(set)
    for e in events:
        if e["type"] == "login" and e["result"] == "success" and e["country"] == "QA":
            known[e["user"]].add(e["country"])
    fails = defaultdict(int)
    for e in events:
        if e["type"] == "login":
            if e["result"] == "failure":
                fails[e["user"]] += 1
            elif e["country"] not in known[e["user"]] and fails[e["user"]] >= 3:
                yield dict(rule="Possible account takeover", severity="critical", mitre="T1078", time=e["time"],
                           detail=f"{e['user']} logged in from new country {e['country']} after {fails[e['user']]} failures")
        if e["type"] == "transfer" and e["amount"] >= 10000 and e["country"] not in known[e["user"]]:
            yield dict(rule="High-value transfer from new location", severity="critical", mitre="T1657", time=e["time"],
                       detail=f"{e['user']} sent {e['amount']} to {e['dest']} from {e['country']}")


def insider_snooping(events, threshold=15):
    cnt = defaultdict(list)
    for e in events:
        if e["type"] == "account_view":
            cnt[e["user"]].append(e)
    for user, es in cnt.items():
        off = [x for x in es if not WORK_START <= ts(x).hour < WORK_END]
        if len(es) >= threshold and off:
            yield dict(rule="Mass account viewing out of hours", severity="high", mitre="T1213", time=es[0]["time"],
                       detail=f"{user} viewed {len(es)} customer accounts, {len(off)} out of hours")


def phishing_click(events):
    for e in events:
        if e["type"] == "email" and e.get("url_clicked"):
            yield dict(rule="Phishing link clicked", severity="medium", mitre="T1566.002", time=e["time"],
                       detail=f"{e['user']} clicked a link in '{e['subject']}' from {e['sender']}")


RULES = [credential_stuffing, account_takeover, insider_snooping, phishing_click]

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    ev = load(sys.argv[1])
    alerts = sorted((a for r in RULES for a in r(ev)), key=lambda a: a["time"])
    print(f"{len(ev)} events, {len(alerts)} alerts")
    for a in alerts:
        print(f"[{a['severity'].upper():8}] {a['time']} {a['rule']} ({a['mitre']}): {a['detail']}")
