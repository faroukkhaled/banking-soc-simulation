#!/usr/bin/env python3
"""Generate synthetic banking-style security logs (JSON lines) with injected attack scenarios.

Usage: python3 simulator/generate_logs.py > sample_logs.jsonl   (seeded, reproducible)
All data is fake.
"""
import json
import random
from datetime import datetime, timedelta

random.seed(42)
START = datetime(2026, 3, 2, 8, 0, 0)
CUSTOMERS = [f"cust{i:03d}" for i in range(1, 31)]
TELLERS = ["teller01", "teller02", "teller03"]
GOOD_IPS = [f"85.10.{random.randint(1,200)}.{random.randint(1,250)}" for _ in range(10)]
events = []


def add(ts, **kw):
    events.append({"time": ts.isoformat(), **kw})


# Normal activity: online banking logins and transfers
for i in range(300):
    ts = START + timedelta(seconds=random.randint(0, 8 * 3600))
    c = random.choice(CUSTOMERS)
    add(ts, type="login", user=c, ip=random.choice(GOOD_IPS), country="QA", result="success")
    if random.random() < 0.4:
        add(ts + timedelta(seconds=40), type="transfer", user=c, amount=random.randint(50, 3000),
            dest=f"acct{random.randint(1000, 1999)}", ip=random.choice(GOOD_IPS), country="QA")

# Scenario 1: credential stuffing against many customers from one IP
ts = START + timedelta(hours=2)
for i in range(40):
    add(ts + timedelta(seconds=i * 2), type="login", user=random.choice(CUSTOMERS),
        ip="198.51.100.7", country="RO", result="failure")

# Scenario 2: account takeover: failures, success from new country, big transfer to new payee
ts = START + timedelta(hours=4)
for i in range(6):
    add(ts + timedelta(seconds=i * 5), type="login", user="cust007", ip="203.0.113.99", country="NG", result="failure")
add(ts + timedelta(seconds=40), type="login", user="cust007", ip="203.0.113.99", country="NG", result="success")
add(ts + timedelta(seconds=120), type="transfer", user="cust007", amount=48000, dest="acct9999",
    ip="203.0.113.99", country="NG")

# Scenario 3: insider, teller views many accounts out of hours
ts = START + timedelta(hours=12)
for c in random.sample(CUSTOMERS, 25):
    add(ts, type="account_view", user="teller02", target=c, ip="10.1.1.15", country="QA")
    ts += timedelta(seconds=20)

# Scenario 4: phishing email delivered to staff and clicked
add(START + timedelta(hours=3), type="email", user="teller01", sender="support@bank-secure-login.example",
    subject="Urgent: verify your account", url_clicked=True)

events.sort(key=lambda e: e["time"])
for e in events:
    print(json.dumps(e))
