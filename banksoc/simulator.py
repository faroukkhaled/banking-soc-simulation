"""Synthetic bank activity with injected attack scenarios. Every event has `_scenario` ground truth.

Event types: login, password_reset, payee_add, transfer, view_account, email_click.
All names, IPs and accounts are fake. Seeded, so runs are reproducible.
"""
import random
from datetime import datetime, timedelta

COUNTRIES_HOME = ["QA"] * 8 + ["AE", "EG"]
START = datetime(2026, 3, 2, 7, 0, 0)


def _ip(r, prefix=None):
    return "%s.%d.%d" % (prefix or r.choice(["85.10", "86.20", "37.210"]), r.randint(0, 255), r.randint(1, 254))


class Bank:
    def __init__(self, seed=5, customers=60, staff=8):
        self.r = random.Random(seed)
        self.events = []
        self.customers = []
        for i in range(customers):
            self.customers.append({
                "user": "cust%03d" % i, "country": self.r.choice(COUNTRIES_HOME),
                "device": "dev-%04x" % self.r.randint(0, 0xFFFF), "avg": self.r.choice([150, 300, 600, 1200]),
                "payees": ["pay-%03d-%d" % (i, k) for k in range(self.r.randint(1, 3))],
            })
        self.staff = ["teller%02d" % i for i in range(staff)]

    def emit(self, t, typ, scenario="benign", **kw):
        ev = {"time": t.isoformat(timespec="seconds"), "type": typ, "_scenario": scenario}
        ev.update(kw)
        self.events.append(ev)

    # ---- benign day ----
    def normal_day(self, day=START):
        r = self.r
        for c in self.customers:
            for _ in range(r.randint(1, 3)):
                t = day + timedelta(minutes=r.randint(0, 780))
                self.emit(t, "login", user=c["user"], ip=_ip(r), country=c["country"], device=c["device"], result="success")
                if r.random() < 0.5:
                    amt = round(abs(r.gauss(c["avg"], c["avg"] / 4)) + 10, 2)
                    self.emit(t + timedelta(minutes=2), "transfer", user=c["user"], payee=r.choice(c["payees"]), amount=amt)
            if r.random() < 0.08:  # people mistype passwords
                t = day + timedelta(minutes=r.randint(0, 700))
                self.emit(t, "login", user=c["user"], ip=_ip(r), country=c["country"], device=c["device"], result="failure")
        for s in self.staff:  # normal staff activity: handful of lookups in hours
            for _ in range(r.randint(5, 15)):
                t = day + timedelta(minutes=r.randint(120, 600))
                self.emit(t, "view_account", staff=s, customer=r.choice(self.customers)["user"])
        # benign near misses
        c = self.customers[0]
        t = day + timedelta(hours=3)
        for k in range(3):  # three legit large rent payments in a day, below structuring pattern thresholds
            self.emit(t + timedelta(hours=k * 4), "transfer", user=c["user"], payee=c["payees"][0], amount=2500.0)
        c2 = self.customers[1]
        self.emit(day + timedelta(hours=4), "login", user=c2["user"], ip=_ip(self.r), country="AE", device=c2["device"], result="success")
        self.emit(day + timedelta(hours=9), "login", user=c2["user"], ip=_ip(self.r), country="QA", device=c2["device"], result="success")

    # ---- scenarios ----
    def credential_stuffing(self, t0):
        r = self.r
        ip = "185.220.101.%d" % r.randint(2, 200)
        targets = r.sample(self.customers, 20)
        for i, c in enumerate(targets):
            self.emit(t0 + timedelta(seconds=i * 6), "login", "stuffing", user=c["user"], ip=ip, country="RU",
                      device="bot-%d" % i, result="failure")
        victim = targets[3]
        self.emit(t0 + timedelta(minutes=3), "login", "stuffing", user=victim["user"], ip=ip, country="RU", device="bot-3", result="success")
        return victim

    def account_takeover(self, t0, victim=None):
        c = victim or self.customers[10]
        ip = "41.58.%d.%d" % (self.r.randint(0, 255), self.r.randint(1, 254))
        self.emit(t0, "login", "ato", user=c["user"], ip=ip, country="NG", device="dev-evil", result="success")
        self.emit(t0 + timedelta(minutes=2), "password_reset", "ato", user=c["user"], ip=ip)
        self.emit(t0 + timedelta(minutes=5), "payee_add", "ato", user=c["user"], payee="pay-new-9999", ip=ip)
        self.emit(t0 + timedelta(minutes=9), "transfer", "ato", user=c["user"], payee="pay-new-9999", amount=48500.0)
        return c

    def impossible_travel(self, t0):
        c = self.customers[20]
        self.emit(t0, "login", "travel", user=c["user"], ip=_ip(self.r), country="QA", device=c["device"], result="success")
        self.emit(t0 + timedelta(minutes=25), "login", "travel", user=c["user"], ip="23.45.67.89", country="US", device="dev-new", result="success")

    def structuring(self, t0):
        c = self.customers[30]
        for k, amt in enumerate([9800, 9650, 9900, 9750]):
            self.emit(t0 + timedelta(hours=k * 2), "transfer", "structuring", user=c["user"], payee="pay-cash-out", amount=float(amt))

    def mule_fan_in(self, t0):
        for i, c in enumerate(self.customers[35:41]):
            self.emit(t0 + timedelta(minutes=i * 7), "transfer", "mule", user=c["user"], payee="pay-mule-77", amount=950.0 + i)

    def insider_browsing(self, t0):
        s = "teller03"
        for i in range(40):
            self.emit(t0 + timedelta(seconds=i * 20), "view_account", "insider", staff=s, customer=self.customers[i % len(self.customers)]["user"])

    def phishing(self, t0):
        c = self.customers[50]
        self.emit(t0, "email_click", "phishing", user=c["user"], url="http://qnb-secure-login.top/verify", reported=True)

    def full(self, days=1):
        for d in range(days):
            self.normal_day(START + timedelta(days=d))
        day = START
        self.credential_stuffing(day + timedelta(hours=2, minutes=10))
        self.account_takeover(day + timedelta(hours=6))
        self.impossible_travel(day + timedelta(hours=7))
        self.structuring(day + timedelta(hours=5))
        self.mule_fan_in(day + timedelta(hours=8))
        self.insider_browsing(day + timedelta(hours=-1, minutes=-40))  # 05:20, off hours
        self.phishing(day + timedelta(hours=4))
        self.events.sort(key=lambda e: e["time"])
        for i, e in enumerate(self.events):
            e["id"] = i
        return self.events


def generate(seed=5, customers=60, days=1):
    return Bank(seed, customers).full(days)
