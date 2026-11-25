"""Streaming detectors. Each keeps its own sliding-window state and sees events in time order.

Every alert carries MITRE ATT&CK technique ids, a severity, the entities involved (used for
correlation) and the ids of the events that triggered it.
"""
from collections import defaultdict, deque
from datetime import datetime

from .geo import COORDS, haversine_km


def ts(ev):
    return datetime.fromisoformat(ev["time"])


class Alert:
    def __init__(self, detector, severity, ev, summary, technique, entities, evidence):
        self.detector = detector
        self.severity = severity
        self.time = ts(ev)
        self.summary = summary
        self.technique = technique
        self.entities = entities  # list of "kind:value"
        self.evidence = evidence  # event ids
        self.scenario = ev.get("_scenario", "benign")

    def as_dict(self):
        return {"detector": self.detector, "severity": self.severity, "time": self.time.isoformat(timespec="seconds"),
                "summary": self.summary, "technique": self.technique, "entities": self.entities,
                "evidence": self.evidence, "scenario": self.scenario}


class Detector:
    name = "base"
    technique = ""

    def process(self, ev):  # -> list[Alert]
        raise NotImplementedError

    def alert(self, sev, ev, summary, entities, evidence):
        return Alert(self.name, sev, ev, summary, self.technique, entities, evidence)


class CredentialStuffing(Detector):
    """Many distinct accounts failing from one IP, then a success from that IP."""
    name = "credential-stuffing"
    technique = "T1110.004"

    def __init__(self, distinct=8, window=600):
        self.distinct, self.window = distinct, window
        self.fails = defaultdict(deque)
        self.flagged = {}

    def process(self, ev):
        if ev["type"] != "login":
            return []
        ip, now = ev["ip"], ts(ev)
        out = []
        if ev["result"] == "failure":
            q = self.fails[ip]
            q.append((now, ev["user"], ev["id"]))
            while q and (now - q[0][0]).total_seconds() > self.window:
                q.popleft()
            users = {u for _, u, _ in q}
            if len(users) >= self.distinct and ip not in self.flagged:
                self.flagged[ip] = now
                out.append(self.alert("high", ev, "%d accounts failed to log in from %s in %ds" % (len(users), ip, self.window),
                                      ["ip:" + ip], [i for _, _, i in q]))
        elif ip in self.flagged:
            out.append(self.alert("critical", ev, "Successful login for %s from credential stuffing source %s" % (ev["user"], ip),
                                  ["ip:" + ip, "user:" + ev["user"]], [ev["id"]]))
        return out


class ImpossibleTravel(Detector):
    """Two successful logins whose implied speed exceeds an airliner."""
    name = "impossible-travel"
    technique = "T1078"

    def __init__(self, max_kmh=900, min_km=500, cooldown=21600):
        self.max_kmh, self.min_km, self.cooldown = max_kmh, min_km, cooldown
        self.last = {}
        self.alerted = {}

    def process(self, ev):
        if ev["type"] != "login" or ev["result"] != "success":
            return []
        user, now, c = ev["user"], ts(ev), ev["country"]
        prev = self.last.get(user)
        self.last[user] = (now, c, ev["id"])
        if not prev or prev[1] == c or c not in COORDS or prev[1] not in COORDS:
            return []
        km = haversine_km(prev[1], c)
        hours = max((now - prev[0]).total_seconds() / 3600, 1e-6)
        quiet = user in self.alerted and (now - self.alerted[user]).total_seconds() < self.cooldown
        if km >= self.min_km and km / hours > self.max_kmh and not quiet:
            self.alerted[user] = now
            return [self.alert("high", ev, "%s logged in from %s then %s %d min later (%.0f km, %.0f km/h)" % (
                user, prev[1], c, hours * 60, km, km / hours), ["user:" + user, "ip:" + ev["ip"]], [prev[2], ev["id"]])]
        return []


class NewPayeeLargeTransfer(Detector):
    """Large transfer to a payee added minutes ago, scaled against the customer's own history."""
    name = "new-payee-large-transfer"
    technique = "T1657"

    def __init__(self, new_payee_window=1800, floor=5000, multiple=8):
        self.w, self.floor, self.multiple = new_payee_window, floor, multiple
        self.added = {}
        self.history = defaultdict(list)
        self.resets = {}

    def process(self, ev):
        t = ev["type"]
        if t == "payee_add":
            self.added[(ev["user"], ev["payee"])] = (ts(ev), ev["id"])
        elif t == "password_reset":
            self.resets[ev["user"]] = (ts(ev), ev["id"])
        elif t == "transfer":
            user, now = ev["user"], ts(ev)
            hist = self.history[user]
            avg = sum(hist) / len(hist) if hist else 0
            hist.append(ev["amount"])
            added = self.added.get((user, ev["payee"]))
            if added and (now - added[0]).total_seconds() <= self.w and ev["amount"] >= max(self.floor, self.multiple * avg):
                ev_ids = [added[1], ev["id"]]
                reset = self.resets.get(user)
                note = ""
                if reset and (now - reset[0]).total_seconds() <= 3600:
                    note = " after a password reset"
                    ev_ids.insert(0, reset[1])
                return [self.alert("critical", ev, "%.2f to a payee added %d min earlier%s (customer avg %.2f)" % (
                    ev["amount"], (now - added[0]).total_seconds() / 60, note, avg), ["user:" + user], ev_ids)]
        return []


class Structuring(Detector):
    """Repeated transfers just under a reporting threshold."""
    name = "structuring"
    technique = "T1657"

    def __init__(self, threshold=10000, band=0.1, count=3, window=86400):
        self.lo, self.hi, self.count, self.window = threshold * (1 - band), threshold, count, window
        self.recent = defaultdict(deque)
        self.flagged = set()

    def process(self, ev):
        if ev["type"] != "transfer" or not (self.lo <= ev["amount"] < self.hi):
            return []
        user, now = ev["user"], ts(ev)
        q = self.recent[user]
        q.append((now, ev["id"], ev["amount"]))
        while q and (now - q[0][0]).total_seconds() > self.window:
            q.popleft()
        if len(q) >= self.count and user not in self.flagged:
            self.flagged.add(user)
            return [self.alert("high", ev, "%d transfers between %.0f and %.0f within a day (total %.2f)" % (
                len(q), self.lo, self.hi, sum(a for _, _, a in q)), ["user:" + user], [i for _, i, _ in q])]
        return []


class MuleFanIn(Detector):
    """Many unrelated accounts paying the same payee in a short window."""
    name = "mule-fan-in"
    technique = "T1657"

    def __init__(self, sources=4, window=3600):
        self.sources, self.window = sources, window
        self.recent = defaultdict(deque)
        self.flagged = set()

    def process(self, ev):
        if ev["type"] != "transfer":
            return []
        payee, now = ev["payee"], ts(ev)
        q = self.recent[payee]
        q.append((now, ev["user"], ev["id"]))
        while q and (now - q[0][0]).total_seconds() > self.window:
            q.popleft()
        users = {u for _, u, _ in q}
        if len(users) >= self.sources and payee not in self.flagged:
            self.flagged.add(payee)
            return [self.alert("high", ev, "%d different customers paid %s within %d min" % (len(users), payee, self.window // 60),
                               ["payee:" + payee] + ["user:" + u for u in sorted(users)], [i for _, _, i in q])]
        return []


class InsiderBrowsing(Detector):
    """A staff member looking at many customer records quickly, or any off-hours burst."""
    name = "insider-browsing"
    technique = "T1213"

    def __init__(self, burst=25, window=900, off_burst=10, hours=(6, 20)):
        self.burst, self.window, self.off_burst, self.hours = burst, window, off_burst, hours
        self.recent = defaultdict(deque)
        self.flagged = set()

    def process(self, ev):
        if ev["type"] != "view_account":
            return []
        staff, now = ev["staff"], ts(ev)
        q = self.recent[staff]
        q.append((now, ev["customer"], ev["id"]))
        while q and (now - q[0][0]).total_seconds() > self.window:
            q.popleft()
        distinct = {c for _, c, _ in q}
        off = not (self.hours[0] <= now.hour < self.hours[1])
        need = self.off_burst if off else self.burst
        if len(distinct) >= need and staff not in self.flagged:
            self.flagged.add(staff)
            return [self.alert("high", ev, "%s viewed %d customer accounts in %d min%s" % (
                staff, len(distinct), self.window // 60, " outside working hours" if off else ""), ["staff:" + staff], [i for _, _, i in q])]
        return []


class PhishingClick(Detector):
    """A user clicked a URL that mail security reported."""
    name = "phishing-click"
    technique = "T1566.002"

    def process(self, ev):
        if ev["type"] == "email_click" and ev.get("reported"):
            return [self.alert("medium", ev, "%s clicked reported phishing URL %s" % (ev["user"], ev["url"]), ["user:" + ev["user"]], [ev["id"]])]
        return []


def default_detectors():
    return [CredentialStuffing(), ImpossibleTravel(), NewPayeeLargeTransfer(), Structuring(), MuleFanIn(), InsiderBrowsing(), PhishingClick()]


def run(events, detectors=None):
    detectors = detectors or default_detectors()
    alerts = []
    for ev in sorted(events, key=lambda e: e["time"]):
        for d in detectors:
            alerts.extend(d.process(ev))
    return alerts
