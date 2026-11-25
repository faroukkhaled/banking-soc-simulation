"""Group alerts into incidents. Alerts sharing an entity within a time gap join the same incident
(union-find). Each incident gets a risk score and a severity."""
from datetime import timedelta

WEIGHT = {"critical": 70, "high": 40, "medium": 15, "low": 3}
TACTIC = {"T1110.004": "Credential Access", "T1078": "Initial Access", "T1566.002": "Initial Access",
          "T1657": "Impact", "T1213": "Collection"}


class Incident:
    def __init__(self, iid, alerts):
        self.id = iid
        self.alerts = sorted(alerts, key=lambda a: a.time)
        self.status = "new"

    @property
    def entities(self):
        out = []
        for a in self.alerts:
            for e in a.entities:
                if e not in out:
                    out.append(e)
        return out

    @property
    def start(self):
        return self.alerts[0].time

    @property
    def end(self):
        return self.alerts[-1].time

    @property
    def tactics(self):
        seen = []
        for a in self.alerts:
            t = TACTIC.get(a.technique, "Other")
            if t not in seen:
                seen.append(t)
        return seen

    @property
    def score(self):
        s = sum(WEIGHT[a.severity] for a in self.alerts) + 10 * (len(self.tactics) - 1)
        return min(100, s)

    @property
    def severity(self):
        s = self.score
        return "critical" if s >= 70 else "high" if s >= 40 else "medium" if s >= 15 else "low"

    @property
    def title(self):
        kinds = sorted({a.detector for a in self.alerts})
        return "%s: %s" % (self.entities[0], ", ".join(kinds))

    def as_dict(self):
        return {"id": self.id, "title": self.title, "severity": self.severity, "score": self.score, "status": self.status,
                "start": self.start.isoformat(timespec="seconds"), "end": self.end.isoformat(timespec="seconds"),
                "entities": self.entities, "tactics": self.tactics, "alerts": [a.as_dict() for a in self.alerts]}


def correlate(alerts, gap=7200):
    alerts = sorted(alerts, key=lambda a: a.time)
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    last_seen = {}
    for i, a in enumerate(alerts):
        for e in a.entities:
            if e in last_seen and (a.time - alerts[last_seen[e]].time) <= timedelta(seconds=gap):
                parent[find(i)] = find(last_seen[e])
            last_seen[e] = i
    groups = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    ordered = sorted(groups.values(), key=lambda g: g[0].time)
    incs = [Incident(n + 1, g) for n, g in enumerate(ordered)]
    return sorted(incs, key=lambda i: -i.score)
