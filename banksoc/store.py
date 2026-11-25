"""SQLite store for events, alerts and incidents with a simple triage workflow and SLA metrics."""
import json
import sqlite3
from datetime import datetime

STATUSES = ("new", "triaging", "true_positive", "false_positive", "closed")
SLA_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440}
SCHEMA = """
create table if not exists events(id integer primary key, time text, type text, body text);
create table if not exists incidents(id integer primary key, title text, severity text, score integer, status text,
  start text, end text, body text, acked text, closed text);
create table if not exists notes(id integer primary key autoincrement, incident_id integer, ts text, author text, text text);
"""


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def load(self, events, incidents):
        self.db.execute("delete from events")
        self.db.execute("delete from incidents")
        self.db.executemany("insert into events values(?,?,?,?)", [(e["id"], e["time"], e["type"], json.dumps(e)) for e in events])
        for i in incidents:
            d = i.as_dict()
            self.db.execute("insert into incidents(id,title,severity,score,status,start,end,body) values(?,?,?,?,?,?,?,?)",
                            (d["id"], d["title"], d["severity"], d["score"], "new", d["start"], d["end"], json.dumps(d)))
        self.db.commit()

    def incidents(self, status=None):
        q = "select id,title,severity,score,status,start,end from incidents"
        args = ()
        if status:
            q += " where status=?"
            args = (status,)
        return [dict(r) for r in self.db.execute(q + " order by score desc", args)]

    def incident(self, iid):
        r = self.db.execute("select * from incidents where id=?", (iid,)).fetchone()
        if not r:
            return None
        d = json.loads(r["body"])
        d.update(status=r["status"], acked=r["acked"], closed=r["closed"])
        d["notes"] = [dict(n) for n in self.db.execute("select ts,author,text from notes where incident_id=? order by id", (iid,))]
        return d

    def set_status(self, iid, status, now=None):
        if status not in STATUSES:
            raise ValueError("status must be one of: " + ", ".join(STATUSES))
        now = now or datetime.now().isoformat(timespec="seconds")
        r = self.db.execute("select acked from incidents where id=?", (iid,)).fetchone()
        if r is None:
            raise KeyError(iid)
        acked = r["acked"] or (now if status != "new" else None)
        closed = now if status in ("closed", "false_positive", "true_positive") else None
        self.db.execute("update incidents set status=?, acked=?, closed=? where id=?", (status, acked, closed, iid))
        self.db.commit()

    def add_note(self, iid, text, author="analyst"):
        self.db.execute("insert into notes(incident_id,ts,author,text) values(?,?,?,?)", (iid, datetime.now().isoformat(timespec="seconds"), author, text))
        self.db.commit()

    def metrics(self):
        rows = [dict(r) for r in self.db.execute("select severity,status,start,acked,closed from incidents")]
        by_sev, ack_mins = {}, []
        for r in rows:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
            if r["acked"]:
                ack_mins.append((datetime.fromisoformat(r["acked"]) - datetime.fromisoformat(r["start"])).total_seconds() / 60)
        counts = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return {"incidents": len(rows), "by_severity": by_sev, "by_status": counts,
                "mean_minutes_to_ack": round(sum(ack_mins) / len(ack_mins), 1) if ack_mins else None,
                "open_critical": sum(1 for r in rows if r["severity"] == "critical" and r["status"] in ("new", "triaging"))}

    def sla_breaches(self, now):
        out = []
        for r in self.db.execute("select id,title,severity,start,acked from incidents where status='new'"):
            waited = (now - datetime.fromisoformat(r["start"])).total_seconds() / 60
            if waited > SLA_MINUTES[r["severity"]]:
                out.append({"id": r["id"], "title": r["title"], "severity": r["severity"], "waited_minutes": round(waited)})
        return out
