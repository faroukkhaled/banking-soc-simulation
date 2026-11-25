import argparse
import json
import sys

from . import api, correlate, detectors, evaluate, report, simulator
from .store import Store


def _pipeline(a):
    events = simulator.generate(a.seed, a.customers, a.days)
    alerts = detectors.run(events)
    return events, alerts, correlate.correlate(alerts)


def cmd_simulate(a):
    events = simulator.generate(a.seed, a.customers, a.days)
    with open(a.out, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    print("wrote %d events to %s" % (len(events), a.out))


def cmd_detect(a):
    events, alerts, incs = _pipeline(a)
    print("%d events, %d alerts, %d incidents\n" % (len(events), len(alerts), len(incs)))
    for i in incs:
        print("#%d [%s] score=%d %s" % (i.id, i.severity.upper(), i.score, i.title))
        for al in i.alerts:
            print("     %s %-26s %s" % (al.time.strftime("%H:%M"), al.detector, al.summary))


def cmd_evaluate(a):
    res = evaluate.evaluate(a.seed, a.customers, a.days)
    print("events=%(events)d alerts=%(alerts)d" % res)
    print("caught:", ", ".join(res["caught"]))
    print("missed:", ", ".join(res["missed"]) or "none")
    print("false positives:", len(res["false_positives"]))
    for f in res["false_positives"]:
        print("  ", f["detector"], f["summary"])
    sys.exit(1 if res["missed"] or res["false_positives"] else 0)


def cmd_report(a):
    _, _, incs = _pipeline(a)
    for i in incs:
        if i.id == a.incident:
            print(report.incident_markdown(i.as_dict()))
            return
    sys.exit("no such incident")


def cmd_serve(a):
    events, _, incs = _pipeline(a)
    store = Store(a.db)
    store.load(events, incs)
    api.serve(store, a.host, a.port)


def main(argv=None):
    p = argparse.ArgumentParser(prog="banksoc")
    p.add_argument("--seed", type=int, default=5)
    p.add_argument("--customers", type=int, default=60)
    p.add_argument("--days", type=int, default=1)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("simulate")
    s.add_argument("--out", default="data/sample_logs.jsonl")
    s.set_defaults(fn=cmd_simulate)
    sub.add_parser("detect").set_defaults(fn=cmd_detect)
    sub.add_parser("evaluate").set_defaults(fn=cmd_evaluate)
    s = sub.add_parser("report")
    s.add_argument("incident", type=int)
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--db", default=":memory:")
    s.set_defaults(fn=cmd_serve)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
