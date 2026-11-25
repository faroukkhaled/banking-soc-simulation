import json
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime
from http.server import ThreadingHTTPServer

from banksoc import api, correlate, detectors, evaluate, geo, report, simulator
from banksoc.store import Store


def login(i, t, user, ip, country, result="success", dev="d"):
    return {"id": i, "time": t, "type": "login", "user": user, "ip": ip, "country": country, "device": dev, "result": result}


class DetectorTests(unittest.TestCase):
    def test_stuffing_needs_distinct_accounts(self):
        same = [login(i, "2026-03-02T10:00:%02d" % i, "bob", "1.1.1.1", "RU", "failure") for i in range(12)]
        self.assertEqual(detectors.run(same), [])
        many = [login(i, "2026-03-02T10:00:%02d" % i, "u%d" % i, "1.1.1.1", "RU", "failure") for i in range(9)]
        al = detectors.run(many)
        self.assertEqual([a.detector for a in al], ["credential-stuffing"])

    def test_stuffing_window_expires(self):
        evs = [login(i, "2026-03-02T%02d:00:00" % (10 + i), "u%d" % i, "1.1.1.1", "RU", "failure") for i in range(9)]
        self.assertEqual(detectors.run(evs), [])

    def test_success_after_stuffing_is_critical(self):
        evs = [login(i, "2026-03-02T10:00:%02d" % i, "u%d" % i, "1.1.1.1", "RU", "failure") for i in range(9)]
        evs.append(login(99, "2026-03-02T10:02:00", "u3", "1.1.1.1", "RU"))
        sev = [a.severity for a in detectors.run(evs)]
        self.assertIn("critical", sev)

    def test_impossible_travel_and_cooldown(self):
        evs = [login(1, "2026-03-02T10:00:00", "a", "1.1.1.1", "QA"), login(2, "2026-03-02T10:30:00", "a", "2.2.2.2", "US"),
               login(3, "2026-03-02T11:00:00", "a", "1.1.1.1", "QA")]
        al = detectors.run(evs)
        self.assertEqual(len(al), 1)

    def test_plausible_travel_ok(self):
        evs = [login(1, "2026-03-02T10:00:00", "a", "1.1.1.1", "QA"), login(2, "2026-03-03T02:00:00", "a", "2.2.2.2", "US")]
        self.assertEqual(detectors.run(evs), [])

    def test_new_payee_transfer_scales_with_history(self):
        evs = [{"id": 1, "time": "2026-03-02T09:00:00", "type": "transfer", "user": "a", "payee": "p1", "amount": 4000.0},
               {"id": 2, "time": "2026-03-02T10:00:00", "type": "payee_add", "user": "a", "payee": "p2"},
               {"id": 3, "time": "2026-03-02T10:05:00", "type": "transfer", "user": "a", "payee": "p2", "amount": 5200.0}]
        self.assertEqual(detectors.run(evs), [])  # 5.2k is about 1.3x her usual 4k: not suspicious
        evs[2]["amount"] = 50000.0
        self.assertEqual(len(detectors.run(evs)), 1)

    def test_old_payee_not_flagged(self):
        evs = [{"id": 1, "time": "2026-03-02T08:00:00", "type": "payee_add", "user": "a", "payee": "p"},
               {"id": 2, "time": "2026-03-02T12:00:00", "type": "transfer", "user": "a", "payee": "p", "amount": 90000.0}]
        self.assertEqual(detectors.run(evs), [])

    def test_structuring(self):
        evs = [{"id": i, "time": "2026-03-02T%02d:00:00" % (8 + i), "type": "transfer", "user": "a", "payee": "p", "amount": 9500.0} for i in range(3)]
        self.assertEqual([a.detector for a in detectors.run(evs)], ["structuring"])
        evs = [dict(e, amount=2500.0) for e in evs]
        self.assertEqual(detectors.run(evs), [])

    def test_mule_fan_in(self):
        evs = [{"id": i, "time": "2026-03-02T10:%02d:00" % (i * 5), "type": "transfer", "user": "u%d" % i, "payee": "m", "amount": 900.0} for i in range(4)]
        self.assertEqual([a.detector for a in detectors.run(evs)], ["mule-fan-in"])

    def test_insider_in_and_out_of_hours(self):
        def views(hour, n):
            return [{"id": i, "time": "2026-03-02T%02d:00:%02d" % (hour, i), "type": "view_account", "staff": "t", "customer": "c%d" % i} for i in range(n)]
        self.assertEqual(len(detectors.run(views(3, 12))), 1)
        self.assertEqual(detectors.run(views(11, 12)), [])
        self.assertEqual(len(detectors.run(views(11, 30))), 1)

    def test_phishing_only_when_reported(self):
        ok = {"id": 1, "time": "2026-03-02T10:00:00", "type": "email_click", "user": "a", "url": "http://x", "reported": False}
        self.assertEqual(detectors.run([ok]), [])
        self.assertEqual(len(detectors.run([dict(ok, reported=True)])), 1)


class GeoTests(unittest.TestCase):
    def test_distance(self):
        self.assertAlmostEqual(geo.haversine_km("QA", "AE"), 380, delta=40)
        self.assertEqual(geo.haversine_km("QA", "QA"), 0)


class PipelineTests(unittest.TestCase):
    def test_full_simulation_catches_every_scenario_cleanly(self):
        for seed in (5, 6, 7, 8):
            res = evaluate.evaluate(seed)
            self.assertEqual(res["missed"], [], seed)
            self.assertEqual(res["false_positives"], [], seed)

    def test_simulation_is_reproducible(self):
        self.assertEqual(simulator.generate(3), simulator.generate(3))

    def test_correlation_merges_shared_entity(self):
        events = simulator.generate(5)
        incs = correlate.correlate(detectors.run(events))
        stuffing = [i for i in incs if any(a.detector == "credential-stuffing" for a in i.alerts)][0]
        self.assertGreaterEqual(len(stuffing.alerts), 2)
        self.assertEqual(stuffing.severity, "critical")
        self.assertLessEqual(stuffing.score, 100)

    def test_incidents_sorted_by_score(self):
        incs = correlate.correlate(detectors.run(simulator.generate(5)))
        scores = [i.score for i in incs]
        self.assertEqual(scores, sorted(scores, reverse=True))


class StoreAndApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        events = simulator.generate(5)
        cls.incs = correlate.correlate(detectors.run(events))
        cls.store = Store()
        cls.store.load(events, cls.incs)
        cls.now = datetime(2026, 3, 2, 18, 0, 0)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), api.make_handler(cls.store, now=lambda: cls.now))
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def call(self, path, data=None):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path), data=None if data is None else json.dumps(data).encode(),
                                     method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_list_and_detail(self):
        code, body = self.call("/api/incidents")
        self.assertEqual(code, 200)
        items = json.loads(body)
        self.assertEqual(len(items), len(self.incs))
        code, body = self.call("/api/incidents/%d" % items[0]["id"])
        self.assertEqual(json.loads(body)["alerts"][0]["technique"][0], "T")

    def test_status_notes_and_validation(self):
        iid = json.loads(self.call("/api/incidents")[1])[0]["id"]
        code, body = self.call("/api/incidents/%d/status" % iid, {"status": "triaging"})
        self.assertEqual(json.loads(body)["status"], "triaging")
        self.assertEqual(self.call("/api/incidents/%d/status" % iid, {"status": "bogus"})[0], 400)
        self.assertEqual(self.call("/api/incidents/%d/notes" % iid, {"text": "  "})[0], 400)
        code, body = self.call("/api/incidents/%d/notes" % iid, {"text": "called customer", "author": "sam"})
        self.assertEqual(json.loads(body)["notes"][0]["author"], "sam")
        self.assertEqual(self.call("/api/incidents/99999/status", {"status": "closed"})[0], 404)

    def test_metrics_and_sla(self):
        m = json.loads(self.call("/api/metrics")[1])
        self.assertEqual(m["incidents"], len(self.incs))
        sla = json.loads(self.call("/api/sla")[1])
        self.assertTrue(all(s["waited_minutes"] > 0 for s in sla))

    def test_dashboard_served_and_unknown_404(self):
        code, body = self.call("/")
        self.assertEqual(code, 200)
        self.assertIn(b"Bank SOC console", body)
        self.assertEqual(self.call("/nope")[0], 404)

    def test_bad_json_is_400(self):
        req = urllib.request.Request("http://127.0.0.1:%d/api/incidents/1/status" % self.port, data=b"{not json", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)

    def test_report_markdown(self):
        inc = self.store.incident(self.incs[0].id)
        md = report.incident_markdown(inc)
        self.assertIn("## Alerts", md)


if __name__ == "__main__":
    unittest.main()
