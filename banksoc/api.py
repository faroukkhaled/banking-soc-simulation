"""Read/write JSON API and a single-page dashboard on http.server (no dependencies).

GET  /                          dashboard
GET  /api/incidents[?status=]   list, highest score first
GET  /api/incidents/<id>        detail with alerts and notes
POST /api/incidents/<id>/status {"status": "triaging"}
POST /api/incidents/<id>/notes  {"text": "...", "author": "..."}
GET  /api/metrics               counts, mean time to acknowledge
GET  /api/sla                   incidents still new past their SLA
"""
import json
import re
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .dashboard import PAGE


def make_handler(store, now=datetime.now):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 65536:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                return self._send(200, PAGE, "text/html")
            if u.path == "/api/incidents":
                st = parse_qs(u.query).get("status", [None])[0]
                return self._send(200, store.incidents(st))
            m = re.fullmatch(r"/api/incidents/(\d+)", u.path)
            if m:
                inc = store.incident(int(m.group(1)))
                return self._send(200, inc) if inc else self._send(404, {"error": "not found"})
            if u.path == "/api/metrics":
                return self._send(200, store.metrics())
            if u.path == "/api/sla":
                return self._send(200, store.sla_breaches(now()))
            self._send(404, {"error": "not found"})

        def do_POST(self):
            u = urlparse(self.path)
            m = re.fullmatch(r"/api/incidents/(\d+)/(status|notes)", u.path)
            if not m:
                return self._send(404, {"error": "not found"})
            iid, what = int(m.group(1)), m.group(2)
            try:
                body = self._body()
                if store.incident(iid) is None:
                    return self._send(404, {"error": "not found"})
                if what == "status":
                    store.set_status(iid, body.get("status", ""))
                else:
                    text = str(body.get("text", "")).strip()
                    if not text:
                        return self._send(400, {"error": "text required"})
                    store.add_note(iid, text[:2000], str(body.get("author", "analyst"))[:50])
                return self._send(200, store.incident(iid))
            except (ValueError, json.JSONDecodeError) as exc:
                return self._send(400, {"error": str(exc)})

    return H


def serve(store, host="127.0.0.1", port=8080):
    srv = ThreadingHTTPServer((host, port), make_handler(store))
    print("dashboard on http://%s:%d" % (host, port))
    srv.serve_forever()
