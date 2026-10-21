"""Demo notification receiver. FAIL_FIRST=n answers the first n requests with 503
to show the outbox retrying with the same Idempotency-Key; repeats are reported."""
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

fail_left = int(os.environ.get("FAIL_FIRST", "0"))
seen = set()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global fail_left
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        key = self.headers.get("idempotency-key", "-")
        auth = "bearer present" if self.headers.get("authorization", "").startswith("Bearer ") else "NO AUTH"
        try:
            f = json.loads(body)
            what = json.dumps(f.get("finding", f))[:160]
        except ValueError:
            what = "(non-json)"
        if fail_left > 0:
            fail_left -= 1
            print(f"503 key={key} {auth} (simulated outage)", flush=True)
            self.send_response(503); self.send_header("Retry-After", "1"); self.send_header("Content-Length", "0"); self.end_headers()
            return
        dup = " DUPLICATE-KEY" if key in seen else ""
        seen.add(key)
        print(f"200 key={key} {auth}{dup} {what}", flush=True)
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 9099), Handler).serve_forever()
