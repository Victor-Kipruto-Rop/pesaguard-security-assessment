import asyncio
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from pg_assess.models import CheckName, Environment, TargetAuthorization
from pg_assess.scanners.http import run_http_checks

class SafeTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=synthetic-secret; Path=/")
        self.end_headers()

    def log_message(self, format, *args):
        pass

def test_http_scanner_reads_headers_and_never_records_cookie_values():
    server = ThreadingHTTPServer(("127.0.0.1", 0), SafeTestHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        now = datetime.now(timezone.utc)
        auth = TargetAuthorization(
            target_id="local-scanner-test",
            base_url=f"http://127.0.0.1:{server.server_port}",
            environment=Environment.LOCAL,
            owner="test owner",
            authorization_reference="TEST-SCANNER",
            approved_by="test approver",
            approved_at=now-timedelta(minutes=1),
            expires_at=now+timedelta(minutes=5),
            allowed_checks=[CheckName.HTTP_HEADERS, CheckName.COOKIE_FLAGS],
        )
        findings = asyncio.run(run_http_checks(auth, 2, "pg-assess-test"))
        assert any("Missing strict-transport-security" in f.title for f in findings)
        cookie_finding = next(f for f in findings if f.check == "cookie_flags")
        assert "synthetic-secret" not in str(cookie_finding.evidence)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
