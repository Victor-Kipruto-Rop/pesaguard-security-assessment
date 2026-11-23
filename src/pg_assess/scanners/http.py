"""Pinned-address HTTP checks. Redirects and DNS re-resolution are deliberately disabled."""
from __future__ import annotations

import asyncio
import http.client
import socket
import ssl
from urllib.parse import urlparse

from ..models import Finding, TargetAuthorization
from ..policy import approved_address

SECURITY_HEADERS = {
    "strict-transport-security": ("high", "Enable HSTS with a suitable max-age and includeSubDomains where safe."),
    "content-security-policy": ("medium", "Define a restrictive Content-Security-Policy for the application."),
    "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Set a privacy-preserving Referrer-Policy."),
    "permissions-policy": ("low", "Restrict browser capabilities with Permissions-Policy."),
    "frame-ancestors": ("medium", "Use CSP frame-ancestors or X-Frame-Options to prevent unauthorized framing."),
}

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host=host, port=port, timeout=timeout)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout)

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host=host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise

def _fetch_headers(auth: TargetAuthorization, path: str, timeout: float,
                   user_agent: str) -> tuple[int, list[tuple[str, str]]]:
    parsed = urlparse(str(auth.base_url))
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    address = approved_address(auth)
    prefix = parsed.path.rstrip("/")
    request_path = (prefix + "/" + path.lstrip("/")) or "/"
    connection_class = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    connection = connection_class(host, port, address, timeout)
    try:
        connection.request("GET", request_path, headers={
            "Host": parsed.netloc,
            "User-Agent": user_agent,
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            "Connection": "close",
        })
        response = connection.getresponse()
        return response.status, response.getheaders()
    finally:
        connection.close()

async def run_http_checks(auth: TargetAuthorization, timeout: float, user_agent: str) -> list[Finding]:
    try:
        status, raw_headers = await asyncio.to_thread(_fetch_headers, auth, "/", timeout, user_agent)
    except Exception as exc:
        return [Finding(check="http_headers", title="Authorized HTTP request failed", severity="high",
            confidence="high", description="The scanner could not complete its pinned-address request.",
            evidence={"error_type": type(exc).__name__},
            recommendation="Verify the approved target IP, certificate, firewall route, and service health.")]
    headers: dict[str, list[str]] = {}
    for key, value in raw_headers:
        headers.setdefault(key.lower(), []).append(value)
    findings: list[Finding] = []
    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        present = header in headers or (header == "frame-ancestors" and
            "content-security-policy" in headers and
            any("frame-ancestors" in value.lower() for value in headers["content-security-policy"]))
        if not present:
            findings.append(Finding(check="http_headers", title=f"Missing {header}",
                severity=severity, confidence="high",
                description=f"The target response did not include {header}.",
                evidence={"http_status": str(status), "header": header},
                recommendation=recommendation))
    server = headers.get("server", [""])[0]
    if server:
        findings.append(Finding(check="http_headers", title="Server header reveals software information",
            severity="info", confidence="high", description="The response exposes a Server header.",
            evidence={"server_header": server[:120]},
            recommendation="Remove or minimize version and product details in response headers."))
    for cookie in headers.get("set-cookie", []):
        low = cookie.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in low]
        if missing:
            findings.append(Finding(check="cookie_flags",
                title="Cookie missing recommended security attributes", severity="medium",
                confidence="medium", description="A response cookie is missing recommended attributes.",
                evidence={"cookie_name": cookie.split("=", 1)[0][:80],
                          "missing_attributes": ", ".join(missing)},
                recommendation="Set Secure, HttpOnly, and an appropriate SameSite attribute. Cookie values are never recorded."))
    if 300 <= status < 400:
        findings.append(Finding(check="http_headers", title="Redirect observed", severity="info",
            confidence="high", description="Redirects are not followed by this scanner.",
            evidence={"location": headers.get("location", [""])[0][:200]},
            recommendation="Verify redirects remain within the authorized hostname and use HTTPS."))
    return findings

async def run_openapi_check(auth: TargetAuthorization, timeout: float, user_agent: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in ("/openapi.json", "/api/openapi.json"):
        try:
            status, raw_headers = await asyncio.to_thread(_fetch_headers, auth, path, timeout, user_agent)
        except Exception as exc:
            findings.append(Finding(check="openapi_exposure", title="OpenAPI probe failed", severity="low",
                confidence="high", description="A bounded schema-header request failed.",
                evidence={"path": path, "error_type": type(exc).__name__},
                recommendation="Verify the target route and network path."))
            continue
        headers = {key.lower(): value for key, value in raw_headers}
        if status == 200 and "json" in headers.get("content-type", ""):
            findings.append(Finding(check="openapi_exposure",
                title="OpenAPI schema publicly reachable", severity="info", confidence="high",
                description=f"An API schema is reachable at {path}.",
                evidence={"path": path, "status": str(status)},
                recommendation="Confirm public API documentation contains no internal endpoints, secrets, or sensitive schema details."))
    return findings

def run_tls_check(auth: TargetAuthorization, timeout: float) -> Finding:
    parsed = urlparse(str(auth.base_url))
    host = parsed.hostname or ""
    if parsed.scheme != "https":
        return Finding(check="tls", title="TLS check not applicable to HTTP target",
            severity="info", confidence="high",
            description="The authorized local target uses HTTP; TLS is required for staging targets.",
            evidence={"scheme": parsed.scheme},
            recommendation="Use HTTPS for staging assessments. Local loopback HTTP is permitted for development.")
    port = parsed.port or 443
    address = approved_address(auth)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                version = sock.version() or "unknown"
                cert = sock.getpeercert()
        return Finding(check="tls", title="TLS certificate validation succeeded",
            severity="info", confidence="high",
            description="The platform trust store accepted the certificate for the authorized hostname.",
            evidence={"tls_version": version, "certificate_subject_present": str(bool(cert.get("subject")))},
            recommendation="Maintain certificate renewal monitoring and modern TLS configuration.")
    except (OSError, ssl.SSLError, ValueError) as exc:
        return Finding(check="tls", title="TLS validation failed", severity="high",
            confidence="high", description="TLS handshake or certificate validation failed.",
            evidence={"error_type": type(exc).__name__},
            recommendation="Inspect certificate chain, hostname coverage, expiry, and supported TLS versions.")
