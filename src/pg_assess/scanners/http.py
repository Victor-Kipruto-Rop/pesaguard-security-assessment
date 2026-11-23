from urllib.parse import urljoin
import httpx
from ..models import Finding, TargetAuthorization

SECURITY_HEADERS = {
    "strict-transport-security": ("high", "Enable HSTS with a suitable max-age and includeSubDomains where safe."),
    "content-security-policy": ("medium", "Define a restrictive Content-Security-Policy for the application."),
    "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Set a privacy-preserving Referrer-Policy."),
    "permissions-policy": ("low", "Restrict browser capabilities with Permissions-Policy."),
    "frame-ancestors": ("medium", "Use CSP frame-ancestors or X-Frame-Options to prevent unauthorized framing."),
}

async def run_http_checks(auth: TargetAuthorization, timeout: float, user_agent: str) -> list[Finding]:
    findings: list[Finding] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                 headers={"User-Agent": user_agent}) as client:
        response = await client.get(str(auth.base_url))
        headers = {k.lower(): v for k, v in response.headers.items()}
        for header, (severity, recommendation) in SECURITY_HEADERS.items():
            present = header in headers or (header == "frame-ancestors" and
                "content-security-policy" in headers and
                "frame-ancestors" in headers["content-security-policy"].lower())
            if not present:
                findings.append(Finding(check="http_headers", title=f"Missing {header}",
                    severity=severity, confidence="high",
                    description=f"The target response did not include {header}.",
                    evidence={"http_status": str(response.status_code), "header": header},
                    recommendation=recommendation))
        server = headers.get("server", "")
        if server:
            findings.append(Finding(check="http_headers", title="Server header reveals software information",
                severity="info", confidence="high",
                description="The response exposes a Server header.",
                evidence={"server_header": server[:120]},
                recommendation="Remove or minimize version and product details in response headers."))
        for cookie in response.headers.get_list("set-cookie"):
            low = cookie.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in low]
            if missing:
                findings.append(Finding(check="cookie_flags",
                    title="Cookie missing recommended security attributes", severity="medium",
                    confidence="medium", description="A response cookie is missing recommended attributes.",
                    evidence={"cookie_name": cookie.split("=", 1)[0][:80],
                              "missing_attributes": ", ".join(missing)},
                    recommendation="Set Secure, HttpOnly, and an appropriate SameSite attribute. Cookie values are never recorded."))
        if response.is_redirect:
            findings.append(Finding(check="http_headers", title="Redirect observed", severity="info",
                confidence="high", description="Redirects are not followed by this scanner.",
                evidence={"location": response.headers.get("location", "")[:200]},
                recommendation="Verify redirects remain within the authorized hostname and use HTTPS."))
    return findings

async def run_openapi_check(auth: TargetAuthorization, timeout: float, user_agent: str) -> list[Finding]:
    findings: list[Finding] = []
    base = str(auth.base_url).rstrip("/") + "/"
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                 headers={"User-Agent": user_agent}) as client:
        for path in ("/openapi.json", "/api/openapi.json"):
            response = await client.get(urljoin(base, path.lstrip("/")))
            if response.status_code == 200 and "json" in response.headers.get("content-type", ""):
                findings.append(Finding(check="openapi_exposure",
                    title="OpenAPI schema publicly reachable", severity="info", confidence="high",
                    description=f"An API schema is reachable at {path}.",
                    evidence={"path": path, "status": str(response.status_code)},
                    recommendation="Confirm public API documentation contains no internal endpoints, secrets, or sensitive schema details."))
    return findings
