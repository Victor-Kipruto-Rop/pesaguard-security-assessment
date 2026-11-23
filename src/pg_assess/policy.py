from ipaddress import ip_address
from urllib.parse import urlparse
from .config import settings
from .models import Environment, TargetAuthorization

class PolicyError(ValueError):
    pass

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

def approved_address(auth: TargetAuthorization) -> str:
    """Return the exact pinned destination address for an authorized target."""
    parsed = urlparse(str(auth.base_url))
    host = (parsed.hostname or "").lower()
    if auth.environment == Environment.LOCAL:
        if host == "localhost":
            return "127.0.0.1"
        try:
            address = ip_address(host)
        except ValueError as exc:
            raise PolicyError("Local target must be a literal loopback address or localhost.") from exc
        if not address.is_loopback:
            raise PolicyError("Local target address must be loopback.")
        return str(address)
    if not auth.approved_ip_addresses:
        raise PolicyError("Staging targets require at least one explicitly approved IP address.")
    try:
        approved = [ip_address(value) for value in auth.approved_ip_addresses]
    except ValueError as exc:
        raise PolicyError("Approved target IP address is invalid.") from exc
    if any(value.is_loopback or value.is_unspecified or value.is_link_local or value.is_multicast for value in approved):
        raise PolicyError("Staging approved IP addresses cannot be loopback, unspecified, link-local, or multicast.")
    if len({str(value) for value in approved}) != len(approved):
        raise PolicyError("Approved target IP addresses must be unique.")
    return str(approved[0])

def validate_target(auth: TargetAuthorization, requested_checks: list[str]) -> None:
    if not auth.is_current():
        raise PolicyError("Authorization is inactive, expired, or has invalid timestamps.")
    parsed = urlparse(str(auth.base_url))
    host = (parsed.hostname or "").lower()
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PolicyError("Target URL must not contain userinfo, query parameters, or fragments.")
    if not host or parsed.scheme not in {"http", "https"}:
        raise PolicyError("Target URL must include a supported scheme and hostname.")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in LOOPBACK_HOSTS):
        raise PolicyError("HTTPS is required except for loopback-only local targets.")
    if auth.environment == Environment.LOCAL:
        if host not in LOOPBACK_HOSTS:
            try:
                if not ip_address(host).is_loopback:
                    raise PolicyError("Local targets must use a loopback address.")
            except ValueError as exc:
                raise PolicyError("Local targets must use an explicit loopback hostname.") from exc
        if auth.approved_ip_addresses:
            try:
                if any(not ip_address(value).is_loopback for value in auth.approved_ip_addresses):
                    raise PolicyError("Local approved IP addresses must all be loopback.")
            except ValueError as exc:
                raise PolicyError("Approved target IP address is invalid.") from exc
    elif auth.environment == Environment.STAGING:
        if host in LOOPBACK_HOSTS:
            raise PolicyError("Staging targets cannot use loopback hostnames.")
        allowed_hosts = {item.strip().lower() for item in settings.assessment_allowed_staging_hosts.split(",") if item.strip()}
        if not allowed_hosts or host not in allowed_hosts:
            raise PolicyError("Staging hostname is not in ASSESSMENT_ALLOWED_STAGING_HOSTS.")
        approved_address(auth)
    else:
        raise PolicyError("Production scanning is disabled in this release.")
    if not requested_checks:
        raise PolicyError("At least one check must be selected.")
    allowed = {item.value for item in auth.allowed_checks}
    denied = sorted(set(requested_checks) - allowed)
    if denied:
        raise PolicyError("Checks not authorized: " + ", ".join(denied))
    if auth.max_requests_per_minute > 60:
        raise PolicyError("Target request rate exceeds the hard limit.")
