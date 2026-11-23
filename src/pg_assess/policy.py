from urllib.parse import urlparse
from .models import Environment, TargetAuthorization

class PolicyError(ValueError):
    pass

def validate_target(auth: TargetAuthorization, requested_checks: list[str]) -> None:
    if not auth.is_current():
        raise PolicyError("Authorization is inactive, expired, or has invalid timestamps.")
    parsed = urlparse(str(auth.base_url))
    host = parsed.hostname or ""
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}):
        raise PolicyError("HTTPS is required except for loopback-only local targets.")
    if auth.environment == Environment.LOCAL and host not in {"localhost", "127.0.0.1", "::1"}:
        raise PolicyError("Local targets must use an explicit loopback hostname.")
    if auth.environment == Environment.STAGING and host in {"localhost", "127.0.0.1", "::1"}:
        raise PolicyError("Staging targets cannot be loopback addresses.")
    if auth.environment == Environment.PRODUCTION:
        raise PolicyError("Production scanning is disabled in this release.")
    if not requested_checks:
        raise PolicyError("At least one check must be selected.")
    allowed = {item.value for item in auth.allowed_checks}
    denied = sorted(set(requested_checks) - allowed)
    if denied:
        raise PolicyError("Checks not authorized: " + ", ".join(denied))
    if auth.max_requests_per_minute > 60:
        raise PolicyError("Target request rate exceeds the hard limit.")
