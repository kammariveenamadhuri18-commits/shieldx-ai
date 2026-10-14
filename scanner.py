from urllib.parse import urlparse
import ipaddress
import re


_ACCOUNT_TERMS = re.compile(r"login|verify|account|password|signin", re.IGNORECASE)
_DOMAIN_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)", re.IGNORECASE)


def _normalize_hostname(host):
    """Return a normalized hostname or None when it is not a valid host."""
    if host.endswith("."):
        host = host[:-1]

    try:
        address = ipaddress.ip_address(host)
        return str(address), True
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None, False

    if len(ascii_host) > 253:
        return None, False

    labels = ascii_host.split(".")
    if not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None, False

    return ascii_host, False


def scan_url(raw_url: str) -> dict:
    if not isinstance(raw_url, str):
        return {"valid": False, "error": "Please enter a URL."}

    raw_url = raw_url.strip()

    if not raw_url:
        return {"valid": False, "error": "Please enter a URL."}

    if any(c.isspace() or ord(c) < 32 for c in raw_url):
        return {
            "valid": False,
            "error": "The URL contains spaces or invalid characters."
        }

    try:
        parsed = urlparse(raw_url)

        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError

        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        return {
            "valid": False,
            "error": "Enter a valid URL starting with http:// or https://."
        }

    if not host:
        return {
            "valid": False,
            "error": "Enter a valid URL starting with http:// or https://."
        }

    normalized_host, is_ip_address = _normalize_hostname(host)
    if normalized_host is None:
        return {
            "valid": False,
            "error": "Enter a valid URL starting with http:// or https://."
        }

    score = 0
    findings = []

    def flag(points, message):
        nonlocal score
        score += points
        findings.append(message)

    if is_ip_address:
        flag(25, "The hostname is an IP address.")

    if "@" in parsed.netloc:
        flag(25, "The URL contains user information before the hostname.")

    if len(raw_url) > 100:
        flag(10, "The URL is unusually long.")

    if normalized_host.count("-") >= 3:
        flag(10, "The hostname contains several hyphens.")

    if _ACCOUNT_TERMS.search(parsed.path + "?" + parsed.query):
        flag(10, "The URL contains account-related terms.")

    if parsed.scheme.lower() == "http":
        flag(5, "The URL does not use HTTPS.")

    score = min(score, 100)

    if score >= 40:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {
        "valid": True,
        "host": normalized_host,
        "score": score,
        "level": level,
        "findings": findings
    }