"""URL extraction and text-only inspection; URLs are never opened or fetched."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .common import evidence
from .domain_analyzer import DomainIntelProvider, analyze_domain

URL_PATTERN = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
    r"|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/[^\s<>\"']*)?"
    r"|(?<![@\w.-])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"']*)?"
)
URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "lnkd.in", "rb.gy", "goo.gl",
}
SUSPICIOUS_PATH_WORDS = {
    "account", "auth", "billing", "confirm", "invoice", "login", "password",
    "payment", "recover", "secure", "signin", "update", "verify",
}


def extract_urls(text: str) -> list[str]:
    """Extract URL-shaped text and trim common surrounding punctuation."""
    return [match.rstrip(".,!?;:)]}") for match in URL_PATTERN.findall(text)]


def links_present(urls: list[str]) -> dict:
    found = bool(urls)
    return evidence("links_present", found, f"Found {len(urls)} URL(s). They were treated as text and not opened." if found else "No URL was found.", "low" if found else "none")


def _parse_url(url: str):
    explicit_scheme = bool(re.match(r"(?i)^https?://", url))
    candidate = url if explicit_scheme else f"http://{url}"
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        # Accessing .port can raise ValueError for malformed port values.
        _ = parsed.port
        if not host:
            return None
        return parsed, host.encode("idna").decode("ascii").lower(), explicit_scheme
    except (ValueError, UnicodeError):
        return None


def analyze_url(url: str, intel: DomainIntelProvider | None = None) -> dict:
    """Inspect one URL as text. The returned link is never requested."""
    parsed_host = _parse_url(url)
    if not parsed_host:
        unavailable = {"indicator": "url_structure", "status": "unknown", "reason": "The URL structure could not be parsed safely.", "severity": "info"}
        return {"url": url, "details": {}, "indicators": [unavailable]}
    parsed, host_ascii, explicit_scheme = parsed_host
    try:
        ipaddress.ip_address(host_ascii.strip("[]"))
        ip_host = True
    except ValueError:
        ip_host = False

    scheme = parsed.scheme.lower()
    indicators = [
        evidence("https_used", scheme == "https", "HTTPS encrypts the connection, but does not prove the site is legitimate." if scheme == "https" else "The URL does not specify HTTPS.", "info"),
        evidence("insecure_http", explicit_scheme and scheme == "http", "The URL explicitly uses unencrypted HTTP." if explicit_scheme and scheme == "http" else "No explicit HTTP scheme was found.", "low" if explicit_scheme and scheme == "http" else "none"),
        evidence("ip_address_host", ip_host, f"The URL uses an IP address as its host ({host_ascii})." if ip_host else "The URL host is a domain name, not an IP address.", "high" if ip_host else "none"),
    ]

    shortener = host_ascii.removeprefix("www.") in URL_SHORTENERS
    indicators.append(evidence("url_shortener", shortener, f"The host {host_ascii} is a known URL-shortening domain." if shortener else "The host is not in the built-in URL shortener list.", "medium" if shortener else "none"))

    domain_result = analyze_domain(host_ascii, intel=intel)
    indicators.extend(domain_result["indicators"])
    path_words = sorted({part.lower() for part in re.findall(r"[a-zA-Z]{3,}", parsed.path) if part.lower() in SUSPICIOUS_PATH_WORDS})
    indicators.append(evidence(
        "suspicious_path_keywords", bool(path_words),
        f"The URL path contains: {', '.join(path_words)}." if path_words else "No common account, payment, or sign-in terms were found in the URL path.",
        "low" if path_words else "none",
    ))
    return {
        "url": url,
        "details": {"scheme": scheme, "host": host_ascii, "path": parsed.path, **domain_result["details"]},
        "indicators": indicators,
    }
