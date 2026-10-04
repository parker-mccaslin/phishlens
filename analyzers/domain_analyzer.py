"""Domain structure analysis with optional, disabled-by-default intel hooks.

No lookups are performed here. Public suffix handling is deliberately
conservative: common multi-label suffixes are recognized and ambiguous
country-code structures are reported as unknown instead of guessed.
"""
from __future__ import annotations

from ipaddress import ip_address
from typing import Protocol

from .common import evidence

MULTI_LABEL_SUFFIXES = {
    "ac.uk", "co.uk", "gov.uk", "org.uk", "com.au", "edu.au", "gov.au",
    "net.au", "org.au", "co.nz", "govt.nz", "net.nz", "org.nz", "com.br",
    "com.cn", "com.hk", "com.mx", "com.sg", "com.tr", "com.tw", "co.in",
    "firm.in", "net.in", "org.in", "co.jp", "ne.jp", "or.jp", "co.za",
}
BRANDS = {
    "paypal": {"paypal.com"}, "google": {"google.com", "google.co.uk", "google.ca"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com"}, "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca"},
    "facebook": {"facebook.com", "fb.com"}, "instagram": {"instagram.com"},
    "netflix": {"netflix.com"}, "whatsapp": {"whatsapp.com"},
    "dropbox": {"dropbox.com"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"},
    "ups": {"ups.com"},
}


class DomainIntelProvider(Protocol):
    """Optional interface for domain age and reputation; implementations may perform I/O."""

    def check_domain(self, registered_domain: str) -> dict:
        """Return domain age and reputation evidence for a registered domain."""


class DisabledDomainIntel:
    """Default provider. It never accesses the network."""

    def check_domain(self, registered_domain: str) -> dict:
        return {
            "domain_age": {"status": "unknown", "reason": "Domain age lookup is disabled."},
            "domain_reputation": {"status": "unknown", "reason": "Reputation lookup is disabled."},
        }


def domain_parts(host: str) -> dict:
    """Return hostname, TLD, registered domain and subdomain when determinable."""
    normalized = host.rstrip(".").lower()
    try:
        ip_address(normalized)
        return {"host": normalized, "tld": None, "registered_domain": None, "subdomain": None, "parse_status": "ip"}
    except ValueError:
        pass
    labels = normalized.split(".") if normalized else []
    if len(labels) < 2 or any(not label for label in labels):
        return {"host": normalized, "tld": labels[-1] if labels else None, "registered_domain": None, "subdomain": None, "parse_status": "unknown"}
    last_two = ".".join(labels[-2:])
    suffix_count = 2 if last_two in MULTI_LABEL_SUFFIXES else 1
    if suffix_count == 1 and len(labels[-1]) == 2 and len(labels) > 2:
        return {"host": normalized, "tld": labels[-1], "registered_domain": None, "subdomain": None, "parse_status": "unknown"}
    if len(labels) <= suffix_count:
        return {"host": normalized, "tld": labels[-1], "registered_domain": None, "subdomain": None, "parse_status": "unknown"}
    registered_start = len(labels) - suffix_count - 1
    return {
        "host": normalized,
        "tld": labels[-1],
        "registered_domain": ".".join(labels[registered_start:]),
        "subdomain": ".".join(labels[:registered_start]) or None,
        "parse_status": "known",
    }


def analyze_domain(host: str, intel: DomainIntelProvider | None = None) -> dict:
    """Analyze hostname structure. Optional intelligence stays disabled by default."""
    parts = domain_parts(host)
    is_ip = parts["parse_status"] == "ip"
    normalized = parts["host"]
    if is_ip:
        registered = evidence("registered_domain", False, "The URL host is an IP address, so it has no registered domain.", "info")
        subdomain = evidence("subdomain", False, "Subdomain structure does not apply to an IP address.", "info")
        tld = evidence("top_level_domain", False, "IP address URLs do not have a top-level domain.", "info")
    elif parts["parse_status"] == "unknown":
        registered = {"indicator": "registered_domain", "status": "unknown", "reason": "The registered domain cannot be determined safely from this hostname.", "severity": "info"}
        subdomain = {"indicator": "subdomain", "status": "unknown", "reason": "Subdomain structure cannot be determined without a known registered domain.", "severity": "info"}
        tld = {"indicator": "top_level_domain", "status": "unknown", "reason": "The hostname does not provide an unambiguous top-level domain.", "severity": "info"}
    else:
        registered = evidence("registered_domain", True, f"Registered domain: {parts['registered_domain']}.", "info")
        subdomain = evidence("subdomain", bool(parts["subdomain"]), f"Subdomain: {parts['subdomain']}." if parts["subdomain"] else "No subdomain is present.", "info")
        tld = evidence("top_level_domain", True, f"Top-level domain: .{parts['tld']}.", "info")

    ascii_or_punycode = any(label.startswith("xn--") for label in normalized.split(".")) or any(ord(char) > 127 for char in normalized)
    punycode = evidence(
        "punycode_or_non_ascii_domain", ascii_or_punycode,
        "The hostname contains a punycode or non-ASCII label; inspect it carefully for lookalike characters." if ascii_or_punycode else "No punycode or non-ASCII hostname characters were found.",
        "medium" if ascii_or_punycode else "none",
    )
    subdomain_count = len((parts.get("subdomain") or "").split(".")) if parts.get("subdomain") else 0
    excessive = evidence(
        "excessive_subdomains", subdomain_count > 3,
        f"The hostname has {subdomain_count} subdomain labels." if subdomain_count > 3 else f"The hostname has {subdomain_count} subdomain labels.",
        "medium" if subdomain_count > 3 else "none",
    ) if parts["parse_status"] == "known" else {"indicator": "excessive_subdomains", "status": "unknown", "reason": "Subdomain count cannot be determined safely.", "severity": "info"}

    brand_hit = None
    if parts["parse_status"] == "known":
        labels = set(normalized.split("."))
        for brand, owned_domains in BRANDS.items():
            if brand in labels and parts["registered_domain"] not in owned_domains:
                brand_hit = brand
                break
    brand = evidence(
        "brand_impersonation", brand_hit is not None,
        f"The hostname includes {brand_hit}, but its registered domain is {parts['registered_domain']}, not a supported {brand_hit} domain." if brand_hit else "No supported brand mismatch was found in the hostname.",
        "high" if brand_hit else "none",
    ) if parts["parse_status"] == "known" else {"indicator": "brand_impersonation", "status": "unknown", "reason": "Brand ownership cannot be compared without an unambiguous registered domain.", "severity": "info"}

    intel_results = (intel or DisabledDomainIntel()).check_domain(parts["registered_domain"]) if parts["registered_domain"] else {
        "domain_age": {"status": "unknown", "reason": "Domain age lookup requires a known registered domain."},
        "domain_reputation": {"status": "unknown", "reason": "Reputation lookup requires a known registered domain."},
    }
    intel_items = []
    for name in ("domain_age", "domain_reputation"):
        result = intel_results.get(name, {})
        item = {"indicator": name, "status": result.get("status", "unknown"), "reason": result.get("reason", "No result was provided by the configured lookup."), "severity": result.get("severity", "info")}
        for key in ("age_days", "registration_date", "provider"):
            if key in result:
                item[key] = result[key]
        intel_items.append(item)
    return {"details": parts, "indicators": [registered, subdomain, tld, punycode, excessive, brand, *intel_items]}
