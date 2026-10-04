"""Domain-age lookup through authoritative RDAP services.

IANA's RDAP DNS bootstrap registry discovers each TLD's RDAP server. The
provider sends only the registered domain name, never an email or URL path.
Callers must keep it opt-in and must treat missing results as unknown.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import threading
import time
from urllib.parse import quote, urlsplit

import httpx

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL_SECONDS = 24 * 60 * 60
MAX_RESPONSE_BYTES = 2_000_000
NEW_DOMAIN_DAYS = 30
REQUEST_TIMEOUT = httpx.Timeout(4.0, connect=2.0)
USER_AGENT = "PhishLens/0.2 (user-enabled domain registration date lookup)"

_bootstrap_lock = threading.Lock()
_bootstrap_document: dict | None = None
_bootstrap_expires_at = 0.0


def _unknown(reason: str) -> dict:
    return {
        "domain_age": {"status": "unknown", "reason": reason, "severity": "info"},
        "domain_reputation": {"status": "unknown", "reason": "Reputation lookup is disabled.", "severity": "info"},
    }


def _valid_domain(domain: str) -> str | None:
    name = domain.rstrip(".").lower()
    if len(name) > 253 or not name or not re.fullmatch(r"[a-z0-9.-]+", name):
        return None
    labels = name.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        return None
    return name


def _rdap_base(domain: str, bootstrap: dict) -> str | None:
    """Find the longest matching suffix in the IANA RDAP DNS bootstrap file."""
    best_suffix = ""
    best_url = None
    for entry in bootstrap.get("services", []):
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        suffixes, urls = entry
        if not isinstance(suffixes, list) or not isinstance(urls, list):
            continue
        for suffix in suffixes:
            if not isinstance(suffix, str):
                continue
            normalized = suffix.lower().lstrip(".")
            if (domain == normalized or domain.endswith("." + normalized)) and len(normalized) > len(best_suffix):
                best_suffix = normalized
                best_url = next((value for value in urls if isinstance(value, str)), None)
    if not best_url:
        return None
    parsed = urlsplit(best_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        return None
    return best_url.rstrip("/") + "/"


def _registration_time(document: dict) -> datetime | None:
    dates = []
    events = document.get("events", [])
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict) or str(event.get("eventAction", "")).lower() != "registration":
            continue
        value = event.get("eventDate")
        if not isinstance(value, str):
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            dates.append(parsed.astimezone(timezone.utc))
    return max(dates) if dates else None


class RDAPDomainIntel:
    """Opt-in provider for registration age; no paid API or key is required."""

    def __init__(
        self,
        *,
        new_domain_days: int = NEW_DOMAIN_DAYS,
        max_queries: int = 5,
        transport: httpx.BaseTransport | None = None,
        bootstrap_data: dict | None = None,
        now: datetime | None = None,
    ) -> None:
        self.new_domain_days = new_domain_days
        self.max_queries = max_queries
        self._transport = transport
        self._bootstrap_data = bootstrap_data
        self._now = now
        self._query_count = 0
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._client = httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=False, transport=transport)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RDAPDomainIntel":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def check_domain(self, registered_domain: str) -> dict:
        """Return age evidence, or `unknown` for unavailable/incomplete RDAP data."""
        domain = _valid_domain(registered_domain)
        if not domain:
            return _unknown("The registered domain is not valid for an RDAP lookup.")
        with self._lock:
            if domain in self._cache:
                return self._cache[domain]
            if self._query_count >= self.max_queries:
                return _unknown("The per-analysis RDAP lookup limit was reached.")
            self._query_count += 1
        try:
            bootstrap = self._bootstrap_data or self._get_bootstrap()
            base = _rdap_base(domain, bootstrap)
            if not base:
                result = _unknown("No secure authoritative RDAP service was found for this domain suffix.")
            else:
                document = self._get_json(base + "domain/" + quote(domain, safe=".-"))
                if not isinstance(document, dict) or document.get("objectClassName") != "domain":
                    result = _unknown("The RDAP service returned no usable domain registration record.")
                else:
                    result = self._age_result(document)
        except Exception:
            # Network and registry failures are unavailable evidence, never risk evidence.
            result = _unknown("The RDAP lookup could not be completed.")
        with self._lock:
            self._cache[domain] = result
        return result

    def _get_bootstrap(self) -> dict:
        global _bootstrap_document, _bootstrap_expires_at
        with _bootstrap_lock:
            if _bootstrap_document is not None and time.monotonic() < _bootstrap_expires_at:
                return _bootstrap_document
            result = self._get_json(IANA_BOOTSTRAP_URL)
            if not isinstance(result, dict) or not isinstance(result.get("services"), list):
                raise ValueError("Invalid RDAP bootstrap data")
            _bootstrap_document = result
            _bootstrap_expires_at = time.monotonic() + BOOTSTRAP_TTL_SECONDS
            return result

    def _get_json(self, url: str) -> dict:
        with self._client.stream("GET", url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT}) as response:
            if response.status_code != 200:
                raise ValueError("RDAP service returned an unavailable status")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("RDAP response exceeded the size limit")
            return json.loads(body)

    def _age_result(self, document: dict) -> dict:
        registered = _registration_time(document)
        now = self._now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        age_seconds = (now.astimezone(timezone.utc) - registered).total_seconds() if registered else None
        if age_seconds is None or age_seconds < 0:
            return _unknown("The RDAP record has no usable past registration date.")
        age_days = int(age_seconds // 86_400)
        new = age_days <= self.new_domain_days
        return {
            "domain_age": {
                "status": "detected" if new else "not_detected",
                "reason": f"RDAP lists registration on {registered.date().isoformat()} ({age_days} days ago)." + (" Recently registered domains deserve extra caution." if new else ""),
                "severity": "medium" if new else "none",
                "age_days": age_days,
                "registration_date": registered.date().isoformat(),
                "provider": "authoritative RDAP",
            },
            "domain_reputation": {"status": "unknown", "reason": "Reputation lookup is disabled.", "severity": "info"},
        }
