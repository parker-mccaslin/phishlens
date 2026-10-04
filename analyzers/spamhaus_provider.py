"""Optional domain reputation checks against the Spamhaus DBL DNS blocklist.

Queries go through the machine's configured DNS resolver. Because this reveals
the queried domain to that resolver and Spamhaus, callers must keep this
provider explicitly opt-in. DNS errors are unknown evidence, never clean results.
"""
from __future__ import annotations

import re
import socket
import threading

DBL_ZONE = "dbl.spamhaus.org"
MAX_QUERIES = 5

_LISTINGS = {
    "127.0.1.2": ("spam domain", "high"),
    "127.0.1.4": ("phishing domain", "high"),
    "127.0.1.5": ("malware domain", "high"),
    "127.0.1.6": ("botnet command-and-control domain", "high"),
    "127.0.1.102": ("legitimate domain abused for spam", "medium"),
    "127.0.1.103": ("legitimate domain abused as a redirector", "medium"),
    "127.0.1.104": ("legitimate domain abused for phishing", "medium"),
    "127.0.1.105": ("legitimate domain abused for malware", "medium"),
    "127.0.1.106": ("legitimate domain abused for command-and-control", "medium"),
}
_ERROR_ADDRESSES = {
    "127.0.1.255", "127.255.255.252", "127.255.255.254", "127.255.255.255",
}


def _valid_domain(domain: str) -> str | None:
    name = domain.rstrip(".").lower()
    if len(name) > 253 or not re.fullmatch(r"[a-z0-9.-]+", name):
        return None
    labels = name.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        return None
    return name


class SpamhausDBLIntel:
    """Query Spamhaus DBL with the system resolver; no HTTP API key is used."""

    def __init__(self, *, max_queries: int = MAX_QUERIES, resolver=None) -> None:
        self.max_queries = max_queries
        self._resolver = resolver or socket.getaddrinfo
        self._query_count = 0
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def check_domain(self, registered_domain: str) -> dict:
        domain = _valid_domain(registered_domain)
        if not domain:
            return self._unknown("The registered domain is not valid for a reputation lookup.")
        with self._lock:
            if domain in self._cache:
                return self._cache[domain]
            if self._query_count >= self.max_queries:
                return self._unknown("The per-analysis reputation lookup limit was reached.")
            self._query_count += 1

        try:
            answers = self._resolver(f"{domain}.{DBL_ZONE}", 80, socket.AF_INET, socket.SOCK_STREAM)
            addresses = {answer[4][0] for answer in answers}
            listed = next((address for address in addresses if address in _LISTINGS), None)
            error = next((address for address in addresses if address in _ERROR_ADDRESSES), None)
            if listed:
                category, severity = _LISTINGS[listed]
                result = {
                    "status": "detected",
                    "reason": f"Spamhaus DBL lists this domain as a {category} (DNS response {listed}).",
                    "severity": severity,
                    "provider": "Spamhaus DBL",
                }
            elif error:
                result = self._unknown(f"Spamhaus DBL could not provide a reliable result (DNS response {error}).")
            elif addresses:
                result = self._unknown("The DNS resolver returned an unexpected reputation response.")
            else:
                result = {
                    "status": "not_detected",
                    "reason": "Spamhaus DBL did not list this domain.",
                    "severity": "none",
                    "provider": "Spamhaus DBL",
                }
        except socket.gaierror as exc:
            if exc.errno == socket.EAI_NONAME:
                result = {
                    "status": "not_detected",
                    "reason": "Spamhaus DBL did not list this domain.",
                    "severity": "none",
                    "provider": "Spamhaus DBL",
                }
            else:
                result = self._unknown("The DNS reputation lookup could not be completed.")
        except Exception:
            result = self._unknown("The DNS reputation lookup could not be completed.")

        with self._lock:
            self._cache[domain] = result
        return result

    @staticmethod
    def _unknown(reason: str) -> dict:
        return {"status": "unknown", "reason": reason, "severity": "info", "provider": "Spamhaus DBL"}
