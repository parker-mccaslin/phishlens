"""Deterministic language indicators; no network or model calls."""
import re
from .common import evidence

URGENCY = re.compile(r"\b(urgent|immediately|act now|expires today|within \d+ hours|final notice|asap)\b", re.I)
ACCOUNT_THREAT = re.compile(r"\b(account (?:will be|has been) (?:suspended|closed|locked)|lose access|unauthorized login|unusual activity|verify your account or)\b", re.I)
REQUEST = re.compile(
    r"\b(?:enter|provide|send|share|confirm|verify|reply with|submit|update)\s+(?:your\s+)?"
    r"(?:password|passcode|one[- ]time code|verification code|bank details|credit card(?: details| number)?|payment details|card details)\b"
    r"|\b(?:pay\s+(?:now|immediately|today)|payment\s+(?:is\s+)?(?:due|required)|wire transfer|send (?:the )?payment)\b"
    r"|\bbuy\b.{0,40}\bgift cards?\b",
    re.I,
)

def urgency(text: str) -> dict:
    found = bool(URGENCY.search(text))
    return evidence("urgency_language", found, "The message uses time pressure." if found else "No clear urgency phrase was found.", "medium" if found else "none")

def account_threat(text: str) -> dict:
    found = bool(ACCOUNT_THREAT.search(text))
    return evidence("account_threat", found, "The message threatens account access or claims suspicious activity." if found else "No clear account threat was found.", "high" if found else "none")

def credential_payment_request(text: str) -> dict:
    found = bool(REQUEST.search(text))
    return evidence("credential_or_payment_request", found, "The message asks for credential or payment information." if found else "No clear request for credentials or payment was found.", "high" if found else "none")
