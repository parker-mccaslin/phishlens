"""Extensible keyword/regex scam-category indicators for v0.2."""
from __future__ import annotations

import re

from .common import evidence

CATEGORY_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "fake_invoice": (re.compile(r"\b(?:overdue invoice|past[- ]due invoice|invoice.{0,30}(?:overdue|past[- ]due|payment due)|pay.{0,25}invoice)\b", re.I), "Unpaid or overdue invoice language appears in the message."),
    "delivery_notice": (re.compile(r"\b(?:delivery.{0,25}(?:failed|held|fee|redelivery)|package.{0,30}(?:on hold|held|delivery fee)|pay.{0,20}(?:redelivery|delivery fee)|tracking.{0,25}(?:issue|problem))\b", re.I), "The message describes a delivery problem or asks for a delivery fee."),
    "password_reset": (re.compile(r"\b(?:password|account)\b.{0,28}\b(?:will be (?:disabled|locked|suspended)|expires? (?:today|soon)|unauthorized|suspicious activity|verify now|must verify|immediately)\b|\b(?:verify|confirm|update)\b.{0,35}\b(?:password|account|login)\b.{0,25}\b(?:now|immediately|today|suspended|locked|expire)\b", re.I), "The message uses a password or account warning to pressure the reader to verify or act."),
    "bank_impersonation": (re.compile(r"\b(?:bank|credit union|debit card|credit card|online banking)\b.{0,65}\b(?:suspend|lock|freeze|unauthorized|verify|confirm|secure|urgent|payment)\b|\b(?:suspend|lock|freeze|unauthorized|verify|confirm|secure|urgent)\b.{0,65}\b(?:bank|credit union|debit card|credit card|online banking)\b", re.I), "The message combines bank or card language with an account or verification warning."),
    "job_scam": (re.compile(r"\b(?:job offer|remote position|work[- ]from[- ]home|hiring you)\b.{0,100}\b(?:upfront fee|processing fee|buy.{0,25}equipment|deposit this check|send.{0,25}(?:refund|gift cards)|guaranteed income)\b|\b(?:upfront fee|processing fee|deposit this check|guaranteed income)\b.{0,100}\b(?:job|position|employment|hiring)\b", re.I), "The job message is paired with an upfront fee, check handling, or unusual purchase request."),
    "prize_scam": (re.compile(r"\b(?:you (?:have )?won|winner|claim your prize|prize money|lottery prize)\b.{0,90}\b(?:fee|pay|payment|claim|tax|gift card)\b|\b(?:pay|payment|fee)\b.{0,90}\b(?:prize|lottery|winner)\b", re.I), "Prize or lottery language is paired with a payment or claim request."),
    "tech_support": (re.compile(r"\b(?:virus detected|computer is infected|device infected|call (?:tech(?:nical)? support|support) now|remote access required|security alert.{0,25}call)\b", re.I), "The message claims a device infection or pressures the reader to contact support."),
    "government_impersonation": (re.compile(r"\b(?:irs|tax office|revenue service|court warrant|police warrant|government agency)\b.{0,75}\b(?:pay|fine|arrest|warrant|refund fee|urgent|immediately)\b|\b(?:pay|fine|arrest|warrant|refund fee|urgent|immediately)\b.{0,75}\b(?:irs|tax office|revenue service|court warrant|police warrant|government agency)\b", re.I), "Government, tax, or law-enforcement language is paired with an urgent threat or payment."),
    "crypto_scam": (re.compile(r"\b(?:guaranteed returns|double your crypto|crypto investment)\b.{0,80}\b(?:guaranteed|send|deposit|wallet|seed phrase|urgent)\b|\b(?:seed phrase|recovery phrase|wallet verification)\b.{0,60}\b(?:send|share|verify|enter|wallet)\b", re.I), "The message promises crypto returns or asks for sensitive wallet information."),
}


def detect_categories(text: str) -> list[dict]:
    """Run every category pattern independently and return a stable result list."""
    results = []
    for category, (pattern, reason) in CATEGORY_PATTERNS.items():
        found = bool(pattern.search(text))
        results.append({
            **evidence(f"category_{category}", found, reason if found else f"No clear {category.replace('_', ' ')} pattern was found.", "high" if found else "none"),
            "category": category,
        })
    return results
