"""Documented v0.2 risk weights and evidence-agreement confidence."""

# Weights are additive by distinct indicator (not by match count or URL count).
# Structural facts such as HTTPS and the registered domain have no risk weight.
WEIGHTS = {
    "urgency_language": 8,
    "account_threat": 14,
    "credential_or_payment_request": 22,
    "links_present": 3,
    "insecure_http": 5,
    "url_shortener": 10,
    "ip_address_host": 15,
    "punycode_or_non_ascii_domain": 12,
    "excessive_subdomains": 7,
    "suspicious_path_keywords": 5,
    "brand_impersonation": 25,
    "domain_age": 15,
    "domain_reputation": 20,
    "category_fake_invoice": 16,
    "category_delivery_notice": 14,
    "category_password_reset": 16,
    "category_bank_impersonation": 25,
    "category_job_scam": 15,
    "category_prize_scam": 16,
    "category_tech_support": 18,
    "category_government_impersonation": 25,
    "category_crypto_scam": 18,
}


def score(evidence_items: list[dict]) -> dict:
    """Combine distinct detected indicators into a score and confidence.

    Confidence rises with the number of different positive indicators that
    agree. It measures evidence agreement, not statistical certainty.
    """
    detected_names = {
        item["indicator"]
        for item in evidence_items
        if item.get("status") == "detected" and WEIGHTS.get(item.get("indicator"), 0) > 0
    }
    value = min(100, sum(WEIGHTS[name] for name in detected_names))
    count = len(detected_names)
    confidence = 0.10 if count == 0 else min(0.92, 0.20 + 0.12 * (count - 1))
    if count == 0:
        label = "Unable to determine"
    elif value < 25:
        label = "Low risk"
    elif value < 50:
        label = "Suspicious"
    elif value < 75:
        label = "High risk"
    else:
        label = "Very high risk"
    return {
        "score": value,
        "label": label,
        "confidence": round(confidence, 2),
        "evidence_count": count,
        "evidence_indicators": sorted(detected_names),
    }
