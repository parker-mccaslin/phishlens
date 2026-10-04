"""Offline coverage for the URL, domain and category analyzers."""
from analyzers.domain_analyzer import DisabledDomainIntel, analyze_domain, domain_parts
from analyzers.pattern_detector import detect_categories
from analyzers.url_analyzer import analyze_url
from risk.scoring import score


def by_name(items):
    return {item["indicator"]: item for item in items}


def by_category(text):
    return {item["category"]: item for item in detect_categories(text)}


def test_domain_parts_handle_common_suffixes_and_uncertain_country_domains():
    assert domain_parts("login.mail.example.co.uk")["registered_domain"] == "example.co.uk"
    assert domain_parts("login.mail.example.co.uk")["subdomain"] == "login.mail"
    assert domain_parts("www.example.com")["tld"] == "com"
    assert domain_parts("login.example.fr")["parse_status"] == "unknown"


def test_url_structure_indicators_are_text_only():
    result = analyze_url("https://paypal.com.account-check.example.test/login/verify")
    items = by_name(result["indicators"])
    assert result["details"]["registered_domain"] == "example.test"
    assert items["https_used"]["status"] == "detected"
    assert items["brand_impersonation"]["status"] == "detected"
    assert items["suspicious_path_keywords"]["status"] == "detected"
    assert items["domain_reputation"]["status"] == "unknown"


def test_shortener_ip_punycode_and_http_signals():
    shortener = by_name(analyze_url("https://www.bit.ly/2x/login")["indicators"])
    assert shortener["url_shortener"]["status"] == "detected"
    assert shortener["insecure_http"]["status"] == "not_detected"
    ip_url = by_name(analyze_url("http://192.0.2.4/login")["indicators"])
    assert ip_url["ip_address_host"]["status"] == "detected"
    assert ip_url["insecure_http"]["status"] == "detected"
    punycode = by_name(analyze_url("https://xn--pple-43d.com/")["indicators"])
    assert punycode["punycode_or_non_ascii_domain"]["status"] == "detected"


def test_reputation_provider_is_mockable_and_off_by_default():
    disabled = by_name(analyze_domain("example.com")["indicators"])
    assert disabled["domain_age"]["status"] == "unknown"
    assert disabled["domain_reputation"]["status"] == "unknown"

    class MockIntel:
        def check_domain(self, registered_domain):
            assert registered_domain == "example.com"
            return {
                "domain_age": {"status": "detected", "reason": "Mock says this domain is newly registered.", "severity": "medium"},
                "domain_reputation": {"status": "not_detected", "reason": "Mock reputation has no reports."},
            }

    mocked = by_name(analyze_domain("example.com", MockIntel())["indicators"])
    assert mocked["domain_age"]["status"] == "detected"
    assert mocked["domain_reputation"]["status"] == "not_detected"
    assert isinstance(DisabledDomainIntel(), DisabledDomainIntel)


def test_each_scam_category_has_a_positive_example():
    messages = {
        "fake_invoice": "Your invoice is overdue. Please pay the overdue invoice today.",
        "delivery_notice": "Your package is on hold; pay a redelivery fee now.",
        "password_reset": "Your password expires today. Verify your account now.",
        "bank_impersonation": "Your bank account is locked. Verify your card details now.",
        "job_scam": "Remote job offer: pay a processing fee before we can send your equipment.",
        "prize_scam": "You have won a prize. Pay a fee today to claim it.",
        "tech_support": "Virus detected on your computer. Call tech support now.",
        "government_impersonation": "IRS notice: pay immediately or face a fine.",
        "crypto_scam": "Crypto investment with guaranteed returns. Send crypto today.",
    }
    for category, message in messages.items():
        assert by_category(message)[category]["status"] == "detected", category


def test_legitimate_messages_do_not_match_scam_categories():
    legitimate = [
        "Your invoice is ready to review. There is no payment deadline.",
        "Your package was delivered today. Tracking is available in our store app.",
        "You requested a password reset. If this was not you, ignore this email.",
        "Your monthly bank statement is ready in the bank's official app.",
        "Thank you for applying. The remote position pays a salary; there is no application fee.",
        "The community raffle winner can collect the prize at Saturday's event.",
        "Contact support if your computer has a problem; we will help during business hours.",
        "The IRS website has the tax filing deadline and forms for this year.",
        "Our crypto investing guide explains volatility and the risk of losing money.",
    ]
    for message in legitimate:
        assert not [item for item in detect_categories(message) if item["status"] == "detected"], message


def test_scoring_counts_distinct_indicators_once_and_reports_agreement():
    result = score([
        {"indicator": "brand_impersonation", "status": "detected"},
        {"indicator": "brand_impersonation", "status": "detected"},
        {"indicator": "urgency_language", "status": "detected"},
        {"indicator": "registered_domain", "status": "detected"},
    ])
    assert result["score"] == 33
    assert result["evidence_count"] == 2
    assert result["confidence"] == 0.32
