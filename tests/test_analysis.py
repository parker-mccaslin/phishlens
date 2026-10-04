"""Offline tests for the v0.1 rules and local API."""
import asyncio
import httpx

from analyzers.language_analyzer import urgency, account_threat, credential_payment_request
from analyzers.url_analyzer import extract_urls, links_present
from risk.scoring import score
from backend import storage
from backend.main import app


def api_request(method, path, json=None):
    async def send():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, json=json)
    return asyncio.run(send())


def test_indicators_are_independent_and_deterministic():
    message = "URGENT: account will be locked. Verify password at https://example.test"
    assert urgency(message)["status"] == "detected"
    assert account_threat(message)["status"] == "detected"
    assert credential_payment_request(message)["status"] == "detected"
    urls = extract_urls(message)
    assert urls == ["https://example.test"]
    assert links_present(urls)["status"] == "detected"


def test_thin_evidence_is_unable_to_determine():
    items = [urgency("Hi, see you tomorrow."), account_threat("Hi, see you tomorrow."), credential_payment_request("Hi, see you tomorrow."), links_present([])]
    result = score(items)
    assert result["label"] == "Unable to determine"
    assert result["evidence_count"] == 0


def test_neutral_invoice_reference_is_not_a_payment_request():
    result = credential_payment_request("Please review the attached invoice. There is no payment deadline.")
    assert result["status"] == "not_detected"


def test_urls_are_only_extracted_as_text():
    assert extract_urls("visit www.example.test/path and https://second.test/end.") == ["www.example.test/path", "https://second.test/end"]
    assert extract_urls("example.net/login, contact help@example.org") == ["example.net/login"]


def test_api_limits_input_and_saves_local_history(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    response = api_request("POST", "/api/analyze", {"text": "URGENT: verify your password at https://example.test"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["report"]["https_notice"] == "HTTPS encrypts a connection; it does not mean a site is legitimate."
    assert payload["report"]["score"] <= 100
    assert len(storage.list_analyses()) == 1
    assert oct(storage.database_path().stat().st_mode & 0o777) == "0o600"
    assert api_request("POST", "/api/analyze", {"text": "x" * 20_001}).status_code == 422
    assert api_request("DELETE", "/api/history").status_code == 200
    assert storage.list_analyses() == []


def test_api_includes_domain_reasons_and_category_specific_advice(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    response = api_request("POST", "/api/analyze", {
        "text": "Your bank account was locked. Verify your card details now at https://paypal.com.login-check.example.test/verify"
    })
    assert response.status_code == 200
    report = response.json()["report"]
    assert report["category"] == "Bank impersonation"
    assert "official app" in report["what_to_do"]
    assert report["score"] >= 25
    assert any("registered domain: example.test" in item["reason"].lower() for item in report["indicators"])
    assert all("test" not in item.get("url", "") or item["url"].startswith("https://") for item in report["indicators"])
