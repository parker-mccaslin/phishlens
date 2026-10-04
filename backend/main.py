"""Loopback-only FastAPI application for the local PhishLens UI."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from analyzers.language_analyzer import urgency, account_threat, credential_payment_request
from analyzers.pattern_detector import detect_categories
from analyzers.url_analyzer import extract_urls, links_present, analyze_url
from analyzers.rdap_provider import RDAPDomainIntel
from analyzers.spamhaus_provider import SpamhausDBLIntel
from backend import config, storage
from risk.scoring import score

MAX_INPUT_CHARS = 20_000
app = FastAPI(title="PhishLens", version="0.2.0")
MAX_ANALYZED_URLS = 20

CATEGORY_GUIDANCE = {
    "bank_impersonation": ("Bank impersonation", "Do not use the message link or phone number. Open your bank’s official app or call the number on your card."),
    "delivery_notice": ("Delivery notice", "Check the shipment in the retailer or carrier’s official app, or enter the tracking number on its known website."),
    "password_reset": ("Password reset", "Open the service’s app or type its known address yourself. Review account security there; do not use the message link."),
    "fake_invoice": ("Fake invoice", "Verify the invoice with the sender using a contact method you already trust. Do not pay through unexpected links or new account details."),
    "job_scam": ("Job scam", "Verify the employer through its official careers site. Do not pay fees, deposit checks, or buy gift cards for a recruiter."),
    "prize_scam": ("Prize scam", "Do not pay a fee or share financial details to claim an unexpected prize. Check directly with the named organization."),
    "tech_support": ("Tech support scam", "Do not call the number in the message or grant remote access. Contact your device maker or support provider through its official site."),
    "government_impersonation": ("Government impersonation", "Do not pay or share personal details through the message. Contact the agency using its official government website."),
    "crypto_scam": ("Crypto scam", "Never share a wallet recovery phrase or send crypto based on an unsolicited message. Verify through your wallet provider’s official channel."),
}
CATEGORY_PRIORITY = ["bank_impersonation", "government_impersonation", "crypto_scam", "tech_support", "password_reset", "job_scam", "prize_scam", "delivery_notice", "fake_invoice"]
class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_INPUT_CHARS)

class SetupRequest(BaseModel):
    api_key: str | None = Field(default=None, max_length=500)
    rules_only: bool = False

class DomainAgeSettingsRequest(BaseModel):
    enabled: bool

def _analyze_urls_with_intel(urls: list[str], age_enabled: bool, reputation_enabled: bool) -> list[dict]:
    """Perform bounded optional age and reputation lookups off the event loop."""
    class CombinedDomainIntel:
        def __init__(self):
            self.age = RDAPDomainIntel(max_queries=5) if age_enabled else None
            self.reputation = SpamhausDBLIntel(max_queries=5) if reputation_enabled else None

        def check_domain(self, domain: str) -> dict:
            age_result = self.age.check_domain(domain).get("domain_age", {}) if self.age else {
                "status": "unknown", "reason": "Domain age lookup is disabled.", "severity": "info"
            }
            reputation_result = self.reputation.check_domain(domain) if self.reputation else {
                "status": "unknown", "reason": "Domain reputation lookup is disabled.", "severity": "info"
            }
            return {"domain_age": age_result, "domain_reputation": reputation_result}

        def close(self):
            if self.age:
                self.age.close()

    provider = CombinedDomainIntel()
    try:
        preliminary = [analyze_url(url) for url in urls]
        domains = list(dict.fromkeys(
            result.get("details", {}).get("registered_domain")
            for result in preliminary
            if result.get("details", {}).get("registered_domain")
        ))[:5]
        if domains:
            with ThreadPoolExecutor(max_workers=min(3, len(domains))) as pool:
                list(pool.map(provider.check_domain, domains))
        return [analyze_url(url, intel=provider) for url in urls]
    finally:
        provider.close()

@app.get("/api/status")
async def status() -> dict:
    return {
        "setup_complete": config.setup_complete(), "key": config.key_status(),
        "domain_age_lookup_enabled": config.domain_age_lookup_enabled(),
        "domain_reputation_lookup_enabled": config.domain_reputation_lookup_enabled(),
    }

@app.post("/api/setup")
async def save_setup(body: SetupRequest) -> dict:
    key = body.api_key.strip() if body.api_key else None
    if key and any(ord(character) < 32 for character in key):
        raise HTTPException(400, "The API key format is invalid.")
    config.save_settings(key, True)
    return {"ok": True, "key": config.key_status()}

@app.post("/api/settings/domain-age")
async def set_domain_age_settings(body: DomainAgeSettingsRequest) -> dict:
    config.save_domain_age_lookup(body.enabled)
    return {"ok": True, "domain_age_lookup_enabled": config.domain_age_lookup_enabled()}


@app.post("/api/settings/domain-reputation")
async def set_domain_reputation_settings(body: DomainAgeSettingsRequest) -> dict:
    config.save_domain_reputation_lookup(body.enabled)
    return {"ok": True, "domain_reputation_lookup_enabled": config.domain_reputation_lookup_enabled()}

@app.post("/api/setup/test")
async def test_gemini() -> dict:
    key = config.api_key()
    if not key:
        raise HTTPException(400, "Add a Gemini API key first, or continue in rules-only mode.")
    try:
        from google import genai
        response = genai.Client(api_key=key).models.generate_content(
            model=config.gemini_model(),
            contents="Reply with the single word READY.",
        )
        if not response.text:
            raise RuntimeError("The service returned an empty response.")
        return {"ok": True, "message": "Connection successful. Your key was not displayed or logged."}
    except Exception as exc:  # SDK errors vary; never return their raw text.
        name, message = type(exc).__name__.lower(), str(exc).lower()
        if "unauthorized" in name or "permissiondenied" in name or "api key" in message or "unauthorized" in message:
            detail = "Google rejected the API key. Check the key in Google AI Studio."
        elif "quota" in name or "resourceexhausted" in name or "quota" in message or "429" in message:
            detail = "The Gemini quota or rate limit was reached. Try again later or check your Google AI Studio project."
        else:
            detail = "Could not reach Gemini. Check your network connection and try again."
        raise HTTPException(502, detail) from None

@app.post("/api/analyze")
async def analyze(body: AnalyzeRequest) -> dict:
    text = body.text.strip()
    if not text:
        raise HTTPException(400, "Paste a message to analyze.")
    all_urls = extract_urls(text)
    urls = all_urls[:MAX_ANALYZED_URLS]
    items = [urgency(text), account_threat(text), credential_payment_request(text), links_present(urls)]
    age_enabled = config.domain_age_lookup_enabled()
    reputation_enabled = config.domain_reputation_lookup_enabled()
    if urls and (age_enabled or reputation_enabled):
        url_analysis = await asyncio.to_thread(_analyze_urls_with_intel, urls, age_enabled, reputation_enabled)
    else:
        url_analysis = [analyze_url(url) for url in urls]
    for url, result in zip(urls, url_analysis):
        for item in result["indicators"]:
            item["url"] = url
            items.append(item)
    category_indicators = detect_categories(text)
    items.extend(category_indicators)
    detected_categories = [item["category"] for item in category_indicators if item["status"] == "detected"]
    primary_category = next((category for category in CATEGORY_PRIORITY if category in detected_categories), None)
    if primary_category:
        category_name, advice = CATEGORY_GUIDANCE[primary_category]
    else:
        category_name = None
        advice = "Do not use links or contact details in an unexpected message. Open the organization’s official app or type its known address yourself."
    detected_reasons = [item["reason"] for item in items if item["status"] == "detected" and item["severity"] != "info"]
    explanation = " ".join(detected_reasons[:3]) or "No high-signal indicators were detected. That does not prove the message is safe."
    report = {
        **score(items), "indicators": items, "urls": urls,
        "url_analysis": url_analysis,
        "domain_age_lookup_enabled": age_enabled,
        "domain_reputation_lookup_enabled": reputation_enabled,
        "url_count_total": len(all_urls),
        "url_analysis_limited": len(all_urls) > MAX_ANALYZED_URLS,
        "categories": detected_categories,
        "category": category_name,
        "why": explanation,
        "what_to_do": advice,
        "https_notice": "HTTPS encrypts a connection; it does not mean a site is legitimate." if urls else None,
        "notice": None,
    }
    item_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    storage.save_analysis(item_id, created_at, text, report)
    return {"id": item_id, "created_at": created_at, "text": text, "report": report}

@app.get("/api/history")
async def history() -> dict:
    return {"items": storage.list_analyses()}

@app.delete("/api/history")
async def clear_history() -> dict:
    storage.delete_history()
    return {"ok": True}

frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=frontend_dist / "assets"), name="assets")
    @app.get("/{path:path}")
    def frontend(path: str):
        candidate = (frontend_dist / path).resolve()
        if candidate.is_relative_to(frontend_dist.resolve()) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(frontend_dist / "index.html")
