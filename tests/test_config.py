"""Configuration tests do not make network requests."""
import asyncio
from types import SimpleNamespace

import httpx

from backend import config
from backend.main import app


def api_request(method, path, json=None):
    async def send():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, json=json)
    return asyncio.run(send())


def test_config_permissions_and_masked_key(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("PHISHLENS_API_KEY", raising=False)
    config.save_settings("secret-value-1234", True)
    assert oct(config.config_dir().stat().st_mode & 0o777) == "0o700"
    assert oct(config.config_path().stat().st_mode & 0o777) == "0o600"
    assert config.key_status()["masked"] == "••••1234"
    assert "secret-value" not in str(config.key_status())


def test_environment_key_overrides_file(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config.save_settings("file-key", True)
    monkeypatch.setenv("GEMINI_API_KEY", "environment-key")
    assert config.api_key() == "environment-key"


def test_connection_check_uses_a_mock_and_never_returns_key(monkeypatch, tmp_path):
    from google import genai

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("PHISHLENS_API_KEY", raising=False)
    config.save_settings("test-secret-key", True)

    class FakeClient:
        def __init__(self, api_key):
            assert api_key == "test-secret-key"
            self.models = self

        def generate_content(self, **kwargs):
            assert kwargs["contents"] == "Reply with the single word READY."
            return SimpleNamespace(text="READY")

    monkeypatch.setattr(genai, "Client", FakeClient)
    response = api_request("POST", "/api/setup/test", {})
    assert response.status_code == 200
    assert "test-secret-key" not in response.text
