"""Private XDG configuration and Gemini key handling."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "phishlens"


def config_path() -> Path:
    return config_dir() / "config.toml"


def load_config() -> dict:
    try:
        with config_path().open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        return {}
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def api_key() -> str | None:
    saved = load_config().get("gemini", {})
    if not isinstance(saved, dict):
        saved = {}
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("PHISHLENS_API_KEY") or saved.get("api_key")


def gemini_model() -> str:
    saved = load_config().get("gemini", {})
    if not isinstance(saved, dict):
        saved = {}
    return os.environ.get("PHISHLENS_GEMINI_MODEL") or saved.get("model") or DEFAULT_GEMINI_MODEL


def save_settings(
    key: str | None,
    setup_complete: bool,
    domain_age_lookup: bool | None = None,
    domain_reputation_lookup: bool | None = None,
) -> None:
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    lines = [f"setup_complete = {'true' if setup_complete else 'false'}\n"]
    if domain_age_lookup is None:
        domain_age_lookup = domain_age_lookup_enabled()
    if domain_reputation_lookup is None:
        domain_reputation_lookup = domain_reputation_lookup_enabled()
    lines.extend([
        "\n[analysis]\n",
        f"domain_age_lookup = {'true' if domain_age_lookup else 'false'}\n",
        f"domain_reputation_lookup = {'true' if domain_reputation_lookup else 'false'}\n",
    ])
    model = gemini_model().replace("\\", "\\\\").replace('"', '\\"')
    lines.extend(["\n[gemini]\n", f'model = "{model}"\n'])
    if key:
        escaped = key.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'api_key = "{escaped}"\n')
    path = config_path()
    temporary = path.with_suffix(".tmp")
    temporary.write_text("".join(lines), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def setup_complete() -> bool:
    return bool(load_config().get("setup_complete", False))


def domain_age_lookup_enabled() -> bool:
    settings = load_config().get("analysis", {})
    return bool(settings.get("domain_age_lookup", False)) if isinstance(settings, dict) else False


def domain_reputation_lookup_enabled() -> bool:
    settings = load_config().get("analysis", {})
    return bool(settings.get("domain_reputation_lookup", False)) if isinstance(settings, dict) else False


def save_domain_age_lookup(enabled: bool) -> None:
    saved = load_config()
    gemini = saved.get("gemini", {})
    key = gemini.get("api_key") if isinstance(gemini, dict) else None
    save_settings(key, setup_complete(), domain_age_lookup=enabled)


def save_domain_reputation_lookup(enabled: bool) -> None:
    saved = load_config()
    gemini = saved.get("gemini", {})
    key = gemini.get("api_key") if isinstance(gemini, dict) else None
    save_settings(key, setup_complete(), domain_reputation_lookup=enabled)


def key_status() -> dict:
    key = api_key()
    if not key:
        return {"configured": False, "masked": None, "source": None}
    masked = f"••••{key[-4:]}" if len(key) >= 4 else "••••"
    source = "environment" if (os.environ.get("GEMINI_API_KEY") or os.environ.get("PHISHLENS_API_KEY")) else "file"
    return {"configured": True, "masked": masked, "source": source}
