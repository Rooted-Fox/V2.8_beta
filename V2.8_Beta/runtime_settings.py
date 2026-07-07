"""Mutable runtime settings — updated from the browser UI without restarting."""
from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock

from config import settings as env_defaults

_STORE_PATH = Path(__file__).parent / "runtime_settings.json"
_lock = Lock()


def _load() -> dict:
    if _STORE_PATH.exists():
        return json.loads(_STORE_PATH.read_text())
    return {}


def _save(data: dict) -> None:
    _STORE_PATH.write_text(json.dumps(data, indent=2))


def get_settings() -> dict:
    data = _load()
    return {
        "provider":              data.get("provider") or "anthropic",
        "anthropic_api_key":     data.get("anthropic_api_key") or env_defaults.anthropic_api_key,
        "agent_model":           data.get("agent_model") or env_defaults.agent_model,
        "azure_foundry_endpoint":data.get("azure_foundry_endpoint") or "",
        "azure_foundry_api_key": data.get("azure_foundry_api_key") or "",
        "zap_api_url":           data.get("zap_api_url") or env_defaults.zap_api_url,
        "zap_api_key":           data.get("zap_api_key") or env_defaults.zap_api_key,
        "slack_webhook_url":     data.get("slack_webhook_url") or env_defaults.slack_webhook_url,
        "nvd_api_key":           data.get("nvd_api_key") or os.getenv("NVD_API_KEY", ""),
        "token_limit":           data.get("token_limit") or 0,
        "ai_enabled":            bool(data.get("ai_enabled", False)),
        "skip_info_findings":    bool(data.get("skip_info_findings", True)),
    }


def update_settings(**kwargs) -> dict:
    with _lock:
        data = _load()
        for key, value in kwargs.items():
            if value is not None and value != "":
                data[key] = value
        _save(data)
        return get_settings()


def has_api_key() -> bool:
    s = get_settings()
    if s["provider"] == "azure_foundry":
        return bool(s["azure_foundry_api_key"]) and bool(s["azure_foundry_endpoint"])
    return bool(s["anthropic_api_key"])


def masked(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"
