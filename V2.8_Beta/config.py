"""Centralized configuration for the OWASP DAST agent tool.

All values are loaded from environment variables (see .env.example).
This file only reads secrets, never stores them.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    agent_model: str = os.getenv("AGENT_MODEL", "claude-opus-4-6")
    db_path: Path = Path(os.getenv("DB_PATH", "findings.db"))
    slack_webhook_url: str = os.getenv("SLACK_WEBHOOK_URL", "")
    zap_api_url: str = os.getenv("ZAP_API_URL", "http://localhost:8090")
    zap_api_key: str = os.getenv("ZAP_API_KEY", "")


settings = Settings()
