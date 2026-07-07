"""Verifies the configured Opus/Anthropic credentials actually work, before
anyone clicks Approve and finds out the hard way mid-triage.

Mirrors exactly the AnthropicFoundry usage pattern:
    client = AnthropicFoundry(api_key=key, base_url=endpoint)
    client.messages.create(model=deployment_name, messages=[...], max_tokens=...)
so a pass/fail here means the same call triage will make is confirmed working.
"""
from __future__ import annotations

import time

from agents.agent import _build_client
from runtime_settings import get_settings


def test_opus_connection() -> dict:
    """Makes one minimal, cheap Opus call and reports exactly what happened.
    Returns a dict the Settings UI can render directly - never raises."""
    rt = get_settings()
    provider = rt.get("provider", "anthropic")

    if provider == "azure_foundry":
        if not rt.get("azure_foundry_endpoint"):
            return {"ok": False, "provider": provider,
                    "error": "Azure Foundry endpoint is not set in Settings."}
        if not rt.get("azure_foundry_api_key"):
            return {"ok": False, "provider": provider,
                    "error": "Azure Foundry API key is not set in Settings."}
    else:
        if not rt.get("anthropic_api_key"):
            return {"ok": False, "provider": provider,
                    "error": "Anthropic API key is not set in Settings."}

    try:
        client = _build_client(rt)
    except Exception as exc:
        return {"ok": False, "provider": provider,
                "error": f"Could not build client: {exc}"}

    model = rt.get("agent_model", "claude-opus-4-6")
    started = time.time()
    try:
        message = client.messages.create(
            model=model,
            max_tokens=20,
            messages=[{"role": "user", "content": "Reply with exactly: OK"}],
        )
        elapsed = round(time.time() - started, 2)
        text = "".join(
            getattr(block, "text", "") for block in message.content
            if getattr(block, "type", "") == "text"
        )
        return {
            "ok": True,
            "provider": provider,
            "model": model,
            "response_time_sec": elapsed,
            "response_preview": text[:100],
            "input_tokens": getattr(message.usage, "input_tokens", None),
            "output_tokens": getattr(message.usage, "output_tokens", None),
        }
    except Exception as exc:
        elapsed = round(time.time() - started, 2)
        return {
            "ok": False,
            "provider": provider,
            "model": model,
            "response_time_sec": elapsed,
            "error": str(exc),
        }
