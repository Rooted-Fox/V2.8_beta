"""Loads the app-specific knowledge base that gets fed into each OWASP
agent: tech stack/auth context, business rules, known false positives,
and past examples used to calibrate severity.

This is how you "train" the agents further without any actual model
fine-tuning - it's all extra context injected into the system prompt.
Edit knowledge_base.yaml; no code changes needed to add new entries.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from models import OwaspCategory

_DEFAULT_PATH = Path(__file__).parent / "knowledge_base.yaml"


class AppKnowledge:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or _DEFAULT_PATH
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return yaml.safe_load(self.path.read_text()) or {}

    @property
    def app_context_block(self) -> str:
        ctx = self._data.get("app_context", {}) or {}
        lines = []
        if ctx.get("tech_stack"):
            lines.append(f"- Tech stack: {ctx['tech_stack']}")
        if ctx.get("auth_flow"):
            lines.append(f"- Auth flow: {ctx['auth_flow']}")
        if ctx.get("sensitive_endpoints"):
            lines.append(f"- Sensitive endpoints: {', '.join(ctx['sensitive_endpoints'])}")
        return "Application context:\n" + "\n".join(lines) if lines else ""

    def for_category(self, category: OwaspCategory) -> str:
        """Build the full context block to append to one agent's system prompt."""
        section = (self._data.get("categories", {}) or {}).get(category.value, {}) or {}
        blocks = []

        if self.app_context_block:
            blocks.append(self.app_context_block)

        rules = section.get("business_rules") or []
        if rules:
            blocks.append("Business rules specific to this application:\n" + "\n".join(f"- {r}" for r in rules))

        false_positives = section.get("known_false_positives") or []
        if false_positives:
            blocks.append(
                "Known false positives for this category - treat findings matching "
                "these patterns as not exploitable unless the evidence clearly differs:\n"
                + "\n".join(f"- {fp}" for fp in false_positives)
            )

        examples = section.get("past_examples") or []
        if examples:
            example_lines = [
                f"- Finding: {ex.get('finding')} | severity assigned: {ex.get('assigned_severity')} | why: {ex.get('why')}"
                for ex in examples
            ]
            blocks.append("Past examples from this application, to calibrate severity judgment:\n" + "\n".join(example_lines))

        return "\n\n".join(blocks)
