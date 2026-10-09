"""Live check of the Groq adapter (uses GROQ_API_KEY/GROQ_MODEL from .env; sends a synthetic text)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.adapters.llm.groq import GroqClient  # noqa: E402
from app.core.config import get_settings  # noqa: E402


def main() -> int:
    s = get_settings()
    if not s.groq_api_key:
        print("GROQ_API_KEY not set")
        return 2
    c = GroqClient(s.groq_api_key.get_secret_value(), s.groq_model, s.groq_base_url, 60)
    print("model:", c.model)
    text = "Invoice 2026-17 issued to ACME on 2026-03-04. Total due: 1200 EUR."
    out = c.complete("Summarize in one sentence.", f"<document>{text}</document>", max_tokens=100)
    print("summary:", out)
    raw = c.complete(
        'Reply with JSON {"currency": string, "date": "YYYY-MM-DD"}.',
        f"<document>{text}</document>",
        json_mode=True,
        max_tokens=100,
    )
    print("json ok:", json.loads(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
