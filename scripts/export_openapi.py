"""Write the OpenAPI snapshot the frontend consumes (docs/api/openapi.json).

.venv/Scripts/python.exe scripts/export_openapi.py
"""

from __future__ import annotations

import json
from pathlib import Path

from app.main import create_app

OUT = Path(__file__).resolve().parents[1] / "docs" / "api" / "openapi.json"

if __name__ == "__main__":
    spec = create_app().openapi()
    OUT.write_text(
        json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {OUT} ({len(spec['paths'])} paths)")
