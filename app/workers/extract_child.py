"""Isolated extraction process: ``python -I -m app.workers.extract_child`` (JSON on stdin/stdout).

Runs untrusted-content parsers in a separate OS process so that a crash, hang or memory blow-up
cannot take down the worker. The parent enforces a wall-clock timeout and (on POSIX) CPU/memory
rlimits; this process receives no credentials, imports no application settings and opens no
sockets itself. Network egress for processing workers must additionally be blocked at the
deployment layer (see docs/security/processing-isolation.md).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from app.modules.processing.extractors import extract, tesseract_ocr


def main() -> int:
    request = json.loads(sys.stdin.read())
    ocr = tesseract_ocr(request["ocr_command"]) if request.get("ocr_command") else None
    result = extract(
        Path(request["path"]),
        content_type=request["content_type"],
        filename=request["filename"],
        max_chars=int(request["max_chars"]),
        max_pages=int(request["max_pages"]),
        out_dir=Path(request["out_dir"]),
        ocr=ocr,
    )
    sys.stdout.write(
        json.dumps(
            {
                "status": result.status,
                "text": result.text,
                "truncated": result.truncated,
                "engine": result.engine,
                "error": result.error,
                "thumbnail": str(result.thumbnail) if result.thumbnail else None,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
