"""Upload the office fixtures into a running dev stack through the real 3-step upload API.

    .venv/Scripts/python.exe scripts/upload_samples.py [folder name]

Signs in as alice@acme.test with the local dev password; for development only.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import sys
import time
import urllib.request
from pathlib import Path

BASE = "http://localhost:8000/api/v1"
FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "office"
TYPES = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".csv": "text/csv",
    ".md": "text/markdown",
}


def call(method: str, path: str, token: str | None = None, body: object | None = None, raw: bytes | None = None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    elif raw is not None:
        headers["content-type"] = "application/octet-stream"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)  # noqa: S310
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
        payload = r.read()
        return json.loads(payload) if payload else None


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "Office samples"
    token = call("POST", "/dev/login", body={"email": "alice@acme.test", "password": "dev-password-123"})["access_token"]
    root = call("GET", "/folders/root", token)["id"]
    folder = call("POST", "/folders", token, {"parent_folder_id": root, "name": name})["id"]
    print("folder:", name, folder)
    for path in sorted(FIXTURES.iterdir()):
        data = path.read_bytes()
        ctype = TYPES.get(path.suffix) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        session = call(
            "POST",
            f"/folders/{folder}/uploads",
            token,
            {"filename": path.name, "size_bytes": len(data), "content_type": ctype, "sha256": hashlib.sha256(data).hexdigest()},
        )
        call("PUT", "/uploads/" + session["upload_url"].split("/uploads/")[1], token, raw=data)
        doc = call("POST", f"/uploads/{session['id']}/finalize", token)
        print(f"  uploaded {path.name:28} {ctype[:40]:40} -> {doc['document_id']}")
    time.sleep(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
