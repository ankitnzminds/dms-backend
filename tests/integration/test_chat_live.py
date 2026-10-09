"""OPT-IN live test of the agent against the real model configured in .env (Groq).

    RUN_LIVE_GROQ=1 uv run pytest tests/integration/test_chat_live.py -s

Sends only synthetic text. It proves tool calling works end to end with the actual provider:
the model must search/retrieve through typed tools, cite [S#], and only PROPOSE a write.
Model behaviour is non-deterministic, so assertions are about the security contract and the
pipeline, not exact wording.
"""

from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RUN_LIVE_GROQ") != "1", reason="set RUN_LIVE_GROQ=1 to call the real model"
    ),
]
API = "/api/v1"


@pytest.fixture()
def live(world, monkeypatch):  # noqa: ANN001, ANN201
    from app.adapters.llm.groq import GroqClient
    from app.core.config import get_settings

    s = get_settings()
    if not s.groq_api_key:
        pytest.skip("GROQ_API_KEY not configured")
    client = GroqClient(s.groq_api_key.get_secret_value(), s.groq_model, s.groq_base_url, 90)
    for target in ("app.modules.chat.orchestrator.get_llm", "app.modules.chat.service.get_llm"):
        monkeypatch.setattr(target, lambda: client)
    return world


def test_live_grounded_answer_and_confirmed_write(live):  # noqa: ANN001
    admin = live.org("LiveChat")
    folder = live.mkdir(admin, live.root_id(admin), "finance")
    live.available_doc(
        admin,
        folder,
        "budget.txt",
        b"Annual budget memo. The approved 2026 marketing budget is 500000 EUR.",
    )
    conv = admin.post(f"{API}/chat/conversations", json={}).json()["id"]

    r = admin.post(
        f"{API}/chat/conversations/{conv}/messages",
        json={
            "content": "What is the approved 2026 marketing budget? Answer from the documents and cite."
        },
    )
    assert r.status_code == 202, r.text
    msgs = admin.get(f"{API}/chat/conversations/{conv}/messages").json()["items"]
    answer = [m for m in msgs if m["role"] == "assistant"][-1]
    print("ANSWER:", answer["content"])
    assert "500" in answer["content"], answer["content"]
    assert answer["citations"], "expected at least one verified citation"

    r = admin.post(
        f"{API}/chat/conversations/{conv}/messages",
        json={
            "content": f"Please create a folder called Audit 2026 inside the finance folder (id {folder})."
        },
    )
    assert r.status_code == 202, r.text
    msgs = admin.get(f"{API}/chat/conversations/{conv}/messages").json()["items"]
    blocks = [b for m in msgs for b in m["blocks"] if b.get("type") == "pending_action"]
    assert blocks, [m["content"] for m in msgs[-2:]]
    kids = admin.get(f"{API}/folders/{folder}/children").json()["items"]
    assert "Audit 2026" not in {k["name"] for k in kids}  # proposed, not executed
    action = admin.get(f"{API}/chat/actions/{blocks[-1]['action_id']}").json()
    done = admin.post(
        f"{API}/chat/actions/{action['id']}/confirm", json={"payload_hash": action["payload_hash"]}
    )
    assert done.status_code == 200 and done.json()["status"] == "executed", done.text
    kids = admin.get(f"{API}/folders/{folder}/children").json()["items"]
    assert any(k["name"].lower().startswith("audit") for k in kids)
