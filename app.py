"""
S1 Prompt Security AI Gateway
=============================

A lightweight homegrown AI agent that routes every prompt and every model
response through SentinelOne Prompt Security's /api/protect endpoint before
anything is shown to the user.

Flow per message:
    1. Scan the USER PROMPT   -> S1 /api/protect   (block / modify / allow)
    2. If allowed, call the LLM
    3. Scan the MODEL RESPONSE -> S1 /api/protect   (block / modify / allow)
    4. Return the (possibly redacted) reply + a full inspection trace to the UI

You do NOT build the detectors (prompt injection, PII, data/model poisoning,
secrets, toxicity, jailbreak, etc.). Those are policies you enable in the S1
console. This app just calls /api/protect and enforces the verdict.

All configuration is read from a .env file in this folder. See .env.example.
"""

import os
import json
import uuid
import logging
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("s1-gateway")

# ---- SentinelOne Prompt Security ----
# Get these two values from the S1 console: Settings/Connectors -> Homegrown Apps.
# PS_PROTECT_URL is the full protect endpoint, e.g. https://eu.prompt.security/api/protect
# PS_APP_ID      is the App-ID shown for the homegrown app you create there.
PS_PROTECT_URL   = os.getenv("PS_PROTECT_URL", "").strip().rstrip("/")
PS_APP_ID        = os.getenv("PS_APP_ID", "").strip()
PS_APP_ID_HEADER = os.getenv("PS_APP_ID_HEADER", "APP-ID").strip()  # header name varies; default APP-ID
# Fail-closed (default) = if S1 is unreachable, BLOCK. Fail-open = allow anyway (only for testing).
PS_FAIL_OPEN     = os.getenv("PS_FAIL_OPEN", "false").lower() in ("1", "true", "yes")
PS_ENABLED       = bool(PS_PROTECT_URL and PS_APP_ID)

# ---- LLM provider ----
LLM_PROVIDER      = os.getenv("LLM_PROVIDER", "openai").lower()      # "openai" or "anthropic"
SYSTEM_PROMPT     = os.getenv("SYSTEM_PROMPT", "You are a helpful assistant.")
REQUEST_TIMEOUT   = float(os.getenv("REQUEST_TIMEOUT", "60"))

OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_BASE_URL   = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL      = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

BASE_DIR = Path(__file__).parent

app = FastAPI(title="S1 Prompt Security AI Gateway")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    user: Optional[str] = "demo-user"


# --------------------------------------------------------------------------- #
# S1 Prompt Security integration
# --------------------------------------------------------------------------- #
def _flatten_findings(value: Any) -> list[dict]:
    """Turn whatever S1 returns under findings/violations/detections into a flat
    list of {label, detail} so the UI can show chips. Handles dicts and lists."""
    out: list[dict] = []
    if isinstance(value, dict):
        for key, val in value.items():
            if val in (False, None, 0, "", [], {}):
                continue
            detail = ""
            if isinstance(val, (dict, list)):
                detail = json.dumps(val, ensure_ascii=False)[:300]
            elif not isinstance(val, bool):
                detail = str(val)
            out.append({"label": str(key), "detail": detail})
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                label = (item.get("type") or item.get("name") or item.get("category")
                         or item.get("detector") or "finding")
                detail = (item.get("description") or item.get("entity")
                          or item.get("value") or "")
                out.append({"label": str(label), "detail": str(detail)[:300]})
            else:
                out.append({"label": str(item), "detail": ""})
    return out


def _normalize_protect(direction: str, data: Any) -> dict:
    """Normalize the S1 /api/protect response into a consistent verdict.

    S1's exact JSON can vary slightly by version/tenant. This parser looks in
    the common places. If your console's API example uses different field names,
    adjust the keys below -- the raw response is always returned under "raw" so
    you can see exactly what came back and tweak this.
    """
    verdict = {"enabled": True, "allowed": True, "action": "allow",
               "modified_text": None, "findings": [], "raw": data}
    if not isinstance(data, dict):
        return verdict

    # The relevant block is usually under result.prompt or result.response.
    node = data
    res = data.get("result")
    if isinstance(res, dict):
        node = res.get(direction) if isinstance(res.get(direction), dict) else res

    action = str(node.get("action") or data.get("action") or data.get("status") or "").lower()
    passed = node.get("passed")
    if passed is None:
        passed = data.get("passed")

    findings: list[dict] = []
    for key in ("findings", "violations", "detections", "categories"):
        v = node.get(key) or data.get(key)
        if v:
            findings.extend(_flatten_findings(v))

    modified = (node.get("modified_text") or node.get("modified")
                or data.get("modified_text"))

    block_words  = ("block", "blocked", "deny", "denied", "reject", "rejected")
    modify_words = ("modify", "modified", "redact", "redacted", "anonymize", "mask", "masked")

    if action in block_words:
        verdict.update(allowed=False, action="block")
    elif action in modify_words or modified:
        verdict.update(allowed=True, action="modify", modified_text=modified)
    elif passed is False:
        verdict.update(allowed=False, action="block")
    else:
        verdict.update(allowed=True, action="allow")

    verdict["findings"] = findings
    return verdict


async def protect(client: httpx.AsyncClient, *, prompt: Optional[str] = None,
                  response: Optional[str] = None, system_prompt: Optional[str] = None,
                  user: Optional[str] = None) -> dict:
    """Call S1 /api/protect for either a prompt or a response.

    Matches the documented Homegrown Apps schema shown in the console:
        { "prompt": ..., "system_prompt": ..., "response": ..., "user": ... }
    Sent with header  APP-ID: <app id>.  All body fields are optional; send
    only what you have (prompt+system_prompt on the way in, response on the way out).
    """
    if not PS_ENABLED:
        return {"enabled": False, "allowed": True, "action": "allow",
                "modified_text": None, "findings": [], "raw": None}

    direction = "prompt" if prompt is not None else "response"
    payload: dict = {}
    if prompt is not None:
        payload["prompt"] = prompt
    if system_prompt:
        payload["system_prompt"] = system_prompt
    if response is not None:
        payload["response"] = response
    if user:
        payload["user"] = user

    headers = {PS_APP_ID_HEADER: PS_APP_ID, "Content-Type": "application/json"}

    try:
        r = await client.post(PS_PROTECT_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return _normalize_protect(direction, r.json())
    except Exception as exc:  # network error, auth error, timeout, bad JSON...
        log.error("S1 protect call failed (%s): %s", direction, exc)
        if PS_FAIL_OPEN:
            return {"enabled": True, "allowed": True, "action": "allow",
                    "modified_text": None,
                    "findings": [{"label": "scanner-error", "detail": f"{exc} (failed open)"}],
                    "raw": None}
        # Fail closed: treat as blocked so nothing slips past an unreachable scanner.
        return {"enabled": True, "allowed": False, "action": "block",
                "modified_text": None,
                "findings": [{"label": "scanner-error", "detail": f"{exc} (failed closed)"}],
                "raw": None}


# --------------------------------------------------------------------------- #
# LLM call
# --------------------------------------------------------------------------- #
async def call_llm(client: httpx.AsyncClient, message: str) -> str:
    if LLM_PROVIDER == "anthropic":
        headers = {"x-api-key": ANTHROPIC_API_KEY,
                   "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        payload = {"model": ANTHROPIC_MODEL, "max_tokens": 1024,
                   "system": SYSTEM_PROMPT,
                   "messages": [{"role": "user", "content": message}]}
        r = await client.post("https://api.anthropic.com/v1/messages",
                              json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()["content"][0]["text"]

    # default: OpenAI-compatible chat completions
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {"model": OPENAI_MODEL,
               "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": message}]}
    r = await client.post(f"{OPENAI_BASE_URL}/chat/completions",
                          json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/config")
async def config():
    """Lets the UI show whether S1 and the LLM are wired up."""
    return {
        "s1_enabled": PS_ENABLED,
        "s1_fail_open": PS_FAIL_OPEN,
        "llm_provider": LLM_PROVIDER,
        "llm_model": ANTHROPIC_MODEL if LLM_PROVIDER == "anthropic" else OPENAI_MODEL,
        "llm_key_set": bool(ANTHROPIC_API_KEY) if LLM_PROVIDER == "anthropic" else bool(OPENAI_API_KEY),
    }


@app.post("/api/chat")
async def chat(req: ChatRequest):
    conversation_id = req.conversation_id or str(uuid.uuid4())
    trace: dict = {"conversation_id": conversation_id, "prompt_scan": None, "response_scan": None}

    async with httpx.AsyncClient() as client:
        # 1) Scan the prompt
        prompt_scan = await protect(client, prompt=req.message,
                                    system_prompt=SYSTEM_PROMPT, user=req.user)
        trace["prompt_scan"] = prompt_scan
        if not prompt_scan["allowed"]:
            return {"blocked": True, "stage": "prompt", "reply": None, "trace": trace}

        prompt_to_send = prompt_scan["modified_text"] or req.message

        # 2) Call the model
        try:
            reply = await call_llm(client, prompt_to_send)
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500] if exc.response is not None else ""
            return {"blocked": False, "stage": "error", "reply": None, "trace": trace,
                    "error": f"LLM error {exc.response.status_code if exc.response else ''}: {body}"}
        except Exception as exc:
            return {"blocked": False, "stage": "error", "reply": None, "trace": trace,
                    "error": f"LLM error: {exc}"}

        # 3) Scan the response
        response_scan = await protect(client, response=reply, user=req.user)
        trace["response_scan"] = response_scan
        if not response_scan["allowed"]:
            return {"blocked": True, "stage": "response", "reply": None, "trace": trace}

        final_reply = reply
        if response_scan["action"] == "modify" and response_scan["modified_text"]:
            final_reply = response_scan["modified_text"]

    return {"blocked": False, "stage": "complete", "reply": final_reply,
            "conversation_id": conversation_id, "trace": trace}


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    log.info("S1 enabled=%s  fail_open=%s  provider=%s", PS_ENABLED, PS_FAIL_OPEN, LLM_PROVIDER)
    uvicorn.run(app, host=host, port=port)
