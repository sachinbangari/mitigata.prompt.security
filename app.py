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
import secrets
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
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

# ---- Optional login (HTTP Basic) ----
# Set APP_PASSWORD to require a login. Leave it empty/unset to keep the app open.
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")

BASE_DIR = Path(__file__).parent
# Serve UI/assets from a "static" subfolder if it exists, otherwise from the
# app's own folder. This makes deployment work whether index.html and logo.png
# are inside static/ (local) or sitting next to app.py (e.g. uploaded loose).
STATIC_DIR = BASE_DIR / "static" if (BASE_DIR / "static").is_dir() else BASE_DIR

_security = HTTPBasic(auto_error=False)


def require_auth(credentials: Optional[HTTPBasicCredentials] = Depends(_security)):
    """If APP_PASSWORD is set, require the right username/password; otherwise open."""
    if not APP_PASSWORD:
        return
    ok = (credentials is not None
          and secrets.compare_digest(credentials.username, APP_USERNAME)
          and secrets.compare_digest(credentials.password, APP_PASSWORD))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )

app = FastAPI(title="S1 Prompt Security AI Gateway", dependencies=[Depends(require_auth)])
if (BASE_DIR / "static").is_dir():
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


# --- verdict vocabulary: how S1 may express allow / modify / block, anywhere ---
_BLOCK_ACTION_WORDS  = {"block", "blocked", "deny", "denied", "reject", "rejected",
                        "prevent", "prevented", "prohibit", "prohibited", "forbidden"}
_MODIFY_ACTION_WORDS = {"modify", "modified", "redact", "redacted", "anonymize",
                        "anonymized", "mask", "masked", "sanitize", "sanitized"}
_ALLOW_ACTION_WORDS  = {"allow", "allowed", "pass", "passed", "log", "logged",
                        "monitor", "audit", "report", "ok", "clean", "approve", "approved"}
_ACTION_KEYS     = {"action", "verdict", "decision", "status", "outcome",
                    "enforcement", "policy_action", "result_action", "mode"}
_BLOCK_FLAG_KEYS = {"blocked", "is_blocked", "should_block", "block",
                    "violated", "is_violation", "denied"}
_PASS_FLAG_KEYS  = {"passed", "allowed", "valid", "is_valid", "ok", "clean"}
_MODIFIED_KEYS   = {"modified_text", "modified", "sanitized_text", "redacted_text"}


def _scan_signals(data: Any) -> dict:
    """Walk the ENTIRE S1 response and collect every verdict signal, wherever it
    sits (top level, result.prompt, inside a violations[] item, etc.). This is
    what lets the gateway enforce a block even when S1 nests the decision."""
    sig = {"block_action": False, "modify": False, "block_flag": False,
           "allow_action": False, "modified_text": None}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = str(k).lower()
                if isinstance(v, str):
                    vl = v.strip().lower()
                    if kl in _ACTION_KEYS:
                        if vl in _BLOCK_ACTION_WORDS:    sig["block_action"] = True
                        elif vl in _MODIFY_ACTION_WORDS: sig["modify"] = True
                        elif vl in _ALLOW_ACTION_WORDS:  sig["allow_action"] = True
                    if kl in _MODIFIED_KEYS and v.strip():
                        sig["modify"] = True
                        if not sig["modified_text"]:
                            sig["modified_text"] = v
                elif isinstance(v, bool):
                    if kl in _BLOCK_FLAG_KEYS and v:
                        sig["block_flag"] = True
                    if kl in _PASS_FLAG_KEYS and v is False:
                        sig["block_flag"] = True
                walk(v)
        elif isinstance(o, list):
            for item in o:
                walk(item)

    walk(data)
    return sig


def _normalize_protect(direction: str, data: Any) -> dict:
    """Normalize the S1 /api/protect response into a consistent verdict.

    The decision is made by scanning the WHOLE response for signals, so a block
    is honoured no matter where S1 puts it. Priority order (so a redaction is not
    mistaken for a hard block):
        1. an explicit block ACTION  -> block
        2. a modify/redact signal    -> modify (allowed, with redacted text)
        3. any block FLAG (passed:false, blocked:true, ...) -> block
        4. otherwise                 -> allow
    The full response is kept under "raw" so you can always see what S1 sent.
    """
    verdict = {"enabled": True, "allowed": True, "action": "allow",
               "modified_text": None, "findings": [], "raw": data}
    if not isinstance(data, dict):
        return verdict

    # Findings (for display) — pull from the usual containers wherever they are.
    findings: list[dict] = []
    node = data
    res = data.get("result")
    if isinstance(res, dict):
        node = res.get(direction) if isinstance(res.get(direction), dict) else res
    for src in ([node] if node is data else [node, data]):
        if isinstance(src, dict):
            for key in ("findings", "violations", "detections", "categories"):
                v = src.get(key)
                if v:
                    findings.extend(_flatten_findings(v))
    verdict["findings"] = findings

    sig = _scan_signals(data)
    if sig["block_action"]:
        verdict.update(allowed=False, action="block")
    elif sig["modify"]:
        verdict.update(allowed=True, action="modify", modified_text=sig["modified_text"])
    elif sig["block_flag"]:
        verdict.update(allowed=False, action="block")
    else:
        verdict.update(allowed=True, action="allow")
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
        v = _normalize_protect(direction, r.json())
        log.info("protect[%s] -> action=%s findings=%s",
                 direction, v["action"], [f["label"] for f in v["findings"]])
        return v
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
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/logo.png")
async def logo():
    return FileResponse(STATIC_DIR / "logo.png")


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
