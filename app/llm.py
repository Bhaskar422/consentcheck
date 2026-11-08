"""Vultr Serverless Inference client (OpenAI-compatible).

The API key lives only in the orchestrator's environment. It is never passed
to the sandbox, so a hostile page cannot read or exfiltrate it.
"""

import json
import os
import re
import time

import httpx

BASE_URL = os.environ.get("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").rstrip("/")
API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "").strip()

# Two different model families: one plans, the other independently verifies.
AGENT_MODEL = os.environ.get("CC_AGENT_MODEL", "glm-5.3-flash")
VERIFIER_MODEL = os.environ.get("CC_VERIFIER_MODEL", "qwen3.8-27b")
REPORT_MODEL = os.environ.get("CC_REPORT_MODEL", "glm-5.3")


def enabled() -> bool:
    return bool(API_KEY)


class LLMError(Exception):
    pass


def image_part(b64_jpeg: str) -> dict:
    return {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64_jpeg}"}}


async def chat(model: str, messages: list, max_tokens: int = 900, temperature: float = 0.0):
    """Return (text, meta). Raises LLMError on any failure."""
    if not API_KEY:
        raise LLMError("VULTR_INFERENCE_API_KEY is not set")
    started = time.time()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            resp = await client.post(
                f"{BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={"model": model, "messages": messages, "max_tokens": max_tokens,
                      "temperature": temperature},
            )
    except httpx.HTTPError as e:
        raise LLMError(f"request failed: {type(e).__name__}") from e
    if resp.status_code != 200:
        raise LLMError(f"HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    try:
        text = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError("unexpected response shape") from e
    usage = data.get("usage") or {}
    meta = {
        "model": model,
        "latency_ms": int((time.time() - started) * 1000),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
    }
    return text, meta


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model reply (tolerates <think> blocks and fences)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    raise LLMError("no JSON object in model reply")
