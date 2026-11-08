"""Check the Vultr Serverless Inference setup before running real audits.

    VULTR_INFERENCE_API_KEY=... .venv/bin/python scripts/check_vultr.py

1. Lists the models the key can use and checks the three configured ones exist.
2. Sends each model a small screenshot and asks for JSON, to confirm it accepts
   images (planner and verifier) and replies in a format ConsentCheck can parse.
"""

import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import llm  # noqa: E402


# A 32x32 solid blue JPEG (1.1 KB), so the check needs no image library.
BLUE_JPEG = (
    "/9j/4AAQSkZJRgABAQAASABIAAD/4QCARXhpZgAATU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAAB"
    "AAIAAIdpAAQAAAABAAAATgAAAAAAAABIAAAAAQAAAEgAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAACCgAwAEAAAAAQAA"
    "ACAAAAAA/+0AOFBob3Rvc2hvcCAzLjAAOEJJTQQEAAAAAAAAOEJJTQQlAAAAAAAQ1B2M2Y8AsgTpgAmY7PhCfv/AABEIACAA"
    "IAMBIgACEQEDEQH/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMDAgQDBQUEBAAAAX0BAgMABBEF"
    "EiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdo"
    "aWpzdHV2d3h5eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5+jp"
    "6vHy8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAAAAQIDBAUGBwgJCgv/xAC1EQACAQIEBAMEBwUEBAABAncAAQIDEQQF"
    "ITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZn"
    "aGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo"
    "6ery8/T19vf4+fr/2wBDAAQEBAQEBAYEBAYJBgYGCQwJCQkJDA8MDAwMDA8SDw8PDw8PEhISEhISEhIVFRUVFRUZGRkZGRwc"
    "HBwcHBwcHBz/2wBDAQQFBQcHBwwHBwwdFBAUHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0d"
    "HR0dHR3/3QAEAAL/2gAMAwEAAhEDEQA/ANqiiivw0/cgooooA//Q2qKKK/DT9yCiiigD/9k="
)


async def main() -> int:
    if not llm.enabled():
        print("VULTR_INFERENCE_API_KEY is not set.")
        return 1
    print(f"Endpoint: {llm.BASE_URL}")
    ok = True
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{llm.BASE_URL}/models", headers={"Authorization": f"Bearer {llm.API_KEY}"})
    if r.status_code != 200:
        print(f"Listing models failed: HTTP {r.status_code} {r.text[:200]}")
        return 1
    available = sorted(m.get("id", "") for m in r.json().get("data", []))
    print(f"{len(available)} models available:\n  " + "\n  ".join(available))

    img = BLUE_JPEG
    for role, model, vision in (("planner", llm.AGENT_MODEL, True), ("verifier", llm.VERIFIER_MODEL, True),
                                ("report", llm.REPORT_MODEL, False)):
        if model not in available:
            print(f"\n[FAIL] {role}: '{model}' is not in the list. Set CC_{'AGENT' if role == 'planner' else role.upper()}_MODEL.")
            ok = False
            continue
        content = [{"type": "text", "text": 'What colour fills this image? Reply with JSON only: {"colour": "<word>"}'}]
        if vision:
            content.append(llm.image_part(img))
        else:
            content = 'Reply with JSON only: {"ok": true}'
        try:
            text, meta = await llm.chat(model, [{"role": "system", "content": "You reply with JSON only."},
                                                {"role": "user", "content": content}], max_tokens=200)
            parsed = llm.extract_json(text)
            print(f"\n[OK]   {role}: {model} replied in {meta['latency_ms']} ms "
                  f"({meta['prompt_tokens']} in / {meta['completion_tokens']} out): {parsed}")
        except llm.LLMError as e:
            print(f"\n[FAIL] {role}: {model}: {e}")
            ok = False
    print("\nAll good." if ok else "\nFix the failures above before auditing.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
