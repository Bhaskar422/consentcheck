"""ConsentCheck sandbox runner.

Runs inside the disposable browser sandbox. It speaks a tiny JSON-lines
protocol over stdin/stdout with the orchestrator:

    -> {"cmd": "open", "url": "...", "wait_ms": 6000}
    <- {"ok": true, "screenshot": "<b64 jpeg>", "candidates": [...], ...}

The runner never sees an API key, never decides what to click on its own and
never writes to the host. Every network request goes through the egress-guard
proxy, which keeps its own independent log.
"""

import base64
import json
import os
import re
import sys
import time
import traceback

from playwright.sync_api import Error as PWError
from playwright.sync_api import sync_playwright

PROXY = os.environ.get("CC_PROXY", "http://egress:8080")
VIEWPORT = {"width": 1280, "height": 800}
MAX_REQUESTS = 20000

# Words used on consent banners, in the languages most EU sites use.
REJECT_WORDS = [
    "reject", "decline", "deny", "refuse", "disagree", "do not accept", "don't accept",
    "necessary only", "only necessary", "essential only", "only essential",
    "necessary cookies only", "strictly necessary only", "use necessary", "continue without",
    "ablehnen", "nur notwendige", "nur erforderliche", "tout refuser", "refuser",
    "continuer sans accepter", "rechazar", "rifiuta", "weigeren", "afwijzen", "rejeitar",
    "recusar", "odrzuć", "avvisa", "afvis", "hylkää", "nein danke", "no, thank you", "no thanks",
    "continua senza accettare", "senza accettare", "continuar sin aceptar", "weiter ohne",
    "n'accepte rien", "je refuse", "nur technisch", "only strictly necessary", "only required",
]
ACCEPT_WORDS = [
    "accept", "agree", "allow all", "allow cookies", "got it", "i understand", "ok",
    "akzeptieren", "zustimmen", "accepter", "aceptar", "accetta", "accepteren",
    "aceitar", "zaakceptuj", "alle zulassen",
]
SETTINGS_WORDS = [
    "settings", "preferences", "customise", "customize", "manage", "more options",
    "options", "einstellungen", "paramètres", "personnaliser", "configurar", "personalizza",
    "további lehetőségek", "weitere optionen", "plus d'options", "altre opzioni", "más opciones",
]
SAVE_WORDS = [
    "save", "confirm my choices", "confirm choices", "confirm", "speichern", "enregistrer",
    "guardar", "salva", "opslaan",
]

# Reject buttons of well-known consent-management platforms (CMPs).
CMP_REJECT_SELECTORS = {
    "OneTrust": "#onetrust-reject-all-handler",
    "Cookiebot": "#CybotCookiebotDialogBodyButtonDecline",
    "Didomi": "#didomi-notice-disagree-button",
    "Usercentrics": "[data-testid='uc-deny-all-button']",
    "Complianz": ".cmplz-deny",
    "CookieYes": ".cky-btn-reject",
    "CookieFirst": "[data-cookiefirst-action='reject']",
    "Google Funding Choices": ".fc-cta-do-not-consent",
    "Osano": ".osano-cm-denyAll",
    "iubenda": ".iubenda-cs-reject-btn",
    "Termly": ".t-declineAllButton",
    "Klaro": ".cm-btn-decline",
    "consentmanager": "#cmpwelcomebtnno",
    "Cookie Consent (Osano OSS)": ".cc-deny",
    "Sourcepoint": "button.sp_choice_type_13",
}

CLICKABLE = "button, a, [role='button'], input[type='button'], input[type='submit'], [onclick]"

# Read the visible label of every clickable element in a frame. Playwright's
# CSS engine pierces open shadow roots, so CMPs in shadow DOM are covered.
LABEL_JS = """
els => els.map(e => {
  const t = (e.innerText || e.value || e.getAttribute('aria-label') || e.title || '').trim();
  return t.replace(/\\s+/g, ' ').slice(0, 80);
})
"""


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _word_re(words):
    return re.compile(r"(?<!\w)(" + "|".join(re.escape(w) for w in words) + r")(?!\w)")


REJECT_RE, ACCEPT_RE = _word_re(REJECT_WORDS), _word_re(ACCEPT_WORDS)
# A "reject" that only covers one vendor or service (e.g. "für Utiq jetzt
# ablehnen") is not a refusal of tracking in general and must never count as
# Reject all. These are reported with their own kind, which is never clickable.
# "Reject and subscribe", "Refuser et s'abonner", "Krone PUR bestellen": the
# refusal option is a paid subscription (consent-or-pay). Never clicked.
PAYWALL_RE = re.compile(
    r"subscri|abonn|abonieren|suscrib|abbona|assina|\bpay\b|pagar|payer|bezahl|bestellen|\bpur\b|\babo\b|zahlen"
)
PARTIAL_RE = re.compile(r"\butiq\b|(?<!\w)(für|for|pour|per|para|voor|för)\s+(?!all\b|alle\b|tout\b|tutti\b|todo\b|todas\b)\w")
SETTINGS_RE, SAVE_RE = _word_re(SETTINGS_WORDS), _word_re(SAVE_WORDS)


def classify(text):
    t = text.lower().strip()
    if not t or len(t) > 60:
        return None

    def has(pattern):
        return pattern.search(t) is not None

    # Order matters: a paid "reject" is not a refusal; then "Reject all" must
    # win over any accept-ish word.
    if has(PAYWALL_RE) and (has(REJECT_RE) or has(ACCEPT_RE) or re.search(r"\bpur\b", t)):
        return "pay_or_consent"
    if has(REJECT_RE):
        return "partial_reject" if has(PARTIAL_RE) else "reject"
    if has(SAVE_RE):
        return "save"
    if has(SETTINGS_RE):
        return "settings"
    if has(ACCEPT_RE):
        return "accept"
    return None


class Audit:
    def __init__(self, pw):
        self.browser = pw.chromium.launch(
            proxy={"server": PROXY},
            args=[
                # The container (gVisor/runc with dropped capabilities) is the
                # sandbox boundary, so Chromium's own setuid sandbox is off.
                "--no-sandbox",
                "--disable-dev-shm-usage",
                # Send even loopback traffic through the egress guard so it
                # is logged and blocked rather than silently bypassing it.
                "--proxy-bypass-list=<-loopback>",
                "--disable-quic",
            ],
        )
        self.context = self.browser.new_context(
            viewport=VIEWPORT,
            ignore_https_errors=True,  # the egress guard inspects TLS
            locale="en-GB",
            timezone_id="Europe/Berlin",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
            ),
        )
        self.page = self.context.new_page()
        self.phase = "before_choice"
        self.t0 = time.time()
        self.requests = []
        self.crashed = False
        self.candidates = {}
        self.cookie_snapshots = {}
        self.page.on("request", self._on_request)
        self.page.on("requestfailed", self._on_failed)
        self.page.on("response", self._on_response)
        self.page.on("crash", self._on_crash)

    # ---- network evidence -------------------------------------------------
    def _on_request(self, req):
        if len(self.requests) >= MAX_REQUESTS:  # a hostile page must not exhaust memory or disk
            return
        self.requests.append({
            "id": len(self.requests),
            "t": round(time.time() - self.t0, 3),
            "phase": self.phase,
            "method": req.method,
            "url": req.url[:2000],
            "type": req.resource_type,
            "frame": (req.frame.url[:300] if req.frame else ""),
            "status": None,
            "blocked_by_guard": None,
            "failed": None,
        })
        req._cc_id = len(self.requests) - 1  # noqa: SLF001

    def _find(self, req):
        idx = getattr(req, "_cc_id", None)
        if idx is not None and idx < len(self.requests):
            return self.requests[idx]
        for r in reversed(self.requests):
            if r["url"] == req.url[:2000]:
                return r
        return None

    def _on_response(self, resp):
        r = self._find(resp.request)
        if r is not None:
            r["status"] = resp.status
            blocked = resp.headers.get("x-consentcheck-blocked")
            if blocked:
                r["blocked_by_guard"] = blocked

    def _on_failed(self, req):
        r = self._find(req)
        if r is not None:
            r["failed"] = (req.failure or "failed")[:200]

    def _on_crash(self, _page):
        self.crashed = True

    # ---- helpers ----------------------------------------------------------
    def screenshot(self):
        try:
            png = self.page.screenshot(type="jpeg", quality=70, timeout=10000)
            return base64.b64encode(png).decode()
        except PWError:
            return None

    def snapshot_cookies(self, label):
        try:
            cookies = self.context.cookies()
        except PWError:
            cookies = []
        self.cookie_snapshots[label] = [
            {k: c.get(k) for k in ("name", "domain", "path", "expires", "httpOnly", "secure", "sameSite")}
            for c in cookies
        ]

    def local_storage_keys(self):
        try:
            return self.page.evaluate("() => Object.keys(window.localStorage || {}).slice(0, 200)")
        except PWError:
            return []

    def find_candidates(self):
        """List clickable consent controls across every frame (incl. shadow DOM)."""
        self.candidates = {}
        out = []
        deadline = time.monotonic() + 20  # heavy ad pages have dozens of frames
        for frame in self.page.frames[:40]:
            if time.monotonic() > deadline:
                break
            try:
                loc = frame.locator(CLICKABLE)
                labels = loc.evaluate_all(LABEL_JS)
            except PWError:
                continue
            for i, text in enumerate(labels[:400]):
                kind = classify(text)
                if not kind or time.monotonic() > deadline:
                    continue
                el = loc.nth(i)
                try:
                    box = el.bounding_box(timeout=1000)
                except PWError:
                    box = None
                if not box or box["width"] < 4 or box["height"] < 4:
                    continue
                if box["y"] > VIEWPORT["height"] * 3:
                    continue
                cid = f"c{len(out)}"
                self.candidates[cid] = el
                out.append({
                    "id": cid, "text": text, "kind": kind, "cmp": None,
                    "frame": "main" if frame == self.page.main_frame else frame.url[:120],
                    "box": {k: round(v) for k, v in box.items()},
                })
            # Known CMP selectors give a high-confidence hint.
            for cmp_name, sel in CMP_REJECT_SELECTORS.items():
                try:
                    hit = frame.locator(sel).first
                    if hit.count() and hit.is_visible(timeout=300):
                        box = hit.bounding_box(timeout=1000)
                        if not box:
                            continue
                        text = (hit.inner_text(timeout=1000) or "").strip()[:80]
                        cid = f"c{len(out)}"
                        self.candidates[cid] = hit
                        out.append({
                            # The selector is a hint; the visible label has the last word
                            # (a CMP "secondary" button can say "More options" or "Subscribe").
                            "id": cid, "text": text or cmp_name + " reject", "kind": classify(text) or "reject",
                            "cmp": cmp_name,
                            "frame": "main" if frame == self.page.main_frame else frame.url[:120],
                            "box": {k: round(v) for k, v in box.items()},
                        })
                except PWError:
                    continue
        return out

    def page_state(self):
        try:
            text = self.page.evaluate("() => (document.body ? document.body.innerText : '').slice(0, 3000)")
        except PWError:
            text = ""
        return {
            "url": self.page.url,
            "title": self._title(),
            "screenshot": self.screenshot(),
            "candidates": self.find_candidates() if not self.crashed else [],
            # Untrusted page text. The orchestrator treats it as data only.
            "page_text": text,
            "crashed": self.crashed,
            "request_count": len(self.requests),
        }

    def _title(self):
        try:
            return self.page.title()[:200]
        except PWError:
            return ""

    # ---- commands ---------------------------------------------------------
    def cmd_open(self, url, wait_ms=6000):
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except PWError as e:
            if self.crashed:
                return {"ok": False, "error": "renderer crashed", "crashed": True}
            return {"ok": False, "error": f"navigation failed: {str(e)[:300]}"}
        self.page.wait_for_timeout(wait_ms)
        self.snapshot_cookies("before_choice")
        return {"ok": True, **self.page_state()}

    def cmd_click(self, candidate_id, new_phase=None):
        el = self.candidates.get(candidate_id)
        if el is None:
            return {"ok": False, "error": f"unknown candidate {candidate_id}"}
        if new_phase:
            self.phase = new_phase
        try:
            el.click(timeout=5000)
        except PWError:
            try:
                el.click(timeout=3000, force=True)
            except PWError as e:
                return {"ok": False, "error": f"click failed: {str(e)[:200]}"}
        self.page.wait_for_timeout(2000)
        return {"ok": True, **self.page_state()}

    def cmd_observe(self, wait_ms=5000, reload=True):
        """After the choice: scroll, wait, then load a fresh page view."""
        try:
            self.page.mouse.wheel(0, 1500)
            self.page.wait_for_timeout(wait_ms)
            if reload:
                self.phase = "after_reject_reload"
                self.page.reload(wait_until="domcontentloaded", timeout=30000)
                self.page.wait_for_timeout(wait_ms)
        except PWError as e:
            if self.crashed:
                return {"ok": False, "error": "renderer crashed", "crashed": True}
            return {"ok": False, "error": str(e)[:300]}
        self.snapshot_cookies("after_choice")
        state = self.page_state()
        state.pop("candidates", None)
        return {"ok": True, **state}

    def cmd_collect(self):
        if "after_choice" not in self.cookie_snapshots:
            self.snapshot_cookies("after_choice")
        secretish = sorted(k for k in os.environ if any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASS")))
        return {
            "ok": True,
            "requests": self.requests,
            "cookies": self.cookie_snapshots,
            "local_storage_keys": self.local_storage_keys(),
            "crashed": self.crashed,
            # Proof for the report: names of credential-like env vars present
            # inside the sandbox (expected: none).
            "sandbox_secret_env_vars": secretish,
            "sandbox_user": os.environ.get("USER") or str(os.getuid()),
        }


def main():
    with sync_playwright() as pw:
        audit = Audit(pw)
        emit({"ok": True, "event": "ready", "uid": os.getuid()})
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                cmd = msg.get("cmd")
                if cmd == "open":
                    res = audit.cmd_open(msg["url"], msg.get("wait_ms", 6000))
                elif cmd == "click":
                    res = audit.cmd_click(msg["candidate_id"], msg.get("phase"))
                elif cmd == "observe":
                    res = audit.cmd_observe(msg.get("wait_ms", 5000), msg.get("reload", True))
                elif cmd == "collect":
                    res = audit.cmd_collect()
                elif cmd == "close":
                    emit({"ok": True, "event": "closing"})
                    break
                else:
                    res = {"ok": False, "error": f"unknown command {cmd}"}
            except Exception as e:  # report, never crash silently
                res = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:300]}",
                       "trace": traceback.format_exc()[-800:], "crashed": audit.crashed}
            emit(res)
        try:
            audit.browser.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
