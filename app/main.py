"""ConsentCheck web app: API + static UI + printable reports."""

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, dashboard, llm, orchestrator
from .report import render_report
from .sandbox import RUNTIME

STATIC = Path(__file__).parent / "static"
SAFE_NAME = re.compile(r"^[\w.\-]+$")
MAX_PENDING = 30       # public visitors, all together (the rest wait in the queue)
MAX_PER_CLIENT = 10    # public visitors, per IP address: queued + running
MAX_PUBLIC_BATCH = 10  # visitors may audit up to 10 sites at once
MAX_BATCH = 200        # admin batch queue
_tasks = set()
_owner: dict[str, str] = {}   # scan id -> client IP that started it

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
log = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(_app):
    orchestrator.load_scans()
    log.info("ConsentCheck admin user '%s', password %s", auth.ADMIN_USER, auth.init(orchestrator.RUNS_DIR))
    yield


app = FastAPI(title="ConsentCheck", lifespan=lifespan)


@app.middleware("http")
async def security(request: Request, call_next):
    # Reject cross-site POSTs even if a browser ignores SameSite (defence in depth).
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host", ""):
            return Response("Cross-origin request refused.", status_code=403)
    response = await call_next(request)
    h = response.headers
    h.setdefault("Content-Security-Policy", CSP)
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


class ScanIn(BaseModel):
    url: str = Field(max_length=2000)


class ApprovalIn(BaseModel):
    reviewer: str = Field("", max_length=80)
    decision: str = Field("approved", max_length=16)
    note: str = Field("", max_length=500)


class LoginIn(BaseModel):
    user: str = Field(max_length=100)
    password: str = Field(max_length=200)


class BatchIn(BaseModel):
    urls: list[str] = Field(max_length=MAX_BATCH)


def normalise_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or len(raw) > 2000:
        raise HTTPException(400, "Enter a website address.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    u = urlparse(raw)
    if u.scheme not in ("http", "https") or not u.hostname or "." not in u.hostname:
        raise HTTPException(400, "That doesn't look like a public website address.")
    return raw


def _public(scan, since=0):
    out = {k: v for k, v in scan.items() if k != "events"}
    out["events"] = scan["events"][since:]
    out["event_count"] = len(scan["events"])
    return out


@app.get("/api/health")
async def health():
    return {"ok": True, "ai": llm.enabled(), "provider": "Vultr Serverless Inference" if llm.enabled() else None,
            "models": {"agent": llm.AGENT_MODEL, "verifier": llm.VERIFIER_MODEL, "report": llm.REPORT_MODEL},
            "runtime": RUNTIME, "max_concurrent": orchestrator.MAX_CONCURRENT}


# ------------------------------------------------------------------ auth
@app.post("/api/auth/login")
async def login(body: LoginIn, request: Request, response: Response):
    ip = request.client.host if request.client else "?"
    auth.check_login(ip, body.user.strip(), body.password)  # raises 401/429 with details
    response.set_cookie(auth.COOKIE, auth.make_session(auth.ADMIN_USER), max_age=auth.SESSION_TTL,
                        httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/")
    return {"user": auth.ADMIN_USER}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    auth.revoke(request)
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request):
    return {"user": auth.session_user(request)}


# ------------------------------------------------------------------ scans
def _pending():
    return sum(1 for s in orchestrator.SCANS.values() if s["status"] in ("queued", "running"))


def _launch(url, client="", batch=False):
    orchestrator.prune_old_runs()
    scan = orchestrator.new_scan(url)
    _owner[scan["id"]] = client
    task = asyncio.create_task(orchestrator.run_scan(scan, batch=batch))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return scan


def _client(request: Request) -> str:
    return request.client.host if request.client else "?"


def _check_visitor_quota(request: Request, n: int) -> None:
    """Visitors (no admin session) may have MAX_PER_CLIENT audits queued or running."""
    if auth.session_user(request):
        return
    client = _client(request)
    mine = sum(1 for sid, ip in _owner.items() if ip == client
               and orchestrator.SCANS.get(sid, {}).get("status") in ("queued", "running"))
    if mine + n > MAX_PER_CLIENT:
        free = max(0, MAX_PER_CLIENT - mine)
        raise HTTPException(429, f"You can have {MAX_PER_CLIENT} audits in progress at once"
                                 + (f"; {free} more can start now." if free else ". Wait for some to finish."))
    if _pending() + n > MAX_PENDING:
        raise HTTPException(429, "The auditor is busy. Try again in a minute.")


def _parse_urls(raw_urls):
    urls, bad = [], []
    for raw in raw_urls:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        try:
            urls.append(normalise_url(raw))
        except HTTPException:
            bad.append(raw.strip()[:200])
    urls = list(dict.fromkeys(urls))
    if not urls:
        raise HTTPException(400, "No valid website addresses.")
    return urls, bad


@app.post("/api/scans")
async def create_scan(body: ScanIn, request: Request):
    url = normalise_url(body.url)
    _check_visitor_quota(request, 1)
    return {"id": _launch(url, _client(request))["id"]}


@app.post("/api/scans/batch")
async def create_batch(body: BatchIn, request: Request):
    """Several sites at once: up to 10 for visitors, up to 200 for a signed-in admin."""
    admin = auth.session_user(request)
    limit = MAX_BATCH if admin else MAX_PUBLIC_BATCH
    urls, bad = _parse_urls(body.urls)
    if len(urls) > limit:
        raise HTTPException(400, f"At most {limit} sites at once" + ("." if admin else
                                 ". Reviewers can sign in to queue larger batches."))
    if admin and _pending() + len(urls) > MAX_BATCH:
        raise HTTPException(429, f"The queue holds at most {MAX_BATCH} audits. {_pending()} are already waiting.")
    _check_visitor_quota(request, len(urls))
    owner = "admin" if admin else _client(request)
    # Admin batches use the batch lane; a visitor's handful of sites runs like single audits.
    ids = [_launch(u, owner, batch=bool(admin) and len(urls) > MAX_PUBLIC_BATCH)["id"] for u in urls]
    return {"queued": len(ids), "ids": ids, "invalid": bad}


def _summary(s):
    return {
        "id": s["id"], "url": s["url"], "status": s["status"], "created": s["created"],
        "verdict": (s.get("result") or {}).get("verdict"),
        "headline": (s.get("result") or {}).get("headline"),
        "approved": bool(s.get("approval")),
    }


@app.get("/api/scans")
async def list_scans(request: Request, ids: str = ""):
    """Visitors may look up the scans they started (by id). The full list is admin-only."""
    if ids:
        wanted = [i for i in ids.split(",")[:25] if i in orchestrator.SCANS]
        scans = [orchestrator.SCANS[i] for i in wanted]
    else:
        auth.require_admin(request)
        scans = list(orchestrator.SCANS.values())
    scans.sort(key=lambda s: s["created"], reverse=True)
    return [_summary(s) for s in scans]


# ------------------------------------------------------------------ dashboard
@app.get("/api/stats")
async def public_stats(request: Request, mine: str = ""):
    """Dashboard for everyone. Aggregate figures cover every audit, but the table only
    names a real site once a human reviewer has approved its audit (plus the visitor's
    own audits, looked up by id). Admins see every row."""
    data = dashboard.stats(list(orchestrator.SCANS.values()))
    admin = auth.session_user(request)
    data["view"] = "admin" if admin else "public"
    if not admin:
        own = set(i for i in mine.split(",")[:50] if i)
        data["unpublished"] = sum(1 for r in data["rows"] if not r["demo"] and r["approved"] != "approved")
        data["rows"] = [dict(r, mine=r["id"] in own) for r in data["rows"]
                        if r["id"] in own or (r["approved"] == "approved" and not r["demo"])]
    return data


@app.get("/api/admin/stats")
async def admin_stats(_user: str = Depends(auth.require_admin)):
    return dashboard.stats(list(orchestrator.SCANS.values()))


@app.post("/api/admin/batch")
async def admin_batch(body: BatchIn, request: Request, _user: str = Depends(auth.require_admin)):
    return await create_batch(body, request)


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, since: int = 0):
    scan = orchestrator.SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _public(scan, max(0, since))


@app.get("/api/scans/{scan_id}/files/{name}")
async def get_file(scan_id: str, name: str):
    if scan_id not in orchestrator.SCANS or not SAFE_NAME.match(name):
        raise HTTPException(404)
    path = (orchestrator.run_dir(scan_id) / name).resolve()
    if not path.is_file() or path.parent != orchestrator.run_dir(scan_id).resolve():
        raise HTTPException(404)
    if path.suffix == ".jpg":
        return FileResponse(path, media_type="image/jpeg")
    # Logs and JSON contain text chosen by the audited site: download, never render.
    return FileResponse(path, filename=path.name, content_disposition_type="attachment")


@app.post("/api/scans/{scan_id}/approve")
async def approve_scan(scan_id: str, body: ApprovalIn, user: str = Depends(auth.require_admin)):
    scan = orchestrator.SCANS.get(scan_id)
    if not scan or scan["status"] != "done":
        raise HTTPException(400, "Only finished scans can be reviewed.")
    if body.decision not in ("approved", "rejected"):
        raise HTTPException(400, "decision must be 'approved' or 'rejected'")
    reviewer = body.reviewer.strip() or user
    return orchestrator.approve(scan, f"{reviewer} (signed in as {user})" if reviewer != user else user,
                                body.decision, body.note.strip()[:500])


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report(scan_id: str):
    scan = orchestrator.SCANS.get(scan_id)
    if not scan or scan["status"] != "done":
        raise HTTPException(404, "Report not ready")
    return render_report(scan)


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
