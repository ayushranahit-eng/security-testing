"""
Security Scanner — FastAPI entry point.

engine.run_scan is async (uses async_playwright). Endpoints offload scans
just await it directly — no threads, no event loop juggling needed.
"""

import json
import io
import asyncio
import os
import sys
import threading
import traceback
import uuid
from datetime import datetime
from urllib.parse import urlparse

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from url_scanner.models import ScanRequest
from config        import DEFAULT_CONFIG
from core.engine   import run_scan
from core.pdf_report import build_pdf_filename, render_pdf_report_sync
from core.reporter import generate_text_report, generate_readable_json
from url_scanner.scanner.cookies import analyse_cookies
from url_scanner.scanner.headers import check_headers
from url_scanner.scanner.ssl_check import check_ssl, evaluate_ssl
import supabase_db as supabase
from ssh_scanner import server as deep_scan_server

app = FastAPI(
    title="Security Scanner API",
    description="Automated web security scanner — powered by Playwright",
    version="1.0.0",
)

SCAN_JOBS: dict[str, dict] = {}
SCAN_LOCK = threading.Lock()


class SignInRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8)


class SignUpRequest(SignInRequest):
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str | None = Field(default=None, max_length=80)
    company_name: str | None = Field(default=None, max_length=160)
    company_url: str | None = Field(default=None, max_length=240)


@app.on_event("startup")
def startup_event():
    if not supabase.enabled():
        return
    try:
        supabase.init_supabase()
        print("Supabase persistence enabled")
    except Exception as exc:
        print(f"Supabase persistence disabled: {exc}")


@app.on_event("shutdown")
def shutdown_event():
    supabase.close_supabase()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
        "https://security-testing-nine.vercel.app",
        "https://securitytool-api.handsintechnology.in",
        *[
            origin.strip().rstrip("/")
            for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        ],
        "null",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

app.mount("/deep-scan", deep_scan_server.app)


def _build_cfg(req: ScanRequest) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg["target_url"] = str(req.url)
    cfg["headless"]   = req.headless
    cfg["max_pages"]  = req.max_pages
    cfg["max_depth"]  = req.max_depth
    return cfg


def _run_scan_blocking(target_url: str, cfg: dict, progress=None) -> dict:
    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(run_scan(target_url, cfg, progress=progress))
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            asyncio.set_event_loop(None)
            loop.close()

    return asyncio.run(run_scan(target_url, cfg, progress=progress))


async def _run_scan_for_request(req: ScanRequest) -> dict:
    return await asyncio.to_thread(
        _run_scan_blocking,
        str(req.url),
        _build_cfg(req),
    )


def _public_job(scan_id: str) -> dict:
    with SCAN_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Scan ID not found")
        return dict(job)


def _update_job(scan_id: str, **updates) -> None:
    persistence_event = updates.get("event")
    with SCAN_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if job is not None:
            event = updates.pop("event", None)
            job.update(updates)
            if event is not None:
                events = job.setdefault("events", [])
                event["sequence"] = len(events) + 1
                event.setdefault("time", datetime.now().isoformat(timespec="seconds"))
                events.append(event)
                job["event_count"] = len(events)
            job["updated_at"] = datetime.now().isoformat(timespec="seconds")
    _persist_scan_update(scan_id, updates, persistence_event)


def _persist_scan_update(scan_id: str, updates: dict, event: dict | None = None) -> None:
    if not supabase.enabled():
        return
    try:
        if supabase.is_ready():
            supabase.update_scan(scan_id, updates, event=event)
    except Exception as exc:
        print(f"Supabase scan update skipped for {scan_id}: {exc}")


def _authenticated_user_id(authorization: str | None) -> str | None:
    token = _bearer_token(authorization)
    if not token:
        return None
    user = supabase.user_from_access_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    return str(user["id"])


async def _run_background_scan(scan_id: str, req: ScanRequest) -> None:
    def progress(update: dict) -> None:
        _update_job(scan_id, **update)

    _update_job(scan_id, status="running", current_step="Queued")

    try:
        data = await asyncio.to_thread(
            _run_scan_blocking,
            str(req.url),
            _build_cfg(req),
            progress,
        )
        with SCAN_LOCK:
            job = SCAN_JOBS.get(scan_id)
            if job is not None:
                job.update({
                    "status": "completed",
                    "current_step": "Scan complete",
                    "result": data,
                    "pages_found": len(data.get("pages", [])),
                    "forms_found": len(data.get("forms", [])),
                    "inputs_found": len(data.get("inputs", [])),
                    "buttons_found": len(data.get("buttons", [])),
                    "api_calls_found": len(data.get("api_calls", [])),
                    "findings_found": len(data.get("findings", [])),
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                    "finished_at": datetime.now().isoformat(timespec="seconds"),
                })
                events = job.setdefault("events", [])
                events.append({
                    "sequence": len(events) + 1,
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "level": "info",
                    "phase": "scan",
                    "message": "Scan completed",
                })
                job["event_count"] = len(events)
        if supabase.enabled():
            try:
                if supabase.is_ready():
                    supabase.complete_scan(scan_id, data)
            except Exception as exc:
                print(f"Supabase scan completion skipped for {scan_id}: {exc}")
    except Exception as exc:
        traceback.print_exc()
        with SCAN_LOCK:
            job = SCAN_JOBS.get(scan_id)
            if job is not None:
                job.update({
                    "status": "failed",
                    "current_step": "Scan failed",
                    "error": str(exc),
                    "event_count": len(job.setdefault("events", [])) + 1,
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                    "finished_at": datetime.now().isoformat(timespec="seconds"),
                })
                job["events"].append({
                    "sequence": job["event_count"],
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "level": "error",
                    "phase": "scan",
                    "message": "Scan failed",
                    "error": str(exc),
                })


def _scan_label(url: str) -> str:
    domain    = urlparse(url).netloc.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{domain}_{timestamp}"


def _next_scan_id() -> str:
    next_number = len(SCAN_JOBS) + 1
    if supabase.enabled():
        try:
            if supabase.is_ready():
                next_number = supabase.next_scan_number()
        except Exception as exc:
            print(f"Supabase scan counter skipped: {exc}")
    return f"SCAN{next_number:07d}"


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _estimate_scan_progress(job: dict) -> dict:
    current_step = str(job.get("current_step") or "")
    scan_phase = str(job.get("scan_phase") or "discovery")
    pages_crawled = max(0, int(job.get("pages_found", 0)))
    pages_pending = max(0, int(job.get("pending_pages", 0)))
    pages_scanned = max(0, int(job.get("pages_scanned", 0)))
    pages_known = max(
        pages_crawled,
        int(job.get("pages_known", 0) or 0),
        pages_crawled + pages_pending,
    )
    page_limit = max(1, int(job.get("max_pages", 20) or 20))
    pages_total = max(0, int(job.get("pages_total", 0) or 0))
    estimated_total_seconds = job.get("estimated_total_seconds")
    if estimated_total_seconds is not None:
        try:
            estimated_total_seconds = max(1, int(estimated_total_seconds))
        except Exception:
            estimated_total_seconds = None
    discovered_total = min(page_limit, max(pages_known, 1))
    crawl_complete = scan_phase in {"active_scan", "post_scan", "completed"} or current_step == "Page crawl limit reached"

    started_at = _parse_iso_timestamp(job.get("created_at"))
    finished_at = _parse_iso_timestamp(job.get("finished_at"))
    reference_time = finished_at or datetime.now()
    elapsed_seconds = 0
    if started_at is not None:
        elapsed_seconds = max(0, int((reference_time - started_at).total_seconds()))

    if job.get("status") == "failed":
        return {
            "elapsed_seconds": elapsed_seconds,
            "remaining_seconds": None,
            "progress_percent": min(95, max(5, int(job.get("progress_percent", 0) or 12))),
            "pages_known": max(pages_crawled, pages_known, pages_total),
            "page_limit": page_limit,
            "crawl_complete": False,
            "eta_finalized": False,
            "note": "Scan failed before the ETA could finish.",
        }

    if job.get("status") == "completed":
        return {
            "elapsed_seconds": elapsed_seconds,
            "remaining_seconds": 0,
            "progress_percent": 100,
            "pages_known": max(pages_crawled, pages_known, pages_total),
            "page_limit": page_limit,
            "crawl_complete": True,
            "eta_finalized": True,
            "note": "Scan complete.",
        }

    if elapsed_seconds <= 0:
        return {
            "elapsed_seconds": 0,
            "remaining_seconds": None,
            "progress_percent": 3,
            "pages_known": max(pages_known, pages_total),
            "page_limit": page_limit,
            "crawl_complete": crawl_complete,
            "eta_finalized": False,
            "note": "Building the first timing estimate.",
        }

    if estimated_total_seconds is None or scan_phase == "discovery":
        crawl_progress = pages_crawled / max(1, discovered_total)
        progress_percent = min(30, max(6, int(crawl_progress * 30)))
        return {
            "elapsed_seconds": elapsed_seconds,
            "remaining_seconds": None,
            "progress_percent": progress_percent,
            "pages_known": max(pages_known, pages_total),
            "page_limit": page_limit,
            "crawl_complete": False,
            "eta_finalized": False,
            "note": "Counting pages and scan tasks before locking the ETA.",
        }

    remaining_seconds = max(0, estimated_total_seconds - elapsed_seconds)
    pages_total = max(1, pages_total or pages_known)

    if scan_phase == "active_scan":
        page_fraction = pages_scanned / max(1, pages_total)
        elapsed_fraction = min(1.0, elapsed_seconds / max(1, estimated_total_seconds))
        progress_percent = min(90, max(32, int(max(page_fraction, elapsed_fraction) * 85)))
        note = "ETA is locked from the counted pages and discovered scan workload."
    elif scan_phase == "post_scan":
        elapsed_fraction = min(1.0, elapsed_seconds / max(1, estimated_total_seconds))
        progress_percent = min(99, max(88, int(elapsed_fraction * 100)))
        note = "All pages were counted first. The scanner is finishing the remaining checks."
    else:
        elapsed_fraction = min(1.0, elapsed_seconds / max(1, estimated_total_seconds))
        progress_percent = min(99, max(32, int(elapsed_fraction * 100)))
        note = "ETA is based on the counted pages and discovered workload."

    return {
        "elapsed_seconds": elapsed_seconds,
        "remaining_seconds": remaining_seconds,
        "progress_percent": progress_percent,
        "pages_known": max(pages_crawled, pages_known, pages_total),
        "page_limit": page_limit,
        "crawl_complete": True,
        "eta_finalized": True,
        "note": note,
    }


def _build_live_status(job: dict) -> dict:
    """Build a human-readable live status response for in-progress scans."""
    status = job.get("status", "unknown")
    current_step = job.get("current_step", "—")
    timing_estimate = _estimate_scan_progress(job)
    
    status_emoji = {
        "queued":  "⏳",
        "running": "🔍",
        "failed":  "❌",
    }.get(status, "⏳")
    
    # Recent events (last 10) with human-friendly format
    raw_events = job.get("events", [])
    recent_events = []
    for ev in raw_events[-10:]:
        phase = ev.get("phase", "")
        msg = ev.get("message", "")
        level = ev.get("level", "info")
        icon = {"info": "ℹ️", "warning": "⚠️", "error": "❌"}.get(level, "ℹ️")
        recent_events.append({
            "time": ev.get("time"),
            "phase": phase,
            "message": f"{icon} {msg}",
            "detail": {k: v for k, v in ev.items()
                       if k not in ("sequence", "time", "level", "phase", "message")}
        })

    return {
        "scan_id": job.get("scan_id"),
        "status": f"{status_emoji} {status.upper()}",
        "current_step": current_step,
        "target": job.get("target"),
        "live_metrics": {
            "pages_crawled": job.get("pages_found", 0),
            "pages_known": timing_estimate["pages_known"],
            "pages_scanned": job.get("pages_scanned", 0),
            "pages_total": job.get("pages_total", 0),
            "forms_found": job.get("forms_found", 0),
            "inputs_discovered": job.get("inputs_found", 0),
            "buttons_tested": job.get("buttons_found", 0),
            "api_calls_captured": job.get("api_calls_found", 0),
            "findings_so_far": job.get("findings_found", 0),
            "pages_pending": job.get("pending_pages", 0),
        },
        "progress_note": _get_step_note(current_step),
        "events_log": {
            "total_events": job.get("event_count", 0),
            "recent": recent_events,
        },
        "timing": {
            "started_at": job.get("created_at"),
            "last_updated": job.get("updated_at"),
            "elapsed_seconds": timing_estimate["elapsed_seconds"],
            "estimated_remaining_seconds": timing_estimate["remaining_seconds"],
            "eta_finalized": timing_estimate["eta_finalized"],
            "eta_note": timing_estimate["note"],
        },
        "error": job.get("error"),
        "progress": {
            "percent": timing_estimate["progress_percent"],
            "crawl_complete": timing_estimate["crawl_complete"],
            "page_limit": timing_estimate["page_limit"],
            "phase": job.get("scan_phase", "discovery"),
        },
    }


def _get_step_note(step: str) -> str:
    """Return a human-friendly note for the current scan step."""
    notes = {
        "Queued":                         "🕐 Scan is queued and will start shortly",
        "Starting scan":                  "🚀 Initializing the security scanner",
        "Launching browser":              "🌐 Launching headless Chromium browser",
        "Loading target page":            "📥 Loading the target URL",
        "Target page loaded":             "✅ Page loaded, beginning analysis",
        "Checking security headers":      "🔐 Inspecting HTTP response security headers",
        "Security headers checked":       "✅ Security headers analyzed",
        "Analyzing cookies":              "🍪 Examining session cookies and security flags",
        "Cookies analyzed":               "✅ Cookie analysis complete",
        "Discovering page elements":      "🔎 Discovering forms, inputs, and buttons",
        "Initial elements discovered":    "✅ Page elements cataloged",
        "Detecting authentication surface":"🔐 Checking whether login or signup functionality exists",
        "Authentication surface detection complete":"✅ Initial auth-surface classification complete",
        "Scan workload estimated":        "📋 Page discovery is complete and the scan has locked an ETA from the counted workload",
        "Scanning discovered page":       "🧪 Running active validation against the counted pages",
        "Interacting with target page":   "🤖 Filling forms and clicking buttons to trigger API calls",
        "Target page interaction complete":"✅ Main page interaction done",
        "Page crawl limit reached":       "📏 Page cap reached — crawl stopped and final checks are continuing",
        "Refreshing authentication surface classification":"🔄 Refreshing auth coverage using all discovered evidence",
        "Authentication coverage classification complete":"✅ Public vs auth-boundary coverage classification complete",
        "Finalizing post-crawl checks":   "🧾 Crawl is complete — finishing validation checks and preparing the final report",
        "Checking HTTP methods":          "🧪 Reviewing allowed HTTP methods and risky verbs like TRACE",
        "HTTP methods checked":           "✅ HTTP method review complete",
        "Validating SSL certificate":     "🔒 Verifying SSL/TLS certificate validity",
        "SSL validation complete":        "✅ SSL certificate checked",
        "Probing sensitive paths":        "🗂️ Testing common sensitive files and endpoints for exposure",
        "Sensitive path probing complete":"✅ Sensitive path review complete",
        "Analyzing CORS security":        "🌐 Checking cross-origin trust behavior",
        "CORS analysis complete":         "✅ CORS review complete",
        "Analyzing CSRF risk":            "🛡️ Reviewing forms for likely anti-CSRF protections",
        "CSRF risk analysis complete":    "✅ CSRF risk review complete",
        "Testing error handling":         "🧯 Checking whether error responses leak technical detail",
        "Error handling analysis complete":"✅ Error handling review complete",
        "Fingerprinting technology":      "🧠 Identifying likely frameworks and server-side technology markers",
        "Technology fingerprinting complete":"✅ Technology fingerprinting complete",
        "Checking GraphQL introspection": "🔎 Testing whether GraphQL schema metadata is publicly exposed",
        "GraphQL introspection check complete":"✅ GraphQL review complete",
        "Scanning JavaScript for secrets":"🔑 Checking first-party JavaScript and inline scripts for exposed keys or tokens",
        "JavaScript secret scan complete":"✅ JavaScript secret scan complete",
        "Checking source maps":          "🧩 Checking whether JavaScript source maps are publicly accessible",
        "Source map check complete":     "✅ Source map review complete",
        "Checking directory listing":    "📂 Checking whether the server exposes browsable directory indexes",
        "Directory listing check complete":"✅ Directory listing review complete",
        "Checking forced browsing":      "🚪 Testing common unlinked routes for direct access",
        "Forced browsing check complete":"✅ Forced browsing review complete",
        "Testing API rate limiting":     "⏱️ Sending a few quick API requests to look for throttling signals",
        "API rate limiting test complete":"✅ API throttling review complete",
        "Scan complete":                  "🎉 Scan finished — results ready",
    }
    return notes.get(step, f"🔄 {step}")


def _build_text_report(data: dict) -> tuple[str, bytes]:
    label = _scan_label(data.get("target", "scan"))
    scan_time = data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    text_bytes = generate_text_report(data, scan_time).encode("utf-8")

    return f"{label}.txt", text_bytes


def _build_pdf_report(data: dict) -> tuple[str, bytes]:
    scan_time = data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    filename = build_pdf_filename(data.get("target", "security-scan"), scan_time)
    content = render_pdf_report_sync(data, scan_time)
    return filename, content


def _download_text_response(data: dict) -> StreamingResponse:
    filename, content = _build_text_report(data)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _download_pdf_response(data: dict) -> StreamingResponse:
    filename, content = _build_pdf_report(data)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Health check ───────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/scan/start", include_in_schema=False)
async def scan_start(req: ScanRequest, authorization: str | None = Header(default=None)):
    """Start a scan in the background. Use the scan_id to poll status."""
    scan_id = _next_scan_id()
    now = datetime.now().isoformat(timespec="seconds")

    with SCAN_LOCK:
        SCAN_JOBS[scan_id] = {
            "scan_id": scan_id,
            "status": "queued",
            "target": str(req.url),
            "current_step": "Queued",
            "pages_found": 0,
            "forms_found": 0,
            "inputs_found": 0,
            "buttons_found": 0,
            "api_calls_found": 0,
            "findings_found": 0,
            "pending_pages": 0,
            "pages_known": 0,
            "pages_scanned": 0,
            "pages_total": 0,
            "scan_phase": "discovery",
            "max_pages": req.max_pages,
            "max_depth": req.max_depth,
            "events": [],
            "event_count": 0,
            "created_at": now,
            "updated_at": now,
            "finished_at": None,
        }

    if supabase.enabled():
        try:
            if supabase.is_ready():
                supabase.create_scan(scan_id, str(req.url), _build_cfg(req), user_id=_authenticated_user_id(authorization))
        except Exception as exc:
            print(f"Supabase scan create skipped for {scan_id}: {exc}")
            with SCAN_LOCK:
                job = SCAN_JOBS.get(scan_id)
                if job is not None:
                    job["persistence_error"] = str(exc)
                    job.setdefault("events", []).append({
                        "sequence": len(job.setdefault("events", [])) + 1,
                        "time": datetime.now().isoformat(timespec="seconds"),
                        "level": "error",
                        "phase": "persistence",
                        "message": "Supabase scan create failed",
                        "error": str(exc),
                    })
                    job["event_count"] = len(job["events"])

    asyncio.create_task(_run_background_scan(scan_id, req))
    return _public_job(scan_id)


@app.get("/debug/supabase", include_in_schema=False)
def debug_supabase():
    payload = {
        "enabled": supabase.enabled(),
        "ready": False,
        "url_configured": bool(supabase.SUPABASE_URL),
        "service_role_key_configured": bool(supabase.SUPABASE_SERVICE_ROLE_KEY),
        "anon_key_configured": bool(supabase.SUPABASE_ANON_KEY),
    }
    if not supabase.enabled():
        return payload
    try:
        payload["ready"] = supabase.is_ready()
        payload["users_count"] = supabase.count_rows("users")
        payload["scans_count"] = supabase.count_rows("scans")
        payload["next_scan_id"] = f"SCAN{supabase.next_scan_number():07d}"
        user = supabase.get_default_user()
        payload["default_user_email"] = user.get("email") if user else None
        payload["default_user_id"] = user.get("id") if user else None
    except Exception as exc:
        payload["error"] = str(exc)
    return payload


@app.get("/scan/status/{scan_id}")
def scan_status(
    scan_id: str,
    download: bool = Query(
        False,
        description="Set true to download the text report after completion. Default false returns readable JSON status.",
    ),
    pdf: bool = Query(
        False,
        description="Set true to download the PDF report after completion.",
    ),
    readable: bool = Query(
        True,
        description="Return engineer-readable JSON with commentary. Set false for raw JSON data.",
    ),
):
    """Return live status for a background scan.
    
    - While running: returns live progress (pages found, API calls, current step, events)
    - When complete (readable=true, default): returns a human-readable JSON report with engineer commentary
    - When complete (download=true): downloads the .txt report file
    - When complete (pdf=true): downloads the .pdf report file
    - When complete (readable=false): returns raw scan data JSON
    """
    if pdf:
        with SCAN_LOCK:
            job = SCAN_JOBS.get(scan_id)
            if job is None:
                raise HTTPException(status_code=404, detail="Scan ID not found")
            if job["status"] == "completed":
                return _download_pdf_response(job["result"])
            raise HTTPException(status_code=409, detail="PDF report is not ready yet")

    if download:
        with SCAN_LOCK:
            job = SCAN_JOBS.get(scan_id)
            if job is None:
                raise HTTPException(status_code=404, detail="Scan ID not found")
            if job["status"] == "completed":
                return _download_text_response(job["result"])
            raise HTTPException(status_code=409, detail="Text report is not ready yet")

    with SCAN_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Scan ID not found")

        # While running — return live progress (always readable)
        if job["status"] != "completed":
            return _build_live_status(dict(job))

        # Completed — return readable or raw
        if readable:
            result = job["result"]
            scan_time = result.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return generate_readable_json(result, scan_time)

    return _public_job(scan_id)


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


@app.post("/auth/signup")
def auth_signup(req: SignUpRequest):
    if not supabase.auth_enabled():
        raise HTTPException(status_code=503, detail="App auth is not configured")
    try:
        return supabase.sign_up_user(
            email=req.email,
            password=req.password,
            first_name=req.first_name,
            last_name=req.last_name,
            company_name=req.company_name,
            company_url=req.company_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/auth/signin")
def auth_signin(req: SignInRequest):
    if not supabase.auth_enabled():
        raise HTTPException(status_code=503, detail="App auth is not configured")
    try:
        return supabase.sign_in_user(req.email, req.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid email or password") from exc


@app.get("/me")
def current_user(authorization: str | None = Header(default=None)):
    if not supabase.enabled() or not supabase.is_ready():
        return {
            "first_name": "Ayush",
            "last_name": "Rana",
            "email": "ayush@example.com",
            "company_name": "Hands In Technology",
            "company_url": None,
            "account_plan": {
                "name": "Basic",
                "no_of_scans_available": 5,
            },
            "scans_used": len(SCAN_JOBS),
            "scans_left": max(0, 5 - len(SCAN_JOBS)),
            "persistence": "memory",
        }

    token = _bearer_token(authorization)
    if token:
        try:
            user = supabase.user_from_access_token(token)
            if user is None:
                raise HTTPException(status_code=401, detail="Invalid session")
            return supabase.current_user_payload(user)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid session") from exc

    return supabase.current_user_payload()


def _deep_scan_sessions(limit: int = 100, include_report: bool = False) -> list[dict]:
    sessions: list[dict] = []
    collection = deep_scan_server.deep_scan_collection()
    if collection is not None:
        projection = None if include_report else {"report_blob": 0}
        docs = collection.find({}, projection).sort("updated_at", -1).limit(limit)
        for doc in docs:
            session = deep_scan_server.session_from_mongo_doc(doc)
            if session:
                sessions.append(session)
        return sessions

    scans_dir = deep_scan_server.SCANS_DIR
    if not scans_dir.exists():
        return []
    for path in sorted(scans_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
        session = deep_scan_server.load_json_file(path, None)
        if isinstance(session, dict):
            sessions.append(session)
    return sessions


def _deep_scan_summary(session: dict) -> dict:
    report = session.get("report") or {}
    return (
        report.get("summary")
        or (session.get("report_summary") or {}).get("summary")
        or {}
    )


def _deep_scan_domain(session: dict) -> str:
    target = session.get("website_url") or (session.get("report_summary") or {}).get("root") or ""
    if not target:
        return "codebase"
    parsed = urlparse(str(target))
    return (parsed.netloc or parsed.path or str(target)).strip("/") or "codebase"


def _public_deep_scan(session: dict) -> dict:
    summary = _deep_scan_summary(session)
    return {
        "scan_id": session.get("id"),
        "id": session.get("id"),
        "url": session.get("website_url") or (session.get("report_summary") or {}).get("root"),
        "domain": _deep_scan_domain(session),
        "status": session.get("status", "unknown"),
        "created_at": session.get("created_at"),
        "updated_at": session.get("updated_at"),
        "completed_at": session.get("updated_at") if session.get("status") == "completed" else None,
        "summary": {
            "findings": int(summary.get("total", 0) or 0),
            "severity_counts": {
                "critical": int(summary.get("critical", 0) or 0),
                "high": int(summary.get("high", 0) or 0),
                "medium": int(summary.get("medium", 0) or 0),
                "low": int(summary.get("low", 0) or 0),
                "info": int(summary.get("info", 0) or 0),
            },
        },
        "scan_source": "deep_scan",
        "scanned_from": "Deep Scan",
    }


def _deep_scan_findings(limit: int = 200) -> list[dict]:
    rows: list[dict] = []
    for session in _deep_scan_sessions(limit=limit, include_report=True):
        report = session.get("report") or {}
        findings = report.get("findings") or []
        domain = _deep_scan_domain(session)
        target = session.get("website_url") or report.get("root") or domain
        for index, finding in enumerate(findings):
            rows.append({
                "id": f"{session.get('id')}-{index}",
                "scan_id": session.get("id"),
                "domain": domain,
                "url": target,
                "vulnerability_name": finding.get("title") or finding.get("vulnerability") or "Security finding",
                "severity": str(finding.get("severity") or "info").lower(),
                "status": "open",
                "description": finding.get("description") or finding.get("note") or "",
                "evidence": {
                    "tool": finding.get("tool"),
                    "category": finding.get("category"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "evidence": finding.get("evidence"),
                },
                "remediation": finding.get("remediation") or "",
                "raw": finding,
                "created_at": report.get("generated_at") or session.get("updated_at") or session.get("created_at"),
                "scan_source": "deep_scan",
                "scanned_from": "Deep Scan",
            })
            if len(rows) >= limit:
                return rows
    return rows


def _url_scan_memory_findings(limit: int = 200) -> list[dict]:
    rows: list[dict] = []
    with SCAN_LOCK:
        jobs = sorted(
            SCAN_JOBS.values(),
            key=lambda item: item.get("updated_at") or item.get("created_at") or "",
            reverse=True,
        )
        for job in jobs:
            result = job.get("result") or {}
            findings = result.get("findings") or []
            target = job.get("target") or result.get("target") or result.get("url") or ""
            parsed = urlparse(str(target))
            domain = (parsed.netloc or parsed.path or str(target)).strip("/") or "unknown"
            for index, finding in enumerate(findings):
                severity = finding.get("severity") or finding.get("risk") or finding.get("level") or "info"
                rows.append({
                    "id": f"{job.get('scan_id')}-{index}",
                    "scan_id": job.get("scan_id"),
                    "domain": domain.lower(),
                    "url": finding.get("url") or target,
                    "vulnerability_name": finding.get("title") or finding.get("name") or finding.get("type") or "Security finding",
                    "severity": str(severity).lower(),
                    "status": "open",
                    "description": finding.get("description") or finding.get("message") or finding.get("detail") or "",
                    "evidence": finding.get("evidence") or finding,
                    "remediation": finding.get("remediation") or finding.get("recommendation") or "",
                    "raw": finding,
                    "created_at": job.get("finished_at") or job.get("updated_at") or job.get("created_at"),
                    "scan_source": "url_scan",
                    "scanned_from": "URL Scan",
                })
                if len(rows) >= limit:
                    return rows
    return rows


@app.get("/account-plans")
def account_plans():
    if not supabase.enabled() or not supabase.is_ready():
        return [
            {
                "name": "Basic",
                "no_of_scans_available": 5,
                "persistence": "memory",
            }
        ]
    return supabase.list_account_plans()


@app.get("/dashboard/summary")
def dashboard_summary(authorization: str | None = Header(default=None)):
    if supabase.enabled() and supabase.is_ready():
        return supabase.dashboard_summary(user_id=_authenticated_user_id(authorization))
    with SCAN_LOCK:
        jobs = list(SCAN_JOBS.values())
    completed = [job for job in jobs if job.get("status") == "completed"]
    failed = [job for job in jobs if job.get("status") == "failed"]
    processing = [job for job in jobs if job.get("status") not in {"completed", "failed"}]
    findings_total = sum(int(job.get("findings_found", 0) or 0) for job in completed)
    return {
        "scans": {
            "total": len(jobs),
            "processing": len(processing),
            "completed": len(completed),
            "failed": len(failed),
            "by_type": {"url_scan": len(jobs), "deep_scan": 0},
        },
        "vulnerabilities": {
            "total": findings_total,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": findings_total,
            "info": 0,
        },
        "domains": {"total": 0, "items": []},
        "risk": "Info",
        "recent_scans": [
            dict(job, result=None, scan_source="url_scan", scanned_from="URL Scan")
            for job in sorted(jobs, key=lambda item: item.get("created_at", ""), reverse=True)[:8]
        ],
        "recent_vulnerabilities": [],
        "persistence": "memory",
    }


@app.get("/scans")
def scans(limit: int = Query(20, ge=1, le=100), authorization: str | None = Header(default=None)):
    if not supabase.enabled() or not supabase.is_ready():
        deep_rows = [_public_deep_scan(session) for session in _deep_scan_sessions(limit=limit)]
        with SCAN_LOCK:
            jobs = sorted(
                SCAN_JOBS.values(),
                key=lambda item: item.get("created_at", ""),
                reverse=True,
            )[:limit]
            url_rows = [
                dict(job, result=None, scan_source="url_scan", scanned_from="URL Scan")
                for job in jobs
            ]
        return sorted(
            url_rows + deep_rows,
            key=lambda item: item.get("updated_at") or item.get("created_at") or "",
            reverse=True,
        )[:limit]

    return supabase.list_scans(limit=limit, user_id=_authenticated_user_id(authorization))


@app.get("/findings")
def findings(
    status: str | None = None,
    severity: str | None = None,
    domain: str | None = None,
    scan_type: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
    limit: int | None = Query(None, ge=1, le=200),
    authorization: str | None = Header(default=None),
):
    effective_size = limit or page_size
    skip = 0 if limit else (page - 1) * effective_size
    normalized_type = (scan_type or "").lower()
    include_url = normalized_type in {"", "all", "url_scan"}
    include_deep = normalized_type in {"", "all", "deep_scan"}

    def row_matches(item: dict) -> bool:
        if status and str(item.get("status", "")).lower() != status.lower():
            return False
        if severity and str(item.get("severity", "")).lower() != severity.lower():
            return False
        if domain and str(item.get("domain", "")).lower() != domain.lower():
            return False
        if search:
            needle = search.lower()
            haystack = " ".join(str(item.get(key) or "") for key in (
                "vulnerability_name",
                "description",
                "domain",
                "url",
                "scan_id",
                "scanned_from",
            )).lower()
            return needle in haystack
        return True

    if not supabase.enabled() or not supabase.is_ready():
        deep_source = _deep_scan_findings(limit=min(200, skip + effective_size)) if include_deep else []
        deep_source = sorted(
            [item for item in deep_source if row_matches(item)],
            key=lambda item: item.get("created_at") or "",
            reverse=True,
        )
        deep_rows = deep_source[:effective_size] if limit else deep_source[skip:skip + effective_size]
        url_rows = _url_scan_memory_findings(limit=min(200, skip + effective_size)) if include_url else []
        combined = [item for item in url_rows + deep_rows if row_matches(item)]
        combined = sorted(combined, key=lambda item: item.get("created_at") or "", reverse=True)
        items = combined[:effective_size] if limit else combined[skip:skip + effective_size]
        return {
            "items": items,
            "total": len(combined),
            "page": page,
            "page_size": effective_size,
            "has_next": (skip + effective_size) < len(combined),
        }

    url_rows = []
    url_total = 0
    if include_url or include_deep:
        selected_scan_type = None if include_url and include_deep else ("url_scan" if include_url else "deep_scan")
        url_rows, url_total = supabase.list_vulnerabilities(
            status=status,
            severity=severity,
            domain=domain,
            scan_type=selected_scan_type,
            search=search,
            page=page,
            page_size=effective_size,
            user_id=_authenticated_user_id(authorization),
        )
    combined = url_rows
    total = url_total
    return {
        "items": combined,
        "total": total,
        "page": page,
        "page_size": effective_size,
        "has_next": (skip + effective_size) < total,
    }


@app.get("/scan/result/{scan_id}", include_in_schema=False)
def scan_result(
    scan_id: str,
    readable: bool = Query(
        True,
        description="Return engineer-readable JSON with commentary. Set false for raw data.",
    ),
):
    """Return final scan result once the background scan has completed."""
    with SCAN_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Scan ID not found")

        if job["status"] == "failed":
            raise HTTPException(
                status_code=500,
                detail=job.get("error", "Scan failed"),
            )

        if job["status"] != "completed":
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "Scan is not complete yet",
                    "status": job["status"],
                    "current_step": job["current_step"],
                },
            )

        result = job["result"]
        if readable:
            scan_time = result.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return generate_readable_json(result, scan_time)
        return result


@app.post("/micro/headers")
async def micro_headers(req: ScanRequest):
    """Run only the security header check."""
    import urllib.request

    findings = []
    try:
        request = urllib.request.Request(
            str(req.url),
            method="GET",
            headers={"User-Agent": "SecurityTestingPlatform/1.0"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    result = check_headers(
        headers,
        DEFAULT_CONFIG["required_security_headers"],
        findings,
    )
    return {
        "target": str(req.url),
        "security_headers": result,
        "findings": findings,
    }


@app.post("/micro/cookies")
async def micro_cookies(req: ScanRequest):
    """Run only the cookie flag check from an initial HTTP request."""
    import http.cookiejar
    import urllib.request

    findings = []
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [("User-Agent", "SecurityTestingPlatform/1.0")]

    try:
        opener.open(str(req.url), timeout=15).close()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    raw_cookies = [
        {
            "name": cookie.name,
            "secure": cookie.secure,
            "httpOnly": "httponly" in [key.lower() for key in cookie._rest],
            "sameSite": cookie._rest.get("SameSite") or cookie._rest.get("samesite"),
        }
        for cookie in jar
    ]

    return {
        "target": str(req.url),
        "cookies": analyse_cookies(raw_cookies, findings),
        "findings": findings,
    }


@app.post("/micro/ssl")
async def micro_ssl(req: ScanRequest):
    """Run only the SSL/TLS certificate check."""
    findings = []
    ssl_info = check_ssl(str(req.url))
    evaluate_ssl(ssl_info, findings)
    return {
        "target": str(req.url),
        "ssl": ssl_info,
        "findings": findings,
    }


# ── POST /scan ─────────────────────────────────────────────────────

@app.post("/scan")
async def scan(req: ScanRequest, authorization: str | None = Header(default=None)):
    """Start a scan. Poll /scan/status/{scan_id} for progress and download."""
    return await scan_start(req, authorization)


# ── POST /scan/download ────────────────────────────────────────────

@app.post("/scan/download", include_in_schema=False)
async def scan_download_json(req: ScanRequest):
    """Run a full scan. Downloads .json file."""
    data     = await _run_scan_for_request(req)
    filename = f"{_scan_label(str(req.url))}.json"
    content  = json.dumps(data, indent=4, ensure_ascii=False).encode("utf-8")

    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── POST /scan/report ──────────────────────────────────────────────

@app.post("/scan/report", include_in_schema=False)
async def scan_download_report(req: ScanRequest):
    """Run a full scan. Downloads .txt report."""
    data      = await _run_scan_for_request(req)
    scan_time = data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    report    = generate_text_report(data, scan_time)
    filename  = f"{_scan_label(str(req.url))}.txt"
    content   = report.encode("utf-8")

    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/scan/report/pdf", include_in_schema=False)
async def scan_download_pdf(req: ScanRequest):
    """Run a full scan. Downloads .pdf report."""
    data = await _run_scan_for_request(req)
    filename, content = await asyncio.to_thread(_build_pdf_report, data)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
