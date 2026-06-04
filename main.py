"""
Security Scanner — FastAPI entry point.

engine.run_scan is async (uses async_playwright). Endpoints offload scans
just await it directly — no threads, no event loop juggling needed.
"""

import json
import io
import asyncio
import sys
import threading
import uuid
from datetime import datetime
from urllib.parse import urlparse

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse

from models        import ScanRequest
from config        import DEFAULT_CONFIG
from core.engine   import run_scan
from core.reporter import generate_text_report, generate_readable_json
from scanner.cookies import analyse_cookies
from scanner.headers import check_headers
from scanner.ssl_check import check_ssl, evaluate_ssl

app = FastAPI(
    title="Security Scanner API",
    description="Automated web security scanner — powered by Playwright",
    version="1.0.0",
)

SCAN_JOBS: dict[str, dict] = {}
SCAN_LOCK = threading.Lock()


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
    except Exception as exc:
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


def _build_live_status(job: dict) -> dict:
    """Build a human-readable live status response for in-progress scans."""
    status = job.get("status", "unknown")
    current_step = job.get("current_step", "—")
    
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
        "Interacting with target page":   "🤖 Filling forms and clicking buttons to trigger API calls",
        "Target page interaction complete":"✅ Main page interaction done",
        "Validating SSL certificate":     "🔒 Verifying SSL/TLS certificate validity",
        "SSL validation complete":        "✅ SSL certificate checked",
        "Scan complete":                  "🎉 Scan finished — results ready",
    }
    return notes.get(step, f"🔄 {step}")


def _build_text_report(data: dict) -> tuple[str, bytes]:
    label = _scan_label(data.get("target", "scan"))
    scan_time = data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    text_bytes = generate_text_report(data, scan_time).encode("utf-8")

    return f"{label}.txt", text_bytes


def _download_text_response(data: dict) -> StreamingResponse:
    filename, content = _build_text_report(data)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Health check ───────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/scan/start", include_in_schema=False)
async def scan_start(req: ScanRequest):
    """Start a scan in the background. Use the scan_id to poll status."""
    scan_id = uuid.uuid4().hex
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
            "events": [],
            "event_count": 0,
            "created_at": now,
            "updated_at": now,
            "finished_at": None,
        }

    asyncio.create_task(_run_background_scan(scan_id, req))
    return _public_job(scan_id)


@app.get("/scan/status/{scan_id}")
def scan_status(
    scan_id: str,
    download: bool = Query(
        False,
        description="Set true to download the text report after completion. Default false returns readable JSON status.",
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
    - When complete (readable=false): returns raw scan data JSON
    """
    if download:
        with SCAN_LOCK:
            job = SCAN_JOBS.get(scan_id)
            if job is None:
                raise HTTPException(status_code=404, detail="Scan ID not found")
            if job["status"] == "completed":
                return _download_text_response(job["result"])

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
async def scan(req: ScanRequest):
    """Start a scan. Poll /scan/status/{scan_id} for progress and download."""
    return await scan_start(req)


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
