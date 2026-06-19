"""
Supabase/Postgres persistence for account, URL scans, scan events, vulnerabilities,
and reports.

This replaces MongoDB for the login page and Scan a Domain module. It uses the
Supabase REST API through Python stdlib so the backend does not need an extra
dependency yet.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from dotenv import load_dotenv


load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip()

DEFAULT_PLAN_NAME = os.getenv("DEFAULT_ACCOUNT_PLAN", "Basic").strip() or "Basic"
DEFAULT_USER_EMAIL = os.getenv("DEFAULT_USER_EMAIL", "ayush@example.com").strip().lower()
DEFAULT_USER_FIRST_NAME = os.getenv("DEFAULT_USER_FIRST_NAME", "Ayush").strip() or "Ayush"
DEFAULT_USER_LAST_NAME = os.getenv("DEFAULT_USER_LAST_NAME", "Rana").strip() or "Rana"
DEFAULT_COMPANY_NAME = os.getenv("DEFAULT_COMPANY_NAME", "Hands In Technology").strip() or "Hands In Technology"
DEFAULT_COMPANY_URL = os.getenv("DEFAULT_COMPANY_URL", "").strip() or None

_default_user: dict[str, Any] | None = None
_scan_id_cache: dict[str, str] = {}


def enabled() -> bool:
    return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)


def is_ready() -> bool:
    if not enabled():
        return False
    try:
        _request("GET", "account_plans", {"select": "id", "limit": "1"})
        return True
    except Exception:
        return False


def init_supabase() -> bool:
    if not enabled():
        return False
    ensure_seed_data()
    return True


def close_supabase() -> None:
    return None


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_seed_data() -> None:
    plans = [
        ("basic", "Basic", 5, {"url_scan": True, "active_monitoring": False, "deep_scan": False}),
        ("advanced", "Advanced", 50, {"url_scan": True, "active_monitoring": True, "deep_scan": False}),
        ("premium", "Premium", None, {"url_scan": True, "active_monitoring": True, "deep_scan": True}),
    ]
    for code, name, scan_limit, features in plans:
        existing = _select_one("account_plans", {"code": f"eq.{code}"})
        if existing is None:
            _request("POST", "account_plans", payload={
                "code": code,
                "name": name,
                "no_of_scans_available": scan_limit,
                "features": features,
            })

    plan = get_plan_by_name(DEFAULT_PLAN_NAME) or get_plan_by_name("Basic")
    user = get_default_user()
    if user is None:
        _request("POST", "users", payload={
            "account_plan_id": plan["id"] if plan else None,
            "first_name": DEFAULT_USER_FIRST_NAME,
            "last_name": DEFAULT_USER_LAST_NAME,
            "email": DEFAULT_USER_EMAIL,
            "company_name": DEFAULT_COMPANY_NAME,
            "company_url": DEFAULT_COMPANY_URL,
        })
        reset_cache()


def reset_cache() -> None:
    global _default_user
    _default_user = None
    _scan_id_cache.clear()


def get_default_user() -> dict[str, Any] | None:
    global _default_user
    if _default_user is None:
        _default_user = _select_one("users", {
            "email": f"eq.{DEFAULT_USER_EMAIL}",
            "select": "*",
        })
    return _default_user


def default_user_id() -> str:
    user = get_default_user()
    if user is None:
        ensure_seed_data()
        user = get_default_user()
    if user is None:
        raise RuntimeError("Default Supabase user was not found")
    return str(user["id"])


def get_plan_by_name(name: str) -> dict[str, Any] | None:
    return _select_one("account_plans", {
        "name": f"eq.{name}",
        "select": "*",
    })


def current_user_payload() -> dict[str, Any]:
    user = get_default_user()
    if user is None:
        ensure_seed_data()
        user = get_default_user()
    if user is None:
        raise RuntimeError("Default Supabase user was not found")

    plan = None
    if user.get("account_plan_id"):
        plan = _select_one("account_plans", {"id": f"eq.{user['account_plan_id']}", "select": "*"})

    scans_used = count_rows("scans", {"user_id": f"eq.{user['id']}"})
    scans_available = plan.get("no_of_scans_available") if plan else 0
    scans_left = None if scans_available is None else max(0, int(scans_available or 0) - scans_used)

    payload = dict(user)
    payload["account_plan"] = plan
    payload["scans_used"] = scans_used
    payload["scans_left"] = scans_left
    payload["persistence"] = "supabase"
    return payload


def list_account_plans() -> list[dict[str, Any]]:
    return _request("GET", "account_plans", {
        "select": "*",
        "order": "no_of_scans_available.asc.nullslast",
    })


def create_scan(scan_id: str, target_url: str, config: dict[str, Any]) -> None:
    now = utcnow()
    row = {
        "scan_id": scan_id,
        "user_id": default_user_id(),
        "scan_type": "url_scan",
        "status": "processing",
        "target_url": target_url,
        "domain": _domain_from_url(target_url),
        "config": {
            "headless": bool(config.get("headless", True)),
            "max_pages": int(config.get("max_pages", 20)),
            "max_depth": int(config.get("max_depth", 2)),
        },
        "summary": {},
        "created_at": now,
        "updated_at": now,
    }
    created = _request("POST", "scans", payload=row, prefer="return=representation")
    if created:
        _scan_id_cache[scan_id] = created[0]["id"]


def create_deep_scan(scan_id: str, website_url: str, commands: dict[str, str]) -> None:
    now = utcnow()
    row = {
        "scan_id": scan_id,
        "user_id": default_user_id(),
        "scan_type": "deep_scan",
        "status": "processing",
        "target_url": website_url or None,
        "domain": _domain_from_url(website_url) if website_url else None,
        "config": {"commands": commands},
        "summary": {},
        "created_at": now,
        "updated_at": now,
    }
    created = _request("POST", "scans", payload=row, prefer="return=representation")
    if created:
        _scan_id_cache[scan_id] = created[0]["id"]


def update_deep_scan_session(session: dict[str, Any], event: dict[str, Any] | None = None) -> None:
    scan_id = session.get("id")
    if not scan_id:
        return
    scan_db_id = get_scan_db_id(scan_id)
    if not scan_db_id:
        return

    summary = _deep_scan_summary_from_session(session)
    config = {"commands": session.get("commands") or {}}
    if session.get("latest_event"):
        config["latest_event"] = session.get("latest_event")

    patch = {
        "status": _normalize_scan_status(session.get("status") or "processing"),
        "target_url": session.get("website_url") or None,
        "domain": _domain_from_url(session.get("website_url") or "") if session.get("website_url") else None,
        "repository_root": (session.get("report_summary") or {}).get("root"),
        "config": config,
        "summary": summary,
        "updated_at": utcnow(),
    }
    if patch["status"] in {"completed", "failed", "cancelled"}:
        patch["completed_at"] = patch["updated_at"]
    _request("PATCH", "scans", {"id": f"eq.{scan_db_id}"}, patch)

    if event is not None:
        insert_scan_event(scan_db_id, scan_id, {
            "timestamp": event.get("timestamp"),
            "stage": event.get("stage"),
            "status": event.get("status"),
            "level": event.get("level", "info"),
            "message": event.get("message") or "Deep Scan event received.",
            **{key: value for key, value in event.items() if key not in {"timestamp", "stage", "status", "level", "message"}},
        })


def complete_deep_scan(scan_id: str, report: dict[str, Any], report_id: str) -> None:
    scan_db_id = get_scan_db_id(scan_id)
    if not scan_db_id:
        return

    now = utcnow()
    summary = _deep_scan_summary(report)
    _request("PATCH", "scans", {"id": f"eq.{scan_db_id}"}, {
        "status": "completed",
        "repository_root": report.get("root"),
        "summary": summary,
        "completed_at": now,
        "updated_at": now,
    })

    _request("DELETE", "vulnerabilities", {"scan_db_id": f"eq.{scan_db_id}"})
    findings = report.get("findings") or []
    if findings:
        scan = _select_one("scans", {"id": f"eq.{scan_db_id}", "select": "target_url,domain"})
        target_url = (scan or {}).get("target_url") or report.get("root") or ""
        domain = (scan or {}).get("domain") or _domain_from_url(target_url)
        user_id = default_user_id()
        rows = [
            _deep_vulnerability_row(user_id, scan_db_id, scan_id, domain, target_url, finding, now)
            for finding in findings
        ]
        _request("POST", "vulnerabilities", payload=rows)

    _request("POST", "scan_reports", payload={
        "report_id": report_id,
        "scan_db_id": scan_db_id,
        "scan_id": scan_id,
        "user_id": default_user_id(),
        "report_type": "deep_scan_json",
        "report_file": report.get("report_file"),
        "summary": summary,
        "raw_json": report,
        "generated_at": report.get("generated_at") or now,
        "created_at": now,
    })


def update_scan(scan_id: str, updates: dict[str, Any], event: dict[str, Any] | None = None) -> None:
    scan_db_id = get_scan_db_id(scan_id)
    if not scan_db_id:
        return

    now = utcnow()
    patch: dict[str, Any] = {"updated_at": now}
    status = updates.get("status")
    if status is not None:
        patch["status"] = _normalize_scan_status(status)
        if status in {"running", "processing"}:
            patch["started_at"] = now
        if status in {"completed", "failed"}:
            patch["completed_at"] = now
    if "error" in updates:
        patch["error_message"] = str(updates["error"])

    progress_keys = {
        "current_step", "pages_found", "forms_found", "inputs_found",
        "buttons_found", "api_calls_found", "findings_found", "pending_pages",
        "pages_known", "pages_scanned", "pages_total", "scan_phase",
        "estimated_total_seconds",
    }
    progress = {key: updates[key] for key in progress_keys if key in updates}
    if progress:
        scan = _select_one("scans", {"id": f"eq.{scan_db_id}", "select": "summary"})
        summary = dict((scan or {}).get("summary") or {})
        summary["progress"] = {**dict(summary.get("progress") or {}), **progress}
        patch["summary"] = summary

    _request("PATCH", "scans", {"id": f"eq.{scan_db_id}"}, patch)

    if event is not None:
        insert_scan_event(scan_db_id, scan_id, event)


def complete_scan(scan_id: str, result: dict[str, Any]) -> None:
    scan_db_id = get_scan_db_id(scan_id)
    if not scan_db_id:
        return

    now = utcnow()
    findings = result.get("findings", []) or []
    severity_counts = _severity_counts(findings)
    summary = {
        "pages": len(result.get("pages", []) or []),
        "forms": len(result.get("forms", []) or []),
        "inputs": len(result.get("inputs", []) or []),
        "api_calls": len(result.get("api_calls", []) or []),
        "findings": len(findings),
        "severity_counts": severity_counts,
        "risk_score": _risk_score(severity_counts),
    }
    _request("PATCH", "scans", {"id": f"eq.{scan_db_id}"}, {
        "status": "completed",
        "summary": summary,
        "completed_at": now,
        "updated_at": now,
    })

    _request("DELETE", "vulnerabilities", {"scan_db_id": f"eq.{scan_db_id}"})
    if findings:
        user_id = default_user_id()
        target_url = result.get("target") or ""
        domain = _domain_from_url(target_url)
        rows = [
            _vulnerability_row(user_id, scan_db_id, scan_id, domain, target_url, finding, now)
            for finding in findings
        ]
        _request("POST", "vulnerabilities", payload=rows)

    _request("POST", "scan_reports", payload={
        "report_id": f"rpt_{uuid.uuid4().hex[:16]}",
        "scan_db_id": scan_db_id,
        "scan_id": scan_id,
        "user_id": default_user_id(),
        "report_type": "json",
        "summary": summary,
        "raw_json": result,
        "generated_at": now,
        "created_at": now,
    })


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    rows = _request("GET", "scans", {
        "select": "*",
        "order": "created_at.desc",
        "limit": str(limit),
    })
    return [_public_scan(row) for row in rows]


def get_deep_scan_session(scan_id: str) -> dict[str, Any] | None:
    scan = _select_one("scans", {
        "scan_id": f"eq.{scan_id}",
        "scan_type": "eq.deep_scan",
        "select": "*",
    })
    if not scan:
        return None
    return _deep_session_from_scan(scan)


def list_deep_scan_sessions(limit: int = 100, include_report: bool = False) -> list[dict[str, Any]]:
    rows = _request("GET", "scans", {
        "select": "*",
        "scan_type": "eq.deep_scan",
        "order": "created_at.desc",
        "limit": str(limit),
    })
    return [_deep_session_from_scan(row, include_report=include_report) for row in rows]


def list_vulnerabilities(
    status: str | None = None,
    severity: str | None = None,
    domain: str | None = None,
    scan_type: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[dict[str, Any]], int]:
    query = {
        "select": "*",
        "order": "created_at.desc",
        "limit": str(page_size),
        "offset": str((page - 1) * page_size),
    }
    count_query = {}
    if scan_type:
        query["scan_type"] = f"eq.{scan_type}"
        count_query["scan_type"] = f"eq.{scan_type}"
    if status:
        query["status"] = f"eq.{status.lower()}"
        count_query["status"] = f"eq.{status.lower()}"
    if severity:
        query["severity"] = f"eq.{severity.lower()}"
        count_query["severity"] = f"eq.{severity.lower()}"
    if domain:
        query["domain"] = f"eq.{domain.lower()}"
        count_query["domain"] = f"eq.{domain.lower()}"
    if search:
        text_filter = f"vulnerability_name.ilike.*{search}*,description.ilike.*{search}*,domain.ilike.*{search}*,url.ilike.*{search}*,scan_id.ilike.*{search}*"
        query["or"] = f"({text_filter})"
        count_query["or"] = f"({text_filter})"

    rows = _request("GET", "vulnerabilities", query)
    total = count_rows("vulnerabilities", count_query)
    return [_public_vulnerability(row) for row in rows], total


def dashboard_summary() -> dict[str, Any]:
    scans_total = count_rows("scans")
    scan_counts = {
        "processing": count_rows("scans", {"status": "eq.processing"}),
        "completed": count_rows("scans", {"status": "eq.completed"}),
        "failed": count_rows("scans", {"status": "eq.failed"}),
        "url_scan": count_rows("scans", {"scan_type": "eq.url_scan"}),
        "deep_scan": count_rows("scans", {"scan_type": "eq.deep_scan"}),
    }
    severity_counts = {
        "critical": count_rows("vulnerabilities", {"severity": "eq.critical"}),
        "high": count_rows("vulnerabilities", {"severity": "eq.high"}),
        "medium": count_rows("vulnerabilities", {"severity": "eq.medium"}),
        "low": count_rows("vulnerabilities", {"severity": "eq.low"}),
        "info": count_rows("vulnerabilities", {"severity": "eq.info"}),
    }
    vulnerabilities_total = sum(severity_counts.values())
    recent_scans = list_scans(limit=8)
    recent_vulnerabilities, _ = list_vulnerabilities(page=1, page_size=8)
    domain_rows = _request("GET", "scans", {
        "select": "scan_id,scan_type,target_url,domain,summary,status,created_at,updated_at",
        "order": "created_at.desc",
        "limit": "200",
    })
    domains = _domain_overview(domain_rows)
    return {
        "scans": {
            "total": scans_total,
            "processing": scan_counts["processing"],
            "completed": scan_counts["completed"],
            "failed": scan_counts["failed"],
            "by_type": {
                "url_scan": scan_counts["url_scan"],
                "deep_scan": scan_counts["deep_scan"],
            },
        },
        "vulnerabilities": {
            "total": vulnerabilities_total,
            **severity_counts,
        },
        "domains": {
            "total": len(domains),
            "items": domains,
        },
        "risk": _risk_label(severity_counts),
        "recent_scans": recent_scans,
        "recent_vulnerabilities": recent_vulnerabilities,
    }


def count_rows(table: str, filters: dict[str, str] | None = None) -> int:
    response_headers = _request(
        "GET",
        table,
        {"select": "id", "limit": "0", **(filters or {})},
        return_headers=True,
        extra_headers={"Prefer": "count=exact"},
    )
    content_range = response_headers.get("Content-Range") or response_headers.get("content-range") or ""
    if "/" in content_range:
        try:
            return int(content_range.rsplit("/", 1)[1])
        except ValueError:
            return 0
    return 0


def next_scan_number() -> int:
    return count_rows("scans") + 1


def get_scan_db_id(scan_id: str) -> str | None:
    if scan_id in _scan_id_cache:
        return _scan_id_cache[scan_id]
    row = _select_one("scans", {"scan_id": f"eq.{scan_id}", "select": "id"})
    if row:
        _scan_id_cache[scan_id] = row["id"]
        return row["id"]
    return None


def insert_scan_event(scan_db_id: str, scan_id: str, event: dict[str, Any]) -> None:
    sequence = count_rows("scan_events", {"scan_db_id": f"eq.{scan_db_id}"}) + 1
    created_at = event.get("time") or event.get("timestamp") or utcnow()
    _request("POST", "scan_events", payload={
        "scan_db_id": scan_db_id,
        "scan_id": scan_id,
        "sequence": sequence,
        "phase": event.get("phase"),
        "stage": event.get("stage"),
        "status": event.get("status"),
        "level": event.get("level", "info"),
        "message": event.get("message") or "Progress update received.",
        "detail": {
            key: value
            for key, value in event.items()
            if key not in {"sequence", "time", "timestamp", "phase", "stage", "status", "level", "message"}
        },
        "created_at": created_at,
    })


def _events_for_scan(scan_db_id: str) -> list[dict[str, Any]]:
    rows = _request("GET", "scan_events", {
        "select": "*",
        "scan_db_id": f"eq.{scan_db_id}",
        "order": "sequence.asc",
    })
    events = []
    for row in rows:
        detail = row.get("detail") or {}
        events.append({
            "timestamp": row.get("created_at"),
            "stage": row.get("stage") or row.get("phase") or "scan",
            "status": row.get("status") or "running",
            "message": row.get("message") or "",
            **detail,
        })
    return events


def _latest_report_for_scan(scan_db_id: str) -> dict[str, Any] | None:
    rows = _request("GET", "scan_reports", {
        "select": "*",
        "scan_db_id": f"eq.{scan_db_id}",
        "order": "created_at.desc",
        "limit": "1",
    })
    return rows[0] if rows else None


def _deep_session_from_scan(scan: dict[str, Any], include_report: bool = True) -> dict[str, Any]:
    config = scan.get("config") or {}
    report_row = _latest_report_for_scan(scan["id"]) if include_report else None
    report = (report_row or {}).get("raw_json") if report_row else None
    report_summary = None
    if report:
        report_summary = {
            "summary": report.get("summary") or {},
            "report_file": report.get("report_file"),
            "generated_at": report.get("generated_at"),
            "root": report.get("root"),
        }
    elif scan.get("summary"):
        report_summary = {
            "summary": {
                "total": (scan.get("summary") or {}).get("findings", 0),
                **((scan.get("summary") or {}).get("severity_counts") or {}),
            },
            "root": scan.get("repository_root"),
        }
    status = scan.get("status") or "processing"
    if status == "processing":
        status = "running"
    return {
        "id": scan.get("scan_id"),
        "website_url": scan.get("target_url") or "",
        "created_at": scan.get("created_at"),
        "updated_at": scan.get("updated_at"),
        "status": status,
        "commands": config.get("commands") or {},
        "report_id": (report_row or {}).get("report_id"),
        "report": report,
        "report_summary": report_summary,
        "events": _events_for_scan(scan["id"]),
        "latest_event": config.get("latest_event"),
    }


def _select_one(table: str, query: dict[str, str]) -> dict[str, Any] | None:
    rows = _request("GET", table, {**query, "limit": "1"})
    return rows[0] if rows else None


def _request(
    method: str,
    table: str,
    query: dict[str, str] | None = None,
    payload: Any = None,
    prefer: str | None = None,
    return_headers: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> Any:
    if not enabled():
        raise RuntimeError("Supabase is not configured")
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    if query:
        url += "?" + urlencode(query)

    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    if extra_headers:
        headers.update(extra_headers)

    data = None
    if payload is not None:
        data = json.dumps(_json_safe(payload), separators=(",", ":")).encode("utf-8")

    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=12) as response:
            if return_headers:
                return dict(response.headers.items())
            body = response.read().decode("utf-8")
            return json.loads(body) if body else []
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Supabase {method} {table} failed: {exc.code} {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Supabase request failed: {exc}") from exc


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _public_scan(row: dict[str, Any]) -> dict[str, Any]:
    scan_type = row.get("scan_type") or "url_scan"
    return {
        **row,
        "url": row.get("target_url"),
        "scan_source": scan_type,
        "scanned_from": "Deep Scan" if scan_type == "deep_scan" else "URL Scan",
    }


def _public_vulnerability(row: dict[str, Any]) -> dict[str, Any]:
    scan_type = row.get("scan_type") or "url_scan"
    return {
        **row,
        "id": row.get("id"),
        "vulnerability_name": row.get("vulnerability_name") or "Security finding",
        "scan_source": scan_type,
        "scanned_from": "Deep Scan" if scan_type == "deep_scan" else "URL Scan",
    }


def _domain_overview(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_domain: dict[str, dict[str, Any]] = {}
    for row in rows:
        domain = row.get("domain") or _domain_from_url(row.get("target_url") or "")
        if not domain:
            continue
        summary = row.get("summary") or {}
        severity = summary.get("severity_counts") or {}
        existing = by_domain.setdefault(domain, {
            "domain": domain,
            "target": row.get("target_url") or domain,
            "scans": 0,
            "total": 0,
            "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "latest": row.get("updated_at") or row.get("created_at"),
        })
        existing["scans"] += 1
        existing["total"] += int(summary.get("findings", 0) or 0)
        existing["counts"]["Critical"] += int(severity.get("critical", 0) or 0)
        existing["counts"]["High"] += int(severity.get("high", 0) or 0)
        existing["counts"]["Medium"] += int(severity.get("medium", 0) or 0)
        existing["counts"]["Low"] += int(severity.get("low", 0) or 0)
        existing["counts"]["Info"] += int(severity.get("info", 0) or 0)
        if str(row.get("updated_at") or row.get("created_at") or "") > str(existing.get("latest") or ""):
            existing["latest"] = row.get("updated_at") or row.get("created_at")
            existing["target"] = row.get("target_url") or domain
    items = []
    for item in by_domain.values():
        risk = _risk_label({
            "critical": item["counts"]["Critical"],
            "high": item["counts"]["High"],
            "medium": item["counts"]["Medium"],
            "low": item["counts"]["Low"],
            "info": item["counts"]["Info"],
        })
        score = _risk_score({
            "critical": item["counts"]["Critical"],
            "high": item["counts"]["High"],
            "medium": item["counts"]["Medium"],
            "low": item["counts"]["Low"],
            "info": item["counts"]["Info"],
        })
        item["risk"] = risk
        item["protection"] = max(0, round(100 - score * 10))
        item["guidance"] = "Review critical and high vulnerabilities first." if risk in {"Critical", "High"} else "Maintain regular scanning cadence."
        items.append(item)
    return sorted(items, key=lambda item: (item["total"], item["scans"]), reverse=True)[:8]


def _risk_label(counts: dict[str, int]) -> str:
    if counts.get("critical", 0):
        return "Critical"
    if counts.get("high", 0):
        return "High"
    if counts.get("medium", 0):
        return "Medium"
    if counts.get("low", 0):
        return "Low"
    return "Info"


def _vulnerability_row(
    user_id: str,
    scan_db_id: str,
    scan_id: str,
    domain: str,
    target_url: str,
    finding: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    vulnerability = finding.get("vulnerability") or finding.get("title") or finding.get("name") or "Security finding"
    severity = str(finding.get("severity") or "info").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"
    evidence = {
        key: value
        for key, value in finding.items()
        if key not in {"vulnerability", "title", "name", "severity"}
    }
    return {
        "vulnerability_id": f"vuln_{uuid.uuid4().hex[:16]}",
        "scan_db_id": scan_db_id,
        "scan_id": scan_id,
        "user_id": user_id,
        "scan_type": "url_scan",
        "domain": domain,
        "url": finding.get("url") or target_url,
        "vulnerability_name": vulnerability,
        "category": finding.get("category") or finding.get("type"),
        "severity": severity,
        "status": "open",
        "description": _description_for(finding),
        "remediation": finding.get("remediation") or finding.get("fix") or finding.get("recommendation") or "",
        "evidence": evidence,
        "file_path": finding.get("file") or finding.get("file_path"),
        "line_number": finding.get("line") or finding.get("line_number"),
        "tool_name": finding.get("tool"),
        "fingerprint": _fingerprint(domain, vulnerability, finding),
        "raw": finding,
        "created_at": now,
        "updated_at": now,
    }


def _deep_vulnerability_row(
    user_id: str,
    scan_db_id: str,
    scan_id: str,
    domain: str,
    target_url: str,
    finding: dict[str, Any],
    now: str,
) -> dict[str, Any]:
    vulnerability = finding.get("title") or finding.get("vulnerability") or "Security finding"
    severity = str(finding.get("severity") or "info").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"
    return {
        "vulnerability_id": f"vuln_{uuid.uuid4().hex[:16]}",
        "scan_db_id": scan_db_id,
        "scan_id": scan_id,
        "user_id": user_id,
        "scan_type": "deep_scan",
        "domain": domain,
        "url": target_url,
        "vulnerability_name": vulnerability,
        "category": finding.get("category"),
        "severity": severity,
        "status": "open",
        "description": finding.get("description") or finding.get("note") or "",
        "remediation": finding.get("remediation") or "",
        "evidence": {
            "tool": finding.get("tool"),
            "category": finding.get("category"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "evidence": finding.get("evidence"),
        },
        "file_path": finding.get("file"),
        "line_number": finding.get("line"),
        "tool_name": finding.get("tool"),
        "fingerprint": _fingerprint(domain, vulnerability, finding),
        "raw": finding,
        "created_at": now,
        "updated_at": now,
    }


def _deep_scan_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = dict(report.get("summary") or {})
    return {
        "findings": int(summary.get("total", len(report.get("findings") or [])) or 0),
        "severity_counts": {
            "critical": int(summary.get("critical", 0) or 0),
            "high": int(summary.get("high", 0) or 0),
            "medium": int(summary.get("medium", 0) or 0),
            "low": int(summary.get("low", 0) or 0),
            "info": int(summary.get("info", 0) or 0),
        },
        "by_category": summary.get("by_category") or {},
        "report_file": report.get("report_file"),
        "generated_at": report.get("generated_at"),
        "root": report.get("root"),
    }


def _deep_scan_summary_from_session(session: dict[str, Any]) -> dict[str, Any]:
    if session.get("report"):
        return _deep_scan_summary(session["report"])
    summary = (session.get("report_summary") or {}).get("summary") or {}
    return {
        "findings": int(summary.get("total", 0) or 0),
        "severity_counts": {
            "critical": int(summary.get("critical", 0) or 0),
            "high": int(summary.get("high", 0) or 0),
            "medium": int(summary.get("medium", 0) or 0),
            "low": int(summary.get("low", 0) or 0),
            "info": int(summary.get("info", 0) or 0),
        },
    }


def _description_for(finding: dict[str, Any]) -> str:
    details = finding.get("details")
    if isinstance(details, list) and details:
        return str(details[0])
    if isinstance(details, str):
        return details
    return str(finding.get("description") or finding.get("message") or finding.get("detail") or "")


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or parsed.path or url).lower().strip("/")


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        counts[severity if severity in counts else "info"] += 1
    return counts


def _risk_score(counts: dict[str, int]) -> float:
    score = (
        counts.get("critical", 0) * 3.0
        + counts.get("high", 0) * 2.0
        + counts.get("medium", 0) * 1.0
        + counts.get("low", 0) * 0.35
        + counts.get("info", 0) * 0.05
    )
    return round(min(10.0, score), 1)


def _fingerprint(domain: str, vulnerability: str, finding: dict[str, Any]) -> str:
    parts = [
        domain,
        vulnerability,
        str(finding.get("url") or finding.get("path") or ""),
        str(finding.get("parameter") or finding.get("header") or finding.get("cookie") or ""),
        str(finding.get("severity") or ""),
    ]
    return hashlib.sha256("|".join(parts).lower().encode("utf-8")).hexdigest()


def _normalize_scan_status(status: str) -> str:
    normalized = str(status or "queued").lower()
    if normalized == "running":
        return "processing"
    if normalized in {"queued", "pending", "processing", "completed", "failed", "cancelled"}:
        return normalized
    return "processing"
