"""
MongoDB persistence for users, account plans, scans, and findings.

Mongo is optional. If MONGODB_URI is not configured, the scanner keeps using
the existing in-memory job store.
"""

import hashlib
import os
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv
from pymongo import ASCENDING, MongoClient
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError


load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "security_testing").strip()

DEFAULT_PLAN_NAME = os.getenv("DEFAULT_ACCOUNT_PLAN", "Basic").strip() or "Basic"
DEFAULT_USER_EMAIL = os.getenv("DEFAULT_USER_EMAIL", "ayush@example.com").strip().lower()
DEFAULT_USER_FIRST_NAME = os.getenv("DEFAULT_USER_FIRST_NAME", "Ayush").strip() or "Ayush"
DEFAULT_USER_LAST_NAME = os.getenv("DEFAULT_USER_LAST_NAME", "Rana").strip() or "Rana"
DEFAULT_COMPANY_NAME = os.getenv("DEFAULT_COMPANY_NAME", "Hands In Technology").strip() or "Hands In Technology"
DEFAULT_COMPANY_URL = os.getenv("DEFAULT_COMPANY_URL", "").strip() or None

_client: MongoClient | None = None
_db = None
_default_user_id = None


def mongo_enabled() -> bool:
    return bool(MONGODB_URI)


def utcnow() -> datetime:
    return datetime.utcnow()


def get_db():
    global _client, _db
    if not mongo_enabled():
        return None
    if _db is None:
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2500)
        _client.admin.command("ping")
        _db = _client[MONGODB_DATABASE]
    return _db


def init_mongo() -> bool:
    """Create indexes and seed the first plan/user when Mongo is configured."""
    if not mongo_enabled():
        return False

    db = get_db()
    now = utcnow()

    db.account_plans.create_index([("name", ASCENDING)], unique=True)
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.scans.create_index([("scan_id", ASCENDING)], unique=True)
    db.scans.create_index([("user_id", ASCENDING), ("created_at", ASCENDING)])
    db.scans.create_index([("domain", ASCENDING), ("created_at", ASCENDING)])
    db.scans.create_index([("status", ASCENDING), ("created_at", ASCENDING)])
    db.findings.create_index([("scan_id", ASCENDING)])
    db.findings.create_index([("user_id", ASCENDING), ("status", ASCENDING), ("severity", ASCENDING)])
    db.findings.create_index([("domain", ASCENDING), ("status", ASCENDING)])
    db.findings.create_index([("fingerprint", ASCENDING)])

    plan = db.account_plans.find_one({"name": DEFAULT_PLAN_NAME})
    if plan is None:
        plan_id = db.account_plans.insert_one({
            "name": DEFAULT_PLAN_NAME,
            "no_of_scans_available": 5,
            "created_at": now,
            "updated_at": now,
        }).inserted_id
    else:
        plan_id = plan["_id"]

    user = db.users.find_one({"email": DEFAULT_USER_EMAIL})
    if user is None:
        user_id = db.users.insert_one({
            "first_name": DEFAULT_USER_FIRST_NAME,
            "last_name": DEFAULT_USER_LAST_NAME,
            "email": DEFAULT_USER_EMAIL,
            "company_name": DEFAULT_COMPANY_NAME,
            "company_url": DEFAULT_COMPANY_URL,
            "account_plan_id": plan_id,
            "created_at": now,
            "updated_at": now,
        }).inserted_id
    else:
        user_id = user["_id"]

    global _default_user_id
    _default_user_id = user_id
    return True


def close_mongo() -> None:
    global _client, _db
    if _client is not None:
        _client.close()
    _client = None
    _db = None


def is_ready() -> bool:
    try:
        return get_db() is not None
    except (PyMongoError, ServerSelectionTimeoutError):
        return False


def default_user_id():
    global _default_user_id
    if _default_user_id is not None:
        return _default_user_id
    db = get_db()
    user = db.users.find_one({"email": DEFAULT_USER_EMAIL}, {"_id": 1})
    if user is None:
        init_mongo()
        user = db.users.find_one({"email": DEFAULT_USER_EMAIL}, {"_id": 1})
    _default_user_id = user["_id"]
    return _default_user_id


def create_scan(scan_id: str, target_url: str, config: dict[str, Any]) -> None:
    db = get_db()
    now = utcnow()
    db.scans.insert_one({
        "user_id": default_user_id(),
        "scan_id": scan_id,
        "domain": _domain_from_url(target_url),
        "url": target_url,
        "status": "queued",
        "config": {
            "headless": bool(config.get("headless", True)),
            "max_pages": int(config.get("max_pages", 20)),
            "max_depth": int(config.get("max_depth", 2)),
        },
        "progress": {
            "current_step": "Queued",
            "pages_found": 0,
            "forms_found": 0,
            "inputs_found": 0,
            "buttons_found": 0,
            "api_calls_found": 0,
            "findings_found": 0,
        },
        "summary": {},
        "events": [],
        "raw_result": None,
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "updated_at": now,
    })


def update_scan(scan_id: str, updates: dict[str, Any], event: dict[str, Any] | None = None) -> None:
    db = get_db()
    now = utcnow()
    set_fields: dict[str, Any] = {"updated_at": now}

    status = updates.get("status")
    if status is not None:
        set_fields["status"] = status
        if status == "running":
            set_fields.setdefault("started_at", now)
        if status in {"completed", "failed"}:
            set_fields["completed_at"] = now

    progress_keys = {
        "current_step", "pages_found", "forms_found", "inputs_found",
        "buttons_found", "api_calls_found", "findings_found", "pending_pages",
        "pages_known", "pages_scanned", "pages_total", "scan_phase",
        "estimated_total_seconds",
    }
    for key in progress_keys:
        if key in updates:
            set_fields[f"progress.{key}"] = updates[key]

    if "error" in updates:
        set_fields["error"] = updates["error"]

    operation: dict[str, Any] = {"$set": set_fields}
    if event is not None:
        clean_event = dict(event)
        clean_event.setdefault("time", now)
        operation["$push"] = {"events": clean_event}

    db.scans.update_one({"scan_id": scan_id}, operation)


def complete_scan(scan_id: str, result: dict[str, Any]) -> None:
    db = get_db()
    now = utcnow()
    findings = result.get("findings", []) or []
    severity_counts = _severity_counts(findings)

    db.scans.update_one(
        {"scan_id": scan_id},
        {
            "$set": {
                "status": "completed",
                "summary": {
                    "pages": len(result.get("pages", []) or []),
                    "forms": len(result.get("forms", []) or []),
                    "inputs": len(result.get("inputs", []) or []),
                    "api_calls": len(result.get("api_calls", []) or []),
                    "findings": len(findings),
                    "severity_counts": severity_counts,
                    "risk_score": _risk_score(severity_counts),
                },
                "raw_result": result,
                "completed_at": now,
                "updated_at": now,
            }
        },
    )

    db.findings.delete_many({"scan_id": scan_id})
    if findings:
        user_id = default_user_id()
        target_url = result.get("target") or ""
        domain = _domain_from_url(target_url)
        db.findings.insert_many([
            _finding_document(user_id, scan_id, domain, target_url, finding, now)
            for finding in findings
        ])


def serialize_doc(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if doc is None:
        return None
    serialized = {}
    for key, value in doc.items():
        if key == "_id":
            serialized["id"] = str(value)
        elif key.endswith("_id") and value is not None:
            serialized[key] = str(value)
        elif isinstance(value, datetime):
            serialized[key] = value.isoformat()
        elif isinstance(value, dict):
            serialized[key] = serialize_doc(value)
        elif isinstance(value, list):
            serialized[key] = [
                serialize_doc(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            serialized[key] = value
    return serialized


def _finding_document(user_id, scan_id: str, domain: str, target_url: str, finding: dict[str, Any], now: datetime) -> dict[str, Any]:
    vulnerability = finding.get("vulnerability") or finding.get("title") or "Security finding"
    severity = str(finding.get("severity") or "Info").lower()
    evidence = {
        key: value
        for key, value in finding.items()
        if key not in {"vulnerability", "severity"}
    }
    return {
        "user_id": user_id,
        "scan_id": scan_id,
        "domain": domain,
        "url": target_url,
        "vulnerability_name": vulnerability,
        "severity": severity,
        "status": "open",
        "description": _description_for(finding),
        "evidence": evidence,
        "remediation": finding.get("remediation") or finding.get("fix") or "",
        "raw": finding,
        "fingerprint": _fingerprint(domain, vulnerability, finding),
        "created_at": now,
        "updated_at": now,
    }


def _description_for(finding: dict[str, Any]) -> str:
    details = finding.get("details")
    if isinstance(details, list) and details:
        return str(details[0])
    if isinstance(details, str):
        return details
    return str(finding.get("description") or finding.get("message") or "")


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or parsed.path or url).lower().strip("/")


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1
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
