"""
JavaScript secret scanner.

Scans first-party JavaScript assets and inline scripts for exposed secrets such
as API keys, cloud credentials, and high-entropy tokens.
"""

import math
import re
import urllib.error
import urllib.request
from html import unescape
from urllib.parse import urljoin, urlparse


SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(r"<script\b(?![^>]+src=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)

SECRET_PATTERNS = [
    {
        "type": "OpenAI API key",
        "regex": re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b"),
        "severity": "Critical",
        "confidence": "High",
    },
    {
        "type": "AWS access key",
        "regex": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "severity": "Critical",
        "confidence": "High",
    },
    {
        "type": "GitHub token",
        "regex": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
        "severity": "Critical",
        "confidence": "High",
    },
    {
        "type": "Stripe secret key",
        "regex": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
        "severity": "Critical",
        "confidence": "High",
    },
    {
        "type": "Stripe publishable key",
        "regex": re.compile(r"\bpk_live_[0-9A-Za-z]{16,}\b"),
        "severity": "Medium",
        "confidence": "High",
    },
    {
        "type": "Google API key",
        "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "severity": "High",
        "confidence": "High",
    },
    {
        "type": "JWT token",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
        "severity": "High",
        "confidence": "Medium",
    },
]

GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]([^'\"]{20,200})['\"]"
)


def scan_javascript_secrets(target_url: str, pages: list, network_calls: list, findings: list, cfg: dict) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    max_js_files = int(cfg.get("max_javascript_files", 25))
    max_inline_pages = int(cfg.get("max_inline_script_pages", 10))
    max_bytes = int(cfg.get("max_download_bytes_per_file", 500_000))

    external_sources = _collect_candidate_js_urls(target_url, network_calls)
    detections = []
    scanned_files = []
    scanned_inline_pages = 0

    for script_url in external_sources[:max_js_files]:
        content = _download_text(script_url, max_bytes)
        if content is None:
            continue
        scanned_files.append(script_url)
        detections.extend(_find_secrets_in_text(content, script_url))

    for page_url in _first_party_pages(target_host, pages)[:max_inline_pages]:
        html = _download_text(page_url, max_bytes)
        if html is None:
            continue
        scanned_inline_pages += 1

        for script_url in SCRIPT_SRC_RE.findall(html):
            full_url = urljoin(page_url, unescape(script_url))
            if _is_first_party_script(target_host, full_url) and full_url not in external_sources and len(scanned_files) < max_js_files:
                content = _download_text(full_url, max_bytes)
                if content is None:
                    continue
                scanned_files.append(full_url)
                detections.extend(_find_secrets_in_text(content, full_url))

        for index, block in enumerate(INLINE_SCRIPT_RE.findall(html), start=1):
            source = f"inline:{page_url}#script-{index}"
            detections.extend(_find_secrets_in_text(block, source))

    detections = _dedupe_detections(detections)
    highest_severity = _highest_severity(detections)

    if detections:
        findings.append({
            "vulnerability": "JavaScript Secrets Exposed",
            "severity": highest_severity,
            "details": [
                f"{item['type']} in {item['source']} ({item['confidence']} confidence)"
                for item in detections[:12]
            ],
            "secrets": detections,
        })

    return {
        "status": "Secrets detected" if detections else "No secrets detected",
        "scanned_javascript_files": len(scanned_files),
        "scanned_inline_script_pages": scanned_inline_pages,
        "detections": detections,
        "note": "Automated matching uses known token formats plus high-entropy assignments. Validate any live credential immediately.",
    }


def _collect_candidate_js_urls(target_url: str, network_calls: list) -> list:
    target_host = urlparse(target_url).netloc.lower()
    candidates = []
    seen = set()

    for call in network_calls:
        raw = unescape(str(call or "").strip())
        if not raw or raw in seen:
            continue
        if _is_first_party_script(target_host, raw):
            seen.add(raw)
            candidates.append(raw)

    return candidates


def _first_party_pages(target_host: str, pages: list) -> list:
    result = []
    seen = set()
    for page in pages:
        raw = str(page or "").strip()
        if not raw or raw in seen:
            continue
        parsed = urlparse(raw)
        host = parsed.netloc.lower()
        if host == target_host or host.endswith("." + target_host):
            seen.add(raw)
            result.append(raw)
    return result


def _is_first_party_script(target_host: str, raw_url: str) -> bool:
    parsed = urlparse(raw_url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    raw_lower = raw_url.lower()
    if not host:
        return False
    if not (host == target_host or host.endswith("." + target_host)):
        return False
    return path.endswith(".js") or path.endswith(".mjs") or ".js?" in raw_lower or ".mjs?" in raw_lower


def _download_text(url: str, max_bytes: int) -> str | None:
    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SecurityTestingPlatform/1.0",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(request, timeout=12) as response:
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = body[:max_bytes]
            content_type = response.headers.get("Content-Type", "")
            charset = "utf-8"
            if "charset=" in content_type:
                charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
            return body.decode(charset or "utf-8", errors="ignore")
    except (urllib.error.URLError, ValueError, OSError):
        return None


def _find_secrets_in_text(content: str, source: str) -> list:
    findings = []
    for pattern in SECRET_PATTERNS:
        for match in pattern["regex"].finditer(content):
            value = match.group(0)
            findings.append({
                "type": pattern["type"],
                "severity": pattern["severity"],
                "confidence": pattern["confidence"],
                "source": source,
                "value_preview": _mask_secret(value),
                "evidence": _context_snippet(content, match.start(), match.end()),
            })

    for match in GENERIC_ASSIGNMENT_RE.finditer(content):
        secret_name = match.group(1)
        secret_value = match.group(2)
        if len(secret_value) < 24 or _shannon_entropy(secret_value) < 4.0:
            continue
        findings.append({
            "type": f"High-entropy {secret_name}",
            "severity": "Medium",
            "confidence": "Medium",
            "source": source,
            "value_preview": _mask_secret(secret_value),
            "evidence": _context_snippet(content, match.start(), match.end()),
        })

    return findings


def _context_snippet(content: str, start: int, end: int, width: int = 80) -> str:
    left = max(0, start - width)
    right = min(len(content), end + width)
    return " ".join(content[left:right].split())


def _mask_secret(value: str) -> str:
    if len(value) <= 10:
        return value
    return f"{value[:6]}...{value[-4:]}"


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _dedupe_detections(detections: list) -> list:
    seen = set()
    deduped = []
    for item in detections:
        key = (item["type"], item["source"], item["value_preview"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _highest_severity(detections: list) -> str:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    if not detections:
        return "Info"
    return min(detections, key=lambda item: order.get(item["severity"], 4))["severity"]
