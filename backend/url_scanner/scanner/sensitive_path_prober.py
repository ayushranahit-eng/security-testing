"""
Sensitive path prober.

Probes well-known sensitive paths against the target origin. The scanner
separates readable exposure from blocked detection:

- HTTP 2xx/3xx-style readable content is treated as exposed.
- HTTP 403 is treated as detected/blocked, not confirmed exposure.
"""

import urllib.error
import urllib.request
from urllib.parse import urlparse


SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/HEAD",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/swagger.json",
    "/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/CHANGELOG.md",
    "/CHANGELOG.txt",
    "/README.md",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/web.config",
    "/.htaccess",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/wp-config.php",
    "/wp-login.php",
    "/admin",
    "/admin/",
    "/administrator",
    "/phpmyadmin",
]


def _severity(path: str, status: int) -> str:
    if status == 404:
        return "none"

    norm = path.lower()
    critical_paths = {
        "/.env", "/.env.local", "/.env.production",
        "/.git/head", "/.git/config",
        "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
        "/wp-config.php",
    }
    high_paths = {
        "/swagger.json", "/openapi.json",
        "/api/swagger.json", "/api/openapi.json",
        "/v1/swagger.json", "/v2/swagger.json",
        "/actuator/env", "/actuator/mappings",
        "/phpinfo.php", "/server-status", "/server-info",
        "/config.json", "/config.yml", "/config.yaml",
        "/settings.py", "/web.config",
    }
    medium_paths = {
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/security.txt", "/.well-known/security.txt",
        "/package.json", "/composer.json", "/gemfile",
        "/.htaccess", "/changelog.md", "/changelog.txt",
        "/readme.md", "/actuator/health",
    }

    if status == 200:
        if norm in critical_paths:
            return "Critical"
        if norm in high_paths:
            return "High"
        if norm in medium_paths:
            return "Medium"
        return "Low"

    if status == 403:
        if norm in critical_paths or norm in high_paths:
            return "Medium"
        return "Low"

    if status in (301, 302, 307, 308):
        return "Info"

    return "Info"


def _probe_path(base_url: str, path: str, timeout: int = 10) -> dict:
    url = base_url.rstrip("/") + path
    result = {
        "path": path,
        "url": url,
        "status": None,
        "content_type": None,
        "size": None,
        "severity": "none",
        "accessible": False,
        "blocked": False,
        "error": None,
    }

    try:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "SecurityTestingPlatform/1.0",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            result.update({
                "status": response.status,
                "content_type": response.headers.get("Content-Type", "").split(";")[0].strip(),
                "size": len(body),
                "severity": _severity(path, response.status),
                "accessible": response.status < 400,
                "blocked": False,
            })

    except urllib.error.HTTPError as error:
        result.update({
            "status": error.code,
            "severity": _severity(path, error.code),
            "accessible": False,
            "blocked": error.code == 403,
        })

    except Exception as exc:
        result["error"] = str(exc)

    return result


def probe_sensitive_paths(base_url: str, findings: list, timeout: int = 10) -> list:
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    probes = []
    hits = []

    print(f"\nProbing {len(SENSITIVE_PATHS)} sensitive paths on {origin}...")

    for path in SENSITIVE_PATHS:
        result = _probe_path(origin, path, timeout)
        probes.append(result)

        severity = result["severity"]
        if severity not in ("Critical", "High", "Medium", "Low"):
            continue

        status = result["status"]
        content_type = result["content_type"] or "unknown"
        size = result["size"]
        blocked = result.get("blocked", False)
        label = "BLOCKED (403)" if blocked else f"ACCESSIBLE ({status})"

        print(f"   [{severity}] {path} - {label} ({content_type}, {size} bytes)")

        hits.append({
            "path": path,
            "url": result["url"],
            "status": status,
            "content_type": content_type,
            "size": size,
            "severity": severity,
            "blocked": blocked,
        })

    print(f"Path probe complete - {len(hits)} sensitive path(s) detected")

    for severity_level in ("Critical", "High", "Medium", "Low"):
        level_hits = [hit for hit in hits if hit["severity"] == severity_level]
        if not level_hits:
            continue

        has_readable_exposure = any(not hit["blocked"] for hit in level_hits)
        findings.append({
            "vulnerability": "Sensitive Path Detected",
            "severity": severity_level if has_readable_exposure else "Low",
            "details": [
                f"{hit['path']} - HTTP {hit['status']}"
                + (
                    " [BLOCKED - not confirmed exposed]"
                    if hit["blocked"]
                    else f", {hit['content_type']}, {hit['size']}B"
                )
                for hit in level_hits
            ],
            "paths": level_hits,
        })

    return probes
