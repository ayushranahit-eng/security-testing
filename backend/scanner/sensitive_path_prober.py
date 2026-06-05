"""
Sensitive Path Prober.

Probes a list of well-known sensitive paths against the target origin.
Uses plain urllib (no browser) — fast, no JS needed.

Each probe records:
  - path         : the path probed
  - url          : full URL
  - status       : HTTP status code
  - content_type : response Content-Type header
  - size         : response body size in bytes
  - severity     : derived from the status code + path importance
  - accessible   : True when the path returned a meaningful response

Findings are appended to the shared findings list using the same
structure as every other scanner module.
"""

import urllib.request
import urllib.error
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Paths to probe — ordered roughly by severity of exposure
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    # Critical — direct secret/data exposure
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/HEAD",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",

    # High — API / admin surface exposure
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

    # Medium — recon / information disclosure
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


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def _severity(path: str, status: int) -> str:
    """
    Derive severity from path category and HTTP status code.

    200 on a secret path  → Critical
    200 on an API spec    → High
    200 on a config file  → High
    200 on recon paths    → Low / Medium
    403 on any path       → Low  (exists but blocked — still informational)
    Other non-404         → Info (not reported as a finding)
    """
    if status == 404:
        return "none"

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
        "/readme.md", "/actuator/health", "/actuator/mappings",
    }

    norm = path.lower()

    if status == 200:
        if norm in critical_paths:
            return "Critical"
        if norm in high_paths:
            return "High"
        if norm in medium_paths:
            return "Medium"
        return "Low"

    if status == 403:
        # Forbidden — path exists, server blocking access
        if norm in critical_paths or norm in high_paths:
            return "Medium"
        return "Low"

    if status in (301, 302, 307, 308):
        return "Info"

    return "Info"


# ---------------------------------------------------------------------------
# Single path probe
# ---------------------------------------------------------------------------

def _probe_path(base_url: str, path: str, timeout: int = 10) -> dict:
    """
    Make a HEAD-then-GET request to base_url + path.
    Returns a result dict regardless of outcome.
    """
    url = base_url.rstrip("/") + path

    result = {
        "path":         path,
        "url":          url,
        "status":       None,
        "content_type": None,
        "size":         None,
        "severity":     "none",
        "accessible":   False,
        "error":        None,
    }

    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "SecurityTestingPlatform/1.0",
                "Accept":     "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result["status"]       = resp.status
            result["content_type"] = resp.headers.get("Content-Type", "").split(";")[0].strip()
            body                   = resp.read()
            result["size"]         = len(body)
            result["severity"]     = _severity(path, resp.status)
            result["accessible"]   = resp.status < 400

    except urllib.error.HTTPError as e:
        result["status"]   = e.code
        result["severity"] = _severity(path, e.code)
        # 403 is still informational — path exists
        result["accessible"] = (e.code == 403)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Public API — matches pattern of every other scanner module
# ---------------------------------------------------------------------------

def probe_sensitive_paths(base_url: str, findings: list,
                          timeout: int = 10) -> list:
    """
    Probe all SENSITIVE_PATHS against base_url.

    Args:
        base_url : target origin (scheme + host, e.g. https://example.com)
        findings : shared findings list — findings appended in-place
        timeout  : per-request timeout in seconds

    Returns:
        List of probe result dicts (all paths, not just hits).
    """
    # Normalise to origin only (strip any path the caller may have passed)
    parsed   = urlparse(base_url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"
    probes   = []
    hits     = []   # paths that produced an actionable finding

    print(f"\n🔍 Probing {len(SENSITIVE_PATHS)} sensitive paths on {origin}...")

    for path in SENSITIVE_PATHS:
        result = _probe_path(origin, path, timeout)
        probes.append(result)

        sev = result["severity"]
        if sev in ("Critical", "High", "Medium", "Low"):
            status  = result["status"]
            ct      = result["content_type"] or "unknown"
            size    = result["size"]
            blocked = (status == 403)

            tag     = "BLOCKED (403)" if blocked else f"ACCESSIBLE ({status})"
            print(f"   {'🔴' if sev == 'Critical' else '🟠' if sev == 'High' else '🟡' if sev == 'Medium' else '🟢'} "
                  f"[{sev}] {path} — {tag}  ({ct}, {size} bytes)")

            hits.append({
                "path":         path,
                "url":          result["url"],
                "status":       status,
                "content_type": ct,
                "size":         size,
                "severity":     sev,
                "blocked":      blocked,
            })

    print(f"✅ Path probe complete — {len(hits)} sensitive path(s) found")

    # ── Build findings ──────────────────────────────────────────────
    # Group by severity so the findings list stays clean
    for severity_level in ("Critical", "High", "Medium", "Low"):
        level_hits = [h for h in hits if h["severity"] == severity_level]
        if not level_hits:
            continue

        findings.append({
            "vulnerability": "Sensitive Path Exposed",
            "severity":      severity_level,
            "details": [
                f"{h['path']} — HTTP {h['status']}"
                + (" [BLOCKED]" if h["blocked"] else f", {h['content_type']}, {h['size']}B")
                for h in level_hits
            ],
            "paths": level_hits,
        })

    return probes
