"""
Directory listing exposure scanner.
"""

# Note:
# This is a web-server exposure check. It identifies browsable directory index
# pages, which can reveal file structure and forgotten assets even when there
# is no direct code-execution flaw.

import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse


def scan_directory_listing(pages: list, findings: list) -> dict:
    candidates = sorted(set(_directory_candidates(pages)))[:15]
    exposed = []

    for url in candidates:
        result = _probe_directory(url)
        if result:
            exposed.append(result)

    if exposed:
        findings.append({
            "vulnerability": "Directory Listing Enabled",
            "severity": "Low",
            "details": [f"{item['url']} - {item['signal']}" for item in exposed],
        })

    return {
        "status": "Directory listing detected" if exposed else "No directory listing detected",
        "exposed_directories": exposed,
    }


def _directory_candidates(pages: list) -> list:
    for page in pages:
        parsed = urlparse(str(page or "").strip())
        if not parsed.scheme or not parsed.netloc:
            continue
        path = parsed.path or "/"
        if "/" not in path.strip("/"):
            yield urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
            continue
        prefix = path.rsplit("/", 1)[0] + "/"
        yield urlunparse((parsed.scheme, parsed.netloc, prefix, "", "", ""))


def _probe_directory(url: str) -> dict | None:
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(100_000).decode("utf-8", errors="ignore").lower()
            if "index of /" in body or "<title>index of" in body or "parent directory" in body:
                return {"url": url, "status": response.status, "signal": "directory index markers present"}
    except urllib.error.HTTPError:
        return None
    except Exception:
        return None
    return None
