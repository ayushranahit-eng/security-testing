"""
Certificate transparency, new subdomain, and subdomain takeover checks.
"""

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


TAKEOVER_FINGERPRINTS = [
    {
        "provider": "GitHub Pages",
        "cname_markers": ("github.io",),
        "body_markers": ("there isn't a github pages site here.",),
    },
    {
        "provider": "Heroku",
        "cname_markers": ("herokudns.com", "herokuapp.com"),
        "body_markers": ("no such app",),
    },
    {
        "provider": "Amazon S3",
        "cname_markers": ("amazonaws.com",),
        "body_markers": ("nosuchbucket", "the specified bucket does not exist"),
    },
    {
        "provider": "Azure App Service",
        "cname_markers": ("azurewebsites.net",),
        "body_markers": ("404 web site not found",),
    },
]


def scan_certificate_transparency(target_url: str, findings: list, cfg: dict) -> dict:
    domain = _best_effort_zone(urlparse(target_url).hostname)
    if not domain:
        return {"status": "No domain available", "domain": None, "subdomains": []}

    records = _fetch_crtsh_records(domain, int(cfg.get("ct_max_records", 1500)))
    subdomains = sorted(_extract_subdomains(domain, records))
    if not records:
        return {
            "status": "No CT records retrieved",
            "domain": domain,
            "subdomains": [],
            "certificates_observed": 0,
            "note": "The CT query may have been blocked, timed out, or returned no records.",
        }

    return {
        "status": "CT records retrieved",
        "domain": domain,
        "subdomains": subdomains,
        "certificates_observed": len(records),
        "note": "Certificate transparency records help map historical and current public subdomain exposure.",
    }


def scan_new_subdomain_alert(ct_result: dict, previous_baseline: dict, findings: list, cfg: dict) -> dict:
    current = set(ct_result.get("subdomains", []))
    previous = set(previous_baseline.get("ct_subdomains", []))
    new_subdomains = sorted(current - previous)

    if previous and new_subdomains:
        findings.append({
            "vulnerability": "New Subdomain Alert",
            "severity": "Low" if len(new_subdomains) <= 3 else "Medium",
            "details": [
                f"New subdomain observed since the last baseline: {item}"
                for item in new_subdomains[:20]
            ],
            "subdomains": new_subdomains,
        })

    return {
        "status": "New subdomains detected" if previous and new_subdomains else "No newly observed subdomains",
        "new_subdomains": new_subdomains,
        "previous_baseline_available": bool(previous),
    }


def scan_subdomain_takeover(ct_result: dict, findings: list, cfg: dict) -> dict:
    subdomains = list(ct_result.get("subdomains", []))
    max_targets = int(cfg.get("subdomain_takeover_max_targets", 20))
    tested = []
    suspected = []

    for host in subdomains[:max_targets]:
        cname = _resolve_cname(host)
        status, body = _fetch_homepage(host)
        tested.append(host)
        match = _match_takeover_fingerprint(cname, body)
        if not match:
            continue
        suspected.append({
            "subdomain": host,
            "provider": match["provider"],
            "cname": cname,
            "http_status": status,
            "confidence": "Medium" if cname else "Low",
        })

    if suspected:
        findings.append({
            "vulnerability": "Subdomain Takeover",
            "severity": "High",
            "details": [
                f"{item['subdomain']} showed an unclaimed {item['provider']} fingerprint"
                for item in suspected[:12]
            ],
            "subdomains": suspected,
        })

    return {
        "status": "Potential takeover fingerprints detected" if suspected else "No takeover fingerprint detected",
        "tested_subdomains": tested,
        "suspected_takeovers": suspected,
    }


def _fetch_crtsh_records(domain: str, max_records: int) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = response.read(2_000_000).decode("utf-8", errors="ignore")
    except Exception:
        return []

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []

    return list(data)[:max_records]


def _extract_subdomains(domain: str, records: list) -> set[str]:
    subdomains = set()
    for item in records:
        raw_names = str(item.get("name_value", "")).splitlines()
        for raw_name in raw_names:
            name = raw_name.strip().lower().lstrip("*.").rstrip(".")
            if not name or name == domain:
                continue
            if name.endswith("." + domain):
                subdomains.add(name)
    return subdomains


def _best_effort_zone(hostname: str | None) -> str | None:
    if not hostname:
        return None
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _resolve_cname(hostname: str) -> str | None:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "CNAME")
        for answer in answers:
            return str(answer.target).rstrip(".").lower()
    except Exception:
        return None
    return None


def _fetch_homepage(hostname: str) -> tuple[int | None, str]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                body = response.read(120_000).decode("utf-8", errors="ignore")
                return response.status, body.lower()
        except urllib.error.HTTPError as error:
            try:
                body = error.read(120_000).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return error.code, body.lower()
        except Exception:
            continue
    return None, ""


def _match_takeover_fingerprint(cname: str | None, body: str) -> dict | None:
    cname_lower = (cname or "").lower()
    for fingerprint in TAKEOVER_FINGERPRINTS:
        cname_match = any(marker in cname_lower for marker in fingerprint["cname_markers"])
        body_match = any(marker in body for marker in fingerprint["body_markers"])
        if cname_match and body_match:
            return fingerprint
        if not cname and body_match:
            return fingerprint
    return None
