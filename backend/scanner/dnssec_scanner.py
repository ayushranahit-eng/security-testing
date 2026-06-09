"""
DNSSEC scanner.

Checks whether the apparent base domain publishes DNSKEY records.
"""

from urllib.parse import urlparse


def scan_dnssec(target_url: str, findings: list) -> dict:
    hostname = urlparse(target_url).hostname
    zone = _best_effort_zone(hostname)
    if not zone:
        return {"status": "No domain available", "domain": None, "dnssec_enabled": None}

    try:
        import dns.resolver
        import dns.exception
    except Exception:
        return {
            "status": "DNSSEC check unavailable",
            "domain": zone,
            "dnssec_enabled": None,
            "note": "Install dnspython to enable DNSSEC checks.",
        }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8
    try:
        answers = resolver.resolve(zone, "DNSKEY")
        keys = [record.to_text() for record in answers]
        return {
            "status": "DNSSEC records detected",
            "domain": zone,
            "dnssec_enabled": True,
            "dnskey_records": keys,
        }
    except dns.resolver.NoAnswer:
        findings.append({
            "vulnerability": "Missing DNSSEC",
            "severity": "Low",
            "details": [f"No DNSKEY record was returned for {zone}"],
        })
        return {
            "status": "No DNSSEC records detected",
            "domain": zone,
            "dnssec_enabled": False,
            "dnskey_records": [],
        }
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return {
            "status": "DNSSEC check inconclusive",
            "domain": zone,
            "dnssec_enabled": None,
            "error": str(exc),
        }


def _best_effort_zone(hostname: str | None) -> str | None:
    if not hostname:
        return None
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname
