"""
Passive host exposure and reputation-style checks using public Shodan data.
"""

import json
import socket
import urllib.request
from urllib.parse import urlparse


RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
RISKY_TAGS = {"ics", "iot", "vpn", "database", "industrial-control-system", "honeypot"}


def scan_passive_host_intelligence(target_url: str, findings: list) -> dict:
    hostname = urlparse(target_url).hostname
    if not hostname:
        return {"status": "No hostname available", "ip": None}

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception as exc:
        return {"status": "IP resolution failed", "ip": None, "error": str(exc)}

    data = _fetch_internetdb(ip_address)
    if not data:
        return {
            "status": "No passive host intelligence available",
            "ip": ip_address,
            "provider": "Shodan InternetDB",
        }

    ports = [int(port) for port in data.get("ports", []) if isinstance(port, int) or str(port).isdigit()]
    vulns = [str(item) for item in data.get("vulns", [])]
    tags = [str(item).lower() for item in data.get("tags", [])]
    risky_ports = [port for port in ports if port in RISKY_PORTS]
    risky_tags = [tag for tag in tags if tag in RISKY_TAGS]
    exposure_score = _compute_exposure_score(ports, vulns, risky_ports, risky_tags)

    if ports or vulns or tags:
        findings.append({
            "vulnerability": "Shodan / Censys Passive Recon",
            "severity": "Low" if exposure_score < 45 else "Medium",
            "details": [
                f"Passive host data for {ip_address}: ports={ports}, tags={tags}, vulns={vulns}"
            ],
            "ip": ip_address,
            "ports": ports,
            "tags": tags,
            "vulns": vulns,
        })

    if risky_ports or risky_tags or vulns:
        findings.append({
            "vulnerability": "IP Reputation Check",
            "severity": "Low" if len(vulns) <= 1 and len(risky_ports) <= 1 else "Medium",
            "details": [
                f"Passive exposure signals for {ip_address}: risky_ports={risky_ports}, risky_tags={risky_tags}, vulns={vulns}"
            ],
            "ip": ip_address,
            "risky_ports": risky_ports,
            "risky_tags": risky_tags,
            "vulns": vulns,
        })

    if exposure_score >= 40:
        findings.append({
            "vulnerability": "Shodan Exposure Score",
            "severity": "Low" if exposure_score < 70 else "Medium",
            "details": [f"Exposure score for {ip_address}: {exposure_score}/100"],
            "ip": ip_address,
            "score": exposure_score,
        })

    return {
        "status": "Passive host intelligence retrieved",
        "provider": "Shodan InternetDB",
        "ip": ip_address,
        "ports": ports,
        "hostnames": data.get("hostnames", []),
        "cpes": data.get("cpes", []),
        "tags": tags,
        "vulns": vulns,
        "risky_ports": risky_ports,
        "risky_tags": risky_tags,
        "exposure_score": exposure_score,
        "note": "This is passive public host intelligence and should be treated as enrichment, not definitive proof of a current live issue.",
    }


def _fetch_internetdb(ip_address: str) -> dict:
    url = f"https://internetdb.shodan.io/{ip_address}"
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def _compute_exposure_score(ports: list[int], vulns: list[str], risky_ports: list[int], risky_tags: list[str]) -> int:
    score = 0
    score += min(20, len(ports) * 4)
    score += min(35, len(vulns) * 12)
    score += min(25, len(risky_ports) * 10)
    score += min(20, len(risky_tags) * 7)
    return min(100, score)
