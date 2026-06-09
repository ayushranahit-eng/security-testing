"""
Open port scanner.

Performs a small TCP connect scan against common public-service ports.
"""

import socket
from urllib.parse import urlparse


PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    3000: "Dev server",
    3306: "MySQL",
    5000: "Dev server",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP alt",
    8080: "HTTP alt",
    8443: "HTTPS alt",
    8888: "HTTP alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
SENSITIVE_PORTS = {21, 22, 25, 3306, 5432, 6379, 9200, 27017}


def scan_open_ports(target_url: str, findings: list, cfg: dict) -> dict:
    hostname = urlparse(target_url).hostname
    if not hostname:
        return {"status": "No hostname available", "open_ports": []}

    timeout = float(cfg.get("open_port_scan_timeout_seconds", 0.75))
    ports = list(cfg.get("open_port_scan_ports", []))
    open_ports = []

    for port in ports:
        if _is_port_open(hostname, int(port), timeout):
            open_ports.append({
                "port": int(port),
                "service": PORT_LABELS.get(int(port), "Unknown"),
                "sensitive": int(port) in SENSITIVE_PORTS,
            })

    risky_open_ports = [
        item for item in open_ports
        if item["port"] not in {80, 443}
    ]
    if risky_open_ports:
        findings.append({
            "vulnerability": "Open Port Scanning",
            "severity": "Medium" if any(item["sensitive"] for item in risky_open_ports) else "Low",
            "details": [
                f"TCP {item['port']} ({item['service']}) accepted connections"
                for item in risky_open_ports
            ],
            "ports": risky_open_ports,
        })

    return {
        "status": "Additional open ports detected" if risky_open_ports else "No additional common open ports detected",
        "hostname": hostname,
        "open_ports": open_ports,
        "note": "This is a lightweight connect scan against a small common-port list, not a full network inventory.",
    }


def _is_port_open(hostname: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except Exception:
        return False
