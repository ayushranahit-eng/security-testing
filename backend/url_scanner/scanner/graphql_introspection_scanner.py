"""
GraphQL introspection scanner.
"""

# Note:
# This is a schema-exposure check. It confirms whether GraphQL introspection is
# reachable, but not whether the surrounding GraphQL authorization model is
# strong or weak.

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }"
}


def scan_graphql_introspection(target_url: str, api_calls: list, findings: list, cfg: dict) -> dict:
    endpoints = _candidate_endpoints(target_url, api_calls, cfg)
    exposed = []

    for endpoint in endpoints:
        result = _probe_graphql(endpoint)
        if result:
            exposed.append(result)

    if exposed:
        findings.append({
            "vulnerability": "GraphQL Introspection",
            "severity": "Low",
            "details": [f"{item['url']} returned schema metadata" for item in exposed],
            "graphql_endpoints": exposed,
        })

    return {
        "status": "GraphQL introspection exposed" if exposed else "No GraphQL introspection exposure detected",
        "tested_endpoints": endpoints,
        "exposed_endpoints": exposed,
    }


def _candidate_endpoints(target_url: str, api_calls: list, cfg: dict) -> list:
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    candidates = set()

    for path in cfg.get("graphql_common_paths", []):
        candidates.add(origin.rstrip("/") + path)
    for call in api_calls:
        call = str(call or "")
        if "/graphql" in call.lower():
            candidates.add(call)
    return sorted(candidates)


def _probe_graphql(url: str) -> dict | None:
    body = json.dumps(INTROSPECTION_QUERY).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "User-Agent": "SecurityTestingPlatform/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            text = response.read(120_000).decode("utf-8", errors="ignore")
            if "__schema" in text and "types" in text:
                return {"url": url, "status": response.status}
    except urllib.error.HTTPError as error:
        text = error.read(120_000).decode("utf-8", errors="ignore")
        if "__schema" in text and "types" in text:
            return {"url": url, "status": error.code}
    except Exception:
        return None
    return None
