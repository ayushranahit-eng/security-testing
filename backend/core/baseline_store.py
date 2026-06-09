"""
Local baseline storage for repeat-scan monitoring features.
"""

import json
from pathlib import Path
from urllib.parse import urlparse


BASELINE_DIR = Path(__file__).resolve().parents[1] / "data" / "baselines"


def load_baseline(target_url: str) -> dict:
    path = _baseline_path(target_url)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_baseline(target_url: str, data: dict) -> str:
    path = _baseline_path(target_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _baseline_path(target_url: str) -> Path:
    parsed = urlparse(target_url)
    host = (parsed.netloc or parsed.path or "target").lower()
    safe_host = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in host)
    return BASELINE_DIR / f"{safe_host}.json"
