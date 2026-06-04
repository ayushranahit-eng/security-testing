from pydantic import BaseModel, HttpUrl
from typing import Any, Optional


class ScanRequest(BaseModel):
    url: HttpUrl
    headless: bool = True
    max_pages: int = 20
    max_depth: int = 2


class ScanResponse(BaseModel):
    target:                    str
    scan_time:                 str
    pages:                     list[str]
    forms:                     list[dict[str, Any]]
    inputs:                    list[dict[str, Any]]
    buttons:                   list[str]
    api_calls:                 list[str]
    security_headers:          dict[str, Any]
    cookies:                   list[dict[str, Any]]
    ssl:                       dict[str, Any]
    sensitive_paths:           list[dict[str, Any]]
    cors_analysis:             dict[str, Any]
    findings:                  list[dict[str, Any]]
