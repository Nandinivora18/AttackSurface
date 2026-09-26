import uuid
from datetime import datetime
from pydantic import BaseModel, field_validator
from typing import Optional
from urllib.parse import urlparse
from app.models.scan import ScanStatus
from app.utils.safe_http import port_policy_error


class ScanCreate(BaseModel):
    url: str
    scan_mode: str = "passive"
    profile: str = "standard"  # 'quick', 'standard', 'custom'
    consent_acknowledged: bool = False
    auth_context: Optional[dict] = None
    design_questionnaire: Optional[dict] = None
    openapi_spec: Optional[dict] = None

    @field_validator("scan_mode")
    @classmethod
    def validate_scan_mode(cls, v: str) -> str:
        v = (v or "passive").strip().lower()
        allowed = {"passive", "safe_active", "authenticated_safe_active"}
        if v not in allowed:
            raise ValueError(f"Invalid scan_mode '{v}'. Allowed modes: {', '.join(sorted(allowed))}")
        return v

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")

        # Reject non-HTTP/HTTPS schemes explicitly before any prefix logic
        lower_v = v.lower()
        if "://" in lower_v:
            scheme = lower_v.split("://", 1)[0]
            if scheme not in ("http", "https"):
                raise ValueError(
                    f"Unsupported URL scheme '{scheme}'. Only http:// and https:// are accepted."
                )

        # Add https:// prefix if no scheme provided
        if not v.startswith(("http://", "https://")):
            v = "https://" + v

        parsed = urlparse(v)
        hostname = parsed.hostname or ""

        if not hostname or "." not in hostname:
            raise ValueError("Invalid URL: must have a valid domain with a TLD (e.g. example.com)")

        # Port policy is enforced here — at request validation time, before the
        # scan is persisted or enqueued — so denied ports never reach the worker.
        try:
            configured_port = parsed.port
        except ValueError:
            raise ValueError("Invalid URL: port out of range 0-65535.")
        policy_msg = port_policy_error(parsed.scheme, configured_port)
        if policy_msg:
            raise ValueError(policy_msg)

        # Block internal/private addresses for security
        blocked = ["localhost", "127.", "192.168.", "10.", "172.16.", "0.0.0.0", "::1"]
        for blocked_host in blocked:
            if hostname.startswith(blocked_host) or hostname == blocked_host.rstrip("."):
                raise ValueError("Scanning internal/private addresses is not allowed")
        return v


class ScanResponse(BaseModel):
    id: uuid.UUID
    url: str
    status: ScanStatus
    progress: int
    current_stage: Optional[str] = None
    error_message: Optional[str] = None
    scan_mode: str = "passive"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeline: Optional[list] = None
    created_at: datetime
    report_id: Optional[uuid.UUID] = None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    id: uuid.UUID
    url: str
    status: ScanStatus
    progress: int
    scan_mode: str = "passive"
    created_at: datetime
    completed_at: Optional[datetime] = None
    overall_score: Optional[int] = None
    grade: Optional[str] = None
    timeline: Optional[list] = None
    report_id: Optional[uuid.UUID] = None
    findings_count: Optional[int] = None
    findings_breakdown: Optional[dict[str, int]] = None

    model_config = {"from_attributes": True}


class ScanProgressEvent(BaseModel):
    scan_id: str
    status: str
    progress: int
    stage: str
    message: str
    timeline: Optional[list] = None
    report_id: Optional[str] = None
    findings_count: Optional[int] = None

