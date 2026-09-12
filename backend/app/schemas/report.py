import uuid
from datetime import datetime, date
from pydantic import BaseModel
from typing import Optional, Any
from app.models.report import RiskLevel
from app.models.finding import Severity


class ScanBasicResponse(BaseModel):
    id: uuid.UUID
    url: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: uuid.UUID
    category: str
    title: str
    description: str
    severity: Severity
    status: str = "open"
    confidence: str = "high"
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    endpoint: Optional[str] = None
    published_date: Optional[date | datetime | str] = None
    recommendation: Optional[str] = None
    problem: Optional[str] = None
    impact: Optional[str] = None
    risk_analysis: Optional[str] = None
    technical_details: Optional[str] = None
    fix_steps: Optional[list[str]] = None
    configuration_example: Optional[str] = None
    best_practices: Optional[str] = None
    official_documentation: Optional[str] = None
    references: Optional[list[str]] = None
    evidence: Optional[str] = None
    owasp_mapping: Optional[dict[str, Any]] = None
    mitre_mapping: Optional[dict[str, Any]] = None
    is_passed_control: bool = False

    model_config = {"from_attributes": True}


class ReportResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    overall_score: int
    grade: str
    risk_level: RiskLevel
    summary: Optional[str] = None
    scan_mode: str = "passive"
    executive_summary: Optional[dict[str, Any]] = None
    tech_stack: Optional[dict] = None
    raw_headers: Optional[dict] = None
    ssl_info: Optional[dict] = None
    dns_info: Optional[dict] = None
    score_breakdown: Optional[dict[str, Any]] = None
    timeline: Optional[list[dict[str, Any]]] = None
    findings: list[FindingResponse] = []
    owasp_summary: Optional[dict[str, Any]] = None
    component_inventory: Optional[list[dict[str, Any]]] = None
    discovered_endpoints: Optional[list[dict[str, Any]]] = None
    scan: Optional[ScanBasicResponse] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    overall_score: int
    grade: str
    risk_level: RiskLevel
    scan_mode: str = "passive"
    created_at: datetime
    scan_url: Optional[str] = None
    findings_count: int = 0

    model_config = {"from_attributes": True}



class ReportSummary(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    overall_score: int
    grade: str
    risk_level: RiskLevel
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    created_at: datetime

    model_config = {"from_attributes": True}
