import uuid
from datetime import datetime, date
from sqlalchemy import String, DateTime, Date, ForeignKey, Enum as SAEnum, Text, Numeric, Uuid as UUID, JSON, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum
from app.database import Base


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, enum.Enum):
    open = "open"
    accepted_risk = "accepted_risk"
    resolved = "resolved"
    false_positive = "false_positive"


class Confidence(str, enum.Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(SAEnum(FindingStatus), default=FindingStatus.open, nullable=False)
    confidence: Mapped[Confidence] = mapped_column(SAEnum(Confidence), default=Confidence.high, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(4, 1), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(25), nullable=True, index=True)   # e.g. "CVE-2021-41773"
    cwe_id: Mapped[str | None] = mapped_column(String(25), nullable=True)               # e.g. "CWE-693"
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    published_date: Mapped[date | None] = mapped_column(Date, nullable=True)             # NVD published date
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    problem: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    technical_details: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix_steps: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    configuration_example: Mapped[str | None] = mapped_column(Text, nullable=True)
    best_practices: Mapped[str | None] = mapped_column(Text, nullable=True)
    official_documentation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    owasp_mapping: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # {id, title, description, reference}
    mitre_mapping: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # {technique_id, technique_name, description, reference}
    is_passed_control: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    report: Mapped["Report"] = relationship("Report", back_populates="findings")
