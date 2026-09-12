import uuid
from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Enum as SAEnum, Text, Uuid as UUID, JSON as JSONB, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum
from app.database import Base


class RiskLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    overall_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    grade: Mapped[str] = mapped_column(String(3), nullable=False, default="F")
    risk_level: Mapped[RiskLevel] = mapped_column(SAEnum(RiskLevel), default=RiskLevel.info, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    tech_stack: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    raw_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ssl_info: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    dns_info: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    score_breakdown: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # per-category scores
    scan_mode: Mapped[str] = mapped_column(String(20), default="passive", nullable=False) # 'passive' vs 'authorized'
    executive_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True) # {overall_risk, business_impact, strengths, weaknesses, critical_issues, quick_wins, priority_fixes, security_posture}
    timeline: Mapped[list | None] = mapped_column(JSONB, nullable=True)         # scan timeline summary
    owasp_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)     # 10-category OWASP matrix
    discovered_endpoints: Mapped[list | None] = mapped_column(JSONB, nullable=True) # crawled endpoint inventory
    component_inventory: Mapped[list | None] = mapped_column(JSONB, nullable=True) # structured component assessment
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["Scan"] = relationship("Scan", back_populates="report")
    user: Mapped["User"] = relationship("User", back_populates="reports")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="report", cascade="all, delete-orphan")
