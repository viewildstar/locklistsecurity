from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aad_tenant_id: Mapped[str] = mapped_column(String(64), index=True)  # GUID
    display_name: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_runs: Mapped[list[ScanRun]] = relationship(back_populates="tenant")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="running")  # running/completed/failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="scan_runs")
    results: Mapped[list[CheckResult]] = relationship(back_populates="scan_run")
    evidence: Mapped[list[EvidenceBlob]] = relationship(back_populates="scan_run")


class CheckResult(Base):
    __tablename__ = "check_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)

    check_key: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(64), default="General")
    status: Mapped[str] = mapped_column(String(32))  # pass/fail/not_detected/error
    severity: Mapped[str] = mapped_column(String(16), default="medium")  # low/medium/high

    summary: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_run: Mapped[ScanRun] = relationship(back_populates="results")


class EvidenceBlob(Base):
    __tablename__ = "evidence_blobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    check_key: Mapped[str] = mapped_column(String(128), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Store raw-ish evidence. Keep it small (trim long lists).
    evidence_json: Mapped[dict] = mapped_column(JSON)

    scan_run: Mapped[ScanRun] = relationship(back_populates="evidence")
