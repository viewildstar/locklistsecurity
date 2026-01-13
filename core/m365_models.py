"""
Database models for M365 Security Compliance
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Boolean, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from core.database import Base


class Tenant(Base):
    """M365 tenant information"""
    __tablename__ = "m365_tenants"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, unique=True, index=True, nullable=False)
    display_name = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    connections = relationship("TenantConnection", back_populates="tenant", cascade="all, delete-orphan")
    scan_runs = relationship("ScanRun", back_populates="tenant", cascade="all, delete-orphan")


class TenantConnection(Base):
    """Authentication credentials for a tenant"""
    __tablename__ = "m365_connections"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, ForeignKey("m365_tenants.tenant_id"), nullable=False)
    auth_type = Column(String, default="client_credentials")  # client_credentials, certificate
    encrypted_secret = Column(Text, nullable=True)  # Encrypted client secret
    client_id = Column(String, nullable=False)
    scopes_granted = Column(JSON, nullable=True)  # List of granted scopes
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_validated_at = Column(DateTime(timezone=True), nullable=True)
    
    tenant = relationship("Tenant", back_populates="connections")


class ScanRun(Base):
    """A single scan execution"""
    __tablename__ = "m365_scan_runs"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, ForeignKey("m365_tenants.tenant_id"), nullable=False)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, default="running")  # running, completed, failed, cancelled
    graph_api_version = Column(String, default="v1.0")
    error_message = Column(Text, nullable=True)
    
    tenant = relationship("Tenant", back_populates="scan_runs")
    check_results = relationship("CheckResult", back_populates="scan_run", cascade="all, delete-orphan")
    evidence_blobs = relationship("EvidenceBlob", back_populates="scan_run", cascade="all, delete-orphan")


class Check(Base):
    """Security check definitions"""
    __tablename__ = "m365_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)  # e.g., "ca_mfa_admins"
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity_default = Column(String, default="medium")  # low, medium, high, critical
    category = Column(String, nullable=False)  # identity_access, logging, licensing
    graph_endpoint = Column(String, nullable=True)  # For reference
    
    check_results = relationship("CheckResult", back_populates="check")


class CheckResult(Base):
    """Results of a security check execution"""
    __tablename__ = "m365_check_results"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("m365_scan_runs.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("m365_checks.id"), nullable=False)
    status = Column(String, nullable=False)  # pass, needs_attention, not_detected, error
    severity = Column(String, nullable=False)  # low, medium, high, critical
    summary_md = Column(Text, nullable=True)  # Human-readable summary
    remediation_md = Column(Text, nullable=True)  # Fix steps
    risk_score = Column(Float, nullable=True)  # 0.0 to 1.0
    observed_data = Column(JSON, nullable=True)  # Structured findings
    
    scan_run = relationship("ScanRun", back_populates="check_results")
    check = relationship("Check", back_populates="check_results")


class EvidenceBlob(Base):
    """Evidence collected for a check"""
    __tablename__ = "m365_evidence_blobs"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("m365_scan_runs.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("m365_checks.id"), nullable=True)
    evidence_json = Column(JSON, nullable=True)  # JSON evidence data
    blob_path = Column(String, nullable=True)  # Path to file if stored separately
    collected_at = Column(DateTime(timezone=True), server_default=func.now())
    source_endpoints = Column(JSON, nullable=True)  # List of Graph API endpoints used
    
    scan_run = relationship("ScanRun", back_populates="evidence_blobs")

