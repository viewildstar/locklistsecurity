from __future__ import annotations

import os
import pathlib

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from core.database import get_db
from core.jwt_utils import extract_bearer_token, verify_access_token
from core.scan import run_scan_once
from core.models import ScanRun, CheckResult, Tenant
from core.reports import (
    generate_csv_results,
    generate_jsonl_evidence,
    generate_pdf_report,
)

# HARD PROOF LOG (cannot be swallowed)
LOG_FILE = pathlib.Path("HIT_LOG.txt")

router = APIRouter(prefix="/api/v1", tags=["m365"])


@router.get("/public-config")
def public_config():
    client_id = os.getenv("AZURE_CLIENT_ID", "")
    authority = os.getenv(
        "AZURE_AUTHORITY",
        "https://login.microsoftonline.com/organizations",
    )

    if not client_id:
        return {"clientId": "", "authority": authority, "scopes": []}

    scopes = [
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Policy.Read.All",
        "RoleManagement.Read.Directory",
        "UserAuthenticationMethod.Read.All",
        "Organization.Read.All",
        "openid",
        "profile",
        "email",
    ]

    return {"clientId": client_id, "authority": authority, "scopes": scopes}


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/scan-once")
async def scan_once(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
):
    # ABSOLUTE PROOF THIS FUNCTION RAN
    LOG_FILE.write_text("SCAN_ONCE WAS HIT\n")

    token = extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    client_id = os.getenv("AZURE_CLIENT_ID", "")
    if client_id:
        try:
            claims = await verify_access_token(token)
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
    else:
        claims = {}

    sr = run_scan_once(db=db, access_token=token)

    # FORCE VISIBILITY OF INTERNAL FAILURE
    if sr.status == "error":
        raise RuntimeError(f"Scan failed internally: {sr.error}")

    return {
        "scan_run_id": sr.id,
        "tenant": {
            "aad_tenant_id": claims.get("tid"),
            "preferred_username": claims.get("preferred_username"),
        },
        "status": sr.status,
        "started_at": sr.started_at,
        "finished_at": sr.finished_at,
        "reports": {
            "jsonl": f"/api/v1/scan-runs/{sr.id}/evidence.jsonl",
            "csv": f"/api/v1/scan-runs/{sr.id}/results.csv",
            "pdf": f"/api/v1/scan-runs/{sr.id}/report.pdf",
        },
    }


@router.get("/scan-runs/{scan_run_id}")
def get_scan(scan_run_id: int, db: Session = Depends(get_db)):
    sr = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not sr:
        raise HTTPException(status_code=404, detail="Scan run not found")

    tenant = db.query(Tenant).filter(Tenant.id == sr.tenant_id).first()
    results = (
        db.query(CheckResult)
        .filter(CheckResult.scan_run_id == scan_run_id)
        .all()
    )

    return {
        "scan_run": {
            "id": sr.id,
            "status": sr.status,
            "started_at": sr.started_at,
            "finished_at": sr.finished_at,
            "error": sr.error,
        },
        "tenant": {
            "aad_tenant_id": tenant.aad_tenant_id if tenant else None,
            "display_name": tenant.display_name if tenant else None,
        },
        "results": [
            {
                "check_key": r.check_key,
                "title": r.title,
                "category": r.category,
                "status": r.status,
                "severity": r.severity,
                "summary": r.summary,
                "remediation": r.remediation,
            }
            for r in results
        ],
    }


@router.get("/scan-runs/{scan_run_id}/evidence.jsonl")
def download_jsonl(scan_run_id: int, db: Session = Depends(get_db)):
    data = generate_jsonl_evidence(db, scan_run_id)
    return Response(
        content=data,
        media_type="application/jsonl",
        headers={
            "Content-Disposition": f"attachment; filename=evidence_{scan_run_id}.jsonl"
        },
    )


@router.get("/scan-runs/{scan_run_id}/results.csv")
def download_csv(scan_run_id: int, db: Session = Depends(get_db)):
    data = generate_csv_results(db, scan_run_id)
    return Response(
        content=data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=results_{scan_run_id}.csv"
        },
    )


@router.get("/scan-runs/{scan_run_id}/report.pdf")
def download_pdf(scan_run_id: int, db: Session = Depends(get_db)):
    pdf_bytes = generate_pdf_report(db, scan_run_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=report_{scan_run_id}.pdf"
        },
    )
