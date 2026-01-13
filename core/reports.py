from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import List, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session

from core.models import ScanRun, Tenant, CheckResult, EvidenceBlob


def _get_scan(db: Session, scan_run_id: int) -> Tuple[ScanRun, Tenant, List[CheckResult], List[EvidenceBlob]]:
    sr = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not sr:
        raise ValueError("Scan run not found")
    tenant = db.query(Tenant).filter(Tenant.id == sr.tenant_id).first()
    results = db.query(CheckResult).filter(CheckResult.scan_run_id == scan_run_id).order_by(CheckResult.category, CheckResult.severity.desc()).all()
    evidence = db.query(EvidenceBlob).filter(EvidenceBlob.scan_run_id == scan_run_id).all()
    return sr, tenant, results, evidence


def generate_jsonl_evidence(db: Session, scan_run_id: int) -> bytes:
    sr, tenant, results, evidence = _get_scan(db, scan_run_id)
    ev_map = {e.check_key: e.evidence_json for e in evidence}

    buf = io.StringIO()
    for r in results:
        row = {
            "scan_run_id": scan_run_id,
            "tenant": {"aad_tenant_id": tenant.aad_tenant_id, "display_name": tenant.display_name},
            "collected_at": datetime.utcnow().isoformat() + "Z",
            "check": {
                "key": r.check_key,
                "title": r.title,
                "category": r.category,
                "status": r.status,
                "severity": r.severity,
                "summary": r.summary,
                "remediation": r.remediation,
            },
            "evidence": ev_map.get(r.check_key, {}),
        }
        buf.write(json.dumps(row, default=str) + "\n")
    return buf.getvalue().encode("utf-8")


def generate_csv_results(db: Session, scan_run_id: int) -> bytes:
    _, tenant, results, _ = _get_scan(db, scan_run_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["tenant", tenant.display_name or tenant.aad_tenant_id])
    writer.writerow([])
    writer.writerow(["check_key", "title", "category", "status", "severity", "summary", "remediation"])
    for r in results:
        writer.writerow([r.check_key, r.title, r.category, r.status, r.severity, r.summary, r.remediation])
    return output.getvalue().encode("utf-8")


def generate_pdf_report(db: Session, scan_run_id: int) -> bytes:
    sr, tenant, results, _ = _get_scan(db, scan_run_id)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "LockList Security – M365 One-time Scan Report")

    y -= 24
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Tenant: {tenant.display_name or '(unknown)'} ({tenant.aad_tenant_id})")
    y -= 14
    c.drawString(50, y, f"Scan run: {sr.id}   Status: {sr.status}   Started: {sr.started_at}   Finished: {sr.finished_at}")

    # Summary counts
    def _count(status: str) -> int:
        return sum(1 for r in results if r.status == status)

    y -= 24
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, f"Summary: PASS {_count('pass')}  FAIL {_count('fail')}  NOT_DETECTED {_count('not_detected')}  ERROR {_count('error')}")

    y -= 18
    c.setFont("Helvetica", 9)
    c.drawString(50, y, "Top findings (first 15):")

    y -= 14
    shown = 0
    for r in results:
        if shown >= 15:
            break
        line = f"[{r.severity.upper()}] {r.status.upper()} – {r.title}"
        c.drawString(50, y, line[:110])
        y -= 12
        shown += 1
        if y < 80:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

    c.showPage()
    c.save()
    return buf.getvalue()
