from __future__ import annotations

import asyncio
from datetime import datetime
from typing import List

from sqlalchemy.orm import Session

from core.graph_client import GraphClient
from core.models import Tenant, ScanRun, CheckResult, EvidenceBlob
from core.checks import ALL_CHECKS, CheckOutput, check_tenant_info


async def _run_checks(gc: GraphClient) -> List[CheckOutput]:
    out: List[CheckOutput] = []
    for fn in ALL_CHECKS:
        try:
            out.append(await fn(gc))
        except Exception as e:
            # Never crash the entire scan for a single check
            key = getattr(fn, "__name__", "unknown")
            out.append(
                CheckOutput(
                    check_key=key,
                    title=key,
                    category="General",
                    status="error",
                    severity="medium",
                    summary=f"Check crashed: {e}",
                    remediation="Review server logs and retry.",
                    evidence={},
                )
            )
    return out


def run_scan_once(db: Session, access_token: str) -> ScanRun:
    """Run a scan synchronously (one-time) using a delegated access token."""

    async def _do() -> ScanRun:
        gc = GraphClient(access_token=access_token)
        aad_tid, display_name = await check_tenant_info(gc)

        # Upsert tenant
        tenant = None
        if aad_tid:
            tenant = db.query(Tenant).filter(Tenant.aad_tenant_id == aad_tid).first()

        if not tenant:
            tenant = Tenant(
                aad_tenant_id=aad_tid or "unknown",
                display_name=display_name or "",
            )
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
        else:
            if display_name and display_name != tenant.display_name:
                tenant.display_name = display_name
                db.commit()

        sr = ScanRun(
            tenant_id=tenant.id,
            status="running",
            started_at=datetime.utcnow(),
        )
        db.add(sr)
        db.commit()
        db.refresh(sr)

        try:
            outputs = await _run_checks(gc)

            for o in outputs:
                db.add(
                    CheckResult(
                        scan_run_id=sr.id,
                        check_key=o.check_key,
                        title=o.title,
                        category=o.category,
                        status=o.status,
                        severity=o.severity,
                        summary=o.summary,
                        remediation=o.remediation,
                    )
                )
                db.add(
                    EvidenceBlob(
                        scan_run_id=sr.id,
                        check_key=o.check_key,
                        evidence_json=o.evidence,
                    )
                )

            sr.status = "completed"
            sr.finished_at = datetime.utcnow()
            db.commit()
            db.refresh(sr)
            return sr

        except Exception:
            raise

    return asyncio.run(_do())
