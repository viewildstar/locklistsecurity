from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from core.database import SessionLocal
from core.m365_models import Tenant


router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/tenants")
def list_tenants(db: Session = Depends(get_db)):
    tenants = db.query(Tenant).order_by(Tenant.created_at.desc()).all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "tenant_id": t.tenant_id,
            "created_at": t.created_at,
        }
        for t in tenants
    ]
