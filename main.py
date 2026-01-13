from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.m365_routes import router as m365_router
from core.database import init_db
from pathlib import Path

app = FastAPI(
    title="LockList Security",
    version="0.1.0",
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)

@app.on_event("startup")
def _startup():
    init_db()

app.include_router(m365_router, prefix="/api/v1")

# Serve a simple dashboard if present
frontend_dir = Path(__file__).parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
