import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.routes import router
from core.database import init_db

app = FastAPI(
    title="LockList Security",
    version="0.1.0",
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)

@app.on_event("startup")
def _startup():
    init_db()

app.include_router(router)

# Serve the frontend from /
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
