from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

# from api.m365_routes import router as m365_router  # uncomment when you add routes
from core.database import init_db

app = FastAPI(title="LockList Security", version="0.1.0")

@app.on_event("startup")
def _startup():
    init_db()

# app.include_router(m365_router, prefix="/api/v1")  # uncomment when you add routes

# Serve your simple dashboard if you have it
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
