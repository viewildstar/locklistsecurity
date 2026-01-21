import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.responses import JSONResponse
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


@app.get("/.well-known/microsoft-identity-association.json")
def microsoft_identity_association():
    """Microsoft identity association file for domain verification."""
    return JSONResponse(
        content={
            "associatedApplications": [
                {
                    "applicationId": "735a8306-a750-402b-a077-0066d9daa9e3"
                }
            ]
        }
    )


# Serve the frontend from /
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
