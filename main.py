import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

# Add CORS middleware to allow frontend to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


# Serve the frontend from / (only if directory exists)
# Try docs directory first (for GitHub Pages compatibility), then frontend
docs_dir = os.path.join(os.path.dirname(__file__), "docs")
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")

if os.path.exists(docs_dir) and os.path.isdir(docs_dir):
    app.mount("/", StaticFiles(directory=docs_dir, html=True), name="frontend")
elif os.path.exists(frontend_dir) and os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
