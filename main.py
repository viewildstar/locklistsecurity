
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routes import router
from core.database import init_db

# Load environment variables
load_dotenv()

app = FastAPI(
    title="LockList Security",
    version="0.1.0",
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)

@app.middleware("http")
async def log_every_request(request, call_next):
    print(">>> REQUEST:", request.method, request.url)
    response = await call_next(request)
    print("<<< RESPONSE:", response.status_code)
    return response


# CORS (safe for local dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

# --------------------
# API ROUTES FIRST
# --------------------
app.include_router(router)

@app.get("/.well-known/microsoft-identity-association.json")
def microsoft_identity_association():
    return JSONResponse(
        content={
            "associatedApplications": [
                {"applicationId": "735a8306-a750-402b-a077-0066d9daa9e3"}
            ]
        }
    )

# --------------------
# STATIC FRONTEND LAST
# --------------------
BASE_DIR = os.path.dirname(__file__)
DOCS_DIR = os.path.join(BASE_DIR, "docs")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if os.path.isdir(DOCS_DIR):
    app.mount(
        "/",
        StaticFiles(directory=DOCS_DIR, html=True),
        name="frontend",
    )
elif os.path.isdir(FRONTEND_DIR):
    app.mount(
        "/",
        StaticFiles(directory=FRONTEND_DIR, html=True),
        name="frontend",
    )
