from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path

from cyberfusion.app.config import settings
from cyberfusion.app.database import init_db
from cyberfusion.app.api import (
    dashboard_router,
    asm_router,
    siem_router,
    cspm_router,
    identity_router,
    apisec_router,
    phishing_router,
    ransomware_router,
    intel_router,
    ai_router,
    pentest_tools_router
)

STATIC_DIR = Path(__file__).parent / "static"

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Unified AI-Powered Enterprise Cyber Defense Platform & Bug Hunting Suite",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all 11 API Routers
app.include_router(dashboard_router)
app.include_router(asm_router)
app.include_router(siem_router)
app.include_router(cspm_router)
app.include_router(identity_router)
app.include_router(apisec_router)
app.include_router(phishing_router)
app.include_router(ransomware_router)
app.include_router(intel_router)
app.include_router(ai_router)
app.include_router(pentest_tools_router)

# Mount Static UI
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
async def health_check():
    return {
        "status": "online",
        "platform": settings.app_name,
        "version": settings.version,
        "pentest_tools": ["Nmap", "Caido", "Nuclei", "Subfinder", "Httpx", "FFUF"]
    }
