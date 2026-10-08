"""
CYBERSHIELD X - FastAPI Main Server
Unified Security Operations, Attack Surface Management, SIEM & AI Analyst Platform.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
import os

from cybershield.app.config import settings
from cybershield.app.database import init_db, AsyncSessionLocal
from cybershield.app.api import (
    dashboard_router,
    asm_router,
    vuln_router,
    siem_router,
    ai_router
)
from cybershield.app.api.dashboard import seed_demo_data

STATIC_DIR = Path(__file__).parent / "static"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schema
    await init_db()
    # Seed default demonstration telemetry
    async with AsyncSessionLocal() as session:
        try:
            await seed_demo_data(session)
        except Exception as e:
            print(f"[!] Warning: Demo seed skipped: {e}")
    yield

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Enterprise-grade AI-Assisted SOC, SIEM & Attack Surface Management Platform",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(dashboard_router)
app.include_router(asm_router)
app.include_router(vuln_router)
app.include_router(siem_router)
app.include_router(ai_router)

# Mount Static Files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
async def serve_dashboard():
    index_file = STATIC_DIR / "index.html"
    return FileResponse(index_file)

@app.get("/health")
async def health_check():
    return {
        "status": "online",
        "system": settings.app_name,
        "version": settings.version,
        "program": settings.program
    }
