"""Main FastAPI application."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
import os

from contextlib import asynccontextmanager
from backend.api import router as api_router
from backend.database.connection import init_db, close_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown
    await close_db()

# Create FastAPI app
app = FastAPI(
    title="AI-Native SOC Platform - Phase 1-3",
    description="Alert Intake, Evidence Collection, Correlation/Compression, RCA & Response Orchestration",
    version="0.3.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)

# Serve frontend static files
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


@app.get("/ui")
async def serve_ui():
    """Serve the SOC Dashboard UI."""
    index_path = os.path.join(frontend_dir, 'index.html')
    if os.path.isfile(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            html = f.read()
        return HTMLResponse(html)
    return JSONResponse({"error": "Frontend not found"}, status_code=404)


@app.get("/")
async def root():
    """Root endpoint with service info."""
    return {
        "name": "AI-Native SOC Platform",
        "phases": "Phase 1-3 (Alert Intake, Correlation, RCA & Response)",
        "version": "0.3.0",
        "status": "running",
        "ui": "/ui",
        "docs": "/docs",
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    }


@app.get("/api/v1")
async def api_root():
    """API v1 root."""
    return {
        "api_version": "v1",
        "endpoints": {
            "alerts": "/api/v1/alerts",
            "evidence": "/api/v1/evidence",
        },
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
