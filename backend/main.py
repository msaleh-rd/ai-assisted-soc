"""Main FastAPI application."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime

from backend.api import router as api_router


# Create FastAPI app
app = FastAPI(
    title="AI-Native SOC Platform - Phase 1-2",
    description="Alert Intake, Evidence Collection & Correlation/Compression Service",
    version="0.2.0",
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


@app.get("/")
async def root():
    """Root endpoint with service info."""
    return {
        "name": "AI-Native SOC Platform",
        "phases": "Phase 1 (Alert Intake & Evidence Collection) + Phase 2 (Correlation & Compression)",
        "version": "0.2.0",
        "status": "running",
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
