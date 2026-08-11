"""API initialization and configuration."""

from fastapi import APIRouter

# Import route modules
from backend.api.routes import alerts, investigations, correlation, rca

router = APIRouter()

# Include routers
router.include_router(alerts.router)
router.include_router(investigations.router)
router.include_router(correlation.router)
router.include_router(rca.router)
