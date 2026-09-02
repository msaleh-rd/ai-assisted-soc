"""API initialization and configuration."""

from fastapi import APIRouter

# Import route modules
from backend.api.routes import alerts, investigations, correlation, rca, discovery, orchestrator, ai_governance

router = APIRouter()

# Include routers
router.include_router(alerts.router)
router.include_router(investigations.router)
router.include_router(correlation.router)
router.include_router(rca.router)
router.include_router(discovery.router)
router.include_router(orchestrator.router)
router.include_router(ai_governance.router)
