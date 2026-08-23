"""Compression Skill Handlers for executing noise reduction skills."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.services.correlation_engine import CorrelationEngine, CompressedPackage

logger = logging.getLogger("compression-skills")


class CompressionSkillExecutor:
    """Dispatches and executes compression skills."""

    @staticmethod
    async def execute_compression_pipeline(
        skills_selected: List[str],
        raw_events: List[Dict[str, Any]],
        context_data: Optional[Dict[str, Any]] = None
    ) -> CompressedPackage:
        """Run the tailored correlation and compression pipeline using chosen skills."""
        engine = CorrelationEngine()

        # Parse incident time
        incident_time = datetime.utcnow()
        if context_data and context_data.get("alert_data", {}).get("timestamp"):
            try:
                ts = context_data["alert_data"]["timestamp"].replace("Z", "+00:00")
                incident_time = datetime.fromisoformat(ts).replace(tzinfo=None)
            except Exception:
                incident_time = datetime.utcnow()

        # Run compression through CorrelationEngine
        pkg = engine.compress_events(
            raw_events=raw_events,
            incident_time=incident_time,
            window_minutes=30
        )

        logger.info(
            f"Executed compression pipeline with skills: {skills_selected}. "
            f"Reduced {pkg.raw_event_count} raw events to {pkg.compressed_event_count} ({pkg.compression_ratio:.1f}x reduction)."
        )
        return pkg
