"""Temporal Worker — runs the InvestigationWorkflow and all agent activities.

Start this as a separate process alongside the FastAPI server:

    python -m backend.services.temporal_worker

The worker connects to the Temporal Server and polls for investigation
workflow tasks on the "soc-investigation-queue" task queue.
"""

import asyncio
import logging
import os
import sys

from temporalio.client import Client
from temporalio.worker import Worker

from backend.services.temporal_workflows import (
    InvestigationWorkflow,
    ALL_ACTIVITIES,
)

TEMPORAL_HOST = os.getenv("TEMPORAL_HOST", "localhost:7233")
TEMPORAL_NAMESPACE = os.getenv("TEMPORAL_NAMESPACE", "default")
TASK_QUEUE = "soc-investigation-queue"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("temporal-worker")


async def main():
    """Connect to Temporal and run the worker until interrupted."""
    logger.info("Connecting to Temporal at %s (namespace=%s)…", TEMPORAL_HOST, TEMPORAL_NAMESPACE)
    
    from backend.database.connection import init_db
    init_db()

    try:
        from backend.services.rag_service import _load_vectorstore
        _load_vectorstore()
        logger.info("Pre-warmed FAISS vectorstore & embeddings")
    except Exception as e:
        logger.warning("Could not pre-warm RAG vectorstore: %s", e)

    client = await Client.connect(TEMPORAL_HOST, namespace=TEMPORAL_NAMESPACE)

    logger.info("Starting worker on task queue '%s'", TASK_QUEUE)
    logger.info("Registered workflow:  InvestigationWorkflow")
    logger.info("Registered activities: %s", [a.fn.__name__ if hasattr(a, 'fn') else a.__name__ for a in ALL_ACTIVITIES])

    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[InvestigationWorkflow],
        activities=ALL_ACTIVITIES,
    )

    logger.info("Worker is running. Press Ctrl+C to stop.")
    await worker.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Worker stopped.")
