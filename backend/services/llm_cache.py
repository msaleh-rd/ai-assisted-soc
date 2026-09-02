"""Redis-backed LLM response cache — Wave 1 / Phase D, Step 3.

Caches structured-output LLM responses keyed by a role-scoped prompt hash, so
that repeated/duplicate prompts (e.g. near-identical alerts arriving in a burst)
don't pay for a fresh LLM call. Falls back to a small in-memory TTL cache when
Redis is unavailable (e.g. in tests, or when REDIS_URL is unset/unreachable) —
mirroring the DB-optional pattern used throughout this codebase
(`evidence_collection.py`, `investigation_ledger.py`).
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("llm_cache")

DEFAULT_TTL_SECONDS = int(os.getenv("LLM_CACHE_TTL_SECONDS", "300"))


class LLMResponseCache:
    """Best-effort cache: tries Redis first, degrades to in-memory TTL dict."""

    def __init__(self):
        self._redis = None
        self._redis_checked = False
        self._memory_store: Dict[str, Dict[str, Any]] = {}

    def _get_redis(self):
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            import redis  # type: ignore
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            client = redis.from_url(redis_url, socket_connect_timeout=0.5, socket_timeout=0.5)
            client.ping()
            self._redis = client
        except Exception as e:
            logger.debug(f"Redis unavailable, falling back to in-memory LLM cache: {e}")
            self._redis = None
        return self._redis

    def get(self, key: str) -> Optional[dict]:
        redis_client = self._get_redis()
        if redis_client:
            try:
                raw = redis_client.get(f"llm_cache:{key}")
                if raw:
                    return json.loads(raw)
                return None
            except Exception as e:
                logger.debug(f"Redis get failed, falling back to in-memory: {e}")
        entry = self._memory_store.get(key)
        if entry:
            if entry["expires_at"] > time.time():
                return entry["value"]
            self._memory_store.pop(key, None)
        return None

    def set(self, key: str, value: dict, ttl: int = DEFAULT_TTL_SECONDS) -> None:
        redis_client = self._get_redis()
        if redis_client:
            try:
                redis_client.setex(f"llm_cache:{key}", ttl, json.dumps(value, default=str))
                return
            except Exception as e:
                logger.debug(f"Redis set failed, falling back to in-memory: {e}")
        self._memory_store[key] = {"value": value, "expires_at": time.time() + ttl}

    def clear(self) -> None:
        self._memory_store.clear()


# Module-level singleton, mirroring investigation_ledger / local_threat_intel_db.
llm_response_cache = LLMResponseCache()
