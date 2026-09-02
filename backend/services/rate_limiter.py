"""Token-bucket rate limiter for LLM calls — Wave 1 / Phase D, Step 3.

Wraps calls to a local/self-hosted model endpoint (e.g. LM Studio) to avoid
overwhelming it under alert bursts, when many investigations/decisions fire
LLM calls concurrently.
"""

import asyncio
import os
import threading
import time


class TokenBucketLimiter:
    """Simple thread-safe token-bucket limiter with an async-friendly acquire()."""

    def __init__(self, rate_per_second: float = 5.0, capacity: int = 10):
        self.rate = rate_per_second
        self.capacity = capacity
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Non-blocking attempt to acquire `tokens`. Returns True if granted."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    async def acquire(self, tokens: float = 1.0, max_wait_seconds: float = 5.0) -> bool:
        """Async wait (polling) until tokens are available or max_wait_seconds elapses.

        Returns True if acquired, False if the wait timed out (caller may still
        proceed — this is a soft limiter, not a hard circuit breaker).
        """
        waited = 0.0
        interval = 0.05
        while waited < max_wait_seconds:
            if self.try_acquire(tokens):
                return True
            await asyncio.sleep(interval)
            waited += interval
        return False


# Module-level singleton, configurable via env vars.
llm_rate_limiter = TokenBucketLimiter(
    rate_per_second=float(os.getenv("LLM_RATE_LIMIT_PER_SECOND", "5")),
    capacity=int(os.getenv("LLM_RATE_LIMIT_BURST", "10")),
)
