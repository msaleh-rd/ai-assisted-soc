"""Tests for the token-bucket LLM rate limiter (Wave 1 / Phase D, Step 3)."""

import asyncio

import pytest

from backend.services.rate_limiter import TokenBucketLimiter


class TestTokenBucketLimiter:
    def test_try_acquire_succeeds_within_capacity(self):
        limiter = TokenBucketLimiter(rate_per_second=1.0, capacity=3)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is True

    def test_try_acquire_fails_when_bucket_exhausted(self):
        limiter = TokenBucketLimiter(rate_per_second=0.001, capacity=1)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False

    def test_bucket_refills_over_time(self):
        limiter = TokenBucketLimiter(rate_per_second=100_000.0, capacity=1)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False
        import time
        time.sleep(0.05)  # 100,000 tokens/sec * 0.05s = 5000 tokens refilled, well above capacity
        assert limiter.try_acquire() is True

    @pytest.mark.asyncio
    async def test_async_acquire_returns_true_when_available(self):
        limiter = TokenBucketLimiter(rate_per_second=10.0, capacity=5)
        acquired = await limiter.acquire(max_wait_seconds=1.0)
        assert acquired is True

    @pytest.mark.asyncio
    async def test_async_acquire_times_out_when_bucket_never_refills_enough(self):
        limiter = TokenBucketLimiter(rate_per_second=0.001, capacity=1)
        assert limiter.try_acquire() is True  # drain the single token
        acquired = await limiter.acquire(tokens=1.0, max_wait_seconds=0.2)
        assert acquired is False
