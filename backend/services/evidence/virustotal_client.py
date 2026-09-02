"""Optional VirusTotal hash-reputation lookup (Phase B, Step 2).

Feature-flagged via the `VT_API_KEY` environment variable. When unset, the
evidence pipeline's malware-analysis skill degrades gracefully to YARA-only
static analysis — this client is a *complement* to local YARA scanning, not
a hard dependency.

Design notes:
- Uses VirusTotal's public API v3 hash-lookup endpoint (read-only, no file
  upload — we only ever query hashes we already computed locally).
- Rate-limited to respect VT's public-tier quota (default: 4 requests/minute).
- Results are cached in-memory with a configurable TTL to avoid redundant
  lookups for the same hash within a short window.
- No live network calls are made unless `VT_API_KEY` is set AND the caller
  invokes `lookup_hash()` — safe to import/instantiate in tests with no key
  configured, and the actual HTTP call is isolated in `_fetch_from_api()` so
  tests can mock it directly without any network access.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

logger = logging.getLogger("virustotal-client")

VT_API_BASE_URL = "https://www.virustotal.com/api/v3/files"
DEFAULT_MIN_REQUEST_INTERVAL_SECONDS = 15.0  # ~4 requests/minute, VT public-tier default
DEFAULT_CACHE_TTL_SECONDS = 3600.0


@dataclass
class VTResult:
    """Parsed VirusTotal hash-reputation result."""
    sha256: str
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    total_engines: int
    detected_names: list
    reputation: int
    permalink: str
    source: str = "virustotal"

    @property
    def is_known_malicious(self) -> bool:
        return self.malicious_count > 0

    @property
    def detection_ratio(self) -> float:
        if self.total_engines <= 0:
            return 0.0
        return round(self.malicious_count / self.total_engines, 4)


class VirusTotalClient:
    """Thin, rate-limited, cached wrapper around VirusTotal's v3 hash-lookup API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        min_request_interval_seconds: float = DEFAULT_MIN_REQUEST_INTERVAL_SECONDS,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
    ):
        self.api_key = api_key if api_key is not None else os.getenv("VT_API_KEY", "").strip()
        self.min_request_interval_seconds = min_request_interval_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: Dict[str, Tuple[float, Optional[VTResult]]] = {}
        self._last_request_time: float = 0.0
        self._rate_limit_lock = asyncio.Lock()

    @property
    def is_enabled(self) -> bool:
        """Whether a VT API key is configured. If False, lookup_hash() always returns None."""
        return bool(self.api_key)

    def _get_cached(self, sha256: str) -> Optional[Tuple[bool, Optional[VTResult]]]:
        entry = self._cache.get(sha256)
        if entry is None:
            return None
        cached_at, result = entry
        if time.monotonic() - cached_at > self.cache_ttl_seconds:
            del self._cache[sha256]
            return None
        return True, result

    async def lookup_hash(self, sha256: str) -> Optional[VTResult]:
        """Look up a SHA256 hash's reputation on VirusTotal.

        Returns None if VT is disabled (no API key), the hash is unknown to VT,
        or the request fails for any reason — callers must treat None as
        "no VT data available", not as a definitive "clean" verdict.
        """
        if not self.is_enabled:
            return None

        sha256 = sha256.strip().lower()

        cached = self._get_cached(sha256)
        if cached is not None:
            _, result = cached
            return result

        async with self._rate_limit_lock:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self.min_request_interval_seconds:
                await asyncio.sleep(self.min_request_interval_seconds - elapsed)
            self._last_request_time = time.monotonic()

            try:
                result = await self._fetch_from_api(sha256)
            except Exception as e:
                logger.error("VirusTotal lookup failed for %s: %s", sha256, e)
                result = None

        self._cache[sha256] = (time.monotonic(), result)
        return result

    async def _fetch_from_api(self, sha256: str) -> Optional[VTResult]:
        """Perform the actual HTTP request to VirusTotal. Isolated for test mocking."""
        import aiohttp

        headers = {"x-apikey": self.api_key}
        url = f"{VT_API_BASE_URL}/{sha256}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 404:
                    return None
                if resp.status != 200:
                    logger.warning("VirusTotal returned status %d for %s", resp.status, sha256)
                    return None
                payload = await resp.json()

        return self._parse_response(sha256, payload)

    @staticmethod
    def _parse_response(sha256: str, payload: dict) -> Optional[VTResult]:
        try:
            attributes = payload["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            detected_names = [
                r.get("result") for r in results.values()
                if r.get("category") == "malicious" and r.get("result")
            ]
            total = sum(stats.values()) if stats else 0

            return VTResult(
                sha256=sha256,
                malicious_count=stats.get("malicious", 0),
                suspicious_count=stats.get("suspicious", 0),
                harmless_count=stats.get("harmless", 0),
                undetected_count=stats.get("undetected", 0),
                total_engines=total,
                detected_names=sorted(set(detected_names))[:10],
                reputation=attributes.get("reputation", 0),
                permalink=f"https://www.virustotal.com/gui/file/{sha256}",
            )
        except (KeyError, TypeError) as e:
            logger.error("Failed to parse VirusTotal response for %s: %s", sha256, e)
            return None


# Module-level singleton, mirroring the LocalThreatIntelDB/YaraScanner pattern.
# Disabled by default (no VT_API_KEY) until an operator opts in.
virustotal_client = VirusTotalClient()
