"""Refresh the local threat-intel index.

Fetches the latest version of each vendored CSV feed directly from the upstream
`mthcht/awesome-lists` GitHub repository (MIT licensed -- see
`backend/data/threat_intel_feeds/README.md`), atomically replaces the local copy on
success, then reloads the process-wide `local_threat_intel_db` singleton used by the
triage/evidence/compression skills so the running process picks up the new data
without a restart.

This is intentionally a simple, idempotent CLI script (matching the style of the other
scripts in this directory) rather than a long-running service: `load_all()` clears and
re-populates the in-memory SQLite index, so it is safe to run repeatedly (e.g. from a
cron job, a scheduled Temporal workflow, or the periodic background task started in
`backend/main.py`). Each feed is fetched and validated independently -- a failed/timed-out
download for one feed never touches its local file or blocks the others, so a network
blip can never wipe out existing local intel.

Usage:
    python -m backend.scripts.refresh_threat_intel
    python -m backend.scripts.refresh_threat_intel --feed-dir /path/to/feeds
    python -m backend.scripts.refresh_threat_intel --no-fetch   # reload local CSVs only, no network
"""

import argparse
import csv
import io
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict

import httpx

from backend.services.threat_intel.local_feeds import (
    FEED_MANIFEST,
    DEFAULT_FEED_DIR,
    local_threat_intel_db,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("refresh-threat-intel")

UPSTREAM_BASE_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists"
FETCH_TIMEOUT_SECONDS = 15.0


def _validate_csv(content: bytes, expected_column: str) -> bool:
    """Best-effort sanity check that a downloaded feed is a well-formed, non-empty CSV
    containing the expected key column -- guards against replacing a good local file
    with an HTML error page or truncated/corrupt download."""
    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or expected_column not in reader.fieldnames:
            return False
        # Require at least one data row.
        return any(True for _ in reader)
    except Exception:
        return False


def fetch_latest_feeds(feed_dir: Path = DEFAULT_FEED_DIR, timeout: float = FETCH_TIMEOUT_SECONDS) -> Dict[str, bool]:
    """Download the current version of each feed in FEED_MANIFEST from upstream and
    atomically replace the local copy on success. Returns per-file success status.
    Best-effort per file -- never raises; a failure leaves the existing local file
    untouched."""
    feed_dir = Path(feed_dir)
    feed_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, bool] = {}

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for filename, meta in FEED_MANIFEST.items():
            url = f"{UPSTREAM_BASE_URL}/{filename}"
            try:
                response = client.get(url)
                response.raise_for_status()
                if not _validate_csv(response.content, meta["key_column"]):
                    logger.warning("Downloaded feed '%s' failed validation; keeping existing local copy.", filename)
                    results[filename] = False
                    continue

                # Atomic replace: write to a temp file in the same directory, then os.replace
                # so a crash/interrupt mid-write can never leave a corrupt/partial CSV behind.
                fd, tmp_path = tempfile.mkstemp(dir=str(feed_dir), prefix=f".{filename}.", suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as tmp_file:
                        tmp_file.write(response.content)
                    os.replace(tmp_path, feed_dir / filename)
                except Exception:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                    raise

                logger.info("Fetched latest '%s' from upstream (%d bytes).", filename, len(response.content))
                results[filename] = True
            except Exception as fetch_err:
                logger.warning("Failed to fetch '%s' from upstream, keeping existing local copy: %s", filename, fetch_err)
                results[filename] = False

    return results


def refresh(feed_dir: Path = DEFAULT_FEED_DIR, fetch_latest: bool = True, timeout: float = FETCH_TIMEOUT_SECONDS) -> dict:
    """Optionally fetch the latest upstream CSVs, then reload the real
    `local_threat_intel_db` singleton (not a throwaway instance) from `feed_dir`,
    returning per-category row counts."""
    if fetch_latest:
        fetch_results = fetch_latest_feeds(feed_dir, timeout=timeout)
        fetched = sum(1 for ok in fetch_results.values() if ok)
        logger.info("Fetched %d/%d feed(s) from upstream.", fetched, len(fetch_results))

    counts = local_threat_intel_db.load_all(feed_dir=feed_dir)
    total = sum(counts.values())
    if not counts:
        logger.warning("No threat-intel feeds were loaded from %s", feed_dir)
    else:
        for category, count in counts.items():
            logger.info("Loaded %d rows for category '%s'", count, category)
        logger.info("Threat-intel refresh complete: %d total rows across %d categories", total, len(counts))
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh the local threat-intel index from upstream CSV feeds.")
    parser.add_argument(
        "--feed-dir",
        type=Path,
        default=DEFAULT_FEED_DIR,
        help="Directory containing the threat-intel CSV feed files (default: backend/data/threat_intel_feeds)",
    )
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="Skip fetching from upstream; only reload the existing local CSVs.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=FETCH_TIMEOUT_SECONDS,
        help="Per-feed HTTP fetch timeout in seconds (default: 15).",
    )
    args = parser.parse_args()
    refresh(args.feed_dir, fetch_latest=not args.no_fetch, timeout=args.timeout)


if __name__ == "__main__":
    main()
