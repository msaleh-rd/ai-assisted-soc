"""Refresh the local threat-intel index.

Reloads `backend/data/threat_intel_feeds/*.csv` into the process-wide
`LocalThreatIntelDB` singleton used by the triage/evidence/compression skills.

This is intentionally a simple, idempotent CLI script (matching the style of the other
scripts in this directory) rather than a long-running service: `load_all()` clears and
re-populates the in-memory SQLite index, so it is safe to run repeatedly (e.g. from a
cron job or a scheduled Temporal workflow) whenever the vendored CSV feeds are updated.

Usage:
    python -m backend.scripts.refresh_threat_intel
    python -m backend.scripts.refresh_threat_intel --feed-dir /path/to/feeds
"""

import argparse
import logging
from pathlib import Path

from backend.services.threat_intel.local_feeds import LocalThreatIntelDB, DEFAULT_FEED_DIR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("refresh-threat-intel")


def refresh(feed_dir: Path = DEFAULT_FEED_DIR) -> dict:
    """Reload all recognized CSV feeds from `feed_dir` and return per-category row counts."""
    db = LocalThreatIntelDB(feed_dir=feed_dir)
    counts = db.load_all()
    total = sum(counts.values())
    if not counts:
        logger.warning("No threat-intel feeds were loaded from %s", feed_dir)
    else:
        for category, count in counts.items():
            logger.info("Loaded %d rows for category '%s'", count, category)
        logger.info("Threat-intel refresh complete: %d total rows across %d categories", total, len(counts))
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh the local threat-intel index from vendored CSV feeds.")
    parser.add_argument(
        "--feed-dir",
        type=Path,
        default=DEFAULT_FEED_DIR,
        help="Directory containing the threat-intel CSV feed files (default: backend/data/threat_intel_feeds)",
    )
    args = parser.parse_args()
    refresh(args.feed_dir)


if __name__ == "__main__":
    main()
