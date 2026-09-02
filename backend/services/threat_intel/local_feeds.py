"""Local Threat-Intel Grounding (Phase A).

Provides deterministic, offline lookups against locally-vendored threat-intelligence
feeds (curated subsets of `mthcht/awesome-lists`, MIT licensed — see
`backend/data/threat_intel_feeds/README.md`) so that Triage/Evidence/Compression skills
can answer "is this a known-bad indicator?" without waiting on or trusting an LLM guess.

Per the project's guiding principle ("ground truth over LLM guesswork"), this module is
intentionally simple: CSVs are loaded into an in-memory SQLite database (stdlib `sqlite3`,
no new runtime dependency) for fast indexed lookup by hash / port / extension / mutex name,
with substring/glob-aware matching for the categories that need it (extensions use `*.ext`
glob patterns; mutex/keyword lists frequently use `*` wildcards too).
"""

from __future__ import annotations

import csv
import fnmatch
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("local-threat-intel")

DEFAULT_FEED_DIR = Path(__file__).resolve().parents[2] / "data" / "threat_intel_feeds"


@dataclass
class IntelMatch:
    """Result of a successful local threat-intel lookup."""
    matched: bool
    category: str = ""
    source_list: str = ""
    confidence: float = 0.0
    value: str = ""
    detail: str = ""
    source: str = "local_threat_intel_db"


# Maps each supported CSV filename to (category, key_column, description_column).
# key_column values may contain glob wildcards ('*') which are matched via fnmatch.
FEED_MANIFEST: Dict[str, Dict[str, str]] = {
    "ransomware_extensions_list.csv": {
        "category": "ransomware_extension",
        "key_column": "file_path",
        "desc_column": "metadata_comment",
        "confidence": "0.97",
    },
    "ransomware_notes_list.csv": {
        "category": "ransomware_note",
        "key_column": "file_name",
        "desc_column": "metadata_description",
        "confidence": "0.95",
    },
    "suspicious_ports_list.csv": {
        "category": "suspicious_port",
        "key_column": "dest_port",
        "desc_column": "metadata_comment",
        "confidence": "0.60",
        "confidence_column": "metadata_confidence",
    },
    "suspicious_mutex_names_list.csv": {
        "category": "suspicious_mutex",
        "key_column": "mutex",
        "desc_column": "metadata_threat",
        "confidence": "0.90",
    },
}

# Maps the free-text confidence labels used in some upstream feeds (e.g. suspicious ports)
# to a numeric confidence score.
_CONFIDENCE_LABELS = {
    "high": 0.85,
    "medium": 0.60,
    "low": 0.35,
    "info": 0.20,
}


class LocalThreatIntelDB:
    """SQLite-backed, in-memory index over locally-vendored threat-intel CSV feeds."""

    def __init__(self, feed_dir: Optional[Path] = None):
        self.feed_dir = Path(feed_dir) if feed_dir else DEFAULT_FEED_DIR
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._exact_categories = {"suspicious_port"}
        self._glob_rows: Dict[str, List[tuple]] = {}  # category -> [(pattern, desc, confidence, source_list)]
        self._loaded_counts: Dict[str, int] = {}

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS intel (
                    category TEXT NOT NULL,
                    key_normalized TEXT NOT NULL,
                    key_original TEXT NOT NULL,
                    description TEXT,
                    confidence REAL,
                    source_list TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_intel_category_key ON intel(category, key_normalized)"
            )
        return self._conn

    def load_all(self, feed_dir: Optional[Path] = None) -> Dict[str, int]:
        """Load (or reload) every recognized CSV feed in `feed_dir` into the index.

        Idempotent: calling this multiple times clears and re-populates the index rather
        than duplicating rows, so it is safe to call from a scheduled refresh job.
        """
        directory = Path(feed_dir) if feed_dir else self.feed_dir
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM intel")
            self._glob_rows.clear()
            self._loaded_counts.clear()

            if not directory.is_dir():
                logger.warning("Threat intel feed directory does not exist: %s", directory)
                return dict(self._loaded_counts)

            for filename, spec in FEED_MANIFEST.items():
                file_path = directory / filename
                if not file_path.is_file():
                    continue
                count = self._load_csv_file(conn, file_path, spec)
                self._loaded_counts[spec["category"]] = count

            conn.commit()
            return dict(self._loaded_counts)

    def _load_csv_file(self, conn: sqlite3.Connection, file_path: Path, spec: Dict[str, str]) -> int:
        category = spec["category"]
        key_column = spec["key_column"]
        desc_column = spec.get("desc_column", "")
        confidence_column = spec.get("confidence_column", "")
        default_confidence = float(spec.get("confidence", "0.5"))
        source_list = file_path.name
        count = 0

        is_glob_category = category not in self._exact_categories
        glob_rows: List[tuple] = []

        with open(file_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw_key = (row.get(key_column) or "").strip()
                if not raw_key:
                    continue
                description = (row.get(desc_column) or "").strip() if desc_column else ""
                confidence = default_confidence
                if confidence_column:
                    label = (row.get(confidence_column) or "").strip().lower()
                    confidence = _CONFIDENCE_LABELS.get(label, default_confidence)

                if is_glob_category:
                    # Store as-is (may contain '*' glob wildcards); matched via fnmatch later.
                    glob_rows.append((raw_key, description, confidence, source_list))
                else:
                    key_normalized = raw_key.strip().lower()
                    conn.execute(
                        "INSERT INTO intel (category, key_normalized, key_original, description, confidence, source_list) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (category, key_normalized, raw_key, description, confidence, source_list),
                    )
                count += 1

        if glob_rows:
            self._glob_rows.setdefault(category, []).extend(glob_rows)

        return count

    def _exact_lookup(self, category: str, key: str) -> Optional[IntelMatch]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT key_original, description, confidence, source_list FROM intel "
            "WHERE category = ? AND key_normalized = ? LIMIT 1",
            (category, str(key).strip().lower()),
        )
        row = cur.fetchone()
        if row is None:
            return None
        key_original, description, conf, source_list = row
        return IntelMatch(
            matched=True,
            category=category,
            source_list=source_list,
            confidence=conf,
            value=key_original,
            detail=description or "",
        )

    def _glob_lookup(self, category: str, value: str) -> Optional[IntelMatch]:
        candidates = self._glob_rows.get(category, [])
        value_lower = str(value).strip().lower()
        for pattern, description, confidence, source_list in candidates:
            if fnmatch.fnmatch(value_lower, pattern.strip().lower()):
                return IntelMatch(
                    matched=True,
                    category=category,
                    source_list=source_list,
                    confidence=confidence,
                    value=pattern,
                    detail=description or "",
                )
        return None

    def lookup_extension(self, filename_or_ext: str) -> Optional[IntelMatch]:
        """Check a filename or bare extension against known ransomware extensions."""
        value = filename_or_ext.strip()
        if not value:
            return None
        # Normalize a bare extension (e.g. "locky" or ".locky") to a glob-matchable suffix.
        candidate = value if value.startswith("*") else f"*.{value.lstrip('.')}" if "." not in value.lstrip("*") else value
        for probe in {value, candidate, f"*{value}" if not value.startswith("*") else value}:
            match = self._glob_lookup("ransomware_extension", probe)
            if match:
                return match
        return None

    def lookup_ransomware_note(self, filename: str) -> Optional[IntelMatch]:
        """Check a filename against known ransomware note filenames."""
        return self._glob_lookup("ransomware_note", filename)

    def lookup_port(self, port: int) -> Optional[IntelMatch]:
        """Check a destination port against known suspicious/malware-associated ports."""
        return self._exact_lookup("suspicious_port", str(int(port)))

    def lookup_mutex(self, mutex_name: str) -> Optional[IntelMatch]:
        """Check a mutex name against known malware/ransomware mutex names."""
        return self._glob_lookup("suspicious_mutex", mutex_name)

    def lookup_keyword(self, text: str, category: str) -> Optional[IntelMatch]:
        """Generic glob-pattern lookup for any loaded category by substring/glob match."""
        return self._glob_lookup(category, text)

    def stats(self) -> Dict[str, int]:
        """Return the number of rows loaded per category (for tests/observability)."""
        return dict(self._loaded_counts)


# Module-level singleton, mirroring the AlertDeduplicator/MaturityGate/EntityRiskTracker pattern.
local_threat_intel_db = LocalThreatIntelDB()
local_threat_intel_db.load_all()
