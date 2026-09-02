"""YARA rule matching for static malware analysis (Phase B, Step 1).

Provides a small, dependency-isolated wrapper around `yara-python` so the
evidence pipeline can scan file bytes/paths against a curated starter ruleset
(`backend/data/yara_rules/*.yar`) — giving the Evidence phase a real
static-analysis capability for file/hash entities instead of relying purely
on LLM judgment (mirrors Phase A's "ground truth over LLM guesswork"
principle, applied to file content rather than metadata).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

logger = logging.getLogger("yara-scanner")

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "data" / "yara_rules"

try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when yara-python is absent
    yara = None  # type: ignore
    YARA_AVAILABLE = False
    logger.warning("yara-python is not installed; YaraScanner will report no matches.")


@dataclass
class YaraMatch:
    """A single rule match against scanned content."""
    rule_name: str
    category: str = ""
    severity: str = ""
    description: str = ""
    mitre_attack: str = ""
    matched_strings: List[str] = field(default_factory=list)


class YaraScanner:
    """Compiles and applies a directory of YARA rules to file bytes/paths."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self._compiled_rules = None
        self._loaded_rule_files: List[str] = []
        if YARA_AVAILABLE:
            self._compile_rules()

    def _compile_rules(self) -> None:
        if not self.rules_dir.is_dir():
            logger.warning("YARA rules directory does not exist: %s", self.rules_dir)
            return

        rule_files = sorted(self.rules_dir.glob("*.yar")) + sorted(self.rules_dir.glob("*.yara"))
        if not rule_files:
            logger.warning("No YARA rule files found in %s", self.rules_dir)
            return

        filepaths = {f"rule_{i}": str(path) for i, path in enumerate(rule_files)}
        try:
            self._compiled_rules = yara.compile(filepaths=filepaths)
            self._loaded_rule_files = [path.name for path in rule_files]
        except Exception as e:
            logger.error("Failed to compile YARA rules from %s: %s", self.rules_dir, e)
            self._compiled_rules = None

    @property
    def is_available(self) -> bool:
        """Whether YARA scanning is functional (library installed and rules compiled)."""
        return YARA_AVAILABLE and self._compiled_rules is not None

    def loaded_rule_files(self) -> List[str]:
        """Names of the rule files successfully compiled into this scanner."""
        return list(self._loaded_rule_files)

    def scan_file(self, path_or_bytes: Union[str, Path, bytes]) -> List[YaraMatch]:
        """Scan a file path or raw bytes against the compiled ruleset.

        Returns an empty list (never raises) if YARA is unavailable, the target
        file doesn't exist, or no rules match — callers should treat "no
        matches" as "static analysis found nothing suspicious", not as an error.
        """
        if not self.is_available:
            return []

        try:
            if isinstance(path_or_bytes, (str, Path)):
                file_path = Path(path_or_bytes)
                if not file_path.is_file():
                    return []
                raw_matches = self._compiled_rules.match(filepath=str(file_path))
            else:
                raw_matches = self._compiled_rules.match(data=path_or_bytes)
        except Exception as e:
            logger.error("YARA scan failed: %s", e)
            return []

        results: List[YaraMatch] = []
        for m in raw_matches:
            meta = m.meta or {}
            matched_strings = []
            try:
                for s in m.strings:
                    # yara-python string identifiers differ across versions
                    # (StringMatch object vs. legacy tuple); extract best-effort.
                    identifier = getattr(s, "identifier", None)
                    if identifier is None and isinstance(s, tuple) and len(s) >= 2:
                        identifier = s[1]
                    if identifier:
                        matched_strings.append(str(identifier))
            except Exception:
                pass

            results.append(YaraMatch(
                rule_name=m.rule,
                category=str(meta.get("category", "")),
                severity=str(meta.get("severity", "")),
                description=str(meta.get("description", "")),
                mitre_attack=str(meta.get("mitre_attack", "")),
                matched_strings=matched_strings,
            ))
        return results


# Module-level singleton, mirroring the LocalThreatIntelDB pattern.
yara_scanner = YaraScanner()
