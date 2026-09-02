"""Run a Compounding Memory distillation pass (Wave 3, Phase J).

Recomputes per-alert-signature false-positive rates and exemplar banks from
all resolved investigations (rows in the `investigations` table with a
non-null `verdict`), refreshing the in-memory prior cache used by
`get_memory_verdict_adjustment()` at Triage time.

Intentionally a simple, idempotent CLI script (matching the style of
`refresh_threat_intel.py`) rather than a long-running service or Temporal
scheduled workflow -- this codebase has no existing Temporal *scheduled*
workflow pattern to hook into (only the per-investigation
`InvestigationWorkflow`). Safe to run repeatedly, e.g. from a cron job or a
Temporal Schedule whenever one is introduced.

Usage:
    python -m backend.scripts.run_distillation
"""

import logging

from backend.services.memory.distillation import compounding_memory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run-distillation")


def main() -> None:
    report = compounding_memory.distill()
    if report.signatures_processed == 0:
        logger.warning("No resolved investigations with a verdict were found -- nothing distilled.")
        return
    for sig, prior in report.priors.items():
        logger.info(
            "Signature '%s': %d resolved case(s), false_positive_rate=%.2f, prior_confidence=%.2f",
            sig, prior.total_count, prior.false_positive_rate, prior.prior_confidence,
        )
    logger.info("Distillation complete: %d alert signature(s) processed.", report.signatures_processed)


if __name__ == "__main__":
    main()
