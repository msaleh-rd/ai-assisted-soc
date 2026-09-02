"""Detection-as-Code CI gate substitute (Wave 2 / Phase H, Step 4).

Replays every rule's fixtures under `backend/detections/` and fails (non-zero
exit code) if a rule doesn't match its positive fixtures or falsely matches
one of its negative fixtures. No CI workflow tooling exists yet in this repo
(confirmed during the implementation audit), so this script is designed to be
runnable standalone now and wired into a CI workflow step later, e.g.:

    python backend/scripts/validate_detections.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.services.detection_engine import DetectionRuleLoader  # noqa: E402


def main() -> int:
    rules = DetectionRuleLoader.load_all()
    if not rules:
        print("No detection rules found under backend/detections/.")
        return 1

    failures = []
    for rule in rules:
        fixtures = DetectionRuleLoader.load_fixtures(rule)
        for event in fixtures["positive"]:
            if not rule.evaluate(event):
                failures.append(f"[{rule.id}] positive fixture did NOT match: {event}")
        for event in fixtures["negative"]:
            if rule.evaluate(event):
                failures.append(f"[{rule.id}] negative fixture INCORRECTLY matched: {event}")

    print(f"Validated {len(rules)} detection rule(s).")
    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All detection rules passed fixture validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
