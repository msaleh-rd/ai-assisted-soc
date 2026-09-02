"""Prompt Registry lock-file verification.

Computes a content hash for every prompt YAML under backend/prompts/ and
compares it against backend/prompts/prompts.lock.json.

Usage:
    python backend/scripts/verify_prompt_lock.py            # verify (CI mode)
    python backend/scripts/verify_prompt_lock.py --write     # regenerate the lock file

Fails (non-zero exit) if any prompt's content changed but its `version` field
in the YAML front-matter was not bumped, or if a prompt is missing from the
lock file. This is the CI gate referenced in the AI-Assisted SOC roadmap
(Quick Win: Prompt Registry versioning, sourced from beenuar/AiSOC's
prompt-drift-prevention pattern).
"""

import hashlib
import json
import os
import sys
from typing import Any, Dict

import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS_DIR = os.path.join(BASE_DIR, "prompts")
LOCK_FILE = os.path.join(PROMPTS_DIR, "prompts.lock.json")


def _content_hash(prompt_data: Dict[str, Any]) -> str:
    """Stable content hash independent of key ordering."""
    canonical = json.dumps(prompt_data, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_prompts() -> Dict[str, Dict[str, Any]]:
    prompts: Dict[str, Dict[str, Any]] = {}
    if not os.path.isdir(PROMPTS_DIR):
        return prompts

    for filename in sorted(os.listdir(PROMPTS_DIR)):
        if not filename.endswith((".yaml", ".yml")):
            continue
        filepath = os.path.join(PROMPTS_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        name = data.get("name")
        if not name:
            continue
        prompts[name] = {
            "version": data.get("version", 1),
            "hash": _content_hash(data),
            "file": filename,
        }
    return prompts


def write_lock() -> Dict[str, Dict[str, Any]]:
    prompts = _load_prompts()
    with open(LOCK_FILE, "w", encoding="utf-8") as f:
        json.dump(prompts, f, indent=2, sort_keys=True)
        f.write("\n")
    return prompts


def verify_lock() -> bool:
    """Return True if the lock file is consistent with current prompts.

    Prints a human-readable diagnostic for every mismatch found.
    """
    current = _load_prompts()

    if not os.path.isfile(LOCK_FILE):
        print(f"ERROR: lock file not found at {LOCK_FILE}. Run with --write to generate it.")
        return False

    with open(LOCK_FILE, "r", encoding="utf-8") as f:
        locked = json.load(f)

    ok = True

    for name, current_entry in current.items():
        locked_entry = locked.get(name)
        if locked_entry is None:
            print(f"ERROR: prompt '{name}' is new but missing from prompts.lock.json.")
            ok = False
            continue

        hash_changed = current_entry["hash"] != locked_entry["hash"]
        version_changed = current_entry["version"] != locked_entry["version"]

        if hash_changed and not version_changed:
            print(
                f"ERROR: prompt '{name}' content changed but version was not bumped "
                f"(still v{current_entry['version']}). Bump the 'version' field in "
                f"{current_entry['file']} and re-run with --write."
            )
            ok = False

    for name in locked:
        if name not in current:
            print(f"WARNING: prompt '{name}' is in the lock file but no longer exists.")

    return ok


def main() -> int:
    if "--write" in sys.argv:
        prompts = write_lock()
        print(f"Wrote {len(prompts)} prompt(s) to {LOCK_FILE}")
        return 0

    if verify_lock():
        print("Prompt lock file is consistent.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
