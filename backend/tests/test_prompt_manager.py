"""Tests for the Prompt Registry: few-shot injection and version-lock verification.

Quick Win (Wave 0) from the AI-Assisted SOC implementation plan — sourced from
implementation_plan1.md idea #10 (pattern from beenuar/AiSOC's prompt-drift
prevention). Confirms:
  1. PromptManager.build_user_prompt() actually injects few_shot_examples
     from the YAML prompts into the rendered prompt string.
  2. backend/scripts/verify_prompt_lock.py detects prompt drift (content
     changed without a version bump) and passes when the lock file matches.
"""

import importlib
import json
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR.parent))
sys.path.insert(0, str(BACKEND_DIR / "scripts"))

from backend.services.prompt_manager import PromptManager


@pytest.fixture()
def manager() -> PromptManager:
    return PromptManager()


def test_few_shot_examples_are_injected_into_rendered_prompt(manager: PromptManager):
    """triage_v1.yaml ships few_shot_examples; the rendered prompt must contain them."""
    rendered = manager.build_user_prompt(
        "triage",
        alert_json='{"alert_name": "test", "severity": "high"}',
    )
    assert "EXAMPLES" in rendered
    assert "Example 1:" in rendered


@pytest.mark.parametrize("prompt_name", ["triage", "rca", "response"])
def test_all_core_prompts_have_few_shot_examples(manager: PromptManager, prompt_name: str):
    """RCA and Response prompts must also carry few-shot examples (not just Triage)."""
    prompt_data = manager._prompts.get(prompt_name)
    assert prompt_data is not None, f"prompt '{prompt_name}' failed to load"
    examples = prompt_data.get("few_shot_examples", [])
    assert len(examples) >= 1, f"prompt '{prompt_name}' has no few_shot_examples"


def test_prompt_metadata_reports_version(manager: PromptManager):
    meta = manager.get_prompt_metadata("triage")
    assert meta["version"] >= 1
    assert meta["name"] == "triage"


def test_missing_prompt_raises_value_error(manager: PromptManager):
    with pytest.raises(ValueError):
        manager.get_system_prompt("does-not-exist")


# --- Prompt lock file verification ---

def _reload_lock_module():
    import verify_prompt_lock  # type: ignore
    importlib.reload(verify_prompt_lock)
    return verify_prompt_lock


def test_lock_file_is_currently_consistent():
    """The committed prompts.lock.json must match the current prompt content.

    This is the CI gate: if this fails, someone edited a prompt YAML without
    running `verify_prompt_lock.py --write` and bumping its version.
    """
    mod = _reload_lock_module()
    assert mod.verify_lock() is True


def test_lock_verification_fails_on_undetected_drift(tmp_path, monkeypatch):
    """Simulate editing a prompt's content without bumping its version."""
    mod = _reload_lock_module()

    fake_prompts_dir = tmp_path / "prompts"
    fake_prompts_dir.mkdir()
    (fake_prompts_dir / "demo_v1.yaml").write_text(
        "name: demo\nversion: 1\nsystem_prompt: |\n  original content\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(mod, "PROMPTS_DIR", str(fake_prompts_dir))
    monkeypatch.setattr(mod, "LOCK_FILE", str(fake_prompts_dir / "prompts.lock.json"))

    mod.write_lock()
    assert mod.verify_lock() is True

    # Drift: content changes, version does not.
    (fake_prompts_dir / "demo_v1.yaml").write_text(
        "name: demo\nversion: 1\nsystem_prompt: |\n  MUTATED content\n",
        encoding="utf-8",
    )
    assert mod.verify_lock() is False

    # Bumping the version alongside the content change should pass again.
    (fake_prompts_dir / "demo_v1.yaml").write_text(
        "name: demo\nversion: 2\nsystem_prompt: |\n  MUTATED content\n",
        encoding="utf-8",
    )
    mod.write_lock()
    assert mod.verify_lock() is True


def test_lock_verification_fails_when_lock_file_missing(tmp_path, monkeypatch):
    mod = _reload_lock_module()
    empty_dir = tmp_path / "empty_prompts"
    empty_dir.mkdir()
    monkeypatch.setattr(mod, "PROMPTS_DIR", str(empty_dir))
    monkeypatch.setattr(mod, "LOCK_FILE", str(empty_dir / "prompts.lock.json"))
    assert mod.verify_lock() is False
