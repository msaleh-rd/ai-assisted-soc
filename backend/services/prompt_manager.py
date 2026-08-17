"""Prompt Manager — loads, versions, and formats YAML prompt templates."""

import os
import yaml
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("prompt-manager")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPTS_DIR = os.path.join(BASE_DIR, "prompts")

class PromptManager:
    """Manages prompt templates loaded from YAML files."""
    
    def __init__(self):
        self._prompts: Dict[str, Dict[str, Any]] = {}
        self._load_prompts()
        
    def _load_prompts(self):
        """Load all YAML prompts from the prompts directory."""
        if not os.path.isdir(PROMPTS_DIR):
            logger.warning(f"Prompts directory not found at {PROMPTS_DIR}")
            return
            
        for filename in os.listdir(PROMPTS_DIR):
            if not filename.endswith(".yaml") and not filename.endswith(".yml"):
                continue
                
            filepath = os.path.join(PROMPTS_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    prompt_data = yaml.safe_load(f)
                    
                name = prompt_data.get("name")
                if name:
                    # In a real system, you might store multiple versions.
                    # Here we just keep the latest loaded one for simplicity.
                    self._prompts[name] = prompt_data
            except Exception as e:
                logger.error(f"Failed to load prompt from {filepath}: {e}")
                
    def get_prompt_metadata(self, name: str) -> Dict[str, Any]:
        """Get the metadata for a prompt (e.g. version)."""
        prompt_data = self._prompts.get(name)
        if not prompt_data:
            return {"version": 0, "name": name}
        return {
            "version": prompt_data.get("version", 1),
            "name": name
        }

    def get_system_prompt(self, name: str) -> str:
        """Get the system prompt part."""
        prompt_data = self._prompts.get(name)
        if not prompt_data:
            raise ValueError(f"Prompt '{name}' not found.")
        return prompt_data.get("system_prompt", "").strip()

    def build_user_prompt(self, name: str, **kwargs) -> str:
        """Build the user prompt by formatting the template with kwargs."""
        prompt_data = self._prompts.get(name)
        if not prompt_data:
            raise ValueError(f"Prompt '{name}' not found.")
            
        template = prompt_data.get("user_template", "")
        
        try:
            # Simple format, allows missing keys to be left as-is if desired, 
            # but standard format requires all keys.
            return template.format(**kwargs)
        except KeyError as e:
            logger.error(f"Missing format variable {e} for prompt '{name}'")
            # Fallback string
            return f"{template}\n[Variables: {kwargs}]"

# Singleton instance
prompt_manager = PromptManager()
