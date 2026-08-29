"""Universal Skill Loader for the AI-Assisted SOC Platform.

Discovers, parses, validates, and manages pluggable SKILL.md catalogs across:
- Triage: backend/services/triage/skills/
- Evidence: backend/services/evidence/skills/
- Compression: backend/services/compression/skills/
- Discovery: backend/services/discovery/skills/
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml
import logging

logger = logging.getLogger("skill-loader")


@dataclass
class SOCSkill:
    """A modular SOC capability defined via a SKILL.md file."""
    name: str
    phase: str  # triage, evidence, compression, discovery
    description: str
    collects: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    method: str = "handler"  # handler, command, llm, statistical
    command_template: str = ""
    command_template_fallback: str = ""
    platform: Optional[str] = None  # win32, linux, or None (cross-platform)
    requires: Dict[str, Any] = field(default_factory=dict)
    body: str = ""  # Markdown body with execution/parsing instructions
    file_path: str = ""
    mitre_attack: List[str] = field(default_factory=list)
    mitre_f3: List[str] = field(default_factory=list)
    nist_csf: List[str] = field(default_factory=list)

    def matches_attributes(self, requested: List[str]) -> List[str]:
        """Return which requested attributes/actions this skill can collect or perform."""
        available = set(self.collects + self.actions)
        return [attr for attr in requested if attr in available]

    def matches_mitre(self, technique_id: str) -> bool:
        """Check if skill is mapped to a given MITRE ATT&CK technique."""
        return technique_id.upper() in [t.upper() for t in self.mitre_attack]

    def render_command(self, values: Dict[str, str], use_fallback: bool = False) -> str:
        """Render command template with placeholder values."""
        template = self.command_template_fallback if use_fallback else self.command_template
        if not template:
            return ""
        result = template
        for key, val in values.items():
            result = result.replace("{{" + key + "}}", str(val))
        return result


class UniversalSkillRegistry:
    """Discovers and caches SKILL.md definitions across all agent directories."""

    def __init__(self, base_services_dir: Optional[str] = None):
        if base_services_dir is None:
            base_services_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.base_services_dir = base_services_dir
        self.extra_skills_dirs: List[str] = []
        self._cache: Dict[str, List[SOCSkill]] = {}  # phase -> list of skills
        self._all_cache: Optional[List[SOCSkill]] = None

    def add_skills_directory(self, directory: str):
        """Add an external directory containing skills (e.g. from an imported library)."""
        if os.path.isdir(directory) and directory not in self.extra_skills_dirs:
            self.extra_skills_dirs.append(directory)
            self.clear_cache()

    def load_phase_skills(self, phase: str) -> List[SOCSkill]:
        """Load all skills for a specific phase (e.g. 'triage', 'evidence', 'compression', 'discovery')."""
        if phase in self._cache:
            return self._cache[phase]

        skills_dir = os.path.join(self.base_services_dir, phase, "skills")
        skills = self._load_from_dir(skills_dir, phase)
        self._cache[phase] = skills
        return skills

    def load_all_skills(self) -> List[SOCSkill]:
        """Load all skills across all phases and external directories."""
        if self._all_cache is not None:
            return self._all_cache

        all_skills = []
        for phase in ["triage", "evidence", "compression", "discovery"]:
            all_skills.extend(self.load_phase_skills(phase))

        for extra_dir in self.extra_skills_dirs:
            all_skills.extend(self._load_from_dir(extra_dir, "external"))

        self._all_cache = all_skills
        return all_skills

    def get_skill(self, name: str, phase: Optional[str] = None) -> Optional[SOCSkill]:
        """Look up a skill by name."""
        candidates = self.load_phase_skills(phase) if phase else self.load_all_skills()
        for skill in candidates:
            if skill.name == name:
                return skill
        return None

    def find_skills_for_actions(self, actions: List[str], phase: Optional[str] = None) -> List[SOCSkill]:
        """Find all skills matching a set of requested action or collection tags."""
        candidates = self.load_phase_skills(phase) if phase else self.load_all_skills()
        matches = []
        for skill in candidates:
            if skill.matches_attributes(actions):
                matches.append(skill)
        return matches

    def find_skills_for_mitre_technique(self, technique_id: str) -> List[SOCSkill]:
        """Find all skills mapped to a specific MITRE ATT&CK technique."""
        candidates = self.load_all_skills()
        return [skill for skill in candidates if skill.matches_mitre(technique_id)]

    def clear_cache(self):
        """Clear cached skills."""
        self._cache.clear()
        self._all_cache = None

    def _load_from_dir(self, skills_dir: str, default_phase: str) -> List[SOCSkill]:
        skills = []
        if not os.path.isdir(skills_dir):
            return skills

        for root, _, files in os.walk(skills_dir):
            if "SKILL.md" in files:
                skill_file = os.path.join(root, "SKILL.md")
                skill = self._parse_skill_file(skill_file, default_phase)
                if skill:
                    skills.append(skill)
        return skills

    def _parse_skill_file(self, path: str, default_phase: str) -> Optional[SOCSkill]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
        except (IOError, OSError) as e:
            logger.error(f"Failed to read skill file {path}: {e}")
            return None

        frontmatter_text, body = self._split_frontmatter(content)
        if not frontmatter_text:
            return None

        try:
            meta = yaml.safe_load(frontmatter_text) or {}
        except Exception as e:
            logger.error(f"YAML parsing error in {path}: {e}")
            return None

        name = meta.get("name")
        if not name:
            return None

        # Parse collects / actions
        collects = meta.get("collects", [])
        if isinstance(collects, str):
            collects = [collects]
        actions = meta.get("actions", [])
        if isinstance(actions, str):
            actions = [actions]

        # Parse frameworks
        mitre_attack = meta.get("mitre_attack", [])
        if isinstance(mitre_attack, str):
            mitre_attack = [mitre_attack]
        mitre_f3 = meta.get("mitre_f3", [])
        if isinstance(mitre_f3, str):
            mitre_f3 = [mitre_f3]
        nist_csf = meta.get("nist_csf", [])
        if isinstance(nist_csf, str):
            nist_csf = [nist_csf]

        return SOCSkill(
            name=str(name),
            phase=str(meta.get("phase", default_phase)),
            description=str(meta.get("description", "")),
            collects=collects,
            actions=actions,
            parameters=meta.get("parameters", {}),
            method=str(meta.get("method", "handler")),
            command_template=str(meta.get("commandTemplate", meta.get("command_template", ""))),
            command_template_fallback=str(meta.get("commandTemplateFallback", meta.get("command_template_fallback", ""))),
            platform=meta.get("platform"),
            requires=meta.get("requires", {}),
            body=body.strip(),
            file_path=path,
            mitre_attack=mitre_attack,
            mitre_f3=mitre_f3,
            nist_csf=nist_csf,
        )

    def _split_frontmatter(self, content: str) -> tuple:
        match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)$', content, re.DOTALL)
        if match:
            return match.group(1), match.group(2)
        return "", content


# Global registry singleton
skill_registry = UniversalSkillRegistry()
