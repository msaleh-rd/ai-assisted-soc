"""Skill loader - parses SKILL.md files with YAML frontmatter."""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class Skill:
    """A discovery skill loaded from a SKILL.md file."""
    name: str
    description: str
    collects: List[str]
    method: str  # command, wmi, snmp, registry
    command_template: str = ""
    command_template_fallback: str = ""
    platform: Optional[str] = None  # win32, linux, or None (cross-platform)
    requires: Dict[str, Any] = field(default_factory=dict)
    body: str = ""  # Markdown body with parsing instructions
    file_path: str = ""

    def matches_attributes(self, requested: List[str]) -> List[str]:
        """Return which requested attributes this skill can collect."""
        return [attr for attr in requested if attr in self.collects]

    def render_command(self, values: Dict[str, str], use_fallback: bool = False) -> str:
        """Render command template with placeholder values."""
        template = self.command_template_fallback if use_fallback else self.command_template
        if not template:
            return ""
        result = template
        for key, val in values.items():
            result = result.replace("{{" + key + "}}", val)
        return result


class SkillLoader:
    """Loads skills from a directory of SKILL.md files."""

    def __init__(self, skills_dir: Optional[str] = None):
        if skills_dir is None:
            skills_dir = os.path.join(os.path.dirname(__file__), "skills")
        self.skills_dir = skills_dir
        self._cache: Optional[List[Skill]] = None

    def load_all(self) -> List[Skill]:
        """Load all skills from the skills directory."""
        if self._cache is not None:
            return self._cache

        skills = []
        if not os.path.isdir(self.skills_dir):
            return skills

        for entry in os.listdir(self.skills_dir):
            skill_dir = os.path.join(self.skills_dir, entry)
            skill_file = os.path.join(skill_dir, "SKILL.md")
            if os.path.isfile(skill_file):
                skill = self._parse_skill_file(skill_file)
                if skill:
                    skills.append(skill)

        self._cache = skills
        return skills

    def find_skills_for_attributes(self, attributes: List[str]) -> List[Skill]:
        """Find skills that can collect the requested attributes."""
        all_skills = self.load_all()
        matches = []
        for skill in all_skills:
            matched = skill.matches_attributes(attributes)
            if matched:
                matches.append(skill)
        return matches

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a skill by name."""
        for skill in self.load_all():
            if skill.name == name:
                return skill
        return None

    def _parse_skill_file(self, path: str) -> Optional[Skill]:
        """Parse a SKILL.md file into a Skill object."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
        except (IOError, OSError):
            return None

        # Split frontmatter from body
        frontmatter, body = self._split_frontmatter(content)
        if not frontmatter:
            return None

        # Parse YAML frontmatter
        meta = self._parse_yaml(frontmatter)
        if not meta.get('name'):
            return None

        collects = meta.get('collects', [])
        if isinstance(collects, str):
            collects = [collects]

        requires = meta.get('requires', {})
        if not isinstance(requires, dict):
            requires = {}

        return Skill(
            name=meta['name'],
            description=meta.get('description', ''),
            collects=collects,
            method=meta.get('method', 'command'),
            command_template=meta.get('commandTemplate', ''),
            command_template_fallback=meta.get('commandTemplateFallback', ''),
            platform=meta.get('platform'),
            requires=requires,
            body=body.strip(),
            file_path=path,
        )

    @staticmethod
    def _split_frontmatter(content: str):
        """Split YAML frontmatter from markdown body."""
        match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)', content, re.DOTALL)
        if match:
            return match.group(1), match.group(2)
        return None, content

    @staticmethod
    def _parse_yaml(text: str) -> Dict[str, Any]:
        """Minimal YAML parser for skill frontmatter."""
        result: Dict[str, Any] = {}
        current_key = ""
        current_list: Optional[List[str]] = None
        nested_obj: Optional[Dict[str, Any]] = None

        for line in text.split('\n'):
            stripped = line.rstrip()

            # Continue collecting list items
            if current_list is not None:
                list_match = re.match(r'^\s+-\s+(.+)$', stripped)
                if list_match:
                    current_list.append(list_match.group(1).strip())
                    continue
                else:
                    result[current_key] = current_list
                    current_list = None

            # Continue collecting nested object
            if nested_obj is not None:
                nested_match = re.match(r'^\s{2,}(\w+):\s*(.*)$', stripped)
                if nested_match:
                    key = nested_match.group(1)
                    val = nested_match.group(2).strip()
                    if not val:
                        # Nested list
                        nested_obj[key] = []
                        current_key = key
                        current_list = nested_obj[key]
                    else:
                        nested_obj[key] = val
                    continue
                else:
                    result[current_key] = nested_obj
                    nested_obj = None

            # Top-level key: value
            kv_match = re.match(r'^(\w[\w-]*):\s*(.*)$', stripped)
            if not kv_match:
                continue

            key = kv_match.group(1)
            value = kv_match.group(2).strip()

            if not value:
                # Could be a list or nested object - peek at next lines
                current_key = key
                # Check if next line is a list item
                idx = text.split('\n').index(line)
                remaining = text.split('\n')[idx + 1:]
                if remaining:
                    next_line = remaining[0]
                    if re.match(r'^\s+-\s', next_line):
                        current_list = []
                    elif re.match(r'^\s{2,}\w', next_line):
                        nested_obj = {}
                    else:
                        result[key] = ""
                else:
                    result[key] = ""
            else:
                result[key] = value

        # Flush any remaining state
        if current_list is not None:
            result[current_key] = current_list
        if nested_obj is not None:
            result[current_key] = nested_obj

        return result
