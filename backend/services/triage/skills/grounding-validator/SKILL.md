---
name: grounding-validator
phase: triage
description: Performs rigorous hallucination detection by cross-referencing extracted entity IDs against raw source alert strings, discarding fabricated or ungrounded entities.
collects:
  - validated_entities
  - hallucination_rate
  - confidence_score
method: handler
parameters:
  extracted_entities:
    type: array
    description: List of entity objects extracted by the LLM
  raw_alert_text:
    type: string
    description: Complete stringified raw alert context
---

# Grounding Validator Skill

## Purpose
Ensures zero hallucinations in downstream investigation stages by mathematically checking that every entity ID (e.g. IP address, filename, username, hostname) literally exists within the raw incoming alert payload.

## Behavior
- Verifies entity IDs against case-insensitive substring search in `raw_alert_text`.
- Drops ungrounded entities.
- Penalizes triage confidence score if key entities fail grounding validation.
