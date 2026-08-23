---
name: duplicate-rollup
phase: compression
description: Deduplicates high-frequency repetitive logs (e.g. 500 file modifications, continuous port scans, repeated failed auth bursts) into consolidated rollup events with occurrence counters.
collects:
  - deduplicated_events
  - raw_count
  - compressed_count
  - compression_ratio
actions:
  - rollup_duplicate_bursts
  - calculate_compression_ratio
method: statistical
parameters:
  similarity_threshold:
    type: float
    default: 0.90
    description: Threshold for collapsing similar log lines
---

# Duplicate Rollup Skill

## Purpose
Prevents flood conditions where hundreds or thousands of identical or near-identical logs overwhelm downstream root-cause analysis, collapsing them into single entries with `occurrence_count` and start/end time boundaries.

## Outputs
- Deduplicated event list
- Total reduction metric (e.g. `raw_events: 120, compressed_events: 8, compression_ratio: 15.0x`)
- Aggregated occurrence metadata
