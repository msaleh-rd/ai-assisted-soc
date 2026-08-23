---
name: behavioral-anomaly-filter
phase: compression
description: Evaluates numerical and categorical event features with an Isolation Forest model to filter out baseline benign activity and isolate anomalous security deviations.
collects:
  - anomaly_scores
  - isolated_outliers
  - baseline_noise_filtered
actions:
  - score_anomalies
  - filter_benign_noise
method: statistical
parameters:
  contamination:
    type: float
    default: 0.05
    description: Expected proportion of outliers in the event stream
---

# Behavioral Anomaly Filter Skill

## Purpose
Separates high-risk anomalous behavior (e.g. sudden spike in outbound SSH sessions, abnormal encryption writes, unusual off-hours administrative commands) from standard enterprise operational noise using unsupervised machine learning.

## Outputs
- Anomaly scores per event (-1.0 to +1.0)
- Filtered subset of high-confidence anomalous events
- Quantified signal-to-noise ratio improvement
