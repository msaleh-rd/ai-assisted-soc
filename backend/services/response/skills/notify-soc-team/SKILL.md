---
name: notify-soc-team
description: Sends an informational notification to the SOC team (via chat/email/paging integration) about an investigation or response action, without changing any system state.
version: 1.0.0
phase: response
method: handler
actions:
  - notify_soc_team
parameters:
  message:
    type: string
    description: Notification message to deliver to the SOC team
  channel:
    type: string
    description: Optional delivery channel (e.g. slack, email, pagerduty)
mitre_attack: []
nist_csf:
  - RS.CO
---

# Notify SOC Team Response Skill

## Overview
Delivers an informational alert to the SOC team about an ongoing investigation, escalation, or completed response action. This skill performs no system state changes and has minimal blast radius, so it is safe to auto-execute at any automation tier.

## Notification Commands
When executed, this skill models delivery of `{{message}}` to `{{channel}}`:

```bash
# Slack webhook notification
curl -X POST -H 'Content-type: application/json' \
  --data '{"text": "{{message}}"}' \
  "$SOC_SLACK_WEBHOOK_URL"

# Email notification
echo "{{message}}" | mail -s "SOC Alert Notification" soc-team@example.com
```

## Rollback Commands
Notifications are informational only and cannot be rolled back; no action is required.
