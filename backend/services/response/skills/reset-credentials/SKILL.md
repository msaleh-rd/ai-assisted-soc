---
name: reset-credentials
description: Forces password resets, revokes Kerberos/OAuth tokens, and terminates active login sessions for compromised accounts.
version: 1.0.0
phase: response
inputs:
  - name: target_user
    type: string
    description: Username or User Principal Name (UPN) to reset
outputs:
  - name: action_status
    type: string
    description: Execution result status
  - name: sessions_revoked
    type: integer
    description: Number of active sessions terminated
mitre_attack:
  - T1078
  - T1110
nist_csf:
  - PR.AC
  - RS.MI
---

# Reset Credentials Response Skill

## Overview
Automates credential revocation and session invalidation across Active Directory and IAM identity providers when an identity compromise is confirmed.
