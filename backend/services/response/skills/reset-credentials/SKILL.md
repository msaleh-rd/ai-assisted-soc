---
name: reset-credentials
description: Forces password resets, revokes Kerberos/OAuth tokens, and terminates active login sessions for compromised accounts.
version: 1.0.0
phase: response
method: handler
actions:
  - reset_user_password
  - revoke_user_sessions
parameters:
  target_user:
    type: string
    description: Username or User Principal Name (UPN) to reset
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
