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

## Containment Commands
When executed for user `{{target_user}}`, this skill models identity remediation:

```bash
# Linux PAM / shadow lock
usermod -L {{target_user}}
pkill -u {{target_user}}

# Windows Active Directory (PowerShell)
Disable-ADAccount -Identity "{{target_user}}"
Revoke-AzureADUserAllRefreshToken -ObjectId "{{target_user}}"
```

## Rollback Commands
To re-enable the user account:

```bash
# Linux PAM unlock
usermod -U {{target_user}}

# Windows Active Directory (PowerShell)
Enable-ADAccount -Identity "{{target_user}}"
```
