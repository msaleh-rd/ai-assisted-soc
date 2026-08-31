---
name: identity-ad-lookup
phase: evidence
description: Queries Active Directory, Okta, or IAM identity providers for user account status, administrative group memberships, MFA enrollment, password age, and anomalous login velocity.
collects:
  - user_profile
  - department
  - admin_privileges
  - mfa_status
  - group_memberships
  - login_history
actions:
  - query_user_identity
  - check_admin_privileges
method: handler
mitre_attack:
  - T1078
  - T1087
  - T1087.001
  - T1110
nist_csf:
  - PR.AC
  - DE.CM
parameters:
  user_id:
    type: string
    description: Username, email, or user principal ID
---

# Identity & Active Directory Lookup Skill

## Purpose
Enriches user entities with organizational context, determining if the compromised account has Domain Admin, Root, or sensitive cloud IAM roles, and whether impossible travel or abnormal login patterns occurred.

## Underlying Identity Queries
When querying Active Directory, Linux PAM, or IAM for user `{{user_id}}`:

```bash
# Linux user identity and group memberships
id {{user_id}}
grep "{{user_id}}" /etc/passwd /etc/group /etc/sudoers

# Windows Active Directory (PowerShell)
Get-ADUser -Identity "{{user_id}}" -Properties MemberOf, AccountExpirationDate, PasswordLastSet, LockedOut
Get-ADPrincipalGroupMembership -Identity "{{user_id}}" | Select-Object Name
```

## Outputs
- User full name, email, department
- Administrative privileges flag (`privileged: true/false`)
- MFA enforcement status
- Recent login locations and failed attempt counts
