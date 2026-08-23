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
parameters:
  user_id:
    type: string
    description: Username, email, or user principal ID
---

# Identity & Active Directory Lookup Skill

## Purpose
Enriches user entities with organizational context, determining if the compromised account has Domain Admin, Root, or sensitive cloud IAM roles, and whether impossible travel or abnormal login patterns occurred.

## Outputs
- User full name, email, department
- Administrative privileges flag (`privileged: true/false`)
- MFA enforcement status
- Recent login locations and failed attempt counts
