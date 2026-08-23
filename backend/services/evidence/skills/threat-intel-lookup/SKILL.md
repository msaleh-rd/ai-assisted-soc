---
name: threat-intel-lookup
phase: evidence
description: Queries external threat intelligence feeds (VirusTotal, AbuseIPDB, AlienVault OTX, CISA KEV) and internal IoC blacklists for reputation scores, malware family associations, and ASN/GeoIP data.
collects:
  - reputation_score
  - is_known_malicious
  - malware_family
  - threat_actor
  - abuse_confidence
  - asn_org
actions:
  - lookup_ip_reputation
  - lookup_hash_reputation
  - lookup_domain_reputation
method: handler
parameters:
  ioc_value:
    type: string
    description: IP address, domain, or cryptographic hash to check
  ioc_type:
    type: string
    description: Type of IOC (ip, domain, hash)
---

# Threat Intel Lookup Skill

## Purpose
Establishes whether an extracted IP, domain, or hash is known to threat researchers, associated with APT campaigns, ransomware syndicates (e.g. LockBit, DoNotCry, Conti), or botnet infrastructure.

## Outputs
- Malicious verdict (`is_known_malicious: true/false`)
- Threat intelligence confidence / abuse score (0.0 to 1.0)
- Associated threat actors and malware families
- Geolocation and Autonomous System Number (ASN)
