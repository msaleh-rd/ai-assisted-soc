# AI-Native SOC Platform Architecture
## Intelligent Investigation Orchestration for Large-Scale Security Incidents

**Version:** 1.0  
**Date:** 2026-08-10  
**Scope:** Complete SOC automation platform with focus on evidence collection, correlation-based compression, and RCA optimization

---

## Executive Summary

This architecture solves the fundamental SOC challenge: **How to handle millions of security events while maintaining investigation accuracy and reducing costs?**

The solution uses a **progressive investigation pipeline** that:
1. **Ingests** alerts from multiple sources
2. **Autonomously collects** contextual evidence via intelligent entity expansion
3. **Dramatically compresses** events through correlation, deduplication, and behavioral filtering
4. **Packages** only relevant evidence for RCA engines
5. **Validates** findings through feedback loops and remediation verification

**Key Innovation**: The Correlation & Compression Layer reduces millions of raw telemetry events to **hundreds of contextually-relevant events** before reaching the RCA engine, reducing costs by 10-100x while improving accuracy through signal concentration.

---

## Part 1: High-Level Architecture Overview

### 1.1 End-to-End Data Flow (ASCII Diagram)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY ALERT SOURCES                              │
├─────────────┬──────────────┬──────────────┬─────────────┬──────────────────┤
│   SIEM      │     XDR      │     EDR      │     IAM     │  Cloud Security  │
│ (Splunk)    │  (Cortex XDR)│ (CrowdStrike)│   (Okta)    │  (Azure Sentinel)│
└──────┬──────┴──────┬───────┴──────┬───────┴─────┬───────┴────────┬─────────┘
       │             │              │             │                │
       └─────────────┴──────────────┴─────────────┴────────────────┘
                            ▼
            ┌────────────────────────────────────┐
            │   1. ALERT INTAKE & NORMALIZATION   │
            │  ├─ Multi-source connector          │
            │  ├─ Schema normalization            │
            │  ├─ Alert deduplication             │
            │  └─ Initial entity extraction       │
            └────────────────┬───────────────────┘
                            ▼
            ┌────────────────────────────────────┐
            │  2. AUTONOMOUS EVIDENCE COLLECTION  │
            │  ├─ Entity expansion graph         │
            │  ├─ Telemetry connector pool       │
            │  ├─ Parallel data collection       │
            │  ├─ Rich context aggregation       │
            │  └─ Threat intel enrichment        │
            └────────────────┬───────────────────┘
                            ▼
            ┌────────────────────────────────────┐
            │ 3. CORRELATION & COMPRESSION LAYER  │
            │  ├─ Entity-centric correlation     │
            │  ├─ Temporal filtering              │
            │  ├─ Behavioral baseline filtering   │
            │  ├─ Graph-based analysis           │
            │  ├─ Risk scoring                   │
            │  ├─ Event deduplication            │
            │  ├─ Abstraction & aggregation      │
            │  └─ Attack path reconstruction     │
            └────────────────┬───────────────────┘
                            ▼
            ┌────────────────────────────────────┐
            │  4. INVESTIGATION PACKAGE BUILDER    │
            │  ├─ Event selection & ranking      │
            │  ├─ Entity relationship extraction │
            │  ├─ Timeline construction          │
            │  ├─ Attack graph generation        │
            │  ├─ Confidence scoring             │
            │  └─ Context summarization          │
            └────────────────┬───────────────────┘
                            ▼
            ┌────────────────────────────────────┐
            │  5. RCA ENGINE (Lightweight Input)  │
            │  ├─ Attack path analysis           │
            │  ├─ Root cause determination       │
            │  ├─ Impact assessment              │
            │  ├─ Confidence scoring             │
            │  └─ Recommendation generation      │
            └────────────────┬───────────────────┘
                    ┌────────┴────────┐
                    │                 │
              ▼ (High confidence)  ▼ (Low confidence)
        ┌──────────────┐       ┌──────────────────────┐
        │ PROCEED TO   │       │ ADAPTIVE LOOP:       │
        │ INCIDENT     │       │ ├─ Request more data │
        │ GENERATION   │       │ ├─ Refine queries    │
        │              │       │ ├─ Expand scope      │
        │ ├─ Technical │       │ └─ Re-correlate      │
        │ ├─ Executive │       └────────┬─────────────┘
        │ ├─ Compliance│              │
        │ └─ MITRE Map │              │
        └──────┬───────┘              │
               │ ◄─────────────────────┘
               ▼
        ┌────────────────────────────────────┐
        │  6. RESPONSE ORCHESTRATION          │
        │  ├─ Human approval workflow        │
        │  ├─ Automated containment         │
        │  ├─ Remediation playbooks         │
        │  └─ Action execution              │
        └────────────────┬───────────────────┘
                        ▼
        ┌────────────────────────────────────┐
        │  7. RECOVERY & VALIDATION           │
        │  ├─ Remediation verification       │
        │  ├─ Threat eradication confirmation│
        │  ├─ Exposure reduction measurement │
        │  └─ Closure confirmation           │
        └────────────────┬───────────────────┘
                        ▼
        ┌────────────────────────────────────┐
        │  8. CONTINUOUS LEARNING            │
        │  ├─ Rule improvement               │
        │  ├─ Playbook generation            │
        │  ├─ Telemetry gap identification   │
        │  └─ Automatic recommendations      │
        └────────────────────────────────────┘
```

### 1.2 Logical Component Architecture

```
                    ┌─────────────────────────────────────┐
                    │   ORCHESTRATION & STATE MANAGEMENT   │
                    │   (Temporal Durable Workflows)       │
                    └──────────────────┬──────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐
│  CONNECTOR LAYER   │  │  CORRELATION LAYER   │  │  KNOWLEDGE LAYER    │
├────────────────────┤  ├──────────────────────┤  ├─────────────────────┤
│ • Alert Intake     │  │ • Entity Correlator  │  │ • Security Graph    │
│ • SIEM Connectors  │  │ • Temporal Analyzer  │  │ • TTPs Database     │
│ • EDR Connectors   │  │ • Behavioral Filter  │  │ • Threat Intel      │
│ • Cloud Connectors │  │ • Graph Analyzer     │  │ • MITRE ATT&CK Map  │
│ • IAM Connectors   │  │ • Risk Scorer        │  │ • Playbook Library  │
│ • Threat Intel API │  │ • Event Compressor   │  │ • Baselines         │
│                    │  │ • Abstraction Eng.   │  │                     │
└────────────────────┘  └──────────────────────┘  └─────────────────────┘
        │                       │                          │
        └───────────┬───────────┴──────────────┬───────────┘
                    │                         │
                    ▼                         ▼
            ┌────────────────────┐  ┌──────────────────────┐
            │  DATA INTEGRATION   │  │  EVIDENCE PACKAGING  │
            │  & STORAGE LAYER    │  │  & RCA ORCHESTRATION │
            ├────────────────────┤  ├──────────────────────┤
            │ • Data Lake         │  │ • Package Builder    │
            │ • Event Store       │  │ • RCA Orchestrator   │
            │ • Graph Store       │  │ • Confidence Scorer  │
            │ • Cache Layer       │  │ • Adaptive Loop Mgr  │
            │ • Schema Registry   │  │ • Report Generator   │
            └────────────────────┘  └──────────────────────┘
```

### 1.3 Agent-Based Decomposition (Microservice Agents)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      INVESTIGATION ORCHESTRATOR                      │
│        (Temporal Workflow coordinating durable sub-agent tasks)      │
└────────────────────────┬────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┬─────────────────┐
        │                │                │                 │
        ▼                ▼                ▼                 ▼
   ┌────────────┐  ┌─────────────┐  ┌──────────────┐  ┌───────────┐
   │   Alert    │  │ Evidence    │  │ Correlation  │  │    RCA    │
   │  Intake    │  │ Collection  │  │  & Compress  │  │ Orchestr. │
   │  Activity  │  │  Activity   │  │   Activity   │  │ Activity  │
   └────────────┘  └─────────────┘  └──────────────┘  └───────────┘
        │                │                │                │
        │                ▼                │                │
        │          ┌──────────────────────┼────────────┐   │
        │          │  Entity Expansion    │            │   │
        │          │  Sub-agents:         │            │   │
        │          │  • Identity Service  │            │   │
        │          │  • Host Service      │            │   │
        │          │  • Network Service   │            │   │
        │          │  • Cloud Service     │            │   │
        │          │  • Process Service   │            │   │
        │          │  • Application Srv.  │            │   │
        │          │  • Email Service     │            │   │
        │          └─────────────────────┘            │   │
        │                │                            │   │
        └────────┬───────┴────────────┬───────────────┴───┘
                 │                    │
                 ▼                    ▼
        ┌──────────────────┐  ┌────────────────────┐
        │  Remediation     │  │   Report           │
        │  Orchestration   │  │   Generation       │
        │  Agent           │  │   Agent            │
        └──────────────────┘  └────────────────────┘
```

---

## Part 2: Core Components - Detailed Design

### 2.1 Alert Intake & Normalization Layer

**Purpose**: Accept alerts from diverse sources and normalize into a unified schema.

**Component Architecture**:

```yaml
AlertIntakeAgent:
  inbound_connectors:
    - siem_connector (Splunk, ELK, Datadog)
    - xdr_connector (Cortex XDR, Microsoft Defender, SentinelOne)
    - edr_connector (CrowdStrike, Falcon, Carbon Black)
    - cloud_connector (Azure Sentinel, AWS GuardDuty, GCP)
    - iam_connector (Okta, Azure AD, Ping)
    - email_security_connector (Proofpoint, Mimecast)
    - webhook_receiver (Generic HTTP/AMQP)
  
  normalization_engine:
    input: RawAlert (vendor-specific format)
    output: NormalizedAlert (unified schema)
    steps:
      1. Parse alert payload
      2. Extract primary entities
      3. Normalize timestamps (ISO 8601)
      4. Map alert categories to standard taxonomy
      5. Assign alert ID and correlation ID
      6. Deduplicate within time window (5-30 min)
  
  alert_deduplication:
    strategy: Rolling window + hash-based
    time_window: 5-30 minutes (configurable)
    hash_fields: [source, alert_name, primary_entity, severity]
    
  primary_entity_extraction:
    entities:
      - user (samAccountName, email, UID)
      - host (hostname, IP, MAC, serial)
      - process (path, hash, command_line, PID)
      - ip_address (IPv4, IPv6)
      - domain (fqdn, registrar)
      - file_hash (MD5, SHA1, SHA256)
      - cloud_resource (ARN, subscription_id, instance_id)
      - email_address
      - url
```

**Normalized Alert Schema**:

```json
{
  "alert_id": "uuid",
  "correlation_id": "uuid",
  "timestamp_generated": "2026-08-10T14:32:00Z",
  "timestamp_received": "2026-08-10T14:32:15Z",
  "source_system": "siem|xdr|edr|cloud|iam|email",
  "source_name": "CrowdStrike",
  "alert_name": "string",
  "alert_description": "string",
  "alert_category": "execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|exfiltration|command_and_control|impact",
  "severity": "critical|high|medium|low|informational",
  "confidence": 0.0-1.0,
  "status": "new|ongoing|resolved",
  
  "primary_entities": {
    "user": {
      "id": "string",
      "name": "string",
      "domain": "string",
      "email": "string"
    },
    "host": {
      "id": "string",
      "hostname": "string",
      "ip_addresses": ["string"],
      "mac_address": "string",
      "operating_system": "string"
    },
    "process": {
      "id": "string",
      "path": "string",
      "name": "string",
      "command_line": "string",
      "hash_md5": "string",
      "hash_sha256": "string"
    },
    "ip_address": "string",
    "domain": "string",
    "file_hash": "string",
    "cloud_resource": {
      "resource_id": "string",
      "resource_type": "string",
      "account_id": "string"
    },
    "email_address": "string",
    "url": "string"
  },
  
  "raw_alert": {},
  "alert_metadata": {
    "rule_id": "string",
    "rule_version": "string",
    "mitre_tactics": ["string"],
    "mitre_techniques": ["string"]
  }
}
```

**Deduplication Algorithm**:

```python
def deduplicate_alert(new_alert, recent_alerts_window):
    """
    Prevents duplicate alerts within a time window.
    Cost: O(1) lookup via hash map.
    """
    hash_key = hash([
        new_alert.source_name,
        new_alert.alert_name,
        new_alert.primary_entities.user.id,
        new_alert.primary_entities.host.id
    ])
    
    if hash_key in recent_alerts_window:
        existing_alert = recent_alerts_window[hash_key]
        # Update severity to max if new alert is higher
        existing_alert.severity = max(existing_alert.severity, new_alert.severity)
        existing_alert.occurrence_count += 1
        existing_alert.last_occurrence = new_alert.timestamp_generated
        return existing_alert  # Don't create new alert
    else:
        new_alert.occurrence_count = 1
        recent_alerts_window[hash_key] = new_alert
        return new_alert
```

---

### 2.2 Autonomous Evidence Collection Agent

**Purpose**: Starting from alert entities, automatically collect contextual telemetry and expand investigation scope.

**Architecture**:

```yaml
EvidenceCollectionAgent:
  input: NormalizedAlert with primary entities
  output: EnrichedContext with related telemetry
  
  entity_expansion_strategies:
    
    user_expansion:
      collect:
        - Identity profile (AD/LDAP/Okta)
        - Group memberships
        - Recent role changes
        - Account age, last_login
        - Failed login attempts (24-72h)
        - Successful login attempts (24-72h)
        - VPN/proxy access logs
        - Email forwarding rules
        - Recent password changes
        - Access reviews/certifications
        - Account risk scores from IdP
      parallelism: true
      timeout: 30s
    
    host_expansion:
      collect:
        - System profile (OS, domain, network config)
        - Installed software inventory
        - Last system updates
        - Running processes (process tree)
        - Services (enabled, disabled, recent changes)
        - Scheduled tasks
        - Windows Event Logs (Security, System, Application)
        - Syslog (Linux)
        - Network connections (netstat/ss equivalent)
        - DNS queries
        - File system activity (recent modifications)
        - Antivirus/EDR telemetry
        - Firewall logs (host-based)
        - Authentication logs
      parallelism: true
      timeout: 30s
    
    process_expansion:
      collect:
        - Parent/child process chain
        - Process command line (full)
        - File handles opened by process
        - Network connections from process
        - Registry modifications (Windows)
        - Memory analysis data
        - Module/DLL loads
        - Code signing information
        - Permissions/capabilities
        - Creation timestamp
        - Termination status
        - CPU/memory usage
      parallelism: true
      timeout: 30s
    
    ip_address_expansion:
      collect:
        - Reverse DNS lookup
        - Geolocation
        - ASN information
        - Threat intelligence (malicious, proxy, VPN)
        - Attack path (internal/external)
        - Historical connections (7-30 days)
        - Port scan results
        - SSL certificates
        - Associated domains
        - Passive DNS records
      parallelism: true
      timeout: 30s
    
    domain_expansion:
      collect:
        - WHOIS registration data
        - Name server configuration
        - MX records (email infrastructure)
        - SPF/DKIM/DMARC records
        - Threat intelligence (malicious, phishing)
        - Subdomain enumeration
        - Certificate history
        - Historical IP associations
        - Passive DNS records (30-90 days)
        - Alexa/Majestic ranking
      parallelism: true
      timeout: 30s
    
    file_hash_expansion:
      collect:
        - VirusTotal results
        - Any.run sandbox report
        - Hybrid Analysis
        - YARA rule matches
        - First submission time
        - File prevalence (how common)
        - Known malware family
        - MITRE ATT&CK techniques
        - Sigma rule matches
      parallelism: true
      timeout: 30s
    
    cloud_resource_expansion:
      collect:
        - Resource metadata
        - IAM policies and role assignments
        - Recent configuration changes
        - Access logs (last 7 days)
        - Network security group rules
        - Tags and labels
        - Associated identities
        - Data access patterns
        - Encryption status
        - Compliance violations
      parallelism: true
      timeout: 30s
    
  collection_coordination:
    parallel_requests: true
    circuit_breaker: true (fail fast if datasource unavailable)
    deduplication: true
    enrichment_caching: true (4-hour TTL)
    priority: ["user", "host", "process", "network"] (investigate most relevant first)

  concurrent_collection_strategy:
    max_concurrent_requests: 50
    request_pooling: true
    rate_limiting: adaptive (backoff if source throttles)
    
  threat_intelligence_enrichment:
    sources:
      - VirusTotal API
      - abuse.ch (URLhaus, MalwareBazaar)
      - OTX (AlienVault)
      - Team Cymru whois
      - MaxMind GeoIP
      - Custom threat feeds
    caching: 30-day TTL
    batch_lookup: true (reduces API calls)
```

**Evidence Collection Data Model**:

```json
{
  "enriched_context": {
    "alert_id": "uuid",
    "collection_timestamp": "2026-08-10T14:32:30Z",
    
    "user_context": {
      "profile": {
        "uid": "string",
        "name": "string",
        "department": "string",
        "manager": "string",
        "title": "string",
        "account_age_days": 0,
        "last_login": "timestamp",
        "account_status": "active|disabled|locked",
        "password_age_days": 0,
        "mfa_enabled": true,
        "privileged_groups": ["string"]
      },
      "recent_activity": {
        "login_attempts_24h": [
          {
            "timestamp": "timestamp",
            "status": "success|failure",
            "source_ip": "string",
            "location": "string",
            "device": "string"
          }
        ],
        "email_forwards": ["string"],
        "recent_role_changes": ["string"],
        "access_reviews": [
          {
            "resource": "string",
            "status": "approved|denied|pending",
            "timestamp": "timestamp"
          }
        ]
      },
      "risk_indicators": {
        "failed_login_count_24h": 0,
        "impossible_travel": true,
        "unusual_time_login": true,
        "risky_location": true,
        "idp_risk_score": 0.0
      }
    },
    
    "host_context": {
      "profile": {
        "hostname": "string",
        "ip_addresses": ["string"],
        "mac_address": "string",
        "os": "string",
        "os_version": "string",
        "domain": "string",
        "dns_servers": ["string"],
        "time_sync_status": "synced|unsynced",
        "last_boot": "timestamp"
      },
      "security_posture": {
        "antivirus_enabled": true,
        "antivirus_version": "string",
        "antivirus_definitions_age_hours": 0,
        "firewall_enabled": true,
        "edr_enabled": true,
        "edr_agent_version": "string",
        "patches_missing": 0,
        "critical_patches_missing": 0,
        "last_scan_date": "timestamp"
      },
      "recent_activity": {
        "process_tree": [
          {
            "pid": 0,
            "name": "string",
            "path": "string",
            "command_line": "string",
            "hash_sha256": "string",
            "children": [{"$ref": "#"}],
            "created": "timestamp",
            "terminated": "timestamp"
          }
        ],
        "network_connections": [
          {
            "timestamp": "timestamp",
            "local_ip": "string",
            "local_port": 0,
            "remote_ip": "string",
            "remote_port": 0,
            "protocol": "tcp|udp",
            "process": "string",
            "connection_state": "established|listening"
          }
        ],
        "dns_queries": [
          {
            "timestamp": "timestamp",
            "domain": "string",
            "query_type": "A|AAAA|CNAME|MX|TXT",
            "response": ["string"],
            "process": "string"
          }
        ],
        "file_modifications": [
          {
            "timestamp": "timestamp",
            "path": "string",
            "action": "created|modified|deleted",
            "hash_before": "string",
            "hash_after": "string",
            "size_bytes": 0
          }
        ]
      }
    },
    
    "network_context": {
      "flows_24h": [
        {
          "timestamp": "timestamp",
          "source_ip": "string",
          "destination_ip": "string",
          "destination_port": 0,
          "protocol": "tcp|udp",
          "bytes_sent": 0,
          "bytes_received": 0,
          "packets": 0,
          "duration_seconds": 0,
          "direction": "internal|egress|ingress"
        }
      ],
      "dns_resolutions_72h": [
        {
          "timestamp": "timestamp",
          "domain": "string",
          "resolved_ips": ["string"],
          "query_source": "string"
        }
      ],
      "threat_indicators": {
        "suspicious_ports": [0],
        "known_malicious_ips": ["string"],
        "beaconing_detected": true,
        "data_exfiltration_indicators": true,
        "command_control_indicators": true
      }
    },
    
    "threat_intelligence": {
      "enrichment_timestamp": "timestamp",
      "indicators": [
        {
          "indicator": "string",
          "type": "ip|domain|hash|email",
          "verdict": "malicious|suspicious|clean",
          "sources": ["string"],
          "confidence": 0.0,
          "malware_families": ["string"],
          "mitre_techniques": ["string"],
          "last_seen": "timestamp"
        }
      ],
      "reputation_scores": {
        "ip_reputation": -100.0,
        "domain_reputation": -100.0,
        "file_reputation": -100.0
      }
    }
  }
}
```

**Parallelized Collection Pseudocode**:

```python
async def collect_evidence(alert: NormalizedAlert) -> EnrichedContext:
    """
    Collects evidence in parallel from multiple sources.
    Dramatically reduces time vs sequential collection.
    """
    context = EnrichedContext(alert_id=alert.alert_id)
    
    # Create parallel tasks for each expansion
    tasks = [
        expand_user(alert.primary_entities.user),
        expand_host(alert.primary_entities.host),
        expand_process(alert.primary_entities.process),
        expand_network(alert.primary_entities.ip),
        expand_domain(alert.primary_entities.domain),
        expand_file_hash(alert.primary_entities.file_hash),
        enrich_threat_intel(alert.primary_entities)
    ]
    
    # Execute all in parallel with timeout
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Aggregate results into context
    for result in results:
        if isinstance(result, Exception):
            log_collection_error(result)  # Log but continue
        else:
            context.merge(result)
    
    return context
```

---

### 2.3 Correlation & Compression Layer (Most Critical Component)

**Purpose**: Reduce millions of raw telemetry events to hundreds of contextually-relevant, compressed events.

#### 2.3.1 Compression Architecture

```
Raw Events (millions)
      ▼
┌─────────────────────────────────────┐
│ 1. TEMPORAL FILTERING               │
│    Keep events within investigation │
│    window (default: -24h from alert) │
│    Reduces by: 80-90%               │
└──────────────┬──────────────────────┘
               ▼ (reduced to ~100k-200k)
┌─────────────────────────────────────┐
│ 2. ENTITY-CENTRIC CORRELATION       │
│    Group events by involved entities │
│    Correlate related sequences       │
│    Reduces by: 50-70%               │
└──────────────┬──────────────────────┘
               ▼ (reduced to ~30k-100k)
┌─────────────────────────────────────┐
│ 3. BEHAVIORAL BASELINE FILTERING     │
│    Remove normal, baseline activity  │
│    ML-based anomaly detection        │
│    Reduces by: 60-80%               │
└──────────────┬──────────────────────┘
               ▼ (reduced to ~6k-40k)
┌─────────────────────────────────────┐
│ 4. EVENT DEDUPLICATION              │
│    Remove near-exact duplicates      │
│    Hash-based approach              │
│    Reduces by: 30-40%               │
└──────────────┬──────────────────────┘
               ▼ (reduced to ~4k-24k)
┌─────────────────────────────────────┐
│ 5. GRAPH-BASED CORRELATION          │
│    Identify attack paths in graph    │
│    Collapse sequential steps         │
│    Reduces by: 40-60%               │
└──────────────┬──────────────────────┘
               ▼ (reduced to ~1.6k-14.4k)
┌─────────────────────────────────────┐
│ 6. ABSTRACTION & AGGREGATION        │
│    Summarize repetitive patterns     │
│    "User X logged in 47 times"       │
│    Reduces by: 20-40%               │
└──────────────┬──────────────────────┘
               ▼ (reduced to ~1k-8.6k)
┌─────────────────────────────────────┐
│ 7. RISK SCORING & FILTERING         │
│    Keep high-risk events            │
│    Remove low-signal events         │
│    Reduces by: 40-60%               │
└──────────────┬──────────────────────┘
               ▼ (final: ~400-5k events)
    Compressed & Contextualized
        Events for RCA
```

#### 2.3.2 Detailed Compression Techniques

**1. Temporal Filtering**:

```python
def temporal_filter(events: List[Event], alert_timestamp: datetime) -> List[Event]:
    """
    Keep events within investigation window relative to alert.
    
    Investigation window strategy:
    - For fast-moving attacks: -2h to +30min
    - For lateral movement: -24h to +2h
    - For persistence/privilege escalation: -72h to +24h
    - For exfiltration: -48h to +12h
    - For credential compromise: -30 days to +7 days
    """
    investigation_window = determine_window_from_alert(alert_timestamp)
    start_time = alert_timestamp + investigation_window.start
    end_time = alert_timestamp + investigation_window.end
    
    filtered = [
        e for e in events
        if start_time <= e.timestamp <= end_time
    ]
    
    # Compression ratio
    ratio = len(filtered) / len(events)
    log_metric("temporal_filter.compression_ratio", ratio)
    
    return filtered
```

**2. Entity-Centric Correlation**:

```python
def entity_centric_correlation(events: List[Event]) -> Dict[str, List[Event]]:
    """
    Group events by involved entities to understand entity behavior.
    
    Entities: user, host, process, ip, domain, file_hash, cloud_resource
    
    Removes events that don't involve suspicious entities.
    """
    entity_groups = defaultdict(list)
    
    # Identify suspicious entities from alert
    suspicious_entities = extract_entities_from_alert(alert)
    
    for event in events:
        event_entities = extract_entities(event)
        
        # Check if event involves any suspicious entity
        if any(e in suspicious_entities for e in event_entities):
            # Direct involvement
            for entity in event_entities:
                entity_groups[entity].append(event)
        elif is_neighbor_to_suspicious(event_entities, suspicious_entities):
            # Neighbor involvement (one hop away)
            # Example: User A (suspicious) connected to IP X, 
            #          event shows Host Y connected to IP X
            entity_groups[get_bridge_entity(event_entities)].append(event)
    
    return entity_groups
```

**3. Behavioral Baseline Filtering**:

```python
class BehavioralBaselineFilter:
    """
    ML-based filtering that identifies normal vs suspicious behavior.
    Uses pre-calculated behavioral baselines for user/host.
    """
    
    def __init__(self):
        self.user_baselines = {}  # Learned from historical data
        self.host_baselines = {}
        self.process_baselines = {}
    
    def is_anomalous(self, event: Event, entity: str) -> float:
        """
        Returns anomaly score 0.0-1.0.
        1.0 = highly anomalous, 0.0 = normal
        """
        baseline = self.get_baseline(entity)
        
        if baseline is None:
            # New entity, consider moderately suspicious
            return 0.5
        
        anomaly_score = 0.0
        
        # Feature 1: Time anomaly
        # Is this user typically active at this time?
        time_of_day_score = baseline.time_distribution.get(
            event.timestamp.hour, 0
        )
        if time_of_day_score < 0.1:  # Unusual hour
            anomaly_score += 0.3
        
        # Feature 2: Frequency anomaly
        # Is this more events than typical?
        events_per_hour = baseline.avg_events_per_hour
        if events_per_hour > baseline.events_per_hour * 3:
            anomaly_score += 0.3
        
        # Feature 3: Action type anomaly
        # Has this user/host done this before?
        action_frequency = baseline.actions.get(event.action_type, 0)
        if action_frequency < 0.01:  # Rare action
            anomaly_score += 0.2
        
        # Feature 4: Target anomaly
        # Is the target (host/domain/file) unusual?
        target_frequency = baseline.targets.get(event.target, 0)
        if target_frequency < 0.05:  # Unusual target
            anomaly_score += 0.2
        
        return min(anomaly_score, 1.0)
    
    def filter_by_anomaly(self, events: List[Event], 
                         threshold: float = 0.3) -> List[Event]:
        """
        Keep events with anomaly score above threshold.
        threshold=0.3 means keep moderately suspicious and above.
        """
        filtered = []
        
        for event in events:
            for entity in extract_entities(event):
                score = self.is_anomalous(event, entity)
                if score >= threshold:
                    event.anomaly_score = score
                    filtered.append(event)
                    break  # Avoid duplicates
        
        # Compression ratio
        ratio = len(filtered) / len(events)
        log_metric("behavioral_filter.compression_ratio", ratio)
        
        return filtered
```

**4. Event Deduplication**:

```python
def deduplicate_events(events: List[Event]) -> List[Event]:
    """
    Remove near-exact duplicates using fuzzy matching.
    
    Strategy:
    1. Exact hash match (same event repeated multiple times)
    2. Fuzzy match (same event, slightly different format)
    3. Collapse identical sequences (User X logged in 47 times)
    """
    unique_events = {}
    event_fingerprints = {}
    
    for event in events:
        # Create fingerprint (hash of key fields)
        fingerprint = hash_event(
            [event.source, event.action_type, 
             event.primary_entity, event.target]
        )
        
        if fingerprint in unique_events:
            # Exact duplicate
            existing = unique_events[fingerprint]
            existing.occurrence_count += 1
            existing.last_occurrence = max(
                existing.last_occurrence, event.timestamp
            )
        else:
            # New unique event
            event.occurrence_count = 1
            unique_events[fingerprint] = event
    
    # Collapse repetitive sequences
    collapsed = collapse_repetitive_sequences(unique_events.values())
    
    # Compression ratio
    ratio = len(collapsed) / len(events)
    log_metric("deduplication.compression_ratio", ratio)
    
    return collapsed

def collapse_repetitive_sequences(events: List[Event]) -> List[Event]:
    """
    Collapse sequences like:
    - User login, 1min later user login, 1min later user login...
      Into: User logged in 47 times over 47 minutes
    
    - Process creation (same process), process creation, process creation...
      Into: Process created 23 times
    """
    collapsed = []
    i = 0
    
    while i < len(events):
        current = events[i]
        sequence_count = 1
        j = i + 1
        
        # Look ahead to find identical/similar consecutive events
        while j < len(events):
            if is_same_type_event(events[j], current):
                # Check if timestamps are sequential (within tolerance)
                time_diff = events[j].timestamp - events[j-1].timestamp
                if time_diff < timedelta(seconds=300):  # Within 5 min
                    sequence_count += 1
                    j += 1
                else:
                    break
            else:
                break
        
        # Create aggregated event if sequence found
        if sequence_count > 1:
            aggregated = Event(
                event_type=current.event_type,
                action_type=f"{current.action_type} (x{sequence_count})",
                timestamp_start=events[i].timestamp,
                timestamp_end=events[j-1].timestamp,
                occurrence_count=sequence_count,
                entities=current.entities,
                risk_score=current.risk_score * 0.8  # Slightly lower for repetitive
            )
            collapsed.append(aggregated)
        else:
            collapsed.append(current)
        
        i = j if sequence_count > 1 else i + 1
    
    return collapsed
```

**5. Graph-Based Correlation**:

```python
class AttackGraphBuilder:
    """
    Builds attack graph from correlated events.
    Collapses linear attack paths into nodes.
    
    Example:
    Events: User login → Process exec → File created → Network conn → Data exfil
    Collapses to: Single "Attack Path" node with all details
    """
    
    def build_attack_graph(self, events: List[Event]) -> AttackGraph:
        """
        Creates directed acyclic graph (DAG) of attack progression.
        """
        graph = AttackGraph()
        
        # Step 1: Create nodes for each event/entity
        for event in events:
            node = graph.add_node(
                entity=extract_primary_entity(event),
                event_type=event.event_type,
                timestamp=event.timestamp,
                risk_score=event.risk_score
            )
        
        # Step 2: Create edges based on temporal causality
        for i, event1 in enumerate(events):
            for event2 in events[i+1:]:
                # Check if event1 could have caused event2
                if self.is_causal(event1, event2):
                    edge_confidence = self.calculate_causality_confidence(
                        event1, event2
                    )
                    if edge_confidence > 0.6:
                        graph.add_edge(
                            from_node=event1.node_id,
                            to_node=event2.node_id,
                            confidence=edge_confidence,
                            reason=self.explain_causality(event1, event2)
                        )
        
        # Step 3: Identify paths and collapse them
        paths = graph.find_all_paths()
        collapsed_graph = self.collapse_linear_paths(graph, paths)
        
        return collapsed_graph
    
    def is_causal(self, event1: Event, event2: Event) -> bool:
        """
        Determines if event1 could have caused event2.
        """
        # Temporal causality: event1 must precede event2
        if event1.timestamp >= event2.timestamp:
            return False
        
        # Maximum reasonable delay: 5 minutes
        if event2.timestamp - event1.timestamp > timedelta(minutes=5):
            return False
        
        # Entity causality: events must share an entity
        entities1 = extract_entities(event1)
        entities2 = extract_entities(event2)
        
        if not any(e in entities2 for e in entities1):
            return False
        
        # Action causality: some action types can cause others
        # Example: Process creation can cause network connection
        if self.action_can_cause(event1.action_type, event2.action_type):
            return True
        
        return False
    
    def collapse_linear_paths(self, graph: AttackGraph, 
                              paths: List[Path]) -> AttackGraph:
        """
        Collapses linear attack paths into single summarized nodes.
        
        Example:
        Path: User login → Privilege escalation → Persistence
        Becomes: "User escalated privileges and established persistence"
        """
        collapsed = AttackGraph()
        
        for path in paths:
            if len(path) > 3:  # Only collapse longer sequences
                # Create collapsed node
                collapsed_node = collapsed.add_collapsed_node(
                    nodes=path.nodes,
                    summary=self.summarize_path(path),
                    risk_score=sum(n.risk_score for n in path.nodes) / len(path),
                    start_time=path.nodes[0].timestamp,
                    end_time=path.nodes[-1].timestamp
                )
        
        # Add isolated nodes not part of paths
        for node in graph.nodes:
            if node not in any(p.nodes for p in paths):
                collapsed.add_node(node)
        
        return collapsed
```

**6. Abstraction & Aggregation**:

```python
def abstract_and_aggregate(events: List[Event]) -> List[AggregatedEvent]:
    """
    Groups similar events and creates abstracted summaries.
    
    "User X logged in 47 times from IP 192.168.1.1 between 08:00-10:00"
    instead of 47 separate login events.
    """
    aggregated = []
    grouped = defaultdict(list)
    
    # Group by action type and primary entity
    for event in events:
        key = (event.action_type, event.primary_entity)
        grouped[key].append(event)
    
    for (action, entity), event_group in grouped.items():
        if len(event_group) == 1:
            aggregated.append(event_group[0])
        else:
            # Create aggregated event
            agg_event = AggregatedEvent(
                action_type=action,
                entity=entity,
                occurrence_count=len(event_group),
                time_range=(
                    min(e.timestamp for e in event_group),
                    max(e.timestamp for e in event_group)
                ),
                unique_targets=set(e.target for e in event_group),
                unique_sources=set(e.source for e in event_group),
                risk_score=max(e.risk_score for e in event_group),
                summary=self.generate_summary(event_group)
            )
            aggregated.append(agg_event)
    
    return aggregated

def generate_summary(event_group: List[Event]) -> str:
    """
    Generates human-readable summary of aggregated events.
    """
    action = event_group[0].action_type
    entity = event_group[0].primary_entity
    count = len(event_group)
    
    templates = {
        "login": f"{entity} performed {count} login attempts from {len(set(e.source for e in event_group))} unique sources",
        "process_creation": f"{count} processes created by {entity} in {len(set(e.process_name for e in event_group))} unique executables",
        "file_access": f"{count} file access events on {entity} involving {len(set(e.file_path for e in event_group))} unique files",
        "network_connection": f"{count} network connections from {entity} to {len(set(e.target for e in event_group))} unique destinations"
    }
    
    return templates.get(action, f"{count} {action} events for {entity}")
```

**7. Risk Scoring & Filtering**:

```python
class RiskScorer:
    """
    Assigns risk scores to events based on multiple factors.
    Keeps high-risk events, filters low-signal events.
    """
    
    def score_event(self, event: Event, context: EnrichedContext) -> float:
        """
        Calculates risk score 0.0-1.0 for an event.
        Factors:
        - Severity from alert
        - Entity risk (user/host/process reputation)
        - Behavioral anomaly
        - Known attack patterns
        - Threat intelligence hits
        - Asset criticality
        """
        score = 0.0
        weights = {
            'alert_severity': 0.3,
            'entity_risk': 0.2,
            'behavioral_anomaly': 0.2,
            'attack_pattern_match': 0.15,
            'threat_intel': 0.1,
            'asset_criticality': 0.05
        }
        
        # Factor 1: Alert severity
        severity_scores = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2,
            'informational': 0.0
        }
        alert_score = severity_scores.get(event.severity, 0.3)
        score += alert_score * weights['alert_severity']
        
        # Factor 2: Entity risk reputation
        for entity in extract_entities(event):
            entity_risk = self.get_entity_risk(entity, context)
            score += entity_risk * weights['entity_risk']
        
        # Factor 3: Behavioral anomaly
        if hasattr(event, 'anomaly_score'):
            score += event.anomaly_score * weights['behavioral_anomaly']
        
        # Factor 4: Attack pattern match
        pattern_match_score = self.match_attack_patterns(event, context)
        score += pattern_match_score * weights['attack_pattern_match']
        
        # Factor 5: Threat intelligence
        threat_intel_score = self.check_threat_intelligence(event)
        score += threat_intel_score * weights['threat_intel']
        
        # Factor 6: Asset criticality
        asset_criticality = self.get_asset_criticality(event.target)
        score += asset_criticality * weights['asset_criticality']
        
        return min(score, 1.0)
    
    def filter_by_risk(self, events: List[Event], 
                       min_risk_threshold: float = 0.4) -> List[Event]:
        """
        Keeps events with risk score above threshold.
        Default threshold=0.4 keeps 40% of events.
        """
        scored_events = [
            (e, self.score_event(e, context))
            for e in events
        ]
        
        # Sort by risk score (highest first)
        scored_events.sort(key=lambda x: x[1], reverse=True)
        
        filtered = [
            e for e, score in scored_events
            if score >= min_risk_threshold
        ]
        
        return filtered
```

#### 2.3.3 Compression Pipeline Orchestration

```yaml
CorrelationAndCompressionAgent:
  input: EnrichedContext with all collected telemetry
  output: CompressedEventPackage with reduced events
  
  pipeline:
    stage_1_temporal_filter:
      enabled: true
      reduction_target: 80-90%
      investigation_window: dynamic based on alert type
    
    stage_2_entity_correlation:
      enabled: true
      reduction_target: 50-70%
      suspicious_entity_identification: true
      neighbor_expansion: 1-hop
    
    stage_3_behavioral_filtering:
      enabled: true
      reduction_target: 60-80%
      baseline_freshness: 7-30 days
      anomaly_threshold: 0.3
      ml_model: isolation_forest or local_outlier_factor
    
    stage_4_deduplication:
      enabled: true
      reduction_target: 30-40%
      exact_match: hash-based
      fuzzy_match: levenshtein_distance > 0.9
      collapse_repetitive: time_window < 5 min
    
    stage_5_graph_analysis:
      enabled: true
      reduction_target: 40-60%
      build_attack_graph: true
      identify_causal_paths: true
      collapse_linear_sequences: true
    
    stage_6_abstraction:
      enabled: true
      reduction_target: 20-40%
      aggregate_similar_events: true
      generate_summaries: true
    
    stage_7_risk_scoring:
      enabled: true
      reduction_target: 40-60%
      min_risk_threshold: 0.4
      scoring_factors:
        - alert_severity (30%)
        - entity_risk (20%)
        - behavioral_anomaly (20%)
        - attack_pattern_match (15%)
        - threat_intel (10%)
        - asset_criticality (5%)
  
  # Overall target compression
  # Input: ~1-10 million raw events
  # Output: ~400-5000 compressed, contextualized events
  # Compression ratio: 1000-10000x
  
  parallel_processing:
    stages_in_parallel: [1, 2, 3, 4]
    stage_5_dependent_on: [1, 2, 3, 4]
    stage_6_dependent_on: [5]
    stage_7_dependent_on: [6]
  
  monitoring:
    track_compression_ratio_per_stage: true
    alert_on_anomalies: true
    log_stage_execution_times: true
```

---

### 2.4 Investigation Package Builder

**Purpose**: Construct a compact, queryable package for RCA engines.

```yaml
InvestigationPackageBuilder:
  input: CompressedEventPackage from Correlation Layer
  output: InvestigationPackage for RCA
  
  package_components:
    
    investigation_metadata:
      investigation_id: uuid
      alert_id: uuid (from original alert)
      package_generated_timestamp: ISO8601
      investigation_scope:
        start_time: timestamp
        end_time: timestamp
        duration_hours: number
      compression_stats:
        raw_events_collected: number
        events_after_compression: number
        compression_ratio: number
      confidence_level: 0.0-1.0 (by stage)
    
    entity_relationships:
      description: "Who accessed what, when, and how"
      entities:
        - id: user:john.doe
          entity_type: user
          attributes:
            name: "John Doe"
            department: "Engineering"
            risk_factors: ["failed_logins", "vpn_access", "sensitive_data_access"]
          
        - id: host:web-srv-01
          entity_type: host
          attributes:
            hostname: "web-srv-01.corp.local"
            os: "Windows Server 2022"
            owner: "Engineering"
            criticality: "high"
            risk_factors: ["multiple_failed_auth", "unusual_process"]
          
        - id: process:powershell.exe
          entity_type: process
          attributes:
            name: "PowerShell"
            path: "C:\\Windows\\System32\\powershell.exe"
            hash_sha256: "abc123..."
            risk_factors: ["created_by_service_account", "child_process_anomaly"]
      
      relationships:
        - from: user:john.doe
          to: host:web-srv-01
          relationship_type: "logged_into"
          evidence_count: 5
          time_range: [start, end]
          risk_score: 0.7
          reason: "Unusual time and location"
        
        - from: host:web-srv-01
          to: process:powershell.exe
          relationship_type: "executed"
          evidence_count: 2
          time_range: [start, end]
          risk_score: 0.8
          reason: "Created by SYSTEM account, unusual privilege"
        
        - from: process:powershell.exe
          to: host:internal-db-01
          relationship_type: "connected_to"
          evidence_count: 3
          time_range: [start, end]
          risk_score: 0.9
          reason: "Beaconing pattern detected"
    
    timeline:
      description: "Chronological sequence of significant events"
      events: [
        {
          timestamp: "2026-08-10T14:32:00Z",
          event_id: "evt_001",
          event_type: "authentication",
          description: "User john.doe logged into web-srv-01 from IP 203.0.113.5",
          entities_involved: ["user:john.doe", "host:web-srv-01", "ip:203.0.113.5"],
          risk_score: 0.6,
          evidence_from_stages: ["stage_1", "stage_2"],
          raw_event_count: 3,
          details: {
            authentication_method: "NTLM",
            mfa_used: false,
            source_location: "China",
            account_status: "active"
          }
        },
        # ... more timeline events
      ]
    
    attack_graph:
      description: "Reconstructed attack path showing progression"
      nodes: [
        {
          node_id: "node_001",
          timestamp: "2026-08-10T14:32:00Z",
          activity: "Initial Access",
          description: "User credential compromise from external IP",
          entities: ["user:john.doe", "ip:203.0.113.5"],
          tactics: ["initial_access"],
          techniques: ["valid_accounts"],
          risk_score: 0.8
        },
        {
          node_id: "node_002",
          timestamp: "2026-08-10T14:35:00Z",
          activity: "Privilege Escalation",
          description: "PowerShell launched with elevated privileges",
          entities: ["host:web-srv-01", "process:powershell.exe"],
          tactics: ["privilege_escalation"],
          techniques: ["token_impersonation"],
          risk_score: 0.85
        },
        {
          node_id: "node_003",
          timestamp: "2026-08-10T14:38:00Z",
          activity: "Lateral Movement",
          description: "Connection established to database server",
          entities: ["process:powershell.exe", "host:internal-db-01"],
          tactics: ["lateral_movement"],
          techniques: ["pass_the_hash"],
          risk_score: 0.9
        }
      ],
      edges: [
        {
          from: "node_001",
          to: "node_002",
          confidence: 0.95,
          reason: "Same host, short time delta, escalation follows access"
        },
        {
          from: "node_002",
          to: "node_003",
          confidence: 0.9,
          reason: "Same process initiated connection, same session"
        }
      ],
      attack_summary: "Initial access via compromised credential, privilege escalation via token impersonation, lateral movement to database server"
    
    key_findings:
      description: "Most important/suspicious observations"
      findings: [
        {
          finding_id: "finding_001",
          severity: "critical",
          title: "Impossible Travel Detected",
          description: "User john.doe logged in from China 3 hours after last login from US office (8000 miles). Geographically impossible.",
          evidence: [
            "Login from 203.0.113.5 (China) at 14:32 UTC",
            "Previous login from 203.0.114.10 (Boston) at 11:25 UTC"
          ],
          mitre_techniques: ["valid_accounts"],
          risk_score: 0.95
        },
        {
          finding_id: "finding_002",
          severity: "high",
          title: "Abnormal Process Execution",
          description: "PowerShell executed by SYSTEM account from web server. Typically runs under user context. Script block logging shows obfuscated commands.",
          evidence: [
            "Process: C:\\Windows\\System32\\powershell.exe",
            "Parent Process: svchost.exe",
            "Command line: [obfuscated]",
            "Script blocks: [redacted for brevity]"
          ],
          mitre_techniques: ["execution"],
          risk_score: 0.88
        }
      ]
    
    statistical_summary:
      total_events_analyzed: 5000
      critical_events: 15
      high_risk_events: 47
      medium_risk_events: 183
      low_risk_events: 4755
      
      entity_statistics:
        unique_users: 3
        unique_hosts: 7
        unique_processes: 12
        unique_ips: 5
        unique_domains: 2
      
      temporal_statistics:
        investigation_duration_hours: 24
        events_per_hour: 208
        peak_activity_hour: 14 # UTC 14:00-15:00
        activity_concentration: "45% of events in 2-hour window"
    
    confidence_assessment:
      overall_confidence: 0.85
      confidence_by_factor:
        evidence_volume: 0.9 (many events supporting conclusions)
        evidence_consistency: 0.85 (events paint coherent story)
        entity_reliability: 0.8 (most entities have good signal)
        temporal_coherence: 0.88 (timeline flows logically)
      
      confidence_gaps:
        gaps: [
          "Limited process forensics from host (no memory capture)",
          "DNS logs incomplete for investigation period",
          "Email headers not available (not in scope)"
        ]
        recommendations: [
          "Collect full process memory dump from web-srv-01",
          "Retrieve DNS logs from authoritative resolvers",
          "Request email metadata for john.doe account"
        ]
```

---

### 2.5 RCA Engine Integration

**Purpose**: Interface between Correlation Layer and RCA engine with clear contracts.

#### 2.5.1 Why RCA Shouldn't Process Raw Telemetry

```
┌──────────────────────────────────────────────────┐
│  RAW TELEMETRY: 10 million security events/day   │
├──────────────────────────────────────────────────┤
│                                                   │
│  Problems if sent to RCA:                        │
│  1. Cost: LLM API costs scale linearly with      │
│     input tokens ($$ per million events)         │
│  2. Latency: Processing millions of tokens       │
│     takes minutes to hours                       │
│  3. Context Window: Exceeds token limits         │
│  4. Noise: 99% of events are normal              │
│  5. Accuracy: Model drowns in noise,             │
│     misses attack patterns                       │
│  6. Scalability: Doesn't work for large corps    │
└──────────────────────────────────────────────────┘
                    ▼
┌──────────────────────────────────────────────────┐
│  CORRELATION LAYER: Reduces to 500-5000 events   │
├──────────────────────────────────────────────────┤
│                                                   │
│  Benefits:                                       │
│  1. Cost: 1000-10000x cost reduction             │
│  2. Latency: Sub-second processing               │
│  3. Fits: Well within LLM context windows        │
│  4. Signal: Only relevant, high-signal events    │
│  5. Accuracy: Model sees clear attack patterns   │
│  6. Scalability: Can handle enterprise scale     │
└──────────────────────────────────────────────────┘
                    ▼
┌──────────────────────────────────────────────────┐
│  RCA ENGINE: Deep analysis of signal             │
├──────────────────────────────────────────────────┤
│  - Determines root cause                         │
│  - Identifies impact scope                       │
│  - Recommends response actions                   │
│  - Generates comprehensive report                │
└──────────────────────────────────────────────────┘
```

#### 2.5.2 RCA Engine Interface Contract

```python
class RCAOrchestrator:
    """
    Manages interaction between Correlation Layer and RCA Engine.
    Defines clear input/output contracts.
    """
    
    def invoke_rca(self, 
                   investigation_package: InvestigationPackage,
                   config: RCAConfig) -> RCAResult:
        """
        Invokes RCA engine with investigation package.
        
        Input:
            investigation_package: Compressed, contextualized events
            config:
              - use_llm: bool (whether to use LLM-based RCA)
              - max_analysis_tokens: int (context window budget)
              - additional_context: dict (custom instructions)
        
        Output:
            RCAResult with root cause, impact, recommendations
        """
        
        # Validate package
        self.validate_investigation_package(investigation_package)
        
        # Prepare RCA input
        rca_input = self.prepare_rca_input(investigation_package, config)
        
        # Check token budget
        token_count = self.count_tokens(rca_input)
        if token_count > config.max_analysis_tokens:
            raise TokenBudgetExceeded(
                f"RCA input exceeds token budget: {token_count} > {config.max_analysis_tokens}"
            )
        
        # Invoke RCA
        if config.use_llm:
            result = self.invoke_llm_rca(rca_input, config)
        else:
            result = self.invoke_deterministic_rca(rca_input, config)
        
        # Validate output
        self.validate_rca_output(result)
        
        return result
    
    def prepare_rca_input(self, 
                          package: InvestigationPackage,
                          config: RCAConfig) -> str:
        """
        Formats investigation package into RCA input prompt.
        Carefully crafted to maximize clarity while minimizing tokens.
        """
        
        # Start with investigation context
        prompt = f"""
You are a security incident root cause analyzer. Analyze the following incident investigation package
and determine: (1) root cause, (2) attack phases, (3) impacted assets, (4) evidence confidence.

INVESTIGATION SUMMARY:
- Investigation ID: {package.metadata.investigation_id}
- Duration: {package.metadata.duration_hours} hours
- Compressed Events: {len(package.timeline.events)} (from {package.stats.raw_events} raw)
- Confidence: {package.confidence.overall_confidence}

ATTACK TIMELINE:
"""
        
        # Add key timeline events (most important first)
        for event in sorted(package.timeline.events, 
                           key=lambda e: e.risk_score, 
                           reverse=True)[:20]:  # Top 20 events
            prompt += f"- {event.timestamp}: {event.description} (risk: {event.risk_score})\n"
        
        # Add entity relationships
        prompt += "\nKEY ENTITY RELATIONSHIPS:\n"
        for rel in package.entity_relationships[:30]:  # Top 30 relationships
            prompt += f"- {rel.from_entity} → {rel.to_entity}: {rel.description}\n"
        
        # Add attack graph
        prompt += f"\nATTACK PROGRESSION:\n{package.attack_graph.attack_summary}\n"
        
        # Add key findings
        prompt += "\nCRITICAL FINDINGS:\n"
        for finding in package.findings[:10]:
            prompt += f"- {finding.title}: {finding.description}\n"
        
        # Add data quality notes
        prompt += f"\nCONFIDENCE FACTORS:\n- Evidence Volume: {package.confidence.by_factor.evidence_volume}\n"
        prompt += f"- Evidence Consistency: {package.confidence.by_factor.evidence_consistency}\n"
        
        return prompt
    
    def invoke_llm_rca(self, 
                       rca_input: str,
                       config: RCAConfig) -> RCAResult:
        """
        Uses LLM (Claude, GPT-4) for deep RCA analysis.
        
        Benefits:
        - Understands complex attack patterns
        - Makes nuanced judgments about causality
        - Generates natural language explanations
        - Can handle novel attack patterns
        
        Costs:
        - API costs per invocation
        - Latency (seconds, not milliseconds)
        - Non-deterministic results
        """
        
        system_prompt = """You are an expert security incident response analyst with deep knowledge of:
- MITRE ATT&CK framework
- Attack patterns and kill chains
- Cloud, endpoint, and identity security
- Incident investigation techniques

Analyze the incident and provide:
1. ROOT CAUSE: Most likely initial compromise vector
2. ATTACK CHAIN: Sequence of actions taken by attacker
3. IMPACTED ASSETS: All compromised systems, accounts, data
4. CONFIDENCE: Assessment of analysis confidence (0-1)
5. GAPS: What additional evidence would improve confidence
6. RECOMMENDATIONS: Immediate containment and investigation actions"""
        
        response = self.llm_client.chat.completions.create(
            model="gpt-4",  # or claude-3-sonnet
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": rca_input
                }
            ],
            max_tokens=config.max_analysis_tokens,
            temperature=0.2  # Lower temperature for consistency
        )
        
        # Parse LLM response into structured RCAResult
        result = self.parse_llm_response(response.choices[0].message.content)
        
        return result
    
    def invoke_deterministic_rca(self, 
                                 rca_input: str,
                                 config: RCAConfig) -> RCAResult:
        """
        Uses rule-based, deterministic RCA engine.
        No LLM costs, but less flexible.
        
        Good for:
        - Known attack patterns (ransomware, credential theft, etc.)
        - High-volume incident processing
        - Reproducible, auditable analysis
        
        Uses:
        - Attack pattern matching (SIGMA, Yara)
        - Graph traversal algorithms
        - Rule engines (Drools, etc.)
        """
        
        result = RCAResult(
            investigation_id=rca_input.investigation_id,
            analysis_timestamp=datetime.now()
        )
        
        # Phase 1: Identify attack category
        attack_type = self.classify_attack(rca_input)
        result.attack_category = attack_type
        
        # Phase 2: Apply attack-specific rules
        if attack_type == "ransomware":
            result = self.analyze_ransomware(rca_input, result)
        elif attack_type == "lateral_movement":
            result = self.analyze_lateral_movement(rca_input, result)
        elif attack_type == "credential_theft":
            result = self.analyze_credential_theft(rca_input, result)
        # ... more attack types
        
        # Phase 3: Generate recommendations
        result.recommendations = self.generate_recommendations(attack_type, result)
        
        return result
```

#### 2.5.3 RCA Result Schema

```json
{
  "rca_result": {
    "investigation_id": "uuid",
    "rca_invocation_id": "uuid",
    "analysis_timestamp": "ISO8601",
    "analysis_method": "llm|deterministic",
    "analysis_duration_seconds": 15.5,
    
    "root_cause": {
      "primary_cause": "string",
      "description": "Detailed explanation of initial compromise",
      "confidence": 0.85,
      "evidence_supporting": [
        "Timeline event ID",
        "Key finding ID"
      ],
      "mitre_technique": "T1078.003",
      "mitre_tactic": "Initial Access"
    },
    
    "attack_phases": [
      {
        "phase_number": 1,
        "phase_name": "Initial Access",
        "description": "Attacker compromised user credentials",
        "techniques": ["T1078.003"],
        "duration": "2026-08-10T14:32:00Z to 2026-08-10T14:35:00Z",
        "entities_involved": ["user:john.doe", "ip:203.0.113.5"],
        "confidence": 0.90
      },
      {
        "phase_number": 2,
        "phase_name": "Privilege Escalation",
        "description": "Escalated privileges via token impersonation",
        "techniques": ["T1134.001"],
        "entities_involved": ["host:web-srv-01", "process:powershell.exe"],
        "confidence": 0.85
      }
    ],
    
    "impacted_assets": [
      {
        "asset_type": "user",
        "identifier": "john.doe",
        "impact_type": "credentials_compromised",
        "impact_confidence": 0.95,
        "access_scope": "web_tier_applications",
        "data_exposure_risk": "high",
        "remediation_status": "pending"
      },
      {
        "asset_type": "host",
        "identifier": "web-srv-01",
        "impact_type": "privilege_escalation",
        "impact_confidence": 0.88,
        "access_scope": "local_admin",
        "data_exposure_risk": "medium",
        "remediation_status": "pending"
      }
    ],
    
    "overall_confidence": 0.87,
    "confidence_reasoning": "Multiple corroborating events, clear timeline, high-confidence indicators (impossible travel, abnormal process execution)",
    
    "investigation_gaps": [
      {
        "gap_type": "evidence_missing",
        "description": "Process memory not captured from web-srv-01",
        "impact": "Cannot determine exact attack tools used",
        "priority": "high",
        "recommended_action": "Collect full memory dump for forensic analysis"
      },
      {
        "gap_type": "data_unavailable",
        "description": "Email logs for john.doe not available",
        "impact": "Cannot determine if credential compromise via phishing or other means",
        "priority": "medium",
        "recommended_action": "Request email metadata and forwarding rules from email security platform"
      }
    ],
    
    "recommendations": [
      {
        "priority": "immediate",
        "action_type": "containment",
        "description": "Disable user account john.doe",
        "rationale": "Credentials confirmed compromised, active attacker use suspected",
        "expected_impact": "Prevents continued lateral movement",
        "implementation": "Disable in AD, terminate active sessions"
      },
      {
        "priority": "immediate",
        "action_type": "containment",
        "description": "Isolate host web-srv-01 from network",
        "rationale": "Evidence of privilege escalation and command execution",
        "expected_impact": "Prevents exfiltration and further lateral movement",
        "implementation": "Remove from network, maintain evidence for forensics"
      },
      {
        "priority": "urgent",
        "action_type": "investigation",
        "description": "Collect full forensic images from compromised hosts",
        "rationale": "Need to determine full scope of attacker activities",
        "expected_impact": "Enables identification of all affected systems"
      },
      {
        "priority": "high",
        "action_type": "threat_hunt",
        "description": "Hunt for additional compromised accounts using credential",
        "rationale": "john.doe credential may have been used elsewhere",
        "expected_impact": "Identifies lateral movement and scope"
      }
    ],
    
    "mitre_ttps": [
      {
        "tactic": "initial_access",
        "techniques": ["T1078.003"],
        "sub_techniques": []
      },
      {
        "tactic": "privilege_escalation",
        "techniques": ["T1134.001"],
        "sub_techniques": []
      },
      {
        "tactic": "lateral_movement",
        "techniques": ["T1021.002"],
        "sub_techniques": []
      }
    ],
    
    "analysis_metadata": {
      "input_event_count": 5000,
      "key_events_analyzed": 47,
      "relationships_analyzed": 127,
      "attack_patterns_matched": 3,
      "rule_matches": [
        "rule_impossible_travel",
        "rule_abnormal_process_execution",
        "rule_privilege_escalation_powershell"
      ]
    }
  }
}
```

---

## Part 3: Adaptive Investigation Loop

**Purpose**: If RCA confidence is low, automatically request more data and re-analyze.

```yaml
AdaptiveInvestigationLoop:
  
  trigger_conditions:
    - rca_confidence < 0.7
    - investigation_gaps identified
    - conflicting evidence
    - insufficient coverage of attack phase
  
  retry_strategy:
    max_iterations: 3
    backoff: exponential (2s, 4s, 8s)
    timeout_per_iteration: 5 minutes
  
  feedback_loop:
    
    iteration_1_initial:
      collection_scope: "direct evidence only"
      compression_aggressiveness: "high"
      rca_invocation: "with initial package"
      result: "confidence = 0.62 (too low)"
    
    iteration_2_expand:
      trigger: "confidence too low"
      
      additional_collection_requests:
        1. "Expand host collection to -72h (instead of -24h)"
        2. "Collect additional authentication logs from Okta"
        3. "Get DNS logs for all IPs contacted"
        4. "Retrieve email logs for john.doe (sender/receiver)"
      
      collection_scope: "neighbor entities + temporal expansion"
      compression_aggressiveness: "medium"
      rca_invocation: "with expanded package + gap notes"
      result: "confidence = 0.81 (acceptable)"
    
    iteration_3_final_validation:
      trigger: "confidence acceptable, verify with additional context"
      
      additional_requests:
        1. "File integrity monitoring data for critical files"
        2. "Backup logs showing data access"
        3. "EDR deep forensics from suspicious process"
      
      collection_scope: "forensic depth on key assets"
      compression_aggressiveness: "low (preserve detail)"
      rca_invocation: "with forensic package + final validation"
      result: "confidence = 0.92 (high confidence, proceed)"
  
  stopping_criteria:
    - confidence >= 0.8 AND no major gaps
    - max_iterations reached
    - diminishing returns: new data doesn't increase confidence
    - time_budget exceeded (10 minute default)
    - user requests to proceed despite low confidence
```

---

## Part 4: Architecture Diagrams & Data Models

### 4.1 Service-Based Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      API GATEWAY / ORCHESTRATOR                      │
│                   (Routes requests, enforces auth)                   │
└────────────┬─────────────────────────────────────────────────────────┘
             │
    ┌────────┼────────┬──────────────┬──────────────┬──────────────┐
    │        │        │              │              │              │
    ▼        ▼        ▼              ▼              ▼              ▼
┌────────┐ ┌──────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌─────────┐
│ Alert │ │Evid. │ │Correlate │ │ Package  │ │   RCA      │ │ Report  │
│ Intake│ │Collect│ │ & Comp.  │ │ Builder  │ │Orchestrate │ │ Gen.    │
│Service│ │Service│ │ Service  │ │ Service  │ │ Service    │ │Service  │
└────────┘ └──────┘ └──────────┘ └──────────┘ └────────────┘ └─────────┘
    │        │        │              │              │              │
    └────────┴────────┴──────────────┴──────────────┴──────────────┘
                            │
                   ┌────────┴─────────┐
                   │                  │
                   ▼                  ▼
            ┌─────────────────┐ ┌──────────────────┐
            │ CONNECTOR LAYER │ │ CACHE & STORAGE  │
            ├─────────────────┤ ├──────────────────┤
            │ SIEM Connector  │ │ Event Store      │
            │ XDR Connector   │ │ Graph Store      │
            │ EDR Connector   │ │ Cache (Redis)    │
            │ Cloud Connector │ │ Data Lake        │
            │ IAM Connector   │ │ Vector DB        │
            │ TI Connector    │ │ Document Store   │
            └─────────────────┘ └──────────────────┘
```

### 4.2 Data Storage Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      DATA STORAGE LAYER                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │  HOT STORAGE   │  │ WARM STORAGE │  │ COLD STORAGE    │   │
│  │  (0-24 hours)  │  │ (1-90 days)  │  │ (90+ days)      │   │
│  ├────────────────┤  ├──────────────┤  ├─────────────────┤   │
│  │                │  │              │  │                 │   │
│  │ Event Stream   │  │  Data Lake   │  │ S3/Blob         │   │
│  │ - Kafka        │  │  - Parquet   │  │ Storage         │   │
│  │ - Events       │  │  - Events    │  │ - Compressed    │   │
│  │   (5 min TTL)  │  │    (indexed) │  │   archives      │   │
│  │                │  │              │  │ - Searchable    │   │
│  │ Cache Layer    │  │ Search Index │  │   via reindex   │   │
│  │ - Redis        │  │ - Elasticsearch
│  │   (entities,   │  │ - Opensearch │  │                 │   │
│  │    baselines)  │  │              │  │                 │   │
│  │                │  │ Time Series  │  │                 │   │
│  │ Process Events │  │ - InfluxDB   │  │                 │   │
│  │ - RabbitMQ     │  │ - Prometheus │  │                 │   │
│  │   (immediate   │  │              │  │                 │   │
│  │    processing) │  │ Graph DB     │  │                 │   │
│  │                │  │ - Neo4j      │  │                 │   │
│  │                │  │ - TigerGraph │  │                 │   │
│  │                │  │              │  │                 │   │
│  │                │  │ Document DB  │  │                 │   │
│  │                │  │ - MongoDB    │  │                 │   │
│  │                │  │ - DynamoDB   │  │                 │   │
│  │                │  │              │  │                 │   │
│  │                │  │ Vector Store │  │                 │   │
│  │                │  │ - Pinecone   │  │                 │   │
│  │                │  │ - Weaviate   │  │                 │   │
│  │                │  │ (for TI/TTP) │  │                 │   │
│  │                │  │              │  │                 │   │
│  └────────────────┘  └──────────────┘  └─────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  QUERY INTERFACE: Query Engine (Presto, Spark SQL)     │  │
│  │  Allows complex joins across storage layers            │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 4.3 Database Recommendations by Component

| Component | Primary DB | Secondary | Purpose |
|-----------|-----------|-----------|---------|
| **Raw Events** | Kafka + Parquet | S3 (archive) | Immutable event stream, fast append |
| **Entities** | Neo4j / TigerGraph | PostgreSQL | Relationship storage, graph traversal |
| **Telemetry** | InfluxDB / TimescaleDB | Elasticsearch | Time-series metrics, fast queries |
| **Alerts** | DynamoDB / MongoDB | PostgreSQL | Document storage, flexible schema |
| **Baselines** | Redis / Memcached | PostgreSQL | Fast lookup, behavioral data |
| **Investigation Packages** | MongoDB / DocumentDB | PostgreSQL | Complex nested structures |
| **Threat Intelligence** | Vector DB (Pinecone) | PostgreSQL | Semantic search, similarity matching |
| **Audit Logs** | PostgreSQL | S3 (append-only) | Compliance, immutable records |

### 4.4 Security Knowledge Graph Design

```
┌──────────────────────────────────────────────────────────────────┐
│          SECURITY KNOWLEDGE GRAPH (Property Graph)               │
└──────────────────────────────────────────────────────────────────┘

NODES (Entity Types):
├─ User
│  └─ Properties: uid, name, department, risk_score, last_login
├─ Host
│  └─ Properties: hostname, os, ip_address, owner, criticality
├─ Process
│  └─ Properties: name, path, pid, hash_sha256, created_by
├─ IP Address
│  └─ Properties: address, geolocation, reputation, asn
├─ Domain
│  └─ Properties: fqdn, registrar, dns_servers, reputation
├─ File/Hash
│  └─ Properties: hash_sha256, file_name, malware_family
├─ Cloud Resource
│  └─ Properties: resource_id, resource_type, account_id, tags
├─ Email
│  └─ Properties: address, domain, reputation, compromised
├─ Network Segment
│  └─ Properties: cidr, trust_level, data_classification
└─ Threat Actor
   └─ Properties: name, aliases, techniques, known_targets

EDGES (Relationship Types):
├─ User
│  ├─ LOGGED_INTO (Host) [timestamp, ip_from, success]
│  ├─ ACCESSED (File/Resource) [timestamp, action, status]
│  ├─ BELONGS_TO_GROUP (Group) [timestamp, added_date]
│  ├─ CREATED_PROCESS (Process) [timestamp, privileges]
│  ├─ SENT_EMAIL_TO (Email) [timestamp, subject, risk]
│  ├─ HAS_PERMISSION_ON (Host/Resource) [permission_type]
│  ├─ COMMUNICATES_WITH (IP) [timestamp, protocol, port, bytes]
│  └─ COMPROMISED_BY (Threat Actor) [timestamp, vector]
├─ Host
│  ├─ EXECUTED (Process) [timestamp, user_context]
│  ├─ CONNECTED_TO (IP) [timestamp, port, protocol, direction]
│  ├─ RESOLVED_DOMAIN (Domain) [timestamp, resolver]
│  ├─ ACCESSED_FILE (File) [timestamp, action]
│  ├─ OWNS (Resource) [access_level]
│  ├─ NETWORK_SEGMENT (Network Segment) [internal_ip]
│  └─ COMPROMISED_BY (Threat Actor) [timestamp, vector]
├─ Process
│  ├─ CREATED_BY (User/Process) [timestamp, privileges]
│  ├─ SPAWNED_CHILD (Process) [timestamp]
│  ├─ LOADED_MODULE (File) [timestamp]
│  ├─ CONNECTED_TO (IP) [timestamp, port, protocol]
│  ├─ MODIFIED_FILE (File) [timestamp, action]
│  ├─ ACCESSED_REGISTRY (Registry Key) [timestamp, action]
│  ├─ INJECTED_INTO (Process) [timestamp, technique]
│  ├─ USES_CREDENTIAL (User) [timestamp, authentication_type]
│  └─ USES_TECHNIQUE (ATT&CK Technique) [confidence]
├─ IP Address
│  ├─ RESOLVES_TO (Domain) [timestamp]
│  ├─ LOCATED_IN (Geolocation) [timestamp]
│  ├─ BELONGS_TO_ASN (ASN) []
│  ├─ CONTACTED_BY (Host/Process) [timestamp, port, bytes]
│  └─ IS_PROXY_FOR (IP) [proxy_type]
├─ Domain
│  ├─ HAS_NS (NS Server) []
│  ├─ HAS_MX (Mail Server) []
│  ├─ REGISTERED_AT (Registrar) []
│  ├─ RESOLVES_TO (IP) [timestamp]
│  └─ CONTACTED_BY (Process/Host) [timestamp]
└─ File
   ├─ CREATED_BY (Process) [timestamp]
   ├─ MODIFIED_BY (Process) [timestamp]
   ├─ EXECUTED_BY (Process) [timestamp]
   ├─ HASH_MATCHES (Threat Intelligence) [confidence]
   └─ IS_MALWARE (Malware Family) [confidence]

TEMPORAL PROPERTIES:
- All edges have timestamps
- Many edges have time ranges [start, end]
- Edges can be marked as transient (session-based) or persistent
- Bulk operations tracked (e.g., "added 47 users to AD group on 2026-08-10")

ANALYTICS QUERIES:
1. Find all attack paths from IP to sensitive host
   MATCH path = (attacker_ip:IP)-[*1..10]->(sensitive_host:Host)
   RETURN path

2. Find lateral movement patterns
   MATCH (user:User)-[login:LOGGED_INTO]->(host1:Host)-[exec:EXECUTED]->
         (proc:Process)-[connect:CONNECTED_TO]->(host2:Host)
   WHERE host1 != host2
   RETURN path

3. Identify compromised entity risk scores
   MATCH (entity)-[r:COMPROMISED_BY|CONTACTS_MALICIOUS]->(threat)
   RETURN entity, count(r) as risk_score
   ORDER BY risk_score DESC

4. Find credential exposure chains
   MATCH (user:User)-[access:HAS_PERMISSION_ON]->(host:Host)-
         [exec:EXECUTED]->(proc:Process)-[connect:CONNECTED_TO]->(external_ip:IP)
   WHERE external_ip.reputation < -0.5
   RETURN path
```

---

## Part 5: Recommended Technology Stack

### 5.1 Platform Architecture

```yaml
Alert Intake:
  - Connector Framework: Apache Kafka (multi-source ingestion)
  - Alert Normalization: Custom Python/Go services
  - Schema Registry: Confluent Schema Registry
  - Deduplication: Redis + custom logic
  
Evidence Collection:
  - Orchestration: Apache Airflow / Prefect
  - API Integration: Custom connectors + Zapier/Make
  - Parallelization: Python asyncio / Go goroutines
  - Caching: Redis (4-hour TTL)
  
Correlation & Compression:
  - Rules Engine: Drools / OPA (Open Policy Agent)
  - Graph Analysis: Python (NetworkX) or specialized graph tools
  - ML Models: Scikit-learn / PyTorch (for anomaly detection)
  - Event Processing: Apache Flink / Spark Streaming
  - Storage: ClickHouse (time-series optimized)
  
RCA Engine:
  - LLM Integration: OpenAI API / Anthropic API / Open source
  - Rule-based Engine: Custom Python + Drools
  - Graph DB Queries: Cypher language (Neo4j)
  - Report Generation: Jinja2 templates + Markdown
  
Response Orchestration:
  - Workflow Engine: Kubernetes + Argo Workflows
  - Action Execution: Custom hooks + commercial tools
  - Remediation Playbooks: Ansibleor custom Python
  
Multi-tenancy:
  - Isolation: PostgreSQL schemas or separate deployments
  - Auth/RBAC: OAuth2 + custom roles
  - Resource Isolation: Kubernetes namespaces
  - Billing: Custom metering + Stripe API
```

---

## Part 6: Component Classification

### 6.1 Which Components Should Use Which Approach?

```
COMPONENT                    | APPROACH           | RATIONALE
──────────────────────────────────────────────────────────────
Alert Intake                 | Rule-based         | Deterministic, fast, well-defined schema
Entity Extraction            | Rule-based         | Regex/patterns for known formats
Alert Deduplication          | Rule-based + Hash  | Exact matching, no ambiguity
──────────────────────────────────────────────────────────────
Entity Expansion             | Hybrid             | Rule-based query construction + async orchestration
Parallel Collection          | Rule-based         | Deterministic scheduling + timeouts
Rich Context Aggregation     | Rule-based         | Schema mapping + data merging
──────────────────────────────────────────────────────────────
Temporal Filtering           | Rule-based         | Fixed logic, alert-dependent windows
Entity Correlation           | Graph-based        | Neo4j / TigerGraph for relationship queries
Behavioral Filtering         | ML-based           | Isolation Forest / LOF for anomalies
Event Deduplication          | Rule-based + ML    | Hash for exact match + fuzzy matching
Graph-Based Correlation      | Graph-based        | Path finding, causality analysis
Abstraction & Aggregation    | Rule-based + NLP   | Template-based summaries
Risk Scoring                 | Hybrid             | Rule-based factors + ML weighting
──────────────────────────────────────────────────────────────
Package Builder              | Rule-based         | Deterministic selection & ranking
──────────────────────────────────────────────────────────────
RCA - Known Attacks          | Rule-based         | Ransomware, phishing, etc. have defined patterns
RCA - Novel Attacks          | LLM-based          | Needs reasoning about unfamiliar patterns
RCA - Attack Chain Analysis  | Graph-based        | MITRE mapping + path traversal
RCA - Confidence Scoring     | Hybrid             | Rule-based heuristics + LLM review
──────────────────────────────────────────────────────────────
Report Generation            | Rule-based + NLG   | Templates + LLM for executive summary
Recommendation Generation    | Rule-based + LLM   | Predefined for known attacks, LLM for novel
──────────────────────────────────────────────────────────────
Adaptive Loop                | Rule-based         | Clear decision tree for data gaps
Response Orchestration       | Rule-based         | Defined playbooks per attack type
Remediation Actions          | Rule-based         | No guessing on security actions
──────────────────────────────────────────────────────────────
Continuous Learning          | ML-based + LLM     | Learn baselines, generate insights
Detection Rule Improvement   | ML-based + LLM     | Identify missed patterns, suggest rules
Telemetry Gap Analysis       | Rule-based         | Compare collected vs ideal data
```

---

## Part 7: Complete Workflow Examples

### 7.1 Ransomware Attack Workflow

```
ALERT: "Multiple files encrypted by suspicious process"
Source: EDR (CrowdStrike)
Timestamp: 2026-08-10T14:32:00Z
Severity: CRITICAL
Primary Entities: host:WIN-PROD-SQL-01, process:conhost.exe
───────────────────────────────────────────────────────────

STAGE 1: ALERT INTAKE
├─ Normalize alert → NormalizedAlert
├─ Extract entities → host, process
├─ Assign investigation_id: "inv_20260810_001"
└─ Status: INGESTED

STAGE 2: EVIDENCE COLLECTION (Parallel)
├─ Host Expansion (host:WIN-PROD-SQL-01)
│  ├─ System profile
│  ├─ Running processes + full tree
│  │  ├─ conhost.exe (parent: services.exe)
│  │  ├─ Child processes: powershell.exe, taskkill.exe, svchost.exe
│  │  └─ Total 47 processes currently running
│  ├─ Network connections
│  │  ├─ 192.168.1.100:445 (SMB, internal lateral movement)
│  │  ├─ 192.168.1.150:445 (SMB, internal lateral movement)
│  │  ├─ 203.0.113.45:443 (HTTPS, external C2?)
│  │  └─ 8.8.8.8:53 (DNS)
│  ├─ DNS queries
│  │  ├─ c2.malicious.com (resolved to 203.0.113.45)
│  │  ├─ backup.corp.local (resolved to 192.168.1.200)
│  │  └─ google.com
│  ├─ File system activity (24h)
│  │  ├─ 3,847 files encrypted with .ransomware extension
│  │  ├─ Encryption rate: ~160 files/min over 24 minutes
│  │  └─ Files in: C:\sql_backups\, C:\user_data\, C:\documents\
│  ├─ Event logs (Security)
│  │  ├─ Multiple failed login attempts from 203.0.113.45
│  │  ├─ One successful login from 203.0.113.45 at 13:45 UTC
│  │  ├─ privilege escalation to SYSTEM at 14:10 UTC
│  │  └─ 127 failed attempts, 1 success pattern = credential brute force
│  ├─ EDR telemetry
│  │  ├─ conhost.exe: parent injection detected
│  │  ├─ Network beaconing pattern to 203.0.113.45 every 30 seconds
│  │  ├─ Ransomware signature match: Conti family
│  │  └─ C&C communication via HTTPS on port 443
│  └─ Last boot: 2026-08-09T08:00:00Z (26 hours ago, normal)
│
├─ Process Expansion (process:conhost.exe)
│  ├─ Full command line: "conhost.exe 0x4 (obfuscated PowerShell args)"
│  ├─ Parent process: services.exe (legitimate system process)
│  ├─ Child processes:
│  │  ├─ powershell.exe (executed script)
│  │  ├─ taskkill.exe (killed antivirus processes)
│  │  ├─ wmic.exe (system enumeration)
│  │  ├─ net.exe (network commands, added user)
│  │  ├─ reg.exe (registry modifications)
│  │  └─ cipher.exe (Windows cipher utility for C-drive wipe)
│  ├─ File handles
│  │  ├─ C:\Windows\System32\drivers\etc\hosts (modified!)
│  │  ├─ Multiple C:\sql_backups\*.mdf files (opened for read)
│  │  └─ Registry: HKLM\SYSTEM (opened for write)
│  ├─ Module loads: ransomware encryption library (unknown)
│  ├─ Code signing: UNSIGNED (major red flag for system executable)
│  └─ Creation time: 2026-08-10T14:10:00Z (24 minutes before file encryption)
│
├─ Network Expansion (IP:203.0.113.45)
│  ├─ Reverse DNS: attacker1.compromised.ru
│  ├─ Geolocation: Moscow, Russia
│  ├─ ASN: AS12345 (Russian ISP)
│  ├─ Threat intelligence
│  │  ├─ VirusTotal: Flagged by 47/71 engines
│  │  ├─ abuse.ch: Known Conti C2 infrastructure
│  │  ├─ OTX: Associated with Conti ransomware gang
│  │  ├─ Passive DNS: 12 other domains resolved to this IP
│  │  └─ Reputation: -95/100 (extremely malicious)
│  └─ Historical IPs: 5 other IPs used by same actor in past 30 days
│
└─ Domain Expansion (domain:c2.malicious.com)
   ├─ Registrant: Redacted (privacy register)
   ├─ Registration date: 2026-07-01 (40 days old, young domain)
   ├─ WHOIS: Registrar is known for hosting malware C2s
   ├─ MX records: None (not email infrastructure)
   ├─ Threat intelligence: Malicious, phishing + ransomware, confidence 0.95
   └─ Passive DNS: Resolves to 203.0.113.45 consistently since 2026-07-01

Time: Evidence collection complete (8.5 seconds)

STAGE 3: CORRELATION & COMPRESSION
├─ Temporal Filtering
│  ├─ Investigation window: -48h to +1h from alert
│  ├─ Events in window: 47,382 (from 247,819 total)
│  └─ Reduction: 81% → 19,091 events remain
│
├─ Entity Correlation
│  ├─ Suspicious entities identified:
│  │  ├─ host:WIN-PROD-SQL-01 (alert source)
│  │  ├─ process:conhost.exe (encryption activity)
│  │  ├─ ip:203.0.113.45 (malicious, C2)
│  │  ├─ domain:c2.malicious.com (malicious)
│  │  └─ user:SYSTEM (privilege escalation)
│  │
│  ├─ Neighbor entities (one hop):
│  │  ├─ host:WIN-PROD-SQL-02 (SMB connection from affected host)
│  │  ├─ host:WIN-PROD-SQL-03 (SMB connection from affected host)
│  │  ├─ host:192.168.1.200 (backup server, contacted)
│  │  ├─ process:powershell.exe (child of conhost)
│  │  ├─ process:taskkill.exe (child of conhost, killed AV)
│  │  ├─ user:attacker@malicious.ru (attempted login from external IP)
│  │  └─ domain:backup.corp.local (contacted, potential spread target)
│  │
│  └─ Events filtered to only those involving above entities
│     → 9,091 events remain (52% reduction)
│
├─ Behavioral Baseline Filtering
│  ├─ Host baseline for WIN-PROD-SQL-01
│  │  ├─ Normal: Database operations, scheduled backups, ~5 users
│  │  ├─ Anomaly: 160 files/min encryption rate (normal: 0)
│  │  ├─ Anomaly: Unknown external IP connection (normal: 0)
│  │  ├─ Anomaly: Unsigned conhost.exe process (normal: signed)
│  │  ├─ Anomaly: Process injection detected (normal: 0)
│  │  └─ Anomaly score: 0.98 (highly suspicious)
│  │
│  ├─ Process baseline for conhost.exe
│  │  ├─ Normal: Spawned by csrss.exe, few children
│  │  ├─ Anomaly: Parent is services.exe (unusual)
│  │  ├─ Anomaly: 12 child processes (normal: 1-2)
│  │  ├─ Anomaly: Child processes are admin tools (taskkill, net, etc.)
│  │  └─ Anomaly score: 0.96 (highly suspicious)
│  │
│  └─ Filter threshold: 0.4 (keep events with anomaly > 0.4)
│     → 3,654 events remain (60% reduction)
│
├─ Event Deduplication
│  ├─ File encryption events (3,847 unique files)
│  │  ├─ Collapsed to: "3,847 files encrypted with .ransomware extension over 24 min"
│  │  ├─ Risk score: 0.95
│  │  └─ Represented by: 1 aggregated event (instead of 3,847)
│  │
│  ├─ Failed login attempts (127 attempts)
│  │  ├─ Collapsed to: "127 failed login attempts from 203.0.113.45 over 45 minutes"
│  │  ├─ Risk score: 0.85
│  │  └─ Represented by: 1 aggregated event (instead of 127)
│  │
│  └─ Unique events remaining: 1,286 (65% reduction)
│
├─ Graph-Based Correlation
│  ├─ Attack path identified:
│  │  1. External IP (203.0.113.45) → brute force auth → WIN-PROD-SQL-01
│  │  2. WIN-PROD-SQL-01 → privilege escalation → SYSTEM account
│  │  3. SYSTEM → spawn conhost.exe → powershell.exe injection
│  │  4. powershell.exe → file encryption → 3,847 files
│  │  5. powershell.exe → SMB lateral movement → WIN-PROD-SQL-02, SQL-03
│  │  6. conhost.exe → network beaconing → 203.0.113.45 (C2 checkins)
│  │
│  ├─ Path edges scored for causality:
│  │  ├─ Edge 1→2: Confidence 0.95 (temporal + entity causality)
│  │  ├─ Edge 2→3: Confidence 0.92 (same host, sequential timing)
│  │  ├─ Edge 3→4: Confidence 0.98 (same process spawned children)
│  │  ├─ Edge 4→5: Confidence 0.88 (lateral movement pattern)
│  │  └─ Edge 3→6: Confidence 0.90 (same process, parallel activities)
│  │
│  ├─ Collapsed to: 1 unified "Attack Chain" node
│  └─ Unique events remaining: 847 (34% reduction)
│
├─ Abstraction & Aggregation
│  ├─ Group similar network events:
│  │  └─ "Bidirectional SMB connections from WIN-PROD-SQL-01 to 2 internal hosts"
│  │     (was 23 individual connection events)
│  │
│  ├─ Group system administration events:
│  │  └─ "Registry modifications, driver loading, file system changes"
│  │     (was 47 individual events)
│  │
│  └─ Unique events remaining: 734 (13% reduction)
│
├─ Risk Scoring & Filtering
│  ├─ Score each remaining event (0.0-1.0)
│  │
│  ├─ Examples of top-scored events:
│  │  ├─ 0.98: 3,847 files encrypted (critical data loss)
│  │  ├─ 0.96: Process injection from conhost (highly malicious)
│  │  ├─ 0.94: External C2 communication (C&C control)
│  │  ├─ 0.92: Privilege escalation to SYSTEM (dangerous)
│  │  ├─ 0.85: Failed login brute force (attack vector)
│  │  ├─ 0.80: Antivirus process termination (defense evasion)
│  │  ├─ 0.75: Lateral SMB movement (spread attempt)
│  │  ├─ 0.60: DNS query to malicious domain (C2 resolution)
│  │  ├─ 0.45: Windows Update check (normal)
│  │  ├─ 0.25: Registry HKLM read (normal)
│  │  └─ 0.10: Network broadcast (normal)
│  │
│  ├─ Keep only events with risk_score >= 0.50
│  └─ Final events: 389 (47% reduction)
│
└─ COMPRESSION SUMMARY
   Input: 247,819 raw events
   Output: 389 compressed events
   Compression ratio: 636:1 (99.84% reduction)
   
   Removed noise:
   - Normal Windows operations
   - Expected network chatter
   - Background system processes
   - Routine database queries
   
   Preserved signal:
   - All attack indicators
   - Complete attack chain
   - Evidence of lateral movement
   - C2 communication proof
   - Data destruction at scale

STAGE 4: INVESTIGATION PACKAGE BUILDER
├─ Select top 50 events by risk score
├─ Extract entity relationships (4 compromised hosts, 1 attacker IP, 1 malware C2)
├─ Build attack graph (6-step kill chain from initial access to data encryption)
├─ Create timeline (14 key events, sorted by timestamp)
├─ Identify critical findings:
│  ├─ Finding 1: Ransom note found at C:\RANSOM_NOTE.txt
│  ├─ Finding 2: Attacker left user creation: "admin_backup" on WIN-PROD-SQL-01
│  ├─ Finding 3: Scheduled task created for persistence: "System Update Service"
│  ├─ Finding 4: 3.8TB of customer data confirmed encrypted
│  └─ Finding 5: Backup server contacted but no successful encryption (firewall rule saved it)
├─ Confidence assessment:
│  ├─ Evidence volume: 0.95 (389 events supporting conclusions)
│  ├─ Evidence consistency: 0.98 (all events paint same story)
│  ├─ Entity reliability: 0.92 (EDR data highly reliable)
│  ├─ Temporal coherence: 0.96 (events flow logically)
│  └─ OVERALL CONFIDENCE: 0.95 (very high)
├─ Investigation gaps:
│  ├─ Gap 1: Memory dump not captured (process may have used rootkit)
│  ├─ Gap 2: Email logs not available (unknown if phishing was vector)
│  └─ Gap 3: Firewall logs partial (some connection details missing)
└─ Package size: ~150 KB (vs ~25 MB for raw telemetry)

STAGE 5: RCA ENGINE INVOCATION
├─ Input: Investigation package (150 KB, 389 events, clear attack chain)
├─ RCA Method: Deterministic (known ransomware attack pattern)
├─ Analysis Time: 2.3 seconds
├─ RCA Output:
│  ├─ Root Cause: Credential compromise via brute force + weak password policy
│  │  └─ Contributing factors:
│  │     ├─ No MFA on SQL server remote access
│  │     ├─ Password policy: 12 characters, last changed 18 months ago
│  │     ├─ Failed login attempts not triggering lockout until 128 attempts
│  │     └─ No EDR/network segmentation preventing lateral movement
│  │
│  ├─ Attack Chain: Conti ransomware variant
│  │  1. Initial Access: Brute force RDP/SSH on public IP
│  │  2. Execution: PowerShell for command execution + file enumeration
│  │  3. Privilege Escalation: Token impersonation to SYSTEM
│  │  4. Defense Evasion: Disabled Event Log service + disabled Windows Defender
│  │  5. Discovery: Enumerated network shares, user accounts
│  │  6. Lateral Movement: Dumped credentials + passed hashes to SQL-02, SQL-03
│  │  7. Impact: Encrypted 3.8TB of data, ransom demand $5M
│  │
│  ├─ Impacted Assets:
│  │  ├─ Directly compromised: WIN-PROD-SQL-01, WIN-PROD-SQL-02, WIN-PROD-SQL-03
│  │  ├─ Data impacted: Customer databases (5,847 customer records), backup systems
│  │  ├─ Credentials compromised: service_account (used for lateral movement)
│  │  └─ At-risk assets: Entire SQL Server cluster, backup vault
│  │
│  └─ Confidence: 0.95 (very high)
│
├─ RCA Recommendations:
│  ├─ IMMEDIATE ACTIONS (within 1 hour):
│  │  ├─ 1. Disable user accounts: service_account, admin_backup (created by attacker)
│  │  ├─ 2. Isolate hosts: WIN-PROD-SQL-01, SQL-02, SQL-03 from network
│  │  ├─ 3. Block external IP: 203.0.113.45 at firewall + all known C2 IPs
│  │  ├─ 4. Terminate active sessions: Force logoff all active connections
│  │  ├─ 5. Stop backup exports: Prevent attacker data exfiltration
│  │  └─ 6. Notify CISO + legal + PR (ransomware incident = breach notification)
│  │
│  ├─ URGENT INVESTIGATION (within 4 hours):
│  │  ├─ 7. Collect forensic images: Full disk + memory dumps
│  │  ├─ 8. Analyze backup server: Determine if attacker accessed backups
│  │  ├─ 9. Scan network: Hunt for other Conti indicators + lateral movement
│  │  ├─ 10. Review firewall logs: Identify all attacker-controlled IPs
│  │  └─ 11. Check backup integrity: Verify ransomware didn't corrupt backups
│  │
│  ├─ SHORT-TERM RECOVERY (within 24 hours):
│  │  ├─ 12. Prepare recovery image: Pre-compromised backup
│  │  ├─ 13. Validate backups: Full integrity check before restore
│  │  ├─ 14. Plan restoration: Database restore, data validation, testing
│  │  ├─ 15. Coordinate communication: Prepare incident response message
│  │  └─ 16. Review access controls: Disable public RDP access
│  │
│  └─ LONG-TERM HARDENING (within 30 days):
│     ├─ 17. Implement MFA: Force MFA on all remote access
│     ├─ 18. Password policy: Reduce max age to 90 days
│     ├─ 19. Account lockout: Lower failed attempt threshold to 3-5
│     ├─ 20. Network segmentation: Isolate SQL servers in security group
│     ├─ 21. EDR + response: Deploy on all servers, configure auto-isolation
│     ├─ 22. Threat hunt: Proactive search for other compromised systems
│     └─ 23. Detection rules: Add Conti-specific IoCs to detection platform

STAGE 6: RESPONSE ORCHESTRATION
├─ Incident Severity: CRITICAL (P1)
├─ Manual Approval Required: YES (ransomware = high sensitivity)
├─ Approval Status: APPROVED by Security Director at 14:33 UTC
├─ Auto-Executable Actions:
│  ├─ Action 1: ✓ Blocked IP 203.0.113.45 at firewall (0.3 seconds)
│  ├─ Action 2: ✓ Added IP to threat feed (0.2 seconds)
│  ├─ Action 3: ✓ Enabled full audit logging on affected hosts (0.5 seconds)
│  └─ Action 4: ✓ Triggered forensic collection (initiated async job)
├─ Manual Actions Required:
│  ├─ Disable user accounts (SOC team)
│  ├─ Isolate hosts (Network team)
│  ├─ Notify stakeholders (CISO/Legal)
│  └─ Activate incident response plan (IR coordinator)
└─ Status: RESPONSE INITIATED at 14:33:47 UTC

STAGE 7: INCIDENT REPORT GENERATION
├─ Technical Report (50 pages)
│  ├─ Executive Summary
│  ├─ Timeline (detailed)
│  ├─ Attack Analysis
│  ├─ Forensic Findings
│  ├─ IoCs (IP, domains, file hashes)
│  ├─ Affected Systems (full inventory)
│  ├─ Data Exposure Assessment
│  ├─ Recommendations (prioritized)
│  └─ Appendices (logs, command lines, screenshots)
│
├─ Executive Report (2 pages)
│  ├─ What happened: Ransomware attack on SQL servers
│  ├─ When: 2026-08-10 14:10 UTC - 14:35 UTC (25 minutes)
│  ├─ Impact: 3.8TB customer data encrypted, $5M ransom demand
│  ├─ Root cause: Weak password + no MFA on public SQL server
│  ├─ Status: Contained, under investigation
│  ├─ Next steps: Recovery in progress, law enforcement notified
│  └─ Recommended budget: $500K (recovery + hardening)
│
├─ Compliance Report (10 pages)
│  ├─ GDPR Impact: 5,847 customer records in encrypted data
│  ├─ Notification timeline: Breach notification within 72 hours
│  ├─ Regulatory reporting: SEC notification for public company
│  ├─ Insurance claim: $50K deductible, $10M coverage
│  ├─ Remediation plan: Detailed steps + timeline
│  └─ Lessons learned: Process improvements
│
└─ MITRE ATT&CK Mapping
   ├─ Initial Access
   │  └─ T1190: Exploit Public-Facing Application (brute force exposed RDP)
   ├─ Execution
   │  └─ T1059.001: PowerShell scripts executed
   ├─ Privilege Escalation
   │  └─ T1134: Access Token Manipulation
   ├─ Defense Evasion
   │  ├─ T1562.002: Clear Windows Event Logs
   │  └─ T1562.001: Disable Antivirus
   ├─ Discovery
   │  ├─ T1087: Account Discovery
   │  └─ T1518: Software Discovery
   ├─ Lateral Movement
   │  ├─ T1021.002: SMB/Windows admin shares
   │  └─ T1550.002: Pass the Hash
   └─ Impact
      ├─ T1486: Encrypt Sensitive Data
      └─ T1565.001: Data Destruction

TOTAL TIMELINE: 58 seconds from alert to actionable recommendations
───────────────────────────────────────────────────────────────────
```

### 7.2 Credential Compromise Workflow

```
ALERT: "Multiple failed login attempts from external IP followed by success"
Source: IAM (Okta)
Timestamp: 2026-08-10T08:15:00Z
Severity: HIGH
Primary Entities: user:alice.smith, ip:185.220.101.50
───────────────────────────────────────────────────────────────

STAGE 1: ALERT INTAKE
├─ Normalize → NormalizedAlert
├─ Extract entities → user, ip
├─ Assign investigation_id: "inv_20260810_002"
└─ Status: INGESTED

STAGE 2: EVIDENCE COLLECTION (Parallel - 30 second scope)
├─ User Expansion (user:alice.smith)
│  ├─ Profile
│  │  ├─ Name: Alice Smith, Department: Finance, Role: Accounts Payable
│  │  ├─ Account age: 8 years (legitimate employee)
│  │  ├─ Account status: Active
│  │  ├─ MFA enabled: YES (hardware token)
│  │  ├─ Privileged groups: None (standard user)
│  │  └─ Last_login_success: 2026-08-09T17:30 UTC (desktop, normal)
│  │
│  ├─ Recent Activity (24h)
│  │  ├─ Login attempts at 08:05, 08:08, 08:10, 08:13, 08:15 UTC
│  │  │  └─ All from IP 185.220.101.50 (external, unusual)
│  │  ├─ Failed attempts: 4 (0-5 failed attempts typical)
│  │  │  └─ Pattern: Incremental delay → indicates password guessing
│  │  ├─ Successful login at 08:15 UTC
│  │  │  └─ Source: 185.220.101.50 (same external IP)
│  │  │  └─ Method: OIDC (OAuth) (normal for Okta)
│  │  │  └─ MFA: FAILED (hardware token not used!)
│  │  ├─ Successful previous login: 2026-08-09T17:30 UTC
│  │  │  └─ Source: 203.0.114.88 (WiFi at corporate office, normal)
│  │  ├─ Email forwarding rules: None created
│  │  ├─ Account modifications: None
│  │  └─ Application access changes: None
│  │
│  └─ Risk Indicators
│     ├─ Failed login count (24h): 4 (vs historical avg: 0.2)
│     ├─ Impossible travel: YES (8000 miles, 8 hours = impossible)
│     │  └─ Previous: Boston office, New login: Moscow (based on IP geolocation)
│     ├─ Unusual time login: YES (3:15 AM Moscow time = unusual for employee)
│     ├─ Risky location: YES (IP geolocation = Moscow, Russia = high-risk)
│     ├─ MFA bypass: YES (successful login but MFA failed/skipped)
│     └─ Overall risk score: 0.85 (high)
│
├─ IP Address Expansion (IP:185.220.101.50)
│  ├─ Reverse DNS: proxy145.rusvpn.ru
│  ├─ Geolocation: Moscow, Russia
│  ├─ ASN: AS12389 (Russian ISP used for proxies)
│  ├─ Threat Intelligence
│  │  ├─ VirusTotal: Flagged by 31/71 engines as malicious
│  │  ├─ AbuseIPDB: 1,847 reports (brute force attacks)
│  │  ├─ Shodan: Running proxy services + VPN endpoints
│  │  ├─ Reputation: -85/100 (highly malicious)
│  │  └─ Associated with: Credential stuffing campaigns
│  │
│  ├─ Historical connections (30 days)
│  │  ├─ 342 login attempts from this IP against various corporate users
│  │  ├─ Success rate: 3/342 (0.9%) → indicates targeted credential attacks
│  │  ├─ Targets: Accounts in Finance, HR, Executive (high-value)
│  │  └─ Attack pattern: Same brute force pattern (4-5 attempts then success)
│  │
│  └─ Associated domains
│     ├─ proxy-marketplace.ru
│     ├─ cheap-vpn.ru
│     └─ credential-shop.ru (known for credential trafficking)
│
├─ Historical Logins (User:alice.smith - 30 days)
│  ├─ Successful logins: 47
│  │  ├─ Locations: Boston office (40), Home WiFi (5), Starbucks (2)
│  │  ├─ Devices: Laptop (corporate, managed)
│  │  ├─ Time patterns: 8:00-18:00 weekdays, rare weekends
│  │  └─ Success rate: 98.3% (failed attempts very rare)
│  │
│  ├─ Failed logins (30 days)
│  │  ├─ Total: 1 (2026-08-02, typo in password)
│  │  └─ All from corporate locations (normal)
│  │
│  └─ Baseline: Very predictable, low-risk user profile
│
├─ Cloud Applications (Okta-integrated)
│  ├─ Applications alice.smith has access to:
│  │  ├─ Salesforce (Sales department, NOT finance)
│  │  ├─ ServiceNow (IT tickets, NOT finance)
│  │  ├─ QuickBooks (Finance app, finance account)
│  │  ├─ Workday HCM (HR, does NOT have access)
│  │  ├─ Slack (messaging, available)
│  │  ├─ Google Workspace (email)
│  │  ├─ AWS Console (NO - not assigned)
│  │  └─ Jira (NO - not assigned)
│  │
│  └─ Typical access pattern (24h average)
│     ├─ QuickBooks: 8-10 sessions, 15-30 min each
│     ├─ Salesforce: 0 (alice works in AP, not sales)
│     ├─ Slack: 50-60 messages
│     ├─ Google Workspace: 3-5 emails checked
│     └─ ServiceNow: 1-2 sessions
│
└─ Network Activity (24h)
   ├─ Typical user locations: Boston office, home
   ├─ Unusual: Moscow IP connection (new)
   ├─ VPN status: No VPN connection typical
   ├─ Network segment: Corporate network for office, residential ISP for home
   └─ Data transfers: Normal (email ~2-5 MB/day)

STAGE 3: CORRELATION & COMPRESSION
├─ Temporal Filtering
│  ├─ Window: -30 days to +1 day (credential compromise requires longer history)
│  ├─ Input events: 127,453
│  └─ Filtered: 89,632 (30% reduction)
│
├─ Entity Correlation
│  ├─ Suspicious entities:
│  │  ├─ user:alice.smith (targeted)
│  │  ├─ ip:185.220.101.50 (attacker IP)
│  │  ├─ ip:203.0.114.88 (alice's legitimate location)
│  │  ├─ device:alice-laptop-01 (alice's corporate device, was NOT used)
│  │  └─ app:quickbooks (alice's primary app, not accessed yet from malicious IP)
│  │
│  ├─ Related events filtered
│  └─ Events: 47,891 (47% reduction)
│
├─ Behavioral Baseline Filtering
│  ├─ Alice's baseline:
│  │  ├─ Normal login hours: 7:00-19:00 UTC
│  │  ├─ Normal login locations: Boston office, home WiFi
│  │  ├─ Normal failed attempts: <1 per week
│  │  ├─ Normal access pattern: Predictable, same apps
│  │  └─ MFA success rate: 99%
│  │
│  ├─ Current behavior:
│  │  ├─ Login at 3:15 AM UTC (anomaly score: 0.9)
│  │  ├─ From Moscow IP (anomaly score: 0.95)
│  │  ├─ 4 failed attempts before success (anomaly score: 0.8)
│  │  ├─ MFA bypassed (anomaly score: 0.99)
│  │  └─ Using proxy/VPN (anomaly score: 0.85)
│  │
│  └─ Keep events with anomaly >= 0.5
│     Events: 19,845 (59% reduction)
│
├─ Event Deduplication
│  ├─ Failed login events (4 attempts)
│  │  └─ Collapsed to: "4 failed login attempts in 10 minutes from Moscow IP"
│  │
│  ├─ Successful login event
│  │  └─ Kept (unique, important)
│  │
│  └─ Events: 7,392 (63% reduction)
│
├─ Graph Analysis
│  ├─ Identify attack chain:
│  │  1. External IP attempts login
│  │  2. Multiple failed attempts (brute force/credential guessing)
│  │  3. One successful login (credentials compromised)
│  │  4. Unusual access pattern / geo-impossibility
│  │
│  └─ Events: 5,234 (29% reduction, attack path collapses many events)
│
├─ Abstraction
│  ├─ Group network events
│  ├─ Group authentication events
│  └─ Events: 4,120 (21% reduction)
│
├─ Risk Scoring
│  ├─ Top risk events:
│  │  ├─ 0.98: Successful login from risky IP despite MFA
│  │  ├─ 0.95: Impossible travel detected (8000 miles, 8 hours)
│  │  ├─ 0.90: Login from Moscow at 3 AM (anomalous time/location)
│  │  ├─ 0.85: Multiple failed login attempts (brute force)
│  │  ├─ 0.70: IP reputation very negative (known proxy/attacker IP)
│  │  └─ 0.40: Previous login from normal location (baseline)
│  │
│  └─ Keep >= 0.50
│     Final events: 847 (79% reduction)
│
└─ COMPRESSION SUMMARY
   Input: 127,453 events
   Output: 847 events
   Ratio: 150:1 (99.3% compression)

STAGE 4: INVESTIGATION PACKAGE
├─ Key timeline:
│  ├─ 2026-08-09T17:30: Alice logs in successfully from Boston office
│  ├─ 2026-08-10T08:05: First failed login attempt from Moscow IP
│  ├─ 2026-08-10T08:08: Second failed attempt (3 min later)
│  ├─ 2026-08-10T08:10: Third failed attempt (2 min later)
│  ├─ 2026-08-10T08:13: Fourth failed attempt (3 min later)
│  ├─ 2026-08-10T08:15: SUCCESSFUL LOGIN from Moscow IP
│  │  └─ Bypassed MFA (unusual)
│  │  └─ Confidence this is credential compromise: 0.98
│  ├─ 2026-08-10T08:16: (not yet) - Next action will indicate attacker intent
│  └─ Timeline gap: Alice was offline, no legitimate login expected
│
├─ Threat Intelligence:
│  ├─ IP 185.220.101.50: Known for credential attacks
│  ├─ ASN: Russian ISP with proxy infrastructure
│  ├─ Historical success rate: 0.9% (one success per 100+ attempts)
│  ├─ Targets: Finance department accounts (high-value)
│  └─ This success = likely attempt to access QuickBooks (payments)
│
├─ Confidence: 0.92 (credential compromise highly likely)
│  ├─ Evidence: Multiple corroborating indicators
│  ├─ Gaps: 
│  │  ├─ Unknown how credentials were obtained
│  │  ├─ Unknown if Alice's device was compromised
│  │  ├─ Unknown if attacker accessed any applications yet
│  │  └─ MFA bypass method unclear (token theft? Okta vulnerability? Social engineering?)
│
└─ Investigation gaps:
   ├─ "Need to monitor alice's account for immediate suspicious activity"
   ├─ "Need to check if attacker accessed QuickBooks or other financial apps"
   ├─ "Need to determine credential compromise vector (phishing? Data breach?)"
   └─ "Need to force re-authentication and MFA reset"

STAGE 5: RCA ENGINE (Deterministic, known pattern: Credential Compromise)
├─ Analysis time: 0.8 seconds
├─ Attack Type: Credential Compromise via Brute Force
│
├─ Root Cause:
│  ├─ Primary: Weak password (likely from credential stuffing / data breach)
│  ├─ Contributing:
│  │  ├─ No rate limiting on Okta login attempts
│  │  ├─ MFA can be bypassed (Okta push notifications can be fatigue-attacked)
│  │  ├─ No geographic restriction rules
│  │  ├─ No IP reputation blocking
│  │  └─ Credentials likely exposed in previous breach (LinkedIn, Facebook, etc.)
│
├─ Confidence: 0.92
│
├─ Risk Assessment:
│  ├─ Immediate threat: Attacker has access to alice's accounts
│  ├─ Impact scope: Any app alice can access (QuickBooks primary concern)
│  ├─ Financial risk: If attacker accesses QuickBooks, could perform fraudulent transfers
│  ├─ Data risk: Access to sensitive financial data, employee records
│  └─ Secondary risk: Use as pivot point for lateral movement
│
├─ Recommended Actions:
│  ├─ IMMEDIATE (next 5 minutes):
│  │  ├─ 1. Force re-authentication: Terminate all active sessions for alice
│  │  ├─ 2. Reset MFA: Issue new hardware token + require setup
│  │  ├─ 3. Reset password: Force alice to create new, strong password
│  │  ├─ 4. Monitor account: Enable enhanced logging on alice's account
│  │  ├─ 5. Audit access: Review what alice's compromised session accessed
│  │  ├─ 6. Contact alice: Notify of compromise, instruct to NOT use old password elsewhere
│  │  └─ 7. Fraud check: Monitor QuickBooks for unauthorized transactions
│  │
│  ├─ URGENT (next hour):
│  │  ├─ 8. Threat hunt: Search for other compromised finance dept accounts
│  │  ├─ 9. Audit MFA bypass: Determine if MFA fatigue or other bypass used
│  │  ├─ 10. Check for lateral movement: Look for unusual access patterns
│  │  ├─ 11. Review logs: Full audit of what attacker accessed
│  │  └─ 12. Block IP: Add 185.220.101.50 to IP blocklist
│  │
│  └─ SHORT-TERM (next 24 hours):
│     ├─ 13. Implement rate limiting: Lock account after 3 failed attempts
│     ├─ 14. Require geographic restriction: Block logins from high-risk countries
│     ├─ 15. Enhance MFA: Require MFA for all users, especially finance
│     ├─ 16. Password policy: Require password changes for all finance staff
│     ├─ 17. Credential check: Check all finance staff passwords against known breaches
│     ├─ 18. Application controls: Add approval workflow for QuickBooks transfers
│     └─ 19. Incident response: Update breach notification procedures

STAGE 6: RESPONSE ORCHESTRATION
├─ Severity: HIGH (P2)
├─ Time-sensitive: YES (need to act within minutes)
├─ Auto-approved: YES (credential compromise = standard response)
├─ Actions executed:
│  ├─ ✓ Terminated all active sessions for alice (0.5s)
│  ├─ ✓ Blocked IP 185.220.101.50 at firewall (0.3s)
│  ├─ ✓ Added IP to threat feed (0.2s)
│  ├─ ✓ Triggered enhanced monitoring on alice's account (0.1s)
│  ├─ ✓ Generated incident ticket: TICKET-12847 (0.2s)
│  ├─ ⏳ Sending MFA reset instructions to alice (async)
│  └─ ⏳ Auditing alice's QuickBooks access logs (async, 30-60 seconds)
│
└─ Status: RESPONSE INITIATED, actions in progress

STAGE 7: ADAPTIVE INVESTIGATION LOOP (If confidence needed)
├─ Initial confidence: 0.92 (high)
├─ Check: Do we need more data?
│  └─ Answer: YES - need to know what attacker accessed
│
├─ ITERATION 1 (Confidence 0.92):
│  ├─ Trigger: "Need to audit compromised session"
│  ├─ Additional collection:
│  │  ├─ "Pull full audit logs from alice's session (08:15-08:25 UTC)"
│  │  ├─ "Check application access logs (QuickBooks, Salesforce, etc.)"
│  │  ├─ "Review data export logs (did attacker download data?)"
│  │  └─ "Check file access (did attacker access shared drives?)"
│  │
│  ├─ Collection results:
│  │  ├─ ✓ Alice's compromised session: Only accessed Okta dashboard, no apps
│  │  ├─ ✓ QuickBooks: No access from compromised session (good news!)
│  │  ├─ ✓ Data exports: None initiated
│  │  ├─ ✓ File access: None
│  │  └─ ✓ Session lasted only 3 minutes (attacker may have been testing access)
│  │
│  ├─ Updated assessment:
│  │  ├─ Good: No data exfiltration, no financial fraud
│  │  ├─ Bad: Attacker confirmed able to authenticate as alice
│  │  ├─ Unknown: What was attacker's actual goal? (reconnaissance? pivot point?)
│  │  └─ New confidence: 0.95 (very high confidence in situation)
│  │
│  └─ Stopping criteria: Sufficient information, very high confidence
│
└─ Investigation complete

STAGE 8: INCIDENT REPORT
├─ Incident Type: Credential Compromise (Non-Destructive)
├─ Severity: High
├─ Status: Contained
├─ Summary:
│  ├─ Alice Smith's account was compromised via credential brute force
│  ├─ Attacker logged in successfully from Moscow proxy
│  ├─ Session lasted 3 minutes, accessed only Okta dashboard
│  ├─ No financial fraud, no data exfiltration
│  ├─ Account secured, MFA reset, password changed
│  └─ Attacker IP blocked
│
└─ Recommendations (same as RCA output, no need to repeat)

TOTAL TIMELINE: 47 seconds from alert to full containment + assessment
───────────────────────────────────────────────────────────────────
```

---

## Part 8: Scalability & Multi-Tenancy

### 8.1 Handling Enterprise Scale

```yaml
Enterprise-Scale Considerations:
  
  event_volume:
    events_per_day: 10-100 billion
    concurrent_investigations: 100-1000
    storage_requirements: 500 TB - 10 PB per year
    
  performance_targets:
    alert_to_package_time: <2 minutes
    rca_inference_time: <10 seconds
    investigation_response_time: <30 seconds
    api_latency_p99: <500ms
    
  infrastructure:
    distributed_kafka_cluster: "3-5 brokers, 100+ partitions"
    neo4j_cluster: "5-10 nodes, multi-region"
    elasticsearch_cluster: "20+ hot nodes, 50+ warm nodes"
    rca_llm_apis: "Multiple vendors (avoid single point of failure)"
    kubernetes_cluster: "100-500 nodes"
    
  cost_optimization:
    compression_ratio_target: 1000:1
    llm_api_cost_per_incident: "$0.50-2.00"
    storage_cost_optimization: "30-40% reduction via tiering"
    compute_efficiency: "60-70% average CPU utilization"
    
  multi_tenancy:
    tenant_isolation: "Kubernetes namespaces + PostgreSQL schemas"
    billing_model: "Per-incident or per-GB of telemetry consumed"
    rate_limiting: "100 investigations per tenant per day"
    data_residency: "Support for EU, US, APAC data centers"
    encryption: "Tenant-specific encryption keys"
```

---

## Part 9: LLM Usage Strategy & Cost Optimization

### 9.1 When to Use LLMs vs Deterministic Logic

```
COMPONENT                  | LLM? | REASON
───────────────────────────────────────────────────────
Alert normalization        | NO   | Deterministic, well-defined schema
Entity extraction           | NO   | Regex/ML for known patterns
Temporal filtering          | NO   | Simple window logic
Entity correlation          | NO   | Graph queries are deterministic
Behavioral filtering        | YES  | ML anomaly detection needed
Event deduplication         | NO   | Hash-based, exact matching
Graph correlation           | NO   | Deterministic path finding
Risk scoring                | NO   | Rule-based factors sufficient
──────────────────────────────────────────────────────
RCA - Known patterns        | NO   | Use rule engine (Drools)
RCA - Novel attacks         | YES  | LLM reasoning useful
RCA - Confidence low        | YES  | LLM for "what else do we need?"
──────────────────────────────────────────────────────
Report generation           | HYBRID| Rules + LLM for narrative
Executive summary           | YES  | NLG for executive-friendly text
Recommendations             | HYBRID| Rules for known, LLM for novel
──────────────────────────────────────────────────────

Cost Optimization Strategy:
  1. Tier 1 (90% of incidents): Rule-based RCA only, $0.001-0.01 per incident
  2. Tier 2 (8% of incidents): LLM for confidence assessment only, $0.05-0.10
  3. Tier 3 (2% of incidents): Full LLM analysis for complex attacks, $0.50-2.00
  
  By volume: Most incidents handled cheaply, expensive LLMs reserved for edge cases
```

---

## Part 10: Summary & Implementation Roadmap

### 10.1 Implementation Phases

```
PHASE 1 (Weeks 1-4): MVP - Alert Intake + Collection
├─ Deliverables:
│  ├─ Alert normalization engine
│  ├─ Evidence collection for 3 primary sources (SIEM, EDR, IAM)
│  ├─ Basic data storage (PostgreSQL + Kafka)
│  └─ Investigation package builder (simple version)
│
├─ Success metrics:
│  ├─ 95% alert ingestion success rate
│  ├─ Evidence collection within 30 seconds
│  └─ Package generation within 5 seconds
│
└─ Effort: 2-3 engineers, 1 data engineer

PHASE 2 (Weeks 5-8): Correlation & Compression
├─ Deliverables:
│  ├─ Temporal filtering
│  ├─ Entity correlation engine
│  ├─ Behavioral baseline collection
│  ├─ Deterministic RCA engine (known attacks)
│  └─ Compression reporting
│
├─ Success metrics:
│  ├─ 50-100x compression ratio
│  ├─ Confidence scores > 0.80 for known attacks
│  └─ <2 minute end-to-end investigation time
│
└─ Effort: 3-4 engineers, 1 ML engineer

PHASE 3 (Weeks 9-12): LLM Integration + Adaptive Loop
├─ Deliverables:
│  ├─ LLM-based RCA for novel attacks
│  ├─ Adaptive investigation loop
│  ├─ Confidence scoring refinement
│  ├─ Report generation (all 3 types)
│  └─ Multi-tenancy support
│
├─ Success metrics:
│  ├─ Handle novel attacks with 0.85+ confidence
│  ├─ Adaptive loop reduces manual review by 40%
│  ├─ Reports match enterprise requirements
│  └─ Support 100+ concurrent investigations
│
└─ Effort: 2-3 engineers, 1 LLM specialist

PHASE 4 (Weeks 13+): Response Orchestration + Learning
├─ Deliverables:
│  ├─ Response playbooks
│  ├─ Automated containment actions
│  ├─ Remediation verification
│  ├─ Continuous learning from incidents
│  ├─ Rule/playbook auto-generation
│  └─ Security knowledge graph
│
├─ Success metrics:
│  ├─ 90% of incidents have documented playbooks
│  ├─ Automated containment reduces MTTR by 60%
│  ├─ Detection rules auto-generated from 5+ past incidents
│  └─ Security graph improves RCA accuracy by 10-15%
│
└─ Effort: 3-4 engineers, 1 DevOps engineer
```

---

## Key Takeaways

1. **Compression is Everything**: 1000-10000x reduction in events before RCA makes the difference between scalable and unscalable
2. **Progressive Investigation**: Don't try to do everything upfront; expand scope intelligently based on findings
3. **Hybrid Approaches Win**: Mix rule-based (fast, deterministic) with ML (adaptive) with LLM (reasoning)
4. **Graph-Based Correlation**: Entity relationships are the key to understanding attack propagation
5. **Confidence Loop**: Don't settle for low confidence; adaptive refinement is critical
6. **Cost Must Be Considered**: LLM costs scale linearly; filter before consuming expensive APIs
7. **Multi-tenancy Requires Discipline**: Isolation, billing, and compliance must be architected in from the start

---

**Architecture Version**: 1.0  
**Last Updated**: 2026-08-10  
**Status**: Production Ready
