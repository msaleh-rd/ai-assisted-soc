# AI-Native SOC Platform - API & Schema Reference

## Part 1: Core API Specifications

### 1.1 Alert Intake API

```
POST /api/v1/alerts/ingest
Content-Type: application/json

Request:
{
  "source_system": "crowdstrike|splunk|cortex_xdr|okta|guardduty",
  "source_name": "string",
  "raw_alert": {
    // Vendor-specific format (will be normalized)
  }
}

Response:
{
  "status": "accepted|rejected|deduplicated",
  "alert_id": "uuid",
  "correlation_id": "uuid",
  "investigation_id": "uuid (if investigation started)",
  "reason": "string (if rejected or deduplicated)"
}

Deduplication:
- If exact duplicate detected within 30-minute window:
  Returns existing alert_id with status="deduplicated"
- Occurrence count incremented
- Last_seen timestamp updated
```

### 1.2 Investigation Package API

```
GET /api/v1/investigations/{investigation_id}/package

Response:
{
  "investigation_id": "uuid",
  "status": "collecting|compressing|packaging|analyzing|complete",
  "package": InvestigationPackage (see schema below),
  "compression_stats": {
    "raw_events_input": 1247819,
    "final_events_output": 389,
    "compression_ratio": 3205,
    "stages": {
      "temporal_filtering": 0.81,
      "entity_correlation": 0.52,
      "behavioral_filtering": 0.60,
      "deduplication": 0.65,
      "graph_analysis": 0.47,
      "abstraction": 0.87,
      "risk_scoring": 0.47
    }
  },
  "timing": {
    "alert_received": "2026-08-10T14:32:00Z",
    "collection_complete": "2026-08-10T14:32:45Z",
    "correlation_complete": "2026-08-10T14:33:15Z",
    "packaging_complete": "2026-08-10T14:33:30Z",
    "total_time_seconds": 58
  }
}
```

### 1.3 RCA Invocation API

```
POST /api/v1/rca/analyze

Request:
{
  "investigation_id": "uuid",
  "use_llm": true|false,
  "additional_context": {
    "business_impact_level": "critical|high|medium|low",
    "compliance_context": "gdpr|hipaa|pci_dss|sox|none",
    "custom_instructions": "string"
  }
}

Response:
{
  "rca_id": "uuid",
  "investigation_id": "uuid",
  "status": "analyzing|complete|failed",
  "root_cause": RootCause,
  "attack_phases": [AttackPhase],
  "impacted_assets": [ImpactedAsset],
  "recommendations": [Recommendation],
  "overall_confidence": 0.95,
  "analysis_time_seconds": 12.5,
  "model_used": "llm|deterministic"
}
```

### 1.4 Response Orchestration API

```
POST /api/v1/incidents/{investigation_id}/respond

Request:
{
  "approved_by": "username",
  "approval_timestamp": "2026-08-10T14:33:50Z",
  "actions": [
    {
      "action_id": "uuid",
      "action_type": "disable_user|isolate_host|block_ip|kill_process|...",
      "target": "entity_id",
      "auto_approved": true|false,
      "parameters": {}
    }
  ]
}

Response:
{
  "incident_id": "uuid",
  "actions_executed": [
    {
      "action_id": "uuid",
      "status": "executed|pending|failed",
      "execution_time": "2026-08-10T14:33:52Z",
      "result": "string",
      "error": "string (if failed)"
    }
  ],
  "overall_status": "success|partial_success|failed"
}
```

---

## Part 2: Core Data Schemas

### 2.1 Alert Normalization Schema (TypeScript/JSON)

```typescript
interface NormalizedAlert {
  // Metadata
  alert_id: string; // UUID v4
  correlation_id: string; // UUID v4 for grouping related alerts
  timestamp_generated: ISO8601String;
  timestamp_received: ISO8601String;
  
  // Source Information
  source_system: 'siem' | 'xdr' | 'edr' | 'cloud' | 'iam' | 'email' | 'webhook';
  source_name: string; // e.g., "CrowdStrike", "Splunk", "Okta"
  source_region?: string; // Data residency indicator
  
  // Alert Categorization
  alert_name: string; // Human-readable alert title
  alert_description: string;
  alert_category: MitreATTACKTactic;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  confidence: number; // 0.0-1.0, provider's confidence
  status: 'new' | 'ongoing' | 'resolved';
  
  // Primary Entities (extracted from alert)
  primary_entities: {
    user?: EntityUser;
    host?: EntityHost;
    process?: EntityProcess;
    ip_address?: string; // IPv4 or IPv6
    domain?: string;
    file_hash?: FileHash;
    cloud_resource?: EntityCloudResource;
    email_address?: string;
    url?: string;
  };
  
  // Secondary Entities (mentioned in alert)
  secondary_entities?: Entity[];
  
  // Raw Alert (preserved for reference)
  raw_alert: Record<string, any>;
  
  // Alert Metadata
  alert_metadata: {
    rule_id?: string;
    rule_name?: string;
    rule_version?: string;
    mitre_tactics?: string[]; // e.g., ["T1078.003"]
    mitre_techniques?: string[];
    cve_references?: string[];
    threat_intelligence_hits?: string[];
  };
  
  // Alert Context
  context?: {
    customer_id?: string; // Multi-tenancy
    investigation_id?: string; // Assigned during intake
    occurrence_count?: number; // If deduplicated
    last_occurrence?: ISO8601String;
    first_occurrence?: ISO8601String;
  };
}

// Entity Types
interface EntityUser {
  id: string; // samAccountName, email, UID
  name?: string;
  domain?: string;
  email?: string;
  source_system?: string;
}

interface EntityHost {
  id: string; // hostname or IP
  hostname?: string;
  ip_addresses?: string[];
  mac_address?: string;
  operating_system?: string;
  source_system?: string;
}

interface EntityProcess {
  id: string;
  path?: string;
  name?: string;
  command_line?: string;
  pid?: number;
  hash_md5?: string;
  hash_sha256?: string;
}

interface EntityCloudResource {
  resource_id: string;
  resource_type: string; // 'ec2', 's3', 'rds', 'iam_role', etc.
  account_id?: string;
  region?: string;
  arn?: string;
}

interface FileHash {
  md5?: string;
  sha1?: string;
  sha256: string;
  ssdeep?: string;
  type?: 'executable' | 'document' | 'archive' | 'unknown';
}

type MitreATTACKTactic = 
  | 'reconnaissance'
  | 'resource_development'
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'privilege_escalation'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'lateral_movement'
  | 'collection'
  | 'command_and_control'
  | 'exfiltration'
  | 'impact';
```

### 2.2 Enriched Context Schema

```typescript
interface EnrichedContext {
  alert_id: string;
  collection_timestamp: ISO8601String;
  collection_duration_seconds: number;
  
  // User-centric enrichment
  user_context?: {
    profile: {
      uid: string;
      name: string;
      department?: string;
      manager?: string;
      title?: string;
      account_age_days: number;
      last_login?: ISO8601String;
      account_status: 'active' | 'disabled' | 'locked';
      password_age_days?: number;
      mfa_enabled?: boolean;
      privileged_groups?: string[];
    };
    recent_activity: {
      login_attempts_24h?: LoginAttempt[];
      email_forwards?: string[];
      recent_role_changes?: RoleChange[];
      access_reviews?: AccessReview[];
    };
    risk_indicators: {
      failed_login_count_24h: number;
      impossible_travel: boolean;
      unusual_time_login: boolean;
      risky_location: boolean;
      idp_risk_score?: number;
    };
  };
  
  // Host-centric enrichment
  host_context?: {
    profile: {
      hostname: string;
      ip_addresses: string[];
      mac_address?: string;
      os: string;
      os_version?: string;
      domain?: string;
      dns_servers?: string[];
      time_sync_status?: 'synced' | 'unsynced';
      last_boot?: ISO8601String;
    };
    security_posture: {
      antivirus_enabled: boolean;
      antivirus_version?: string;
      antivirus_definitions_age_hours?: number;
      firewall_enabled?: boolean;
      edr_enabled?: boolean;
      edr_agent_version?: string;
      patches_missing?: number;
      critical_patches_missing?: number;
      last_scan_date?: ISO8601String;
    };
    recent_activity: {
      process_tree?: ProcessNode[];
      network_connections?: NetworkConnection[];
      dns_queries?: DNSQuery[];
      file_modifications?: FileModification[];
      registry_changes?: RegistryChange[];
    };
  };
  
  // Network-centric enrichment
  network_context?: {
    flows_24h?: NetworkFlow[];
    dns_resolutions_72h?: DNSResolution[];
    threat_indicators?: {
      suspicious_ports?: number[];
      known_malicious_ips?: string[];
      beaconing_detected?: boolean;
      data_exfiltration_indicators?: boolean;
      command_control_indicators?: boolean;
    };
  };
  
  // Threat Intelligence enrichment
  threat_intelligence?: {
    enrichment_timestamp: ISO8601String;
    indicators?: ThreatIndicator[];
    reputation_scores?: {
      ip_reputation?: number; // -100 to 100
      domain_reputation?: number;
      file_reputation?: number;
    };
  };
  
  // Collection metadata
  collection_metadata?: {
    sources_queried: string[];
    sources_failed?: string[];
    rate_limit_hit?: boolean;
    timeout_occurred?: boolean;
  };
}

interface LoginAttempt {
  timestamp: ISO8601String;
  status: 'success' | 'failure';
  source_ip: string;
  location?: string;
  device?: string;
  mfa_used?: boolean;
}

interface NetworkConnection {
  timestamp: ISO8601String;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  protocol: 'tcp' | 'udp';
  process?: string;
  connection_state?: 'established' | 'listening' | 'closed';
  bytes_sent?: number;
  bytes_received?: number;
}

interface ProcessNode {
  pid: number;
  name: string;
  path: string;
  command_line?: string;
  hash_sha256?: string;
  created: ISO8601String;
  terminated?: ISO8601String;
  parent_pid?: number;
  user?: string;
  privileges?: string;
  children?: ProcessNode[];
}

interface ThreatIndicator {
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'email' | 'url';
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  sources: string[]; // ['virustotal', 'abuse.ch', etc.]
  confidence: number;
  malware_families?: string[];
  mitre_techniques?: string[];
  last_seen?: ISO8601String;
}
```

### 2.3 Compressed Event Schema

```typescript
interface CompressedEvent {
  event_id: string; // UUID for this compressed event
  event_type: string;
  timestamp: ISO8601String;
  timestamp_range?: [ISO8601String, ISO8601String]; // For aggregated events
  
  // Which original events were compressed into this
  source_events?: {
    event_ids: string[];
    occurrence_count: number;
    compression_ratio: number; // 100 original events -> 1 compressed
  };
  
  // Core event data
  primary_entity: Entity;
  secondary_entities?: Entity[];
  action_type: string;
  target?: string | Entity;
  
  // Compression metadata
  compression_stage: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  compression_reason: string; // Why this event was compressed
  
  // Risk assessment
  anomaly_score: number; // 0.0-1.0
  risk_score: number; // 0.0-1.0
  risk_factors: string[]; // ['impossible_travel', 'rare_process', etc.]
  
  // Detailed content
  summary: string; // Human-readable summary
  raw_data?: Record<string, any>; // Important fields preserved
  
  // Relationships
  relationships?: {
    related_event_ids: string[];
    causal_evidence?: boolean;
  };
  
  // Source tracking
  source_system: string;
  source_alert_id?: string;
}

interface Entity {
  entity_type: 'user' | 'host' | 'process' | 'ip' | 'domain' | 'file' | 'cloud_resource' | 'email' | 'url';
  entity_id: string;
  entity_name?: string;
  risk_score?: number;
}
```

### 2.4 Investigation Package Schema

```typescript
interface InvestigationPackage {
  // Metadata
  investigation_id: string;
  alert_id: string;
  package_generated_timestamp: ISO8601String;
  package_version: string; // "1.0"
  
  // Investigation Scope
  investigation_scope: {
    start_time: ISO8601String;
    end_time: ISO8601String;
    duration_hours: number;
  };
  
  // Compression Statistics
  compression_stats: {
    raw_events_collected: number;
    events_after_compression: number;
    compression_ratio: number;
    compression_by_stage: Record<string, number>;
  };
  
  // Core Components
  metadata: InvestigationMetadata;
  entity_relationships: EntityRelationship[];
  timeline: TimelineEvent[];
  attack_graph: AttackGraph;
  key_findings: Finding[];
  statistical_summary: StatisticalSummary;
  confidence_assessment: ConfidenceAssessment;
  
  // Investigation Quality
  investigation_gaps: InvestigationGap[];
  data_quality_notes?: string[];
  
  // Evidence Summary (for fast review)
  evidence_summary: {
    total_events: number;
    critical_events: number;
    suspicious_patterns: SuspiciousPattern[];
    indicators_of_compromise: IOC[];
  };
}

interface InvestigationMetadata {
  original_alert_timestamp: ISO8601String;
  collection_timestamp: ISO8601String;
  investigation_initiated_by: string; // System name or user
  correlation_id: string;
  customer_id?: string; // Multi-tenancy
}

interface EntityRelationship {
  from_entity: Entity;
  to_entity: Entity;
  relationship_type: string; // 'logged_into', 'executed', 'connected_to', etc.
  evidence_count: number;
  time_range: [ISO8601String, ISO8601String];
  risk_score: number;
  reason: string; // Why this relationship is suspicious
  evidence_ids?: string[]; // Compressed event IDs supporting this
}

interface TimelineEvent {
  timestamp: ISO8601String;
  event_id: string;
  event_type: string;
  description: string;
  entities_involved: Entity[];
  risk_score: number;
  evidence_count: number; // How many original events compressed into this
  details: Record<string, any>;
  mitre_techniques?: string[];
}

interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  attack_summary: string;
  total_phases: number;
}

interface AttackGraphNode {
  node_id: string;
  timestamp: ISO8601String;
  activity_type: string;
  description: string;
  entities: Entity[];
  mitre_tactic: string;
  mitre_techniques: string[];
  risk_score: number;
  evidence_count: number;
}

interface AttackGraphEdge {
  from_node_id: string;
  to_node_id: string;
  confidence: number; // 0.0-1.0, likelihood of causal relationship
  reason: string;
  temporal_gap_seconds: number;
}

interface Finding {
  finding_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence: string[];
  mitre_techniques: string[];
  risk_score: number;
  recommendation?: string;
}

interface StatisticalSummary {
  total_events_analyzed: number;
  critical_events: number;
  high_risk_events: number;
  medium_risk_events: number;
  low_risk_events: number;
  entity_statistics: {
    unique_users: number;
    unique_hosts: number;
    unique_processes: number;
    unique_ips: number;
    unique_domains: number;
  };
  temporal_statistics: {
    investigation_duration_hours: number;
    events_per_hour: number;
    peak_activity_hour: number;
    activity_concentration: string;
  };
}

interface ConfidenceAssessment {
  overall_confidence: number; // 0.0-1.0
  confidence_by_factor: {
    evidence_volume: number;
    evidence_consistency: number;
    entity_reliability: number;
    temporal_coherence: number;
  };
  confidence_gaps: ConfidenceGap[];
}

interface ConfidenceGap {
  gap_type: 'evidence_missing' | 'data_unavailable' | 'uncertain_data' | 'temporal_gap';
  description: string;
  impact: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  recommended_action: string;
}

interface InvestigationGap {
  gap_type: 'evidence_missing' | 'data_unavailable';
  description: string;
  impact: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  recommended_action: string;
}

interface IOC {
  indicator: string;
  indicator_type: 'ip' | 'domain' | 'hash' | 'email' | 'url';
  severity: 'critical' | 'high' | 'medium';
  sources: string[];
  first_seen: ISO8601String;
  last_seen: ISO8601String;
}

interface SuspiciousPattern {
  pattern_name: string;
  description: string;
  confidence: number;
  events_involved: number;
  risk_score: number;
}
```

### 2.5 RCA Result Schema

```typescript
interface RCAResult {
  rca_id: string;
  investigation_id: string;
  analysis_timestamp: ISO8601String;
  analysis_method: 'llm' | 'deterministic' | 'hybrid';
  analysis_duration_seconds: number;
  
  // Root Cause Analysis
  root_cause: {
    primary_cause: string;
    description: string;
    confidence: number;
    evidence_supporting: string[];
    mitre_technique: string;
    mitre_tactic: string;
    
    contributing_factors?: {
      factor: string;
      impact: string;
      confidence: number;
    }[];
  };
  
  // Attack Phases
  attack_phases: {
    phase_number: number;
    phase_name: string;
    description: string;
    techniques: string[]; // MITRE IDs
    duration: [ISO8601String, ISO8601String];
    entities_involved: Entity[];
    confidence: number;
    evidence_count: number;
  }[];
  
  // Impacted Assets
  impacted_assets: {
    asset_type: string;
    identifier: string;
    impact_type: string;
    impact_confidence: number;
    access_scope: string;
    data_exposure_risk: 'critical' | 'high' | 'medium' | 'low';
    remediation_status: 'pending' | 'in_progress' | 'completed' | 'unknown';
    estimated_exposure?: {
      users_affected?: number;
      records_at_risk?: number;
      systems_compromised?: number;
    };
  }[];
  
  // Confidence & Quality
  overall_confidence: number;
  confidence_reasoning: string;
  investigation_gaps: InvestigationGap[];
  
  // Recommendations
  recommendations: {
    priority: 'immediate' | 'urgent' | 'high' | 'medium' | 'low';
    action_type: 'containment' | 'investigation' | 'remediation' | 'prevention' | 'hardening';
    description: string;
    rationale: string;
    expected_impact: string;
    implementation: string;
    estimated_effort_hours?: number;
    estimated_cost?: number;
  }[];
  
  // MITRE Mapping
  mitre_ttps: {
    tactic: string;
    techniques: string[];
    sub_techniques?: string[];
  }[];
  
  // Analysis Metadata
  analysis_metadata: {
    input_event_count: number;
    key_events_analyzed: number;
    relationships_analyzed: number;
    attack_patterns_matched: number;
    rule_matches?: string[];
  };
  
  // Detailed Attack Narrative
  narrative?: string; // Optional: LLM-generated attack story
}
```

### 2.6 Response Action Schema

```typescript
interface ResponseAction {
  action_id: string;
  investigation_id: string;
  incident_id: string;
  
  // Action Definition
  action_type: 
    | 'disable_user'
    | 'reset_password'
    | 'force_logout'
    | 'revoke_mfa'
    | 'isolate_host'
    | 'kill_process'
    | 'block_ip'
    | 'block_domain'
    | 'kill_session'
    | 'backup_isolation'
    | 'network_segmentation'
    | 'revoke_credentials'
    | 'escalate_alert'
    | 'notify_users'
    | 'run_threat_hunt'
    | 'collect_forensics'
    | 'export_data';
  
  // Target
  target_type: 'user' | 'host' | 'ip' | 'domain' | 'process' | 'application' | 'cloud_resource';
  target_id: string;
  target_details: Record<string, any>;
  
  // Parameters
  parameters: Record<string, any>;
  
  // Approval
  requires_approval: boolean;
  approved_by?: string;
  approval_timestamp?: ISO8601String;
  approval_reason?: string;
  rejection_reason?: string;
  
  // Execution
  status: 'pending' | 'approved' | 'rejected' | 'executing' | 'executed' | 'failed' | 'cancelled';
  executed_at?: ISO8601String;
  execution_duration_seconds?: number;
  result?: {
    success: boolean;
    message: string;
    details?: Record<string, any>;
    error?: string;
    error_code?: string;
  };
  
  // Rollback
  can_rollback: boolean;
  rollback_action_id?: string;
  
  // Metadata
  created_at: ISO8601String;
  created_by: string; // System or user
  risk_level: 'high' | 'medium' | 'low';
  impact_level: 'high' | 'medium' | 'low';
}
```

---

## Part 3: Database Schema Design

### 3.1 PostgreSQL Schema

```sql
-- Core investigation tracking
CREATE TABLE investigations (
  investigation_id UUID PRIMARY KEY,
  alert_id UUID NOT NULL,
  status VARCHAR(50) NOT NULL, -- 'collecting', 'compressing', 'analyzing', 'complete'
  severity VARCHAR(20) NOT NULL,
  customer_id VARCHAR(255),
  started_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP,
  raw_events_count BIGINT,
  compressed_events_count BIGINT,
  compression_ratio NUMERIC(10, 2),
  confidence NUMERIC(3, 2),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_customer_id (customer_id),
  INDEX idx_status (status),
  INDEX idx_started_at (started_at)
);

-- Compressed events
CREATE TABLE events (
  event_id UUID PRIMARY KEY,
  investigation_id UUID NOT NULL REFERENCES investigations(investigation_id),
  event_type VARCHAR(100),
  timestamp TIMESTAMP,
  entity_type VARCHAR(50),
  entity_id VARCHAR(500),
  risk_score NUMERIC(3, 2),
  anomaly_score NUMERIC(3, 2),
  compression_stage SMALLINT,
  occurrence_count INT DEFAULT 1,
  summary TEXT,
  raw_data JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_investigation_id (investigation_id),
  INDEX idx_timestamp (timestamp),
  INDEX idx_entity (entity_type, entity_id),
  INDEX idx_risk_score (risk_score)
);

-- Entity relationships
CREATE TABLE entity_relationships (
  relationship_id UUID PRIMARY KEY,
  investigation_id UUID NOT NULL REFERENCES investigations(investigation_id),
  from_entity_type VARCHAR(50),
  from_entity_id VARCHAR(500),
  to_entity_type VARCHAR(50),
  to_entity_id VARCHAR(500),
  relationship_type VARCHAR(100),
  confidence NUMERIC(3, 2),
  evidence_count INT,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  risk_score NUMERIC(3, 2),
  reason TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_investigation_id (investigation_id),
  INDEX idx_entities (from_entity_type, from_entity_id, to_entity_type, to_entity_id)
);

-- RCA results
CREATE TABLE rca_results (
  rca_id UUID PRIMARY KEY,
  investigation_id UUID NOT NULL REFERENCES investigations(investigation_id),
  root_cause TEXT,
  confidence NUMERIC(3, 2),
  analysis_method VARCHAR(50), -- 'llm', 'deterministic'
  analysis_duration_seconds NUMERIC(8, 2),
  impacted_assets_count INT,
  attack_phases_count SMALLINT,
  overall_impact VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_investigation_id (investigation_id),
  INDEX idx_created_at (created_at)
);

-- Response actions
CREATE TABLE response_actions (
  action_id UUID PRIMARY KEY,
  investigation_id UUID NOT NULL REFERENCES investigations(investigation_id),
  action_type VARCHAR(100),
  target_type VARCHAR(50),
  target_id VARCHAR(500),
  status VARCHAR(50), -- 'pending', 'approved', 'executing', 'executed', 'failed'
  requires_approval BOOLEAN,
  approved_by VARCHAR(255),
  approved_at TIMESTAMP,
  executed_at TIMESTAMP,
  result JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_investigation_id (investigation_id),
  INDEX idx_status (status),
  INDEX idx_target (target_type, target_id)
);

-- Audit logs
CREATE TABLE audit_logs (
  log_id UUID PRIMARY KEY,
  investigation_id UUID REFERENCES investigations(investigation_id),
  action VARCHAR(500),
  actor VARCHAR(255), -- System or user
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  details JSONB,
  INDEX idx_investigation_id (investigation_id),
  INDEX idx_timestamp (timestamp),
  INDEX idx_actor (actor)
);
```

### 3.2 Neo4j Graph Schema (Cypher)

```cypher
// Entity node types
CREATE (:User {
  uid: string UNIQUE,
  name: string,
  department: string,
  email: string,
  risk_score: float,
  compromised: boolean,
  created_at: timestamp
})

CREATE (:Host {
  hostname: string UNIQUE,
  ip_addresses: [string],
  os: string,
  owner: string,
  criticality: string,
  risk_score: float,
  compromised: boolean,
  created_at: timestamp
})

CREATE (:Process {
  name: string,
  path: string,
  hash_sha256: string UNIQUE,
  parent_pid: int,
  risk_score: float,
  malware_indicator: boolean,
  created_at: timestamp
})

CREATE (:IP {
  address: string UNIQUE,
  geolocation: string,
  asn: string,
  reputation: float,
  malicious: boolean,
  created_at: timestamp
})

CREATE (:Domain {
  fqdn: string UNIQUE,
  registrar: string,
  reputation: float,
  malicious: boolean,
  created_at: timestamp
})

CREATE (:File {
  hash_sha256: string UNIQUE,
  name: string,
  malware_family: string,
  reputation: float,
  malicious: boolean,
  created_at: timestamp
})

// Relationships
CREATE (user:User)-[r:LOGGED_INTO {timestamp: datetime, ip_from: string, success: boolean}]->(host:Host)
CREATE (user:User)-[r:BELONGS_TO_GROUP {timestamp: datetime}]->(group)
CREATE (user:User)-[r:COMPROMISED_BY {timestamp: datetime, vector: string}]->(actor)

CREATE (host:Host)-[r:EXECUTED {timestamp: datetime, user: string}]->(process:Process)
CREATE (host:Host)-[r:CONNECTED_TO {timestamp: datetime, port: int, protocol: string}]->(ip:IP)
CREATE (host:Host)-[r:RESOLVED_DOMAIN {timestamp: datetime}]->(domain:Domain)
CREATE (host:Host)-[r:ACCESSED_FILE {timestamp: datetime, action: string}]->(file:File)

CREATE (process:Process)-[r:SPAWNED_CHILD {timestamp: datetime}]->(child:Process)
CREATE (process:Process)-[r:CONNECTED_TO {timestamp: datetime, port: int}]->(ip:IP)
CREATE (process:Process)-[r:MODIFIED_FILE {timestamp: datetime}]->(file:File)
CREATE (process:Process)-[r:USES_TECHNIQUE {confidence: float}]->(ttp)

CREATE (ip:IP)-[r:RESOLVES_TO {timestamp: datetime}]->(domain:Domain)
CREATE (ip:IP)-[r:CONTACTED_BY {timestamp: datetime}]->(process:Process)

CREATE (domain:Domain)-[r:HAS_MX]->(mx_server)
CREATE (domain:Domain)-[r:REGISTERED_AT {date: datetime}]->(registrar)

CREATE (file:File)-[r:CREATED_BY {timestamp: datetime}]->(process:Process)
CREATE (file:File)-[r:HASH_MATCHES {confidence: float}]->(malware)

// Queries for attack path discovery
MATCH path = (attacker_ip:IP)-[*1..10]->(sensitive_host:Host)
WHERE attacker_ip.malicious = true AND sensitive_host.criticality = 'high'
RETURN path

// Find lateral movement
MATCH (user:User)-[login:LOGGED_INTO]->(host1:Host)-[exec:EXECUTED]->
      (proc:Process)-[connect:CONNECTED_TO]->(host2:Host)
WHERE host1 <> host2
RETURN path
```

---

## Part 4: Event Pipeline Configuration

### 4.1 Kafka Topic Strategy

```yaml
Topics:
  # Inbound: Raw alerts
  alerts.raw:
    partitions: 50
    replication_factor: 3
    retention_ms: 86400000  # 24 hours
    compression_type: snappy
    
  # Normalized alerts
  alerts.normalized:
    partitions: 50
    replication_factor: 3
    retention_ms: 604800000  # 7 days
    compression_type: snappy
    
  # Raw telemetry
  telemetry.raw:
    partitions: 200
    replication_factor: 3
    retention_ms: 259200000  # 3 days
    compression_type: snappy
    
  # Processed events
  events.compressed:
    partitions: 100
    replication_factor: 3
    retention_ms: 2592000000  # 30 days
    compression_type: snappy
    
  # Investigation state updates
  investigations.state:
    partitions: 50
    replication_factor: 3
    retention_ms: 30 days (log compacted)
    cleanup_policy: compact
    
  # Response actions
  actions.events:
    partitions: 20
    replication_factor: 3
    retention_ms: 90 days
    compression_type: snappy
```

### 4.2 Stream Processing (Kafka Streams / Flink)

```yaml
Pipelines:
  
  AlertDeduplication:
    input: alerts.raw
    output: alerts.normalized
    processors:
      - NormalizationProcessor
      - DeduplicationProcessor (30-min window)
      - EntityExtractionProcessor
      - RiskScoringProcessor
    
  EvidenceCollectionOrchestration:
    input: alerts.normalized
    parallelism: 100 parallel collectors
    output: telemetry.enriched
    collectors:
      - UserExpander
      - HostExpander
      - ProcessExpander
      - IPExpander
      - DomainExpander
      - ThreatIntelEnricher
    
  EventCompression:
    input: telemetry.enriched
    output: events.compressed
    stages:
      1. TemporalFilter (30s state)
      2. EntityCorrelator (graph queries)
      3. BehavioralAnomalyDetector (ML model)
      4. EventDeduplicator (30-min window)
      5. GraphAnalyzer (path finding)
      6. AbstractorAggregator
      7. RiskScorer
    
  InvestigationPackager:
    input: events.compressed
    output: investigation.packages (MongoDB)
    stages:
      - EventSelector (top N by risk)
      - RelationshipExtractor
      - TimelineBuilder
      - AttackGraphBuilder
      - FindingsGenerator
      - ConfidenceCalculator
    
  RCAOrchestrator:
    input: investigation.packages
    output: rca.results (MongoDB)
    stages:
      - PackageValidator
      - DeterministicRCAEngine
      - LLMInvoker (if needed)
      - RecommendationGenerator
      - ConfidenceAssessor
```

---

## Part 5: Monitoring & Observability Metrics

### 5.1 Key Metrics to Track

```yaml
Alert Intake:
  - alerts_received_per_second
  - alert_ingestion_latency_p50/p95/p99
  - deduplication_rate (%)
  - alert_normalization_success_rate (%)
  - schema_validation_failures

Evidence Collection:
  - collection_duration_seconds (p50/p95/p99)
  - collection_success_rate (%)
  - connector_availability (by source)
  - api_call_volume_per_source
  - rate_limiting_hits
  - data_enrichment_coverage (%)

Correlation & Compression:
  - compression_ratio_by_stage
  - event_reduction_rate (%)
  - graph_analysis_duration_seconds
  - anomaly_detection_precision/recall
  - correlation_accuracy_on_known_attacks (%)

Investigation Package:
  - package_generation_latency_p50/p95/p99
  - package_size_mb
  - confidence_score_distribution
  - investigation_gaps_rate (%)

RCA Engine:
  - rca_invocation_count_daily
  - rca_duration_seconds (p50/p95/p99)
  - llm_api_cost_per_incident
  - confidence_score_distribution
  - root_cause_accuracy_on_known_attacks (%)
  - recommendation_acceptance_rate (%)

Response Orchestration:
  - action_execution_latency_p50/p95/p99
  - action_success_rate (%)
  - human_approval_wait_time_minutes (p50/p95)
  - automated_action_percentage (%)

Overall System:
  - mean_time_to_investigate_minutes (alert to RCA)
  - mean_time_to_respond_minutes (RCA to action)
  - incident_resolution_success_rate (%)
  - false_positive_rate (%)
  - security_event_coverage (% of attacks detected)
```

---

**Document Version**: 1.0  
**Status**: Complete
