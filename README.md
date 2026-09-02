D:\projects\ai-assisted-soc# AI-Native SOC Platform

## Overview

This codebase implements an AI-Native SOC Platform. **Phases 1-3** (Alert Intake, Evidence Collection, Correlation/Compression, RCA & Response Orchestration) are complete, as is the full **Wave 0-3** program from [DETAILED_IMPLEMENTATION_PLAN.md](DETAILED_IMPLEMENTATION_PLAN.md) (deterministic threat-intel grounding, an auditable Investigation Ledger, a multi-model router, agentic-security hardening, the L0-L4 Automation Maturity Gate, Detection-as-Code, an Investigation Swarm, Compounding Memory, a declarative Playbook Engine, a Self-Play Purple Team, and ingest-time security knowledge graph writes). Wave 4 (enterprise integrations, production hardening, scalability) is scoped but paused pending real vendor credentials/infrastructure decisions — see [ROADMAP.md](ROADMAP.md) and [DETAILED_IMPLEMENTATION_PLAN.md](DETAILED_IMPLEMENTATION_PLAN.md) for full status.

The platform is designed to:
1. **Ingest** security alerts from multiple sources (CrowdStrike, Splunk, etc.)
2. **Normalize** alerts to a standard schema
3. **Deduplicate** similar alerts within a configurable window
4. **Autonomously collect** evidence by expanding entities across telemetry sources
5. **Enrich** context with threat intelligence and baseline comparisons
6. **Reason** over that evidence via an auditable, self-correcting agentic pipeline (Triage → Evidence → Compression → RCA → Response), grounded in local threat-intel and gated by a blast-radius-aware automation policy

## Current Status (2026-09-02)

| Area | Status |
|---|---|
| Alert Intake, Evidence Collection, Correlation/Compression, RCA, Response Orchestration (Phases 1-3) | ✅ Complete |
| Local threat-intel grounding, Investigation Ledger, Multi-model router, Agentic security hardening (Wave 1) | ✅ Complete |
| Maturity Gate + Entity-Risk full rollout, Detection-as-Code + Live Actions (Wave 2) | ✅ Complete |
| Investigation Swarm, Compounding Memory, Playbook Engine, Self-Play Purple Team, Security Knowledge Graph (Wave 3) | ✅ Complete |
| AI Governance UI page + read-only API surfacing all of the above | ✅ Complete |
| Enterprise integrations, AuthN/RBAC, Kubernetes/multi-tenancy (Wave 4) | ⏸️ Paused (needs real credentials/infra decisions) |

**Regression baseline:** 380 backend tests passing (`pytest backend/tests/`, excluding 3 files that require a live LM Studio/Temporal server), zero known regressions.

## Architecture

```
Raw Alerts (Multiple Sources)
    ↓
[Alert Intake Service]
├─ Normalize to standard schema
├─ Extract entities (user, host, process, IP, domain, file)
└─ Deduplicate within time window
    ↓
[Investigation Context]
    ↓
[Temporal Workflow Orchestrator] ← [Temporal Worker & Server]
├─ Phase 1: Triage (serial)
├─ Phase 2: Evidence Collection + Network Discovery (parallel)
├─ Phase 3: Correlation & Compression (serial)
├─ Phase 4: RCA Engine (serial)
└─ Phase 5: Response Planning (serial)
    ↓
[Enriched Investigation Context]
└─ Ready for Analyst Review
```

## Project Structure

```
backend/
├── models/
│   ├── alert.py          # Alert data models
│   └── entities.py       # Entity node and relationship models
├── services/
│   ├── alert_normalizer.py      # Multi-vendor alert normalizers
│   ├── alert_deduplicator.py    # Alert deduplication logic
│   ├── alert_intake.py          # Main intake orchestration
│   ├── orchestrator.py          # Legacy agent execution logic
│   ├── temporal_workflows.py    # Temporal Workflows & Activities
│   ├── temporal_worker.py       # Standalone Temporal Worker
│   └── temporal_client.py       # Temporal API Client
├── api/
│   ├── routes/
│   │   ├── alerts.py            # Alert ingestion endpoints
│   │   └── orchestrator.py      # Temporal workflow endpoints
│   └── schemas.py               # Pydantic request/response schemas
├── database/
│   ├── postgres.py              # PostgreSQL models
│   └── neo4j.py                # Neo4j graph client
├── tests/
└── main.py                      # FastAPI application

docker-compose.yml              # Local development setup with Temporal
requirements.txt                # Python dependencies
Dockerfile                      # Container image
```

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start all services (includes Temporal, PostgreSQL, Neo4j, Redis, API, and Worker)
docker compose up -d

# Wait for services to be ready (~30 seconds)
sleep 30

# View Temporal Web UI
open http://localhost:8080

# View API docs
open http://localhost:8000/docs
```

### Local Development

```bash
# Install dependencies
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Start backend dependencies & Temporal
docker compose -f docker-compose-postgres.yml up -d

# Start Temporal Worker (Terminal 1)
$env:TEMPORAL_HOST="localhost:7233"
python -m backend.services.temporal_worker

# Start FastAPI server (Terminal 2)
$env:USE_TEMPORAL="true"
$env:TEMPORAL_HOST="localhost:7233"
uvicorn backend.main:app --reload --port 8000

# Run tests
pytest backend/tests/ -v
```

## API Endpoints

### Alert Ingestion

**POST** `/api/v1/alerts/ingest`
```json
{
  "source": "crowdstrike",
  "raw_alert": { ... }
}
```

Response:
```json
{
  "status": "accepted|deduplicated|error",
  "alert_id": "...",
  "investigation_id": "...",
  "occurrence_count": 1,
  "severity": "high"
}
```

**POST** `/api/v1/alerts/ingest-batch`
```json
{
  "source": "splunk",
  "alerts": [ { ... }, { ... } ]
}
```

**GET** `/api/v1/alerts/pending`
- Get alerts pending evidence collection (called by evidence service)

**GET** `/api/v1/alerts/stats`
- Service statistics (tracked alerts, dedup window, etc.)

### Evidence Collection

**POST** `/api/v1/evidence/collect`
```json
{
  "investigation_id": "...",
  "max_depth": 2
}
```

**GET** `/api/v1/evidence/stats`
- Evidence collection statistics

## Key Features Implemented

### 1. Multi-Vendor Alert Normalization
- **CrowdStrike normalizer**: EDR alerts with process execution, DNS queries, network connections
- **Splunk normalizer**: SIEM alerts from any detection search
- **Factory pattern**: Easy to add more normalizers

Example:
```python
from backend.services.alert_normalizer import AlertNormalizerFactory

normalizer = AlertNormalizerFactory.create_normalizer('crowdstrike')
result = normalizer.normalize(raw_alert)

if result.success:
    normalized = result.normalized_alert
    print(f"Alert: {normalized.alert_name}")
    print(f"Severity: {normalized.severity}")
    print(f"Entities: {normalized.primary_entities}")
```

### 2. Alert Deduplication
- **Fingerprint-based**: Creates hash of alert key fields
- **Time-windowed**: Configurable dedup window (default 30 minutes)
- **Intelligent merging**: 
  - Increments occurrence count
  - Upgrades severity if duplicate is higher
  - Merges additional entities
  - Tracks parent-child relationships

Example:
```python
from backend.services.alert_deduplicator import AlertDeduplicator

dedup = AlertDeduplicator(window_seconds=1800)
result = dedup.deduplicate(normalized_alert)

if result.is_duplicate:
    print(f"Duplicate of: {result.parent_alert_id}")
    print(f"Total occurrences: {result.occurrence_count}")
else:
    print("New alert")
```

### 3. Autonomous Evidence Collection
- **Parallel collectors**: User, Host, Process, IP, Domain, File
- **Enrichment data**: Profile, activity, security posture
- **Threat intelligence**: Reputation scores, known malware, geolocation
- **Risk scoring**: Contextual risk assessment for each entity
- **Extensible**: Registry pattern for adding custom collectors

Example:
```python
from backend.services.evidence_collection import get_evidence_orchestrator

orchestrator = get_evidence_orchestrator()
context = await orchestrator.collect_for_alert(
    normalized_alert,
    max_depth=2
)

for entity_id, entity in context['entities'].items():
    print(f"Entity: {entity.entity_name}")
    print(f"Risk Score: {entity.risk_score}")
    print(f"Enrichment: {entity.enrichment_data}")
```

### 4. Entity Graph Preparation
- **Entity models**: User, Host, Process, IP, Domain, File
- **Relationship types**: Logged-in-to, Executed, Connected-to, Loaded, etc.
- **Neo4j ready**: Graph prepared for storage in Neo4j
- **MITRE ATT&CK mapping**: Alert categories aligned with tactics

### 5. AI Governance & Reasoning Safety (Wave 1-3)
- **Investigation Ledger**: every agentic LLM decision (prompt, response, decision, token/latency cost) recorded and replayable per investigation.
- **Local Threat-Intel Grounding**: deterministic ransomware/mutex/port/note lookups (vendored from `mthcht/awesome-lists`) checked before/alongside any LLM call.
- **L0-L4 Automation Maturity Gate**: every response skill is blast-radius-scored and gated by the configured automation tier before auto-executing.
- **Detection-as-Code**: YAML-defined, fixture-tested rules (`backend/detections/`) evaluated by a real `DetectionEngine`.
- **Playbook Engine**: declarative YAML incident-response playbooks (`backend/playbooks/`) that can drive the real Triage/Evidence/Compression/RCA/Response agents end-to-end.
- **Investigation Swarm & Compounding Memory**: parallel competing-hypothesis generation for stuck/complex cases, plus per-alert-signature false-positive priors that bound Triage's confidence.
- **Self-Play Purple Team**: replays canned attack campaigns against the real detection ruleset and auto-drafts coverage-gap rules for review.
- All of the above are now visible and operable from the frontend's **AI Governance** page, backed by a new read-only `backend/api/routes/ai_governance.py` API (`/api/v1/ai-governance/*`).

## Data Flow Example

### CrowdStrike "Suspicious PowerShell" Alert

```
Raw Alert (CrowdStrike):
{
  "name": "Suspicious Process Execution",
  "event_type": "process_execution",
  "severity": 4,
  "user_id": "john.doe",
  "computer_name": "WORKSTATION-001",
  "process_name": "powershell.exe",
  "local_ip": "192.168.1.100",
  "remote_ip": "203.0.113.5"
}
        ↓
Normalization:
- Normalize severity: 4 → HIGH
- Extract entities: user, host, process, IP
- Map to MITRE: execution
- Assign investigation_id and correlation_id
        ↓
Normalized Alert:
{
  "alert_id": "c3d4e5f6...",
  "investigation_id": "a1b2c3d4...",
  "source_system": "edr",
  "source_name": "CrowdStrike",
  "alert_name": "Suspicious Process Execution",
  "severity": "high",
  "primary_entities": {
    "user": { "id": "john.doe", "name": "John Doe" },
    "host": { "id": "abc123", "hostname": "WORKSTATION-001", "ip": "192.168.1.100" },
    "process": { "name": "powershell.exe" },
    "remote_ip": "203.0.113.5"
  }
}
        ↓
Deduplication:
- Fingerprint: md5("CrowdStrike|Suspicious Process Execution|execution|john.doe|abc123|203.0.113.5")
- Check if seen in last 30 minutes
- If duplicate: merge, increment count, upgrade severity
- If new: queue for evidence collection
        ↓
Evidence Collection (Parallel):
- User Evidence:     john.doe → profile, MFA status, group membership, risk
- Host Evidence:     WORKSTATION-001 → OS, patches, processes, security posture
- Process Evidence:  powershell.exe → signature status, parent, modules loaded
- IP Evidence:       203.0.113.5 → geolocation (malicious?), reputation
- Domain Evidence:   (if domain accessed) → registration, DNS records
        ↓
Enriched Investigation Context:
{
  "investigation_id": "a1b2c3d4...",
  "entities": {
    "john.doe": {
      "type": "user",
      "name": "John Doe",
      "email": "john.doe@company.com",
      "mfa_enabled": true,
      "last_login": "2024-08-10T09:30:00Z",
      "groups": ["Engineering", "Development"],
      "risk_score": 0.1
    },
    "WORKSTATION-001": {
      "type": "host",
      "os": "Windows 10",
      "patches": "up-to-date",
      "security_posture": "compliant",
      "running_processes": 147,
      "risk_score": 0.15
    },
    "203.0.113.5": {
      "type": "ip",
      "geolocation": "San Francisco, USA",
      "asn": "AS15169 (Google)",
      "reputation": "clean",
      "risk_score": 0.0
    }
  },
  "relationships": [
    { "source": "john.doe", "target": "WORKSTATION-001", "type": "logged_in_to" },
    { "source": "WORKSTATION-001", "target": "powershell.exe", "type": "executed" },
    { "source": "203.0.113.5", "target": "WORKSTATION-001", "type": "connected_to" }
  ]
}
```

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://soc_user:soc_password@localhost:5432/soc_platform
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=soc_password

# Services
ALERT_DEDUP_WINDOW_SECONDS=1800  # 30 minutes
EVIDENCE_COLLECTION_MAX_DEPTH=2
EVIDENCE_COLLECTION_MAX_PARALLEL=10

# Logging
LOG_LEVEL=info
```

## Testing

```bash
# Run all tests
pytest backend/tests/ -v

# Run specific test file
pytest backend/tests/test_alert_normalizer.py -v

# Run with coverage
pytest backend/tests/ --cov=backend

# Run specific test
pytest backend/tests/test_alert_normalizer.py::test_crowdstrike_normalization -v
```

## Completed: Phase 2 (Agentic Orchestration & Skills)

Phase 2 successfully introduced the AI-driven investigation capabilities:

1. **Pluggable Universal Skill Registry**
   - Deprecated monolithic scripts in favor of modular `SOCSkill` capabilities.
   - Natively supports the open **agentskills.io** standard.
   - Automatically maps skills to MITRE ATT&CK and NIST CSF frameworks.
   - Instant integration of 800+ open-source cybersecurity skills.

## Completed: Phase 3 & Wave 1-3 (RCA, Response, AI Reasoning & Safety)

Phase 3 wired real RCA (`sx_truerca` causal analysis + LLM synthesis) and response
orchestration (Maturity Gate, kill-switch, audit trail) into the pipeline. The
subsequent Wave 0-3 program (see [DETAILED_IMPLEMENTATION_PLAN.md](DETAILED_IMPLEMENTATION_PLAN.md))
then hardened and scaled the agentic core:

- **Wave 0 (Quick Wins)**: Prompt Registry with few-shot injection + lockfile versioning; the L0-L4 Automation Maturity Gate; time-decayed Entity-Risk scoring with auto-promotion.
- **Wave 1**: local threat-intel grounding (Phase A); YARA/VirusTotal malware-analysis evidence (Phase B); the replayable Investigation Ledger (Phase C); the multi-model router, LLM response caching, rate limiting and structured-output validation (Phase D); agentic-security hardening against prompt injection/goal drift with a kill switch (Phase E).
- **Wave 2**: full Maturity Gate + Entity-Risk rollout across every response/triage/evidence call site (Phases F/G); Detection-as-Code rules plus a Live Actions dispatch registry (Phase H).
- **Wave 3**: an Investigation Swarm for stuck/complex cases (Phase I); Compounding Memory learning per-signature false-positive priors (Phase J); a declarative Playbook Engine (Phase K); a Self-Play Purple Team that red-teams the detection ruleset (Phase L); ingest-time Security Knowledge Graph writes with blast-radius queries (Phase M).
- **AI Governance UI**: a new frontend page + read-only API making every one of the above subsystems observable and operable, not just backend-internal.

Wave 4 (enterprise tool integrations, production hardening, Kubernetes/multi-tenancy)
is scoped in detail in [DETAILED_IMPLEMENTATION_PLAN.md](DETAILED_IMPLEMENTATION_PLAN.md)
but intentionally paused pending real vendor credentials and infrastructure decisions.

2. **AI Planner & ReAct Supervisor**
   - Dynamic orchestrator evaluates evidence at every step.
   - Autonomous ReAct loops (e.g., dynamically scheduling deep-dive forensics when new C2 infrastructure is discovered).
   - Eliminates rigid, static playbooks.

3. **7-Stage Compression & RCA Engine**
   - 50x+ noise reduction via temporal, behavioral, and graph-based filtering skills.
   - LLM-powered Root Cause Analysis explicitly maps attack paths and causal relationships.

## Next Steps (Phase 3)

Phase 3 will focus on extending the agentic capabilities:

1. **Triage & Scope Expansion**
   - Migrate the initial Triage phase to utilize the new Universal Skill Registry.
   
2. **Response Orchestration**
   - Wire up active response skills (containment, isolation, password resets) using the same pluggable architecture.
   - Implement human-in-the-loop (HITL) approval workflows for critical actions.

3. **Advanced Threat Intel**
   - Connect specific Anthropic Cybersecurity Skills to live threat feeds.

## Performance Targets

| Component | Target | Status |
|-----------|--------|--------|
| Alert ingestion latency | < 100ms | ✅ |
| Deduplication rate | 15-30% | ✅ |
| Evidence collection time | < 30s (parallelized) | ✅ |
| Entity extraction coverage | > 90% | ✅ |
| API availability | > 99% | ✅ (with proper deployment) |

## Database Schemas

### PostgreSQL Tables (Phase 1)
- `alerts`: Normalized alerts
- `investigations`: Investigation records
- `entities`: Entity data
- `events`: Correlated events
- `audit`: Audit trail

### Neo4j Graph (Phase 1 Prep)
- Entity nodes with attributes
- Relationship edges (logged_in_to, executed, connected_to, etc.)
- Ready for attack path analysis in Phase 2

## Contributing

To add support for a new alert source:

1. Create a new normalizer class extending `BaseAlertNormalizer`
2. Implement `normalize()` method
3. Register with factory: `AlertNormalizerFactory.register_normalizer('source_name', MyNormalizer)`
4. Add tests in `backend/tests/`

Example:
```python
from backend.services.alert_normalizer import BaseAlertNormalizer, AlertNormalizationResult

class MySourceNormalizer(BaseAlertNormalizer):
    def __init__(self):
        super().__init__("My Source", AlertSource.SIEM)
    
    def normalize(self, raw_alert):
        # Implementation
        return AlertNormalizationResult(success=True, normalized_alert=alert)
```

## License

TBD

## References

- [Original Design Documents](C:\tmp\ai-native-soc-platform)
- [Architecture Overview](C:\tmp\ai-native-soc-platform\ARCHITECTURE.md)
- [API Specifications](C:\tmp\ai-native-soc-platform\API_AND_SCHEMAS.md)
- [Deployment Guide](C:\tmp\ai-native-soc-platform\DEPLOYMENT_CHECKLIST.md)
