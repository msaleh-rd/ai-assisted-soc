# AI-Assisted SOC — System Architecture

> **Document Version**: 2.0 (Dual-Mode ReAct Supervisor Architecture)
> **Last Updated**: 2026-08-24

## Table of Contents

- [1. High-Level Architecture](#1-high-level-architecture)
- [2. Dual-Mode Investigation Engine](#2-dual-mode-investigation-engine)
- [3. Phase-by-Phase Deep Dive](#3-phase-by-phase-deep-dive)
- [4. Data Flow & Blackboard Architecture](#4-data-flow--blackboard-architecture)
- [5. Technology Stack](#5-technology-stack)
- [6. Directory Map](#6-directory-map)

---

## 1. High-Level Architecture

```
                                ┌──────────────────────────────────────────────────────┐
                                │                   ALERT SOURCES                       │
                                │  CrowdStrike │ Wazuh │ Suricata │ Splunk │ Syslog    │
                                └───────────────────────┬──────────────────────────────┘
                                                        │
                                                        ▼
                            ┌───────────────────────────────────────────────┐
                            │           Alert Intake & Normalization         │
                            │  alert_normalizer.py → alert_deduplicator.py  │
                            └───────────────────────┬───────────────────────┘
                                                    │
                         ┌──────────────────────────┼──────────────────────────┐
                         │                          │                          │
                         ▼                          ▼                          ▼
               ┌─────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
               │   REST API      │     │   SSE Streaming API  │     │   Temporal Client │
               │ /api/v1/alerts  │     │ /api/v1/investigate  │     │  temporal_client  │
               └────────┬────────┘     └──────────┬───────────┘     └────────┬─────────┘
                        │                         │                          │
                        └─────────────────────────┼──────────────────────────┘
                                                  │
                                                  ▼
                        ┌─────────────────────────────────────────────────────┐
                        │              OrchestratorAgent                       │
                        │  Dual-Mode:                                         │
                        │  ┌─────────────────┐ ┌───────────────────────────┐  │
                        │  │  Static 5-Phase  │ │  Autonomous ReAct         │  │
                        │  │  Deterministic   │ │  Supervisor Loop          │  │
                        │  │  DAG Pipeline    │ │  (AI-Driven)              │  │
                        │  └─────────────────┘ └───────────────────────────┘  │
                        └────────────────────────┬────────────────────────────┘
                                                 │
                   ┌─────────────┬───────────────┼───────────────┬─────────────┐
                   ▼             ▼               ▼               ▼             ▼
            ┌───────────┐ ┌───────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐
            │  Triage   │ │ Evidence  │ │ Compression  │ │   RCA    │ │  Response    │
            │  Agent    │ │ Agent     │ │ Agent        │ │  Agent   │ │  Planner     │
            └───────────┘ └───────────┘ └──────────────┘ └──────────┘ └──────────────┘
                   │             │               │               │             │
                   ▼             ▼               ▼               ▼             ▼
            ┌───────────┐ ┌───────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐
            │ LLM +     │ │ Skill     │ │ 7-Stage      │ │ Causal   │ │ FAISS RAG    │
            │ MITRE Ref │ │ Handlers  │ │ Correlation  │ │ Graph +  │ │ Vectorstore  │
            │ triage_v1 │ │ + Log     │ │ Engine       │ │ LLM      │ │ + Playbooks  │
            │ .yaml     │ │ Ingestor  │ │              │ │ rca_v1   │ │ response_v1  │
            └───────────┘ └───────────┘ └──────────────┘ └──────────┘ └──────────────┘
                                                                             │
                                                                             ▼
                                                                    ┌──────────────┐
                                                                    │ HITL Approval │
                                                                    │ Dashboard     │
                                                                    └──────────────┘
```

### Key Infrastructure Components

| Component | Technology | Purpose |
|:---|:---|:---|
| **API Server** | FastAPI | REST + SSE endpoints for alerts, investigations, RCA |
| **Workflow Engine** | Temporal.io | Durable, fault-tolerant workflow execution |
| **Database** | PostgreSQL | Investigation records, event records, audit logs |
| **Graph Database** | Neo4j | Entity relationships, attack graphs |
| **Vector Database** | FAISS | Playbook similarity search for response planning |
| **LLM Backend** | LM Studio (local) | Qwen2.5-7B for structured reasoning |
| **Embedding Model** | all-MiniLM-L6-v2 | Sentence embeddings for RAG retrieval |

---

## 2. Dual-Mode Investigation Engine

The system supports two execution modes controlled by the `use_ai_planner` flag:

### Mode A: Deterministic Static Pipeline (`use_ai_planner = false`)

```
[Alert] ──► Phase 1: Triage ──► Phase 2: Evidence ║ Discovery ──► Phase 3: Compression ──► Phase 4: RCA ──► Phase 5: Response
                                     (parallel)
```

- **Execution**: Fixed 5-phase DAG with predetermined ordering.
- **Characteristics**: 100% deterministic, predictable latency (~20s), zero planning LLM calls.
- **Best for**: Routine alerts, standard triage, automated pipelines.

### Mode B: Autonomous ReAct Supervisor (`use_ai_planner = true`)

```
                          ┌──────────────────────────────────────────────────┐
                          ▼                                                  │
[Alert] ──► Triage ──► [Supervisor: "What should I investigate next?"]       │
                          │                                                  │
                          ├──► gather_evidence (targeted by entity) ─────────┤
                          ├──► discover_network (targeted by IP) ────────────┤
                          ├──► compress_events (7-stage noise reduction) ────┤
                          ├──► perform_rca (attack chain synthesis) ─────────┤
                          ├──► terminate_benign (early exit) ────────────────┘
                          └──► finalize_response ──► Response Planner
```

- **Execution**: LLM-driven Observation → Thought → Action loop bounded to 4 iterations.
- **Characteristics**: Dynamic phase selection, lateral movement pivoting, forensic gap filling.
- **Best for**: Complex intrusions, APTs, multi-host lateral movement, ambiguous alerts.

### Supervisor Decision Schema

```python
class SupervisorDecision:
    thought: str          # Step-by-step forensic reasoning
    action: Literal[      # Chosen action from catalog
        "gather_evidence",
        "discover_network",
        "compress_events",
        "perform_rca",
        "terminate_benign",
        "finalize_response"
    ]
    target_entities: List[str]     # Entities to focus on
    target_skills: List[str]       # Specific skills to deploy
    specific_goal: str             # Forensic question to answer
    pivot_entity_detected: str     # New lateral pivot entity
```

---

## 3. Phase-by-Phase Deep Dive

### Phase 1: Alert Triage

**File**: `backend/services/orchestrator.py` → `TriageAgent`
**Prompt**: `backend/prompts/triage_v1.yaml`
**LLM Schema**: `TriageOutput`

```
                    ┌──────────────────────┐
                    │   Raw Security Alert  │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  Format Normalization │  Standardize vendor-specific fields
                    │  (CrowdStrike, Wazuh, │  into uniform schema
                    │   Splunk, Suricata)   │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  LLM Classification   │  MITRE ATT&CK technique mapping
                    │  (triage_v1.yaml)     │  Severity: Critical/High/Medium/Low
                    │                       │  Classification: ransomware/lateral/...
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  Entity Extraction    │  Users, Hosts, IPs, Files, Processes
                    │  + Grounding          │  verify_entities() against raw alert text
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │  Confidence Scoring   │  LLM confidence × entity grounding
                    │                       │  Penalize if no entities verified
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────────────────────┐
                    │  OUTPUT: TriageOutput                  │
                    │  • classification: "ransomware"        │
                    │  • severity: "Critical"                │
                    │  • technique: "T1486"                  │
                    │  • entities_identified: [root,         │
                    │    linuxshare, 192.168.100.50,         │
                    │    donotcry]                           │
                    │  • confidence: 0.98                    │
                    └──────────────────────────────────────┘
```

**Algorithm**:
1. Parse raw alert JSON.
2. Invoke LLM with MITRE ATT&CK reference table (40+ techniques) and few-shot examples.
3. Extract structured `TriageOutput` via Pydantic-constrained decoding.
4. Verify each extracted entity against the raw alert text (`verify_entities`): reject hallucinated entities.
5. Write `classification`, `severity`, and `entities` to the shared `InvestigationContext`.

---

### Phase 2: Evidence Collection & Network Discovery (Parallel)

**Files**:
- `backend/services/orchestrator.py` → `EvidenceAgent`
- `backend/services/evidence/skill_handlers.py` → `EvidenceSkillExecutor`
- `backend/services/evidence/log_ingestor.py` → `LogIngestor`
- `backend/services/orchestrator.py` → `NetworkDiscoveryAgent`

```
            ┌──────────────────────────────────────────────────────┐
            │                  Seed Entities from Triage            │
            │   [user:root, host:linuxshare, ip:192.168.100.50,    │
            │    file:donotcry]                                     │
            └──────────────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                              ▼
        ┌───────────────────┐          ┌───────────────────┐
        │  Evidence Agent   │          │  Discovery Agent   │
        │  (Runs Parallel)  │          │  (Runs Parallel)   │
        └────────┬──────────┘          └────────┬──────────┘
                 │                               │
      ┌──────────┴───────────────┐               │
      ▼                          ▼               ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐
│ Skill Dispatch│   │ Log Ingestor │   │ ICMP Ping, TCP Port  │
│ per Entity    │   │ (Real Files) │   │ Scan, DNS, Traceroute│
│              │   │              │   │                      │
│ host→ edr,   │   │ Auto-detect: │   │ Probes IP entities   │
│   persistence│   │ • Wazuh JSON │   │ for reachability     │
│ ip→ threat-  │   │ • Suricata   │   │ and open services    │
│   intel, flow│   │ • audit.log  │   │                      │
│ user→ AD     │   │ • auth.log   │   │                      │
│ file→ file-  │   │ • syslog     │   │                      │
│   forensics  │   │              │   │                      │
└──────┬───────┘   └──────┬───────┘   └──────────┬───────────┘
       │                  │                       │
       └──────────────────┼───────────────────────┘
                          ▼
              ┌──────────────────────────────────┐
              │  Entity Graph Assembly             │
              │  Nodes: {file:donotcry → risk:0.95,│
              │    host:linuxshare → risk:0.80}    │
              │  Edges: [root→linuxshare,          │
              │    donotcry→linuxshare]             │
              └──────────────────────────────────┘
```

**Evidence Agent Algorithm**:
1. Read seed entities from `InvestigationContext.entities`.
2. Check for `REQUEST_EVIDENCE` messages from other agents (targeted re-investigation).
3. For each entity, dispatch skill handlers based on entity type:
   - `host` → `edr-process-tree`, `persistence-auditor`
   - `ip` → `threat-intel-lookup`, `network-flow-analyzer`
   - `user` → `identity-ad-lookup`
   - `file` → `file-forensics`, `threat-intel-lookup`
4. Each skill handler queries the `LogIngestor` which auto-discovers and reads real log files:
   - Wazuh JSON (rule + agent fields)
   - Suricata eve.json (event_type field)
   - Linux audit.log (type= prefix)
   - Linux auth.log / syslog
5. Build entity graph from skill results: merge enrichment data, risk scores, threat intel.
6. Add heuristic relationship edges (user→host, process→host).
7. Write `entity_graph` and `relationships` to `InvestigationContext`.

**Log Ingestor Algorithm** (`log_ingestor.py`):
1. Recursively scan dataset directory.
2. Read first 5 lines of each file to auto-classify format (no reliance on naming conventions).
3. Parse matching files into normalized event records.
4. Entity search via in-memory full-text scan: match entity ID in any field of parsed events.
5. Return matched events with extracted metadata (hostname, uid, process, timestamp).

---

### Phase 3: 7-Stage Compression Engine

**Files**:
- `backend/services/orchestrator.py` → `CompressionAgent`
- `backend/services/correlation_engine.py` → `CorrelationEngine`

```
[300 Raw Log Events]
        │
  Stage 1: Temporal Filter ───────────> Keep events within ±24h of incident time.
        │                                Reduction: ~4%
        │
  Stage 2: Entity Correlator ─────────> Keep only events matching investigated entities.
        │                                Reduction: ~73%
        │
  Stage 3: Behavioral Filter ────────> Remove known-benign daemon noise:
        │                               timesyncd, systemd session cleanup,
        │                               DHCP renewals, NTP updates.
        │                               Preserve: sudo, curl, chpasswd, audit,
        │                               execve, network connections.
        │                               Reduction: ~94%
        │
  Stage 4: Deduplication ────────────> Hash-based dedup of identical log lines.
        │                               Merge repeated sequences.
        │
  Stage 5: Graph Analysis ───────────> Build entity relationship subgraph.
        │                               Identify multi-hop lateral movement paths.
        │                               PageRank-based node importance scoring.
        │
  Stage 6: Abstraction ──────────────> Summarize high-volume patterns into
        │                               human-readable action descriptions.
        │                               Convert raw hex/syscall to text.
        │
  Stage 7: Risk Scoring ─────────────> Calculate composite risk score (0.0-1.0)
        │                               per event based on: threat intel match,
        │                               behavioral anomaly, entity risk,
        │                               temporal proximity to incident.
        │
[5 Compressed High-Signal Timeline Milestones]
```

**Algorithm**:
1. Gather raw events from three sources (priority order):
   - PostgreSQL `EventRecord` table (if available)
   - Real log files via `LogIngestor`
   - Alert-derived fallback events
2. Parse incident timestamp from alert data.
3. Pass through `CorrelationEngine.compress_events()` which runs all 7 stages sequentially.
4. Each stage implements `BaseStage.process()` and returns filtered events + `StageMetrics`.
5. Generate `CompressionPackage` containing: timeline, attack_graph, risk_score, stage_metrics.
6. Write compressed timeline and attack graph to `InvestigationContext.compressed_events`.

---

### Phase 4: Root Cause Analysis (RCA)

**Files**:
- `backend/services/orchestrator.py` → `RCAAnalystAgent`
- `backend/services/rca_engine.py` → `RCAEngine`
- `backend/services/sx_truerca/causal_analyzer.py` → `CausalAnalyzer`
- `backend/prompts/rca_v1.yaml`

```
 ┌──────────────────────────────────────────────────────────┐
 │ INPUT: Compressed Timeline + Entity Graph + Evidence      │
 └────────────────────────┬─────────────────────────────────┘
                          │
                          ▼
           ┌──────────────────────────────┐
           │  1. Topological Causal Graph   │  Build directed NetworkX graph.
           │     (CausalAnalyzer)           │  Add nodes: entities + events.
           │                                │  Add edges: temporal ordering,
           │                                │  entity co-occurrence,
           │                                │  process parent-child.
           └──────────────┬────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  2. Modified PageRank Scoring  │  Rank nodes by influence.
           │                                │  Highest-ranked node = patient zero.
           │                                │  Compute blast radius = # affected
           │                                │  entities reachable from root cause.
           └──────────────┬────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  3. LLM Attack Chain          │  Feed compressed timeline + entity
           │     Reconstruction            │  graph + MITRE context to LLM.
           │     (rca_v1.yaml)             │  Generate structured RCAOutput:
           │                                │  root_cause, attack_chain,
           │                                │  confidence_score.
           └──────────────┬────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  4. Confidence Check           │  If confidence < 0.70:
           │                                │    Post REQUEST_EVIDENCE message
           │                                │    → triggers re-investigation
           └──────────────┬────────────────┘
                          ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  OUTPUT: RCAOutput                                            │
  │  • root_cause: "donotcry ransomware downloaded and executed"  │
  │  • patient_zero: "linuxshare"                                 │
  │  • blast_radius: 3                                            │
  │  • attack_chain: [Initial Access → Execution → Impact]       │
  │  • confidence_score: 0.88                                     │
  └──────────────────────────────────────────────────────────────┘
```

**Algorithm**:
1. Read compressed timeline, entity graph, and relationships from `InvestigationContext`.
2. Feed into `RCAEngine` which:
   a. Constructs a `networkx.DiGraph` from entities and temporal events.
   b. Applies modified PageRank algorithm weighted by risk scores.
   c. Identifies patient zero (highest-ranked node) and blast radius.
3. Invoke LLM with `rca_v1.yaml` prompt containing entity graph, timeline, MITRE context.
4. Parse `RCAOutput` via Pydantic schema.
5. If `confidence_score < 0.70`, post `REQUEST_EVIDENCE` message to the blackboard for adaptive re-investigation loop.
6. Write `rca_findings` and `causal_candidates` to `InvestigationContext`.

---

### Phase 5: Response Planning & Playbook RAG

**Files**:
- `backend/services/orchestrator.py` → `ResponsePlannerAgent`
- `backend/services/rag_service.py` → FAISS vectorstore
- `backend/prompts/response_v1.yaml`

```
 ┌─────────────────────────────────────────────────────────┐
 │ INPUT: Root Cause + Entity Graph + Classification        │
 └────────────────────────┬────────────────────────────────┘
                          │
                          ▼
           ┌──────────────────────────────┐
           │  1. Semantic Playbook Search   │  Embed root cause + classification
           │     (FAISS + MiniLM-L6-v2)    │  with HuggingFace embeddings.
           │                                │  Retrieve top-K relevant playbook
           │                                │  sections from vectorstore.
           │                                │  Section-aware priority ranking.
           └──────────────┬────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  2. LLM Response Generation    │  Feed RCA + retrieved playbook
           │     (response_v1.yaml)        │  sections to LLM.
           │                                │  Generate structured ResponseOutput:
           │                                │  • actions_recommended
           │                                │  • critical_actions count
           │                                │  • summary
           └──────────────┬────────────────┘
                          ▼
           ┌──────────────────────────────┐
           │  3. HITL Approval Gate         │  Critical actions tagged for
           │                                │  human-in-the-loop review:
           │                                │  isolate_host, kill_process,
           │                                │  block_ip, reset_credentials.
           └──────────────┬────────────────┘
                          ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  OUTPUT: ResponseOutput                                       │
  │  • critical_actions: 3                                        │
  │  • actions_recommended:                                       │
  │    [isolate linuxshare, kill donotcry, block 192.42.1.174]   │
  └──────────────────────────────────────────────────────────────┘
```

**Algorithm**:
1. Read root cause, classification, and entity graph from `InvestigationContext`.
2. Query `rag_service.search_playbook()`:
   a. Map classification to playbook name (e.g., `ransomware` → `Malware Execution`).
   b. Embed query with `all-MiniLM-L6-v2`.
   c. Retrieve top-4 documents from FAISS, ranked by section priority.
3. Format retrieved playbook sections as RAG context.
4. Invoke LLM with `response_v1.yaml` prompt + RAG context + RCA findings.
5. Parse `ResponseOutput` via Pydantic schema.
6. Tag critical actions for HITL approval.

---

## 4. Data Flow & Blackboard Architecture

All agents communicate through a shared `InvestigationContext` (blackboard pattern):

```
┌──────────────────────────────────────────────────────────────────────┐
│                    InvestigationContext (Blackboard)                   │
│                                                                       │
│  alert_data ──────────── Raw alert JSON from SIEM/EDR                │
│  use_ai_planner ──────── True = ReAct Supervisor, False = Static     │
│                                                                       │
│  ┌─────────────── Phase 1 Outputs ────────────────────────┐          │
│  │  entities: [{type: "host", id: "linuxshare"}, ...]     │          │
│  │  classification: "ransomware"                           │          │
│  │  severity: "Critical"                                   │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  ┌─────────────── Phase 2 Outputs ────────────────────────┐          │
│  │  entity_graph: {file:donotcry: {risk: 0.95, ...}, ...} │          │
│  │  relationships: [{src, tgt, type}, ...]                 │          │
│  │  evidence: {...enrichment data...}                      │          │
│  │  raw_events: [{event from log ingestor}, ...]           │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  ┌─────────────── Phase 3 Outputs ────────────────────────┐          │
│  │  compressed_events: {                                   │          │
│  │    original_events: 300,                                │          │
│  │    compressed_events: 5,                                │          │
│  │    compression_ratio: "60.0x",                          │          │
│  │    timeline: [{timestamp, entity, action, risk}, ...],  │          │
│  │    stages: [{name, input, output, reduction%}, ...]     │          │
│  │  }                                                      │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  ┌─────────────── Phase 4 Outputs ────────────────────────┐          │
│  │  rca_findings: {root_cause, patient_zero,               │          │
│  │    blast_radius, confidence_score, attack_chain}        │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  ┌─────────────── Supervisor State ───────────────────────┐          │
│  │  supervisor_history: [{thought, action, entities}, ...] │          │
│  │  pivot_entities: [{id, type}, ...]                      │          │
│  │  completed_actions: ["gather_evidence:linuxshare", ...] │          │
│  │  messages: [AgentMessage(REQUEST_EVIDENCE, ...), ...]   │          │
│  │  iteration: 0..4                                        │          │
│  │  confidence_history: [0.0, 0.72, 0.88]                 │          │
│  └────────────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────────┘
```

### Inter-Agent Communication (AgentMessage)

Agents communicate asynchronously through typed messages on the blackboard:

| Message Type | Source | Target | Purpose |
|:---|:---|:---|:---|
| `REQUEST_EVIDENCE` | RCA Agent | Evidence Agent | Request additional evidence for specific entities |
| `LOW_CONFIDENCE` | RCA Agent | Orchestrator | Signal that confidence is too low |
| `NEW_ENTITY` | Evidence Agent | Supervisor | Notify about newly discovered pivot entity |

---

## 5. Technology Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                         │
│  FastAPI  │  SSE Streaming  │  Temporal Worker  │  React UI     │
├─────────────────────────────────────────────────────────────────┤
│                        INTELLIGENCE LAYER                        │
│  LangChain  │  Pydantic Schemas  │  Prompt Templates (YAML)    │
│  FAISS RAG  │  HuggingFace Embeddings  │  LM Studio (Local)    │
├─────────────────────────────────────────────────────────────────┤
│                        DATA LAYER                                │
│  PostgreSQL  │  Neo4j  │  FAISS Vectorstore  │  Real Log Files  │
├─────────────────────────────────────────────────────────────────┤
│                        INFRASTRUCTURE                            │
│  Docker Compose  │  Temporal Server  │  Docker Networks          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Directory Map

```
ai-assisted-soc/
├── backend/
│   ├── api/routes/
│   │   ├── alerts.py              # Alert intake REST endpoints
│   │   ├── orchestrator.py        # Investigation SSE + Temporal endpoints
│   │   ├── correlation.py         # Compression engine API
│   │   ├── discovery.py           # Network discovery API
│   │   ├── investigations.py      # Investigation CRUD
│   │   └── rca.py                 # RCA engine API
│   ├── services/
│   │   ├── orchestrator.py        # OrchestratorAgent + all 6 sub-agents
│   │   ├── supervisor.py          # ReAct Supervisor Agent (AI-driven)
│   │   ├── pipeline_core.py       # Shared plan definitions + synthesis
│   │   ├── investigation_context.py # Blackboard state container
│   │   ├── llm_client.py          # LLM routing + Pydantic schemas
│   │   ├── prompt_manager.py      # YAML prompt template loader
│   │   ├── correlation_engine.py  # 7-stage noise reduction pipeline
│   │   ├── rag_service.py         # FAISS playbook vectorstore
│   │   ├── rca_engine.py          # RCA engine + NetworkX causal graph
│   │   ├── alert_normalizer.py    # Multi-vendor alert normalization
│   │   ├── alert_deduplicator.py  # Sliding window deduplication
│   │   ├── evidence_collection.py # Entity-based evidence orchestrator
│   │   ├── temporal_client.py     # Temporal workflow client
│   │   ├── temporal_worker.py     # Temporal worker process
│   │   ├── temporal_workflows.py  # Durable workflow + activity definitions
│   │   ├── evidence/
│   │   │   ├── log_ingestor.py    # Universal heterogeneous log parser
│   │   │   └── skill_handlers.py  # Evidence skill execution engine
│   │   └── sx_truerca/
│   │       └── causal_analyzer.py # Production RCA causal analysis
│   ├── prompts/
│   │   ├── triage_v1.yaml         # Triage LLM prompt (MITRE ATT&CK)
│   │   ├── rca_v1.yaml            # RCA LLM prompt
│   │   ├── response_v1.yaml       # Response planner LLM prompt
│   │   ├── planner_v1.yaml        # Static AI planner prompt
│   │   └── supervisor_v1.yaml     # ReAct Supervisor prompt
│   ├── database/
│   │   ├── postgres.py            # SQLAlchemy models
│   │   └── connection.py          # DB connection factories
│   ├── data/vectorstore/          # FAISS index + playbook embeddings
│   └── tests/
│       ├── test_react_supervisor.py    # Supervisor + dual-mode tests (6)
│       ├── test_temporal_activities.py # Temporal activity tests (1)
│       ├── test_correlation_engine.py  # 7-stage pipeline tests (10)
│       ├── test_evidence_collection.py # Evidence collector tests (4)
│       ├── test_discovery.py           # Network discovery tests (17)
│       ├── test_investigation_builder.py # Investigation builder tests (10)
│       ├── test_llm_evaluation.py      # LLM accuracy tests (5)
│       ├── test_phase3.py              # RCA + response tests (18)
│       └── test_agentic_skills.py      # Skill handler tests (6+)
└── frontend/                      # React web application
```
