# AI-Assisted SOC Platform — Master Roadmap

> **Last audited:** 2026-08-17  
> **Audit scope:** Full codebase review of backend, frontend, infrastructure, tests, and documentation.

---

## 📊 Current State Assessment

### What Is Fully Implemented & Working

| Component | File(s) | Status |
|---|---|---|
| **Alert Normalization** | `alert_normalizer.py` (352 lines) | ✅ Production-quality. CrowdStrike + Splunk parsers, entity extraction via regex, factory pattern. |
| **Alert Deduplication** | `alert_deduplicator.py` (146 lines) | ✅ Sliding-window dedup with SHA-256 fingerprinting. |
| **Alert Intake API** | `routes/alerts.py`, `alert_intake.py` | ✅ `POST /api/v1/alerts`, batch, stats, pending. In-memory store. |
| **Entity Model** | `models/entities.py` (244 lines) | ✅ Rich entity graph model: User, Host, IP, File, Process, Domain. Factory pattern. |
| **Evidence Collection** | `evidence_collection.py` (386 lines) | ⚠️ Orchestrator exists, but all collectors return **hardcoded mock data**. |
| **Correlation / Compression Engine** | `correlation_engine.py` (691 lines) | ✅ Full 7-stage pipeline (temporal, entity, behavioral, dedup, graph, abstraction, risk). Uses numpy. |
| **Investigation Builder** | `investigation_builder.py` (633 lines) | ✅ Package builder with timeline, entity graph, attack patterns, confidence scoring. |
| **RCA Engine (sx-truerca)** | `sx_truerca/causal_analyzer.py`, `rca_config.py` | ✅ Causal graph analysis with configurable thresholds, temporal precedence, blast-radius. |
| **RCA Integration** | `rca_engine.py` (662 lines) | ⚠️ Integration layer exists but uses **simulated data** — not wired to real compressed packages. |
| **Response Orchestration** | `response_orchestration.py` (607 lines) | ⚠️ Full ActionExecutor framework with rollback, but all actions are **mock** (`asyncio.sleep`). |
| **Report Generation** | `report_generation.py` (585 lines) | ✅ Executive, technical, forensic, compliance, incident-log report templates. |
| **Network Discovery Agent** | `discovery/agent.py` + 8 skill plugins | ✅ Real probes: ping, nslookup, port-scan, whois, traceroute, WMI. YAML-driven skill system. |
| **Agentic Orchestrator** | `orchestrator.py` (763 lines) | ✅ 5-phase plan-delegate-synthesize. Triage/RCA/Response agents call **real LLM** via LangChain. Evidence/Compression agents still use simulated data. |
| **LLM Client** | `llm_client.py` (54 lines) | ✅ LM Studio integration via `langchain-openai`. Structured output schemas: `TriageOutput`, `RCAOutput`, `ResponseOutput`. |
| **RAG Service** | `rag_service.py` + `ingest_playbooks.py` | ✅ FAISS vectorstore, HuggingFace embeddings, 4 IR playbooks ingested. |
| **Temporal Workflows** | `temporal_workflows.py` (446 lines) | ✅ Full durable workflow: 5-phase execution, parallel activities, retry policy, queryable progress. |
| **Temporal Client** | `temporal_client.py` (145 lines) | ✅ Start/query/cancel/list workflows. |
| **Temporal Worker** | `temporal_worker.py` | ✅ Registers all 6 activities, connects to Temporal server. |
| **API (Orchestrator)** | `routes/orchestrator.py` (291 lines) | ✅ SSE streaming, Temporal mode toggle, progress polling, investigation listing. |
| **API (RCA)** | `routes/rca.py` (480+ lines) | ✅ Full RCA API with incident lifecycle, response execution. Uses mock data internally. |
| **API (Correlation)** | `routes/correlation.py` | ✅ Compression pipeline, investigation packages, full-chain investigation endpoint. |
| **API (Discovery)** | `routes/discovery.py` | ✅ Network discovery endpoint with real probes. |
| **Frontend UI** | `index.html` + `styles.css` + `app.js` | ✅ 10-page SPA: Dashboard, Alert Ingestion, Evidence, Compression, Investigation, RCA, Response, Incidents, Discovery, Orchestrator. Dark theme, SSE streaming. |
| **Database Layer** | `database/postgres.py`, `database/neo4j.py` | ⚠️ SQLAlchemy models + Neo4j client defined, but **never called** from services. All data is in-memory. |
| **Docker Infrastructure** | `docker-compose.yml` | ✅ Postgres, Neo4j, Redis, Temporal stack (server + admin-tools + UI + dedicated PG). |
| **Tests** | `backend/tests/` (8 test files) | ⚠️ Tests exist for Phase 1-2 services. **No tests** for orchestrator, LLM agents, temporal workflows, or RAG. |

---

### Critical Gaps Identified

#### 🔴 Gap 1: Evidence & Compression Agents Are Fully Mocked
The `EvidenceAgent` (line 152-214 of `orchestrator.py`) builds a fake entity graph from the triage output. The `CompressionAgent` (line 284-326) runs a hardcoded math formula (`entity_count * 12`). Neither agent calls the real `EvidenceCollectionOrchestrator` or `CorrelationEngine` services that are fully implemented in the codebase.

#### 🔴 **Gap 2: Database Layer Is Dead Code (RESOLVED)**
`database/postgres.py` defines `AlertRecord`, `InvestigationRecord`, `RCAResultRecord` SQLAlchemy models. `database/neo4j.py` defines a full `Neo4jClient`. These have now been successfully wired into the alert ingestion lifecycle and Temporal workflow lifecycle.

#### 🔴 **Gap 3: No Persistence of Investigation Results (RESOLVED)**
When an investigation completes via Temporal, the results are now persisted to the `investigations` and `rca_results` tables in Postgres, and entities are written to Neo4j.

#### 🔴 **Gap 4: Response Actions Are Simulated (RESOLVED)**
`response_orchestration.py` now leverages real API frameworks (`httpx`) to send active responses (e.g. `_isolate_host`, `_block_ip`) with graceful fallbacks. The system also includes a Human-in-the-Loop Temporal wait condition so the AI cannot trigger them without authorization.

#### 🔴 Gap 5: No Authentication / Authorization
All API endpoints are wide open. No login, no RBAC, no API keys. The CORS policy is `allow_origins=["*"]`.

#### 🟡 Gap 6: Frontend Is a Monolith
The entire UI is a single 770-line HTML file, a 23KB CSS file, and a 48KB JavaScript file. No component framework, no build system, no TypeScript. Works for a demo, but hard to maintain.

#### 🟡 Gap 7: LLM Prompts Are Fragile
The response agent's prompt engineering required 3 iterations to get the LLM to extract full sentences instead of headers. The prompts are hardcoded strings with no versioning, no A/B testing, and no evaluation framework.

#### 🟡 Gap 8: No Logging / Observability
There is `logger = logging.getLogger(...)` defined in 2 files but no structured logging, no log aggregation, no Prometheus metrics, no OpenTelemetry tracing.

#### 🟡 Gap 9: Chunking Strategy Causes RAG Failures
The playbook ingestion uses `chunk_size=1000` with `chunk_overlap=100`. This splits a 1,700-character playbook into chunks that separate the "Containment Actions" from the triage steps, causing retrieval misses. No metadata-aware chunking, no per-section splitting.

#### 🟡 Gap 10: No CI/CD Pipeline
No GitHub Actions, no linting, no `pyproject.toml`, no pre-commit hooks. Tests are run manually.

---

## 🎯 Roadmap: From Current State to Production-Grade

### Phase 4: Wire the Real Engines (Close the Simulation Gap)
*Goal: Replace all `asyncio.sleep()` + hardcoded-data agents with the real services that already exist in the codebase.*

- [ ] **Wire EvidenceAgent to real `EvidenceCollectionOrchestrator`**
  - Call `evidence_collection.py` collectors instead of building fake entity graphs
  - Feed real entity nodes + relationships into the context
- [ ] **Wire CompressionAgent to real `CorrelationEngine`**
  - Run the actual 7-stage compression pipeline on collected evidence
  - Return real `CompressedPackage` with actual event data
- [ ] **Wire RCA Agent to real `sx_truerca.CausalAnalyzer`**
  - Build a real causal graph from the entity relationships
  - Use `rca_engine.py`'s `RCAOrchestrator` instead of just prompting the LLM
  - Combine causal analysis + LLM reasoning for hybrid RCA
- [x] **Activate database persistence**
  - Call `postgres.py` models from alert intake, evidence collection, and investigation completion
  - Store entity graphs in Neo4j via `neo4j.py` client
  - Persist Temporal workflow results to Postgres on completion
- [x] **Add Alembic migrations** for the Postgres schema

---

### Phase 5: RAG & Prompt Engineering Hardening
*Goal: Make the LLM outputs reliable and deterministic.*

- [x] **Section-aware playbook chunking**
  - Split playbooks by markdown headers (`## Containment Actions`, `## Eradication & Recovery`)
  - Store section metadata (title, playbook name) as document metadata
  - Use metadata filtering in retrieval, not just similarity search
- [x] **Prompt versioning system**
  - Store prompts as versioned YAML/JSON files under `backend/prompts/`
  - Include few-shot examples in each prompt template
  - Log prompt version + LLM response for every invocation
- [x] **Evaluation harness**
  - Build a test suite of 10+ alert scenarios with expected outputs
  - Score LLM outputs against ground truth using exact-match and semantic similarity
  - Run as a CI check before merging prompt changes
- [x] **Multi-model support**
  - Abstract `get_llm()` to support model routing (e.g., fast model for triage, powerful model for RCA)
  - Add fallback chain: primary model → secondary model → deterministic fallback

---

### Phase 6: Human-in-the-Loop (HITL) & Active Response
*Goal: Move from "Response Planning" to actual "Response Execution" with human approval.*

- [x] **Temporal Signals for approval gates**
  - Insert `workflow.await_condition()` before executing critical response actions
  - Emit a `pending_approval` SSE event to the frontend
- [x] **Approval queue UI**
  - New "Pending Approvals" page in the dashboard
  - Show the AI's response plan, confidence score, and affected entities
  - "Approve" / "Reject" / "Modify" buttons that send Temporal signals
- [x] **Action execution engine**
  - Replace `asyncio.sleep()` in `response_orchestration.py` with real API calls:
    - EDR API → isolate host, kill process
    - IAM API → reset credentials, disable account, enforce MFA
    - Firewall API → block IP/domain
  - Implement rollback for each action type
- [x] **Audit trail**
  - Log every action (AI-recommended, human-approved, executed, rolled-back) to Postgres
  - Immutable append-only audit table with timestamps and actor IDs

---

### Phase 7: Enterprise Tool Integrations
*Goal: Replace mocked data sources with real security tool connections.*

- [ ] **SIEM Integration (Splunk / Elastic)**
  - Webhook receiver for real-time alert ingestion
  - Query API for historical event retrieval by entity
- [ ] **EDR Integration (CrowdStrike / SentinelOne / Defender)**
  - Query process trees, file events, network connections for the Evidence Agent
  - Execution API for containment actions (isolate host, quarantine file)
- [ ] **Identity & Access (Active Directory / Okta / Entra ID)**
  - Enrich user entities with group memberships, MFA status, risk score
  - Execute response actions (disable account, force password reset)
- [ ] **Threat Intelligence**
  - VirusTotal, AbuseIPDB, GreyNoise API integrations
  - Automatic IOC enrichment during evidence collection
  - MITRE ATT&CK mapping for all detected techniques
- [ ] **Ticketing (ServiceNow / Jira)**
  - Auto-create incident tickets from completed investigations
  - Bi-directional sync for status updates

---

### Phase 8: Production Hardening & Observability
*Goal: Make the platform production-ready for enterprise deployment.*

- [ ] **Authentication & RBAC**
  - OAuth2/OIDC integration (Keycloak, Okta, or Entra ID)
  - Role-based access: Analyst, Senior Analyst, SOC Manager, Admin
  - API key management for programmatic access
- [ ] **Structured logging & tracing**
  - Structured JSON logging with correlation IDs across all services
  - OpenTelemetry instrumentation for distributed tracing
  - Trace spans for each agent execution, LLM call, and database query
- [ ] **Prometheus metrics + Grafana dashboards**
  - Agent execution duration histograms
  - LLM token usage, latency, and error rate counters
  - Compression ratios, alert intake throughput
  - Investigation queue depth and completion time
- [ ] **Rate limiting & input validation**
  - Rate limit alert intake endpoints
  - Validate and sanitize all LLM inputs to prevent prompt injection
- [ ] **Secrets management**
  - Move all credentials out of `docker-compose.yml` and `.env` files
  - Use Docker secrets or HashiCorp Vault
- [ ] **CI/CD pipeline**
  - GitHub Actions: lint (ruff), type-check (mypy), test (pytest), build (Docker)
  - Pre-commit hooks for formatting and import sorting
  - `pyproject.toml` with proper dependency management

---

### Phase 9: Scalability & Multi-Tenancy
*Goal: Scale from single-instance to enterprise-grade deployment.*

- [ ] **Kubernetes deployment**
  - Helm charts for all services
  - Horizontal pod autoscaler for Temporal workers
  - Separate worker pools for CPU-intensive (compression) vs IO-intensive (LLM) tasks
- [ ] **Multi-tenancy**
  - Tenant isolation at database level (schema-per-tenant or row-level security)
  - Tenant-specific playbook libraries and prompt configurations
  - Per-tenant API key scoping
- [ ] **Event-driven architecture**
  - Replace in-memory alert queue with Redis Streams or Kafka
  - Async alert processing pipeline that decouples intake from investigation
- [ ] **Frontend modernization**
  - Migrate from vanilla JS to React/Next.js or Vue
  - Component library for reusable SOC widgets
  - WebSocket for real-time dashboard updates (replace SSE polling)
  - Mobile-responsive design

---

## 📋 Priority Matrix

| Priority | Item | Impact | Effort |
|---|---|---|---|
| 🔴 P0 | Wire Evidence/Compression agents to real engines | High | Medium |
| ✅ P0 | Activate database persistence | High | Medium |
| ✅ P0 | Section-aware playbook chunking | High | Low |
| ✅ P1 | Human-in-the-Loop approval gates | High | High |
| 🟡 P1 | Prompt versioning + evaluation harness | Medium | Medium |
| 🟡 P1 | Structured logging + OpenTelemetry | Medium | Medium |
| 🟡 P1 | CI/CD pipeline (GitHub Actions) | Medium | Low |
| 🟢 P2 | Authentication & RBAC | High | High |
| 🟢 P2 | SIEM webhook ingestion | High | Medium |
| 🟢 P2 | EDR integration for real containment | High | High |
| 🟢 P2 | Prometheus + Grafana observability | Medium | Medium |
| 🔵 P3 | Kubernetes Helm charts | Medium | High |
| 🔵 P3 | Frontend framework migration | Low | High |
| 🔵 P3 | Multi-tenancy | Low | Very High |
