# AI-Assisted SOC Platform — Master Roadmap

> **Last audited:** 2026-09-02
> **Audit scope:** Deep code review of every file in `backend/services/`, `backend/api/`, `backend/database/`, `backend/prompts/`, `frontend/`, and all infrastructure files. Focused on **AI quality, agentic architecture, and workflow robustness**.
> **See also:** [DETAILED_IMPLEMENTATION_PLAN.md](DETAILED_IMPLEMENTATION_PLAN.md) — the actively-executed successor plan covering Quick Wins + Wave 1 (Phases A-E) + Wave 2 (Phases F-H) + Wave 3 (Phases I-M), all **complete** as of this audit (380 backend tests passing, zero regressions). Wave 4 (Phases N-P, roughly this doc's Phases 9-11) is **paused** pending real vendor credentials/infrastructure decisions — see that document's "Next steps" section.

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
| **Response Orchestration** | `response_orchestration.py` (644 lines) | ✅ Full ActionExecutor with `httpx` API calls + mock fallback. Rollback support. |
| **Report Generation** | `report_generation.py` (585 lines) | ✅ Executive, technical, forensic, compliance, incident-log report templates. |
| **Network Discovery Agent** | `discovery/agent.py` + 8 skill plugins | ✅ Real probes: ping, nslookup, port-scan, whois, traceroute, WMI. YAML-driven skill system. |
| **Agentic Orchestrator** | `orchestrator.py` (772 lines) | ✅ 5-phase plan-delegate-synthesize. Triage/RCA/Response agents call **real LLM** via LangChain. Evidence/Compression agents still use simulated data. |
| **LLM Client** | `llm_client.py` (70 lines) | ✅ LM Studio integration via `langchain-openai`. Structured output schemas: `TriageOutput`, `RCAOutput`, `ResponseOutput`. Role-based model routing. |
| **Prompt Manager** | `prompt_manager.py` (79 lines) | ✅ YAML-based prompt loading with versioning and templating. |
| **RAG Service** | `rag_service.py` + `ingest_playbooks.py` | ✅ FAISS vectorstore, HuggingFace embeddings, section-aware retrieval with classification filtering. |
| **Temporal Workflows** | `temporal_workflows.py` (605 lines) | ✅ Full durable workflow: 5-phase execution, parallel activities, retry policy, queryable progress, HITL approval gate. |
| **Temporal Client** | `temporal_client.py` (145 lines) | ✅ Start/query/cancel/list workflows. |
| **Temporal Worker** | `temporal_worker.py` | ✅ Registers all 8 activities, connects to Temporal server. |
| **Human-in-the-Loop** | Temporal signals + frontend UI | ✅ `workflow.wait_condition()` gate, Approve/Reject signals, `execute_response_activity`. |
| **Audit Trail** | `AuditRecord` in Postgres | ✅ Immutable append-only audit table for all response actions. |
| **Database Persistence** | `connection.py`, `postgres.py`, `neo4j.py` | ✅ `db.merge()` for idempotent writes. Investigations + RCA results to Postgres, entities to Neo4j. |
| **API (Orchestrator)** | `routes/orchestrator.py` (324 lines) | ✅ SSE streaming, Temporal mode, progress polling, investigation listing, approval endpoint. |
| **API (RCA)** | `routes/rca.py` (480+ lines) | ✅ Full RCA API with incident lifecycle, response execution. Uses mock data internally. |
| **API (Correlation)** | `routes/correlation.py` | ✅ Compression pipeline, investigation packages, full-chain investigation endpoint. |
| **API (Discovery)** | `routes/discovery.py` | ✅ Network discovery endpoint with real probes. |
| **Frontend UI** | `index.html` + `styles.css` + `app.js` | ✅ 13-page SPA: Dashboard, Alert Ingestion, Evidence, Compression, Investigation, RCA, Response, Pending Approvals, Incidents, Discovery, Orchestrator, Investigation History, **AI Governance** (new, Wave 1-3 visibility). Dark theme, SSE streaming. |
| **Docker Infrastructure** | `docker-compose.yml` | ✅ Postgres, Neo4j, Redis, Temporal stack (server + admin-tools + UI + dedicated PG). |
| **Tests** | `backend/tests/` (9 test files) | ⚠️ Tests exist for Phase 1-2 services. **No tests** for orchestrator, LLM agents, temporal workflows, or RAG. |

---

## 🔍 Deep Audit: AI, Agentic & Workflow Gaps

### 🔴 CRITICAL — Gaps That Undermine the "AI-Assisted" Promise

---

#### Gap A: Evidence & Compression Agents Are Fake (The Data Supply Chain Is Broken)

**Severity:** 🔴 Critical — This is the #1 gap in the entire system.

The **EvidenceAgent** (`orchestrator.py:154-216`) does not collect real evidence. It takes the entity list from Triage and constructs a **hardcoded fake graph** with `risk_score: 0.7` and `evidence_count: 3` for every entity. It lists `data_sources_queried: ["EDR", "SIEM", "Active Directory", "Threat Intel"]` but never queries any of them. The real `EvidenceCollectionOrchestrator` (386 lines, with User/Host/IP/File/Process collectors) is never called.

The **CompressionAgent** (`orchestrator.py:286-328`) runs a **hardcoded math formula** (`entity_count * 12`) instead of the real 7-stage `CorrelationEngine` (691 lines).

**Impact:** The RCA Agent receives fabricated evidence, so its root-cause analysis is based on fiction. The entire pipeline from Evidence→Compression→RCA is operating on fake data. The LLM is reasoning over fabricated numbers.

---

#### Gap B: RCA Agent Has No Memory / No Reasoning Chain

**Severity:** 🔴 Critical

The RCA Agent (`orchestrator.py:331-373`) sends a single LLM prompt and trusts the output completely. It has:
- **No chain-of-thought verification** — the LLM's attack chain is accepted as gospel
- **No self-critique loop** — if the RCA confidence is low, the system never re-investigates
- **No evidence cross-referencing** — the LLM doesn't validate its conclusions against the evidence
- **No memory across investigations** — each investigation starts from zero, even if the same attacker hit the same host yesterday
- **Hardcoded confidence of 0.95** on the triage agent regardless of output quality

The `_synthesize` method mentions "Low confidence. Adaptive re-investigation recommended" but **never actually triggers re-investigation**. It's just a string.

---

#### Gap C: Agents Cannot Talk to Each Other (No Inter-Agent Communication)

**Severity:** 🔴 Critical

The orchestrator follows a rigid **linear pipeline** (Triage → Evidence → Compression → RCA → Response). Agents cannot:
- **Ask follow-up questions** — if the RCA agent needs more evidence, it can't request it
- **Challenge each other** — the Response agent can't push back if RCA confidence is low
- **Share context dynamically** — the Evidence agent doesn't know what the RCA agent is looking for
- **Branch the investigation** — if two attack vectors are detected, the system can't fork into parallel investigation threads

The `_resolve_inputs` method is a giant hardcoded if/elif chain with no dynamic input resolution, no context bus, no shared blackboard.

---

#### Gap D: The Orchestrator Plan Is Static (Not AI-Driven)

**Severity:** 🟡 High

The `OrchestratorAgent.plan()` method returns the **exact same 5-phase plan regardless of the alert**. A phishing email gets the same pipeline as a ransomware attack. The LLM is never consulted during planning.

A truly agentic system would:
- Have the LLM decide which agents to deploy based on the alert
- Skip irrelevant agents (e.g., skip network discovery for an email-based attack)
- Add extra agents for complex scenarios (e.g., add a "Threat Intel" agent for known APT indicators)
- Dynamically adjust the plan mid-investigation if new evidence changes the picture

---

#### Gap E: No Confidence Calibration or Hallucination Detection

**Severity:** 🟡 High

All three LLM agents (Triage, RCA, Response) blindly trust LLM output:
- `TriageAgent` hardcodes `confidence = 0.95`
- `RCAAnalystAgent` uses the LLM's self-reported confidence
- `ResponsePlannerAgent` hardcodes `confidence = 0.90`

There is no output validation, no cross-validation against known patterns, no hallucination detection, and no entity grounding against the original alert data.

---

#### Gap F: Prompts Don't Include Few-Shot Examples in LLM Calls

**Severity:** 🟡 High

The YAML prompt files contain `few_shot_examples` (see `triage_v1.yaml:22-52`), but the `PromptManager.build_user_prompt()` method **never includes them** in the actual LLM call. They're stored but ignored. Few-shot examples are critical for local/small models to produce correctly structured output.

---

#### Gap G: No LLM Call Observability

**Severity:** 🟡 High

Every LLM call in the system is a black box:
- No token counting, no latency tracking, no input/output logging
- No prompt/response caching — identical alerts re-trigger identical LLM calls
- No rate limiting — a flood of alerts can overwhelm the LLM endpoint
- No fallback chain — if the LLM is down, the entire system fails

---

### 🟡 IMPORTANT — Workflow & Architecture Gaps

---

#### Gap H: The Temporal Workflow Duplicates the In-Memory Orchestrator

**Severity:** 🟡 Medium

There are **two complete orchestration implementations** that must be kept in sync:
1. `orchestrator.py` — the in-memory SSE-streaming orchestrator (772 lines)
2. `temporal_workflows.py` — the Temporal workflow (605 lines)

Both have their own `_build_plan()`, `_resolve_inputs()`, and `_synthesize()` methods. If you fix a bug in one, you must remember to fix the other.

---

#### Gap I: Temporal Workflow Has No Timeout or Deadletter Handling

**Severity:** 🟡 Medium

The workflow has no overall timeout. If a human never approves the HITL gate, the workflow hangs forever. There is no approval timeout, no deadletter queue, no alerting when a workflow is stuck, and no cancel button in the UI.

---

#### Gap J: Approval Queue UI Doesn't Show Action Details

**Severity:** 🟡 Medium

The Pending Approvals page shows the workflow ID and a generic "Action Required" message, but does NOT show the specific actions recommended, the confidence score, affected entities, or the playbook section the recommendation was based on.

---

#### Gap K: No Investigation Dashboard or Historical View

**Severity:** 🟡 Medium

Investigation results are persisted to Postgres but there is no UI to browse past investigations, no way to drill into completed investigations, and no search/filter capabilities.

---

### 🟢 NICE-TO-HAVE — Quality & Polish Gaps

---

#### Gap L: No Automated Test Coverage for AI Components

Tests exist for Phase 1-2 services but there are zero tests for the orchestrator, temporal workflows, LLM client, RAG service, prompt manager, or the HITL approval flow.

#### Gap M: Frontend Is Unmaintainable

The entire UI is 3 files (now larger after the new AI Governance page). No component framework, no build system, no TypeScript. **Note (2026-09-02):** a new "AI Governance" page was added to this same vanilla-JS SPA to surface the Wave 1-3 subsystems (Detection Rules, Entity Risk, Maturity Gate, Playbooks, Compounding Memory, Purple Team, Investigation Ledger) — this closes the *visibility* gap for those features but does **not** address the underlying maintainability gap (still no build system/framework/TypeScript); a full framework migration remains Wave 4 / Phase P, currently paused.

#### Gap N: No Authentication / RBAC

All endpoints are open. `CORS: allow_origins=["*"]`. No login, no API keys, no role-based access control.

---

## 🎯 Roadmap: From Current State to Master-Level AI SOC

### Phase 4: Fix the Data Supply Chain (Close the Simulation Gap)
*Goal: Every agent must reason over REAL data, not fabricated numbers.*
*Priority: 🔴 P0 — Nothing else matters until this is fixed.*

- [x] **Wire EvidenceAgent to real `EvidenceCollectionOrchestrator`**
  - Call `evidence_collection.py` collectors instead of building fake entity graphs
  - Feed real entity nodes + relationships into the context
  - Query PostgreSQL `EntityRecord` and `EventRecord` for real telemetry data
- [x] **Wire CompressionAgent to real `CorrelationEngine`**
  - Run the actual 7-stage compression pipeline on collected evidence
  - Return real `CompressedPackage` with actual event data, timeline, patterns, and metrics
- [x] **Wire RCA to hybrid mode: `sx_truerca.CausalAnalyzer` + LLM**
  - Build a real causal graph from the entity relationships
  - Use `CausalAnalyzer` for structural root-cause analysis
  - Combine causal analysis + LLM reasoning for hybrid RCA
  - Pass the causal graph as structured context to the LLM prompt
- [x] **Unify orchestrator implementations**
  - Extract shared logic (plan building, input resolution, synthesis) into a single module
  - Have both `orchestrator.py` and `temporal_workflows.py` import from it
  - Eliminate the drift risk between the two implementations

---

### Phase 5: Make the Agents Actually Intelligent
*Goal: Transform the linear pipeline into a true multi-agent reasoning system.*
*Priority: 🔴 P0 — This is what makes it "AI-Assisted" vs "AI-Decorated".*

- [x] **Adaptive re-investigation loop**
  - If RCA confidence < 0.7, automatically trigger a second round of evidence collection
  - Allow the RCA agent to request specific additional data from the Evidence agent
  - Cap at 3 iterations to prevent infinite loops
  - Track confidence improvement across iterations
- [x] **Dynamic planning with LLM**
  - Use the LLM to generate the investigation plan based on the alert type
  - Different alerts should produce different agent configurations
  - Allow the plan to be modified mid-investigation when new evidence emerges
- [x] **Inter-agent communication via shared context bus**
  - Create an `InvestigationContext` object that all agents can read/write
  - Agents can post questions that other agents answer in subsequent phases
  - The Evidence agent can receive "additional queries" from the RCA agent
- [x] **Entity grounding and hallucination detection**
  - After Triage, verify that every entity ID actually exists in the raw alert
  - Flag any LLM-generated entity that can't be traced to source data
  - Cross-reference the RCA attack chain against the evidence timeline
- [x] **Multi-model routing with quality gates**
  - Fast model for Triage (latency matters), powerful model for RCA (quality matters)
  - Add a "verifier" step: a second LLM call that validates the first one's output
  - Implement fallback chain: primary model → fallback model → deterministic rules
- [x] **Include few-shot examples in LLM calls**
  - Update `PromptManager` to inject `few_shot_examples` from YAML into the prompt
  - Add few-shot examples for RCA and Response prompts (currently only Triage has them)

---

### Phase 6: LLM Observability & Reliability
*Goal: Every LLM interaction must be traceable, measurable, and recoverable.*
*Priority: 🟡 P1*

- [x] **LLM call instrumentation** — *Done via the Investigation Ledger (`investigation_ledger.py`) + `model_router.py` tagging every decision's tier/source; ledger replayable via `GET /api/v3/orchestrator/investigations/{id}/ledger` and now viewable in the frontend's AI Governance page.*
  - Log every prompt, response, token count, and latency to a structured log
  - Add a `llm_calls` Postgres table for tracking *(implemented as `investigation_ledger_entries`)*
  - Dashboard widget showing LLM health metrics *(cost-summary endpoint + UI)*
- [x] **Prompt/response caching** — *Done via `llm_cache.py` (`LLMResponseCache`, Redis-backed with in-memory TTL fallback), wired into `supervisor.py`'s ReAct loop.*
  - Cache LLM responses by prompt hash in Redis
  - TTL-based invalidation
  - Cache hit/miss metrics
- [x] **Structured output validation** — *Done via `llm_client.validate_triage_output()` + retry-up-to-2 wired into `TriageAgent.execute()`.*
  - After every `structured_llm.ainvoke()`, validate the Pydantic model thoroughly
  - Check that severity is one of the allowed values
  - Check that entity types are valid enum values
  - Reject and retry if validation fails (up to 2 retries)
- [x] **Rate limiting for LLM endpoints** — *Done via `rate_limiter.py` (`TokenBucketLimiter`), wired into `supervisor.py`'s ReAct loop.*
  - Add a token bucket rate limiter for the LM Studio endpoint
  - Queue requests during bursts instead of failing
- [x] **Prompt evaluation harness (CI-grade)**
  - 10+ test scenarios with ground-truth expected outputs
  - Automated scoring: entity extraction accuracy, classification accuracy, action quality
  - Run on every prompt YAML change before merge

---

### Phase 7: Workflow Hardening
*Goal: Make Temporal workflows production-resilient.*
*Priority: 🟡 P1*

- [x] **Approval timeout with escalation**
  - Add a `workflow.wait_condition()` with a timeout
  - If timeout occurs before response, auto-mark timed_out and proceed safely
- [ ] **Workflow cancellation from UI**
  - Add "Cancel Investigation" button to the Orchestrator UI
  - Wire it to the existing `DELETE` endpoint
- [ ] **Investigation retry and resume**
  - If a workflow fails mid-investigation, allow resuming from the last completed phase
  - Store phase checkpoints in the Temporal state
- [ ] **Deadletter handling**
  - After max retries, move failed investigations to a deadletter queue
  - Alert the SOC team via the dashboard
- [ ] **Concurrent investigation limits**
  - Limit to N concurrent investigations to prevent LLM overload
  - Queue additional investigations with priority ordering

---

### Phase 8: Rich Approval & Investigation UX
*Goal: Give analysts the context they need to make informed decisions.*
*Priority: 🟡 P1*

- [x] **Detailed approval cards**
  - Show specific actions recommended (e.g., "Isolate WORKSTATION-042")
  - Show RCA confidence score and root cause summary
  - Show affected entities with risk scores
  - Show playbook section that informed the recommendation
  - Add "Modify" option to let the analyst edit the action list
- [x] **Investigation history dashboard**
  - List all past investigations with status, severity, duration, and outcome
  - Click to drill into full agent reports, entity graph, and attack chain
  - Filter by date range, severity, classification, status
- [ ] **Real-time investigation streaming**
  - Show live progress of running investigations on the dashboard
  - Display which agent is currently executing
- [ ] **Deduplicate pending approvals in frontend**
  - Track workflow IDs already displayed in the approval list
  - Prevent duplicate rows when SSE events are re-emitted

---

### Phase 9: Enterprise Tool Integrations
*Goal: Replace mocked data sources with real security tool connections.*
*Priority: 🟢 P2*

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

### Phase 10: Production Hardening & Observability
*Goal: Make the platform production-ready for enterprise deployment.*
*Priority: 🟢 P2*

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

### Phase 11: Scalability & Multi-Tenancy
*Goal: Scale from single-instance to enterprise-grade deployment.*
*Priority: 🔵 P3*

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
| 🔴 P0 | Wire Evidence/Compression agents to real engines (Gap A) | Critical | Medium |
| ✅ Done | Adaptive re-investigation loop (Gap B) | Critical | High |
| ✅ Done | Inter-agent communication / shared context (Gap C) | Critical | High |
| ✅ Done | Dynamic AI-driven planning (Gap D) | High | Medium |
| ✅ Done | Confidence calibration & hallucination detection (Gap E) | High | Medium |
| ✅ Done | Include few-shot examples in LLM calls (Gap F) | High | Low |
| ✅ Done | LLM observability & call logging (Gap G) | High | Medium |
| ✅ Done | Unify orchestrator implementations (Gap H) | Medium | Medium |
| ✅ Done | Approval timeout & escalation (Gap I) | Medium | Low |
| ✅ Done | Rich approval cards with action details (Gap J) | High | Medium |
| ✅ Done | Investigation history dashboard & search (Gap K) | High | Medium |
| ✅ Done | Activate database persistence | High | Medium |
| ✅ Done | Section-aware playbook chunking | High | Low |
| ✅ Done | Human-in-the-Loop approval gates | High | High |
| ✅ Done | Prompt versioning system | Medium | Low |
| ✅ Done | Multi-model routing | Medium | Low |
| ✅ Done | Automated test coverage for AI components (Gap L) | Medium | Medium |
| 🟢 P2 (Wave 4, paused) | Authentication & RBAC (Gap N) | High | High |
| 🟢 P2 (Wave 4, paused) | SIEM/EDR webhook ingestion | High | Medium |
| 🟢 P2 (Wave 4, paused) | Prometheus + Grafana observability | Medium | Medium |
| 🔵 P3 (Wave 4, paused) | Kubernetes Helm charts | Medium | High |
| 🔵 P3 (Wave 4, paused) | Frontend framework migration (Gap M) | Low | High |
| 🔵 P3 (Wave 4, paused) | Multi-tenancy | Low | Very High |
| ✅ Done | Local threat-intel grounding, Investigation Ledger, Model Router, Agentic security hardening (Wave 1 A-E) | Critical | High |
| ✅ Done | Maturity Gate rollout, Entity-Risk rollout, Detection-as-Code + Live Actions (Wave 2 F-H) | High | High |
| ✅ Done | Hypothesis Swarm, Compounding Memory, Playbook Engine, Purple Team, Security Knowledge Graph (Wave 3 I-M) | High | Very High |
| ✅ Done | AI Governance UI page surfacing all Wave 1-3 subsystems | Medium | Medium |

---

## ✅ Completed Milestones

| Milestone | Date | Notes |
|---|---|---|
| Phase 1: Alert Intake & Normalization | 2026-08 | CrowdStrike + Splunk parsers, dedup, entity extraction |
| Phase 2: Correlation & Compression | 2026-08 | 7-stage pipeline, investigation builder |
| Phase 3: RCA & Response Planning | 2026-08 | sx-truerca integration, LLM-powered agents, report generation |
| Database Persistence (Gap 2+3) | 2026-08-17 | Postgres + Neo4j wired to Temporal workflows |
| Section-Aware RAG Chunking (Gap 9) | 2026-08-17 | Metadata-filtered playbook retrieval |
| Prompt Versioning (Gap 7) | 2026-08-17 | YAML prompts with version tracking |
| Temporal Workflow Integration | 2026-08-17 | Durable 5-phase workflow with parallel activities |
| Human-in-the-Loop (Phase 6) | 2026-08-17 | Temporal signals, approval UI, active response engine, audit trail |
| Multi-Model Routing | 2026-08-17 | Role-based model selection in `llm_client.py` |
| Unify Orchestrator Logic (Gap H) | 2026-08-18 | Extracted shared pipeline logic to `pipeline_core.py` |
| Structured Response & Rich UI (Gap J) | 2026-08-18 | ResponsePlanner produces JSON actions, parsed by UI into Rich Approval Cards |
| Inter-Agent Communication (Gap C) | 2026-08-18 | Added LLM message bus schema and removed hardcoded python communication simulations |
| Investigation History & Explorer (Gap K) | 2026-08-19 | Search toolbar, KPI stats, 4-tab drill-down panel, CoT reasoning logs, and Canvas attack graph |
| Agentic Pluggable Skills Framework | 2026-08-23 | Universal SKILL.md engine, 23 skills across Triage/Evidence/Compression/Discovery, 102 unit/integration tests |
| Quick Wins: Maturity Gate, Entity-Risk, Prompt Registry | 2026-09-02 | `maturity_gate.py`, `entity_risk.py`, `prompts.lock.json` + few-shot injection fix |
| Wave 1 Phase A: Local Threat-Intel Grounding | 2026-09-02 | `local_feeds.py` (SQLite-indexed CSV feeds from `mthcht/awesome-lists`), wired into Triage/Evidence/Compression skills |
| Wave 1 Phase B: Malware-Analysis Evidence Skill | 2026-09-02 | `yara_scanner.py` + feature-flagged `virustotal_client.py`, wired into file-forensics evidence collection |
| Wave 1 Phase C: Investigation Ledger | 2026-09-02 | `investigation_ledger.py` — every agentic LLM call recorded (prompt/response/decision/cost), replayable via API + UI |
| Wave 1 Phase D: Multi-Model Router + LLM Observability | 2026-09-02 | `model_router.py`, `llm_cache.py`, `rate_limiter.py`, structured-output validation with retry |
| Wave 1 Phase E: Agentic AI Security Hardening | 2026-09-02 | `agentic_security.py` — untrusted-data delimiting, goal-drift detection, skill authorization gate, kill switch |
| Wave 2 Phase F/G: Maturity Gate + Entity-Risk full rollout | 2026-09-02 | All 7 response skills mapped to blast radius; entity-risk tracked from Triage + Evidence with auto-promotion |
| Wave 2 Phase H: Detection-as-Code + Live Actions | 2026-09-02 | `detection_engine.py` (YAML rules + fixtures), `live_actions.py` registry gated by the Maturity Gate |
| Wave 3 Phase I: Investigation Swarm | 2026-09-02 | `hypothesis_swarm.py` — parallel competing-hypothesis generation for complex/stuck investigations |
| Wave 3 Phase J: Compounding Memory | 2026-09-02 | `memory/distillation.py` — per-alert-signature false-positive priors, bounded ±0.10 Triage confidence adjustment |
| Wave 3 Phase K: Playbook Engine | 2026-09-02 | `playbook_engine.py` — declarative YAML playbooks driving real Triage/Evidence/Compression/RCA/Response agents |
| Wave 3 Phase L: Self-Play Purple Team | 2026-09-02 | `self_play/purple_team.py` — canned attack campaigns replayed against `DetectionEngine`, auto-drafts coverage-gap rules |
| Wave 3 Phase M: Security Knowledge Graph at Ingest | 2026-09-02 | Neo4j `get_blast_radius()`/`get_neighbors()`, ingest-time user→host→process graph writes |
| AI Governance UI + read-only API | 2026-09-02 | New `frontend` page + `backend/api/routes/ai_governance.py` surfacing Detection Rules, Entity Risk, Maturity Gate, Playbooks, Compounding Memory, Purple Team, and the Investigation Ledger |
