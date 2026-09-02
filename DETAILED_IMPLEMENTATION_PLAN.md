# AI-Assisted SOC — Detailed Implementation Plan
**Status:** Wave 1-3 complete, Wave 4 paused · **Last updated:** 2026-09-02
**Supersedes/combines:** `implementation_plan.md`, `implementation_plan1.md`, open portions of `ROADMAP.md`

---

## 0. Vision & Framing

Project's own stated vision (from `implementation_plan.md`): **"Add AI IN the SOC, not just USE AI."**
This means: the AI must *drive* investigations (choose what to look at next, decide when it has enough evidence, decide what action to recommend) rather than being a single LLM call bolted onto a static pipeline. The existing `backend/services/supervisor.py` ReAct loop is the seed of this — this plan hardens, grounds, and scales that idea.

**Guiding principles for every phase below:**
1. **Ground truth over LLM guesswork** — deterministic data (threat-intel feeds, YARA, MITRE mappings) must answer what it can before the LLM is asked.
2. **Every AI decision must be auditable and replayable** — no black-box reasoning in a security product.
3. **Autonomy must be earned and gated by blast radius** — nothing destructive auto-executes without a graduated trust model.
4. **The agents themselves are an attack surface** — prompt injection via alert/log content must be defended like any other untrusted input.

**Verified current state (via direct code inspection, 2026-09-02):**
- ROADMAP.md Phases 1-5 are genuinely complete.
- ROADMAP.md Phases 6-8 are now genuinely complete (see Wave 1/2 below); Phases 9-11 (Wave 4) remain open and are explicitly paused pending real vendor credentials/infrastructure decisions.
- All 12 ideas from `implementation_plan1.md` (sourced from `beenuar/AiSOC`) are now implemented: `investigation_ledger.py`, `model_router.py`, `entity_risk.py`, `maturity_gate.py`, `playbook_engine.py`, `self_play/purple_team.py`, `hypothesis_swarm.py`, `memory/distillation.py` all exist under `backend/services/`. `prompt_manager.py` now injects `few_shot_examples` into the rendered prompt.

---

## 1. Source Repos — What Each Contributes

| Repo | Role in this plan | License/legal note |
|---|---|---|
| **beenuar/AiSOC** | Architectural blueprint — backbone of Waves 1-3 (12 ideas). Not code-copied; patterns re-implemented natively for this stack (Python/FastAPI/Postgres/Neo4j vs their LangGraph/TypeScript/ClickHouse). | MIT — safe to study/re-implement patterns. |
| **mthcht/awesome-lists** | Data source — CSV threat-intel feeds (ransomware extensions/notes, LOLDrivers hashes, hijacklibs, malicious SSL certs, Tor/VPN IPs, phishing domains, suspicious ports/mutexes/named pipes/services/tasks, offensive-tool keywords). | MIT — safe to vendor/submodule. |
| **rshipp/awesome-malware-analysis** | Reference catalog (not code) — informs which categories of malware-analysis tooling to integrate (YARA, VirusTotal, hash-based lookups). We build our own thin skill, not fork their list. | CC-BY-4.0 (list itself), tools referenced have their own licenses (YARA: BSD, VT: commercial API). |
| **requie/AI-Red-Teaming-Guide** | Methodology reference — OWASP Top 10 for Agentic Applications (ASI01-ASI10) mapping used to harden `supervisor.py`/`prompt_manager.py` against prompt injection, goal hijack, tool misuse. | MIT — guide content, not code. |
| **MorDavid/BruteForceAI** | Adversary technique reference only — its LLM-driven login-brute-force evasion pattern (rotating User-Agent + synchronized jittered delay) becomes the **basis for one detection rule**, no code/tool integration. | Non-Commercial License — confirms we must NOT integrate/redistribute their code; detection-rule authorship from first principles is safe. |
| **projectdiscovery/naabu**, **edoardottt/cariddi**, **evyatarmeged/Raccoon** | **Excluded by decision** — offensive recon/attack-surface tools (port scanning, web crawling, OSINT). Project stays reactive/investigation-focused; revisit only if scope later expands to proactive attack-surface monitoring. | N/A (not used) |

---

## 2. Wave & Phase Overview (Dependency Graph)

```
Quick Wins (parallel, no deps) ─┐
                                  ├──> Wave 1 (A,B,C,D,E) ──> Wave 2 (F,G,H) ──> Wave 3 (I,J,K,L,M) ──> Wave 4 (N,O,P)
Phase D.2/D.3 (few-shot+versioning) ┘
Phase F (Maturity Gate) ┘
Phase G (Entity Risk) ┘
```

- **Wave 1** must land before Wave 2 (Maturity Gate needs the Ledger for audit; Detection-as-Code benefits from grounded threat-intel).
- **Wave 2** must land before Wave 3 (Swarm/Memory/Playbook/Purple-Team all consume risk scores, detection rules, and the ledger).
- **Wave 4** is largely independent of Wave 3 and can run in parallel once Wave 2 is stable, if you have a second workstream.

---

## 3. Status Summary (as of 2026-09-02)

| Wave | Phases | Status |
|---|---|---|
| Wave 0 | Quick Wins (Prompt Registry, Maturity Gate, Entity-Risk) | ✅ Complete |
| Wave 1 | A (Threat-Intel Grounding), B (Malware Analysis), C (Investigation Ledger), D (Model Router + Observability), E (Agentic Security Hardening) | ✅ Complete |
| Wave 2 | F (Maturity Gate rollout), G (Entity-Risk rollout), H (Detection-as-Code + Live Actions) | ✅ Complete |
| Wave 3 | I (Investigation Swarm), J (Compounding Memory), K (Playbook Engine), L (Self-Play Purple Team), M (Security Knowledge Graph) | ✅ Complete |
| Wave 4 | N (Enterprise Integrations), O (Production Hardening), P (Scalability & Multi-Tenancy) | ⏸️ Paused — needs real vendor credentials/infra decisions |

**Regression baseline:** 380 backend tests passing (`pytest backend/tests/` minus 3 files requiring live LM Studio/Temporal servers), zero regressions across every phase above. A new read-only **AI Governance API** (`backend/api/routes/ai_governance.py`) and matching frontend page now expose Detection Rules, Entity Risk, the Maturity Gate, Playbooks, Compounding Memory, and the Purple Team to the UI — these subsystems were previously backend-only with no HTTP surface.

Full per-phase implementation detail (files touched, design decisions, scoping notes, and exact test counts) is preserved in this repository's `ROADMAP.md` "Completed Milestones" table and in the project's session history.

---

## 4. Wave 4 — Enterprise Integration & Production Readiness (PAUSED)

*(ROADMAP.md Phases 9-11.)*

### Phase N: Enterprise Tool Integrations
Real SIEM webhook ingestion (Splunk/Elastic), EDR query+action APIs (CrowdStrike/SentinelOne/Defender), identity provider enrichment (AD/Okta/Entra ID), hosted threat-intel APIs (VirusTotal/AbuseIPDB/GreyNoise), ticketing sync (ServiceNow/Jira). **Blocked on:** real vendor credentials/sandbox access.

### Phase O: Production Hardening
AuthN/RBAC (OAuth2/OIDC), OpenTelemetry tracing, Prometheus/Grafana, secrets management (Vault), rate limiting, CI/CD. **Blocked on:** choice of auth provider and availability of Prometheus/Grafana/Vault infrastructure.

### Phase P: Scalability & Multi-Tenancy
Kubernetes/Helm, multi-tenancy, event-driven ingestion (Redis Streams/Kafka), frontend framework migration (React/Next.js/Vue). **Blocked on:** scope decision — is K8s/multi-tenant deployment even in scope for this engagement, and should the frontend rewrite happen now or later.

**Do not start Wave 4** without new explicit instructions specifying: which vendor(s) to target for Phase N, which auth provider/infra is available for Phase O, and whether Phase P's frontend rewrite/Kubernetes work is in scope.

---

## 5. Explicitly Excluded (by decision)
- **projectdiscovery/naabu** (port scanner), **edoardottt/cariddi** (web crawler/secret finder), **evyatarmeged/Raccoon** (OSINT/subdomain enum) — all are offensive recon/attack-surface tools. Decision: this project stays reactive/investigation-focused rather than adding proactive attack-surface monitoring.
- **MorDavid/BruteForceAI** — excluded as a tool integration (offensive credential-attack tool, non-commercial license, out of scope for a defensive SOC platform); included **only** as the technique reference for one detection rule (Phase H).

## 6. Cross-Cutting Risks & Mitigations
- **Two orchestration implementations drift** (`orchestrator.py` vs `temporal_workflows.py`) — mitigated via `pipeline_core.py` as the shared source-of-truth for logic touched by C, D, E, I, K.
- **No CI system confirmed present** — `backend/scripts/verify_prompt_lock.py` and `backend/scripts/validate_detections.py` are CI-gate substitutes, ready to be wired into a real CI workflow whenever one is stood up.
- **LLM/local-model variability** — Phase D's structured-output validation and fallback chain are the safety net for local LM Studio models producing malformed output under load.
- **Legal/licensing** — verified safe per-source in section 1 above.

## 7. Verification Checklist (per wave, end-to-end smoke test)
- **Wave 1 done when:** a known-bad indicator (ransomware extension or Tor IP) scores high risk deterministically (no LLM call), and a completed investigation's full decision trail is replayable via the Ledger API. ✅ Verified.
- **Wave 2 done when:** a HIGH/CRITICAL response action is correctly queued for approval below L4, and the BruteForceAI-pattern detection rule fires on a synthetic credential-stuffing log via the CI fixture gate. ✅ Verified.
- **Wave 3 done when:** the previously-known "stuck in Evidence loop" case resolves via the Swarm instead of looping, a ransomware alert drives the full Playbook Engine sequence, and a Purple-Team campaign run produces a coverage report with at least one auto-drafted detection rule. ✅ Verified.
- **Wave 4 done when:** the platform requires authentication on all routes, traces are visible end-to-end for one investigation, and a multi-tenant concurrent load test shows correct data isolation. ⏸️ Not started.
