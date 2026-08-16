# AI-Assisted SOC Platform: Future Roadmap

This document outlines the strategic phases required to take the current AI-Assisted SOC Platform from its current state (Phase 3: Simulated Orchestration) to a fully autonomous, production-ready enterprise security platform.

## Current State (Phase 3 Complete)
✅ Event ingestion via FastAPI.
✅ Multi-agent delegation (Triage, Evidence, Discovery, Compression, RCA, Response).
✅ Enterprise-grade orchestration using Temporal (Durable workflows, retries).
✅ Simulated AI outputs and Mock integrations.
✅ Interactive UI for monitoring the investigation pipeline.

---

## 🎯 Phase 4: True AI Integration (LLM Implementation)
*Goal: Replace the current static/mocked agent outputs with real Large Language Models.*
- [ ] **Agent Framework Integration:** Implement an AI framework (e.g., LangChain, LlamaIndex, or AutoGen) within the Temporal activities.
- [ ] **Prompt Engineering:** Develop strict, deterministic system prompts for each agent (Triage, RCA, Response).
- [ ] **Structured Outputs:** Enforce strict JSON schema outputs from the LLMs using tools like OpenAI structured outputs or Instructor to ensure the Orchestrator can parse the results.
- [ ] **RAG for Playbooks:** Connect the Response Agent to a Vector Database containing the organization's incident response playbooks.

## 🎯 Phase 5: Human-in-the-Loop (HITL) & Active Response
*Goal: Move from "Response Planning" to actual "Response Execution" safely.*
- [ ] **Temporal Signals:** Implement Temporal `workflow.await_condition()` to pause the workflow before executing critical response actions (e.g., isolating a host).
- [ ] **Approval UI:** Update the SOC Dashboard to show a "Pending Approval" queue where human analysts can review the AI's response plan and click "Approve" or "Reject".
- [ ] **Action Execution Engine:** Build the actual execution scripts to carry out approved actions (e.g., calling an EDR API to contain a host).

## 🎯 Phase 6: Enterprise Tool Integrations
*Goal: Replace mocked API responses with real security tool connections.*
- [ ] **SIEM Integration (Splunk/Elastic):** Connect the Alert Intake API directly to a SIEM webhook to ingest real production alerts.
- [ ] **EDR Integration (CrowdStrike/SentinelOne):** Connect the Evidence Agent to query real telemetry (process trees, network connections).
- [ ] **Identity & Access (Active Directory/Okta):** Connect to directory services to enrich user entities.
- [ ] **Threat Intel:** Integrate VirusTotal, GreyNoise, or MITRE ATT&CK APIs for the Evidence Agent to score external IPs and hashes.

## 🎯 Phase 7: Production Hardening
*Goal: Ensure the platform can handle enterprise scale and meet security compliance.*
- [ ] **Authentication & RBAC:** Secure the FastAPI backend and UI with OAuth2/OIDC. Ensure analysts can only see alerts they are authorized for.
- [ ] **Audit Logging:** Ensure every action taken by the AI (and every human approval) is immutably logged for compliance.
- [ ] **Scalability:** Deploy the Temporal Workers onto Kubernetes (K8s) using auto-scaling metrics to spin up more workers during a massive malware outbreak.
- [ ] **Telemetry:** Export Prometheus metrics for agent duration, compression ratios, and LLM token usage to a Grafana dashboard.
