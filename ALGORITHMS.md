# AI-Assisted SOC — Algorithm Reference

> **Document Version**: 2.0
> **Last Updated**: 2026-08-24

This document describes each algorithm used in the AI-Assisted SOC investigation
pipeline, with pseudocode, complexity analysis, and data structure specifications.

---

## Table of Contents

- [1. Alert Normalization & Deduplication](#1-alert-normalization--deduplication)
- [2. Triage Classification Algorithm](#2-triage-classification-algorithm)
- [3. Entity Grounding Algorithm](#3-entity-grounding-algorithm)
- [4. Evidence Skill Dispatch Algorithm](#4-evidence-skill-dispatch-algorithm)
- [5. Universal Log Ingestion Algorithm](#5-universal-log-ingestion-algorithm)
- [6. 7-Stage Noise Reduction Pipeline](#6-7-stage-noise-reduction-pipeline)
- [7. Causal Graph & PageRank RCA Algorithm](#7-causal-graph--pagerank-rca-algorithm)
- [8. Playbook RAG Retrieval Algorithm](#8-playbook-rag-retrieval-algorithm)
- [9. ReAct Supervisor Decision Algorithm](#9-react-supervisor-decision-algorithm)
- [10. Adaptive Re-Investigation Loop](#10-adaptive-re-investigation-loop)

---

## 1. Alert Normalization & Deduplication

**File**: `backend/services/alert_normalizer.py`, `backend/services/alert_deduplicator.py`

### Normalization

```
ALGORITHM NormalizeAlert(raw_alert):
    format ← DetectVendorFormat(raw_alert)  // CrowdStrike, Wazuh, Splunk, Suricata
    
    normalizer ← NormalizerFactory.get(format)
    
    normalized ← NormalizedAlert(
        alert_id:     normalizer.extract_id(raw_alert),
        timestamp:    normalizer.extract_timestamp(raw_alert),
        severity:     normalizer.map_severity(raw_alert),
        description:  normalizer.extract_description(raw_alert),
        entities:     normalizer.extract_entities(raw_alert),
        raw_payload:  raw_alert
    )
    
    RETURN normalized
```

### Sliding-Window Deduplication

```
ALGORITHM DeduplicateAlert(alert, window_minutes=15):
    fingerprint ← SHA256(alert.source + alert.description + alert.entities)
    
    IF fingerprint IN sliding_window_cache:
        existing ← sliding_window_cache[fingerprint]
        IF (alert.timestamp - existing.timestamp) < window_minutes:
            existing.count += 1
            RETURN DUPLICATE
    
    sliding_window_cache[fingerprint] ← alert
    EvictExpiredEntries(sliding_window_cache, window_minutes)
    RETURN UNIQUE
```

**Complexity**: O(1) average per alert (hash-based lookup).

---

## 2. Triage Classification Algorithm

**File**: `backend/services/orchestrator.py` → `TriageAgent.execute()`
**Prompt**: `backend/prompts/triage_v1.yaml`

```
ALGORITHM TriageClassify(alert_data, context):
    // Step 1: Format prompt with MITRE ATT&CK reference tables
    system_prompt ← LoadYAML("triage_v1.yaml").system_prompt
    user_prompt   ← FormatTemplate("triage_v1.yaml".user_template,
                                    alert_json=JSON(alert_data))
    
    // Step 2: Invoke LLM with Pydantic-constrained output
    llm ← GetLLM(role="triage")                    // Qwen2.5-7B, temp=0.1
    structured_llm ← llm.with_structured_output(TriageOutput)
    result ← AWAIT structured_llm.ainvoke(system_prompt + user_prompt)
    
    // Step 3: Verify extracted entities against raw alert text
    raw_text ← JSON(alert_data)
    valid_entities ← VerifyEntities(result.entities_identified, raw_text)
    
    // Step 4: Compute confidence with grounding penalty
    llm_confidence ← result.confidence              // e.g., 0.98
    IF len(valid_entities) == 0:
        confidence ← MIN(llm_confidence, 0.40)       // Heavy penalty
    ELSE:
        confidence ← llm_confidence
    
    // Step 5: Write to shared blackboard
    context.entities ← valid_entities
    context.classification ← result.classification    // e.g., "ransomware"
    context.severity ← result.severity                // e.g., "Critical"
    
    RETURN TriageReport(confidence, entities, classification, severity)
```

### TriageOutput Schema

```
TriageOutput:
    severity:              Literal["Critical", "High", "Medium", "Low"]
    classification:        str       // e.g., "ransomware", "lateral_movement"
    tactic:                str       // MITRE tactic name
    technique:             str       // e.g., "T1486 - Data Encrypted for Impact"
    confidence:            float     // 0.0 - 1.0
    initial_assessment:    str       // Human-readable summary
    requires_immediate_action: bool
    entities_identified:   List[Entity]  // [{type: "host", id: "linuxshare"}, ...]
```

---

## 3. Entity Grounding Algorithm

**File**: `backend/services/llm_client.py` → `verify_entities()`

```
ALGORITHM VerifyEntities(extracted_entities, raw_alert_text):
    verified ← []
    raw_lower ← LOWERCASE(raw_alert_text)
    
    FOR entity IN extracted_entities:
        entity_id ← entity.id
        
        // Exact substring match (case-insensitive)
        IF LOWERCASE(entity_id) IN raw_lower:
            verified.append(entity)
            CONTINUE
        
        // Fuzzy match: check if entity appears as a token boundary
        IF RegexMatch(r'\b' + escape(entity_id) + r'\b', raw_alert_text):
            verified.append(entity)
            CONTINUE
        
        // Reject: entity was hallucinated by LLM
        LOG("Rejected hallucinated entity: " + entity_id)
    
    RETURN verified
```

**Complexity**: O(E × T) where E = entities, T = alert text length.

---

## 4. Evidence Skill Dispatch Algorithm

**File**: `backend/services/evidence/skill_handlers.py` → `EvidenceSkillExecutor`

```
ALGORITHM DispatchEvidenceSkills(entities, context):
    entity_graph ← {}
    skill_deployments ← []
    
    FOR entity IN entities:
        type ← entity.type
        id   ← entity.id
        
        // Entity-type → skill mapping
        target_skills ← SWITCH type:
            "host", "endpoint"  → ["edr-process-tree", "persistence-auditor"]
            "ip", "domain"      → ["threat-intel-lookup", "network-flow-analyzer"]
            "user", "account"   → ["identity-ad-lookup"]
            "file", "process"   → ["file-forensics", "threat-intel-lookup"]
            DEFAULT             → ["threat-intel-lookup"]
        
        FOR skill_name IN target_skills:
            result ← AWAIT EvidenceSkillExecutor.execute_skill(
                skill_name, entity_id=id, entity_type=type,
                context_data={alert: context.alert_data}
            )
            
            // Merge into entity graph
            eid ← type + ":" + id
            IF eid NOT IN entity_graph:
                entity_graph[eid] ← {
                    type, id,
                    risk_score: result.risk_score,
                    enrichment: result.enrichment_data,
                    threat_intel: result.threat_intel
                }
            ELSE:
                entity_graph[eid].enrichment.UPDATE(result.enrichment_data)
                entity_graph[eid].risk_score ← MAX(existing, result.risk_score)
            
            skill_deployments.append({skill_name, id, result.risk_score})
    
    RETURN entity_graph, skill_deployments
```

### Skill Handler: 3-Tier Data Fetching

```
ALGORITHM ExecuteSkill(skill_name, entity_id, entity_type):
    // Tier 1: Database query
    db_results ← QueryPostgres(entity_id)
    
    // Tier 2: Log file ingestion
    ingestor ← GetLogIngestor()
    log_results ← ingestor.search_entity(entity_id, entity_type, max=100)
    
    // Tier 3: Heuristic IOC enrichment
    ioc_score ← ComputeIOCScore(entity_id, entity_type, log_results)
    
    enrichment ← Merge(db_results, log_results)
    
    RETURN {
        risk_score: ioc_score,
        enrichment_data: enrichment,
        threat_intel: ExtractThreatIntel(log_results)
    }
```

---

## 5. Universal Log Ingestion Algorithm

**File**: `backend/services/evidence/log_ingestor.py` → `LogIngestor`

```
ALGORITHM AutoDiscoverLogFiles(dataset_path):
    classified_files ← {}
    
    FOR file IN RecursiveScan(dataset_path):
        IF file.size == 0 OR file.is_binary:
            SKIP
        
        // Read first 5 lines for format detection
        sample ← ReadLines(file, count=5)
        
        format ← CLASSIFY:
            IF any line has {"rule": ..., "agent": ...}  → WAZUH_JSON
            IF any line has {"event_type": ...}           → SURICATA_JSON
            IF any line starts with "type=" and "msg=audit(" → AUDIT_LOG
            IF any line matches ISO-timestamp syslog      → AUTH_SYSLOG
            IF any line matches traditional syslog        → GENERIC_SYSLOG
            ELSE                                          → UNKNOWN (skip)
        
        classified_files[file.path] ← format
    
    RETURN classified_files

ALGORITHM SearchEntity(entity_id, entity_type, max_results=100):
    matches ← []
    entity_lower ← LOWERCASE(entity_id)
    
    FOR file, format IN classified_files:
        parser ← GetParser(format)       // Wazuh, Suricata, Audit, Auth
        
        FOR record IN parser.parse_file(file):
            // Full-text entity match across all fields
            record_text ← LOWERCASE(JSON(record))
            IF entity_lower IN record_text:
                normalized ← NormalizeRecord(record, format)
                matches.append(normalized)
                IF len(matches) >= max_results:
                    RETURN matches
    
    RETURN matches
```

**Complexity**: O(F × L) where F = number of log files, L = average lines per file.

---

## 6. 7-Stage Noise Reduction Pipeline

**File**: `backend/services/correlation_engine.py` → `CorrelationEngine`

```
ALGORITHM CompressEvents(raw_events, incident_time, investigation_id):
    events ← raw_events
    stage_metrics ← []
    
    // Stage 1: Temporal Filter
    window ← [incident_time - 24h, incident_time + 24h]
    events ← [e FOR e IN events IF e.timestamp IN window]
    stage_metrics.append(Metrics("Temporal Filter", input, output))
    
    // Stage 2: Entity Correlation
    investigated_entities ← GetInvestigatedEntityIDs()
    events ← [e FOR e IN events IF
        e.entity IN investigated_entities OR
        e.user IN investigated_entities OR
        e.host IN investigated_entities]
    stage_metrics.append(Metrics("Entity Correlation", input, output))
    
    // Stage 3: Behavioral Filter
    BENIGN_PATTERNS ← [
        "systemd-timesyncd", "systemd-logind",
        "DHCP", "session closed", "session opened",
        "cron", "run-parts", ...
    ]
    events ← [e FOR e IN events IF NOT MatchesBenignPattern(e, BENIGN_PATTERNS)]
    stage_metrics.append(Metrics("Behavioral Filter", input, output))
    
    // Stage 4: Deduplication
    seen_hashes ← {}
    unique_events ← []
    FOR e IN events:
        hash ← SHA256(e.event_type + e.entity + e.action)
        IF hash NOT IN seen_hashes:
            seen_hashes[hash] ← 1
            unique_events.append(e)
        ELSE:
            seen_hashes[hash] += 1
    events ← unique_events
    stage_metrics.append(Metrics("Deduplication", input, output))
    
    // Stage 5: Graph Analysis
    G ← BuildEntityGraph(events)
    connected_components ← FindConnectedComponents(G)
    events ← KeepLargestComponent(events, connected_components)
    lateral_paths ← FindMultiHopPaths(G)
    stage_metrics.append(Metrics("Graph Analysis", input, output))
    
    // Stage 6: Abstraction
    FOR e IN events:
        e.action ← AbstractToHumanReadable(e.raw_action)
        // Convert hex syscalls → readable text
        // Merge sequential micro-events → summary event
    stage_metrics.append(Metrics("Abstraction", input, output))
    
    // Stage 7: Risk Scoring
    FOR e IN events:
        e.risk_score ← CompositeRisk(
            threat_intel_match(e),      // Weight: 0.35
            behavioral_anomaly(e),      // Weight: 0.25
            entity_risk(e),             // Weight: 0.20
            temporal_proximity(e)       // Weight: 0.20
        )
    events ← SORT(events, key=risk_score, descending=True)
    stage_metrics.append(Metrics("Risk Scoring", input, output))
    
    // Build output
    timeline ← ExtractTimeline(events)
    attack_graph ← ExtractAttackSubgraph(G)
    
    RETURN CompressionPackage(
        original_event_count: len(raw_events),
        compressed_event_count: len(events),
        compression_ratio: len(raw_events) / MAX(len(events), 1),
        timeline: timeline,
        attack_graph: attack_graph,
        stage_metrics: stage_metrics,
        risk_score: MAX(e.risk_score FOR e IN events),
        confidence: ComputePipelineConfidence(stage_metrics)
    )
```

### Behavioral Filter Rules

```
BENIGN_PATTERNS = {
    "systemd-timesyncd",     // NTP time sync noise
    "systemd-logind",        // Login session lifecycle
    "session closed",        // PAM session teardown
    "session opened",        // PAM session creation
    "run-parts",             // Cron helper invocations
    "DHCP",                  // DHCP renewals
    "dhclient",              // DHCP client activity
    "anacron",               // Scheduled job runner
    "logrotate",             // Log rotation daemon
}

SECURITY_PRESERVES = {
    "sudo",                  // Privilege escalation
    "curl", "wget",          // File download (potential C2)
    "chpasswd", "passwd",    // Credential modification
    "EXECVE",                // Process execution (audit)
    "chmod", "chown",        // Permission changes
    "iptables",              // Firewall modifications
    "ssh", "sshd",           // Remote access
    "PROMISC",               // Network sniffing mode
}
```

---

## 7. Causal Graph & PageRank RCA Algorithm

**File**: `backend/services/rca_engine.py`, `backend/services/sx_truerca/causal_analyzer.py`

```
ALGORITHM RootCauseAnalysis(compressed_timeline, entity_graph, entities):
    // Step 1: Build Causal Directed Graph
    G ← nx.DiGraph()
    
    FOR event IN compressed_timeline:
        G.add_node(event.entity, risk=event.risk_score, timestamp=event.timestamp)
        IF event has parent_entity:
            G.add_edge(event.parent_entity, event.entity,
                       weight=event.risk_score,
                       timestamp=event.timestamp)
    
    FOR relationship IN entity_graph.relationships:
        G.add_edge(relationship.source, relationship.target,
                   type=relationship.type)
    
    // Step 2: Modified PageRank (risk-weighted)
    pagerank_scores ← nx.pagerank(G,
        personalization={node: G.nodes[node].risk FOR node IN G.nodes},
        weight='weight'
    )
    
    // Step 3: Identify Patient Zero
    patient_zero ← ARGMAX(pagerank_scores)
    
    // Step 4: Compute Blast Radius
    blast_radius ← len(nx.descendants(G, patient_zero))
    
    // Step 5: LLM Attack Chain Reconstruction
    chain ← AWAIT LLM.invoke(rca_v1.yaml,
        timeline=compressed_timeline,
        entity_graph=entity_graph,
        patient_zero=patient_zero
    )
    
    RETURN RCAOutput(
        root_cause: chain.root_cause,
        patient_zero: patient_zero,
        blast_radius: blast_radius,
        confidence_score: chain.confidence_score,
        attack_chain: chain.attack_chain
    )
```

---

## 8. Playbook RAG Retrieval Algorithm

**File**: `backend/services/rag_service.py`

```
ALGORITHM SearchPlaybook(query, classification, top_k=4):
    // Step 1: Map classification to playbook name for metadata filtering
    playbook_name ← CLASSIFICATION_TO_PLAYBOOK.get(classification)
    
    // Step 2: Embed query with sentence transformer
    embedding ← MiniLM_L6_v2.encode(query)
    
    // Step 3: FAISS approximate nearest neighbor search
    candidates ← faiss_index.similarity_search(embedding, k=top_k * 3)
    
    // Step 4: Filter by playbook metadata (if classification matched)
    IF playbook_name:
        candidates ← [c FOR c IN candidates
                       IF c.metadata.playbook_name == playbook_name]
    
    // Step 5: Section-priority ranking
    SECTION_PRIORITY = {
        "containment actions": 4,
        "eradication & recovery": 3,
        "triage & investigation": 2,
        "description": 1,
        "post-incident": 0
    }
    
    FOR candidate IN candidates:
        section ← candidate.metadata.section_title
        candidate.priority ← SECTION_PRIORITY.get(LOWERCASE(section), 0)
    
    candidates ← SORT(candidates, key=priority, descending=True)
    
    RETURN candidates[:top_k]
```

---

## 9. ReAct Supervisor Decision Algorithm

**File**: `backend/services/supervisor.py` → `SupervisorAgent`

```
ALGORITHM SupervisorDecideNextStep(context):
    // Step 1: Prepare observation summary from investigation blackboard
    observation ← {
        alert: context.alert_data.summary,
        classification: context.classification,
        severity: context.severity,
        entities: FormatEntities(context.entities + context.pivot_entities),
        timeline: FormatTimeline(context.compressed_events.timeline),
        rca_confidence: context.rca_findings.confidence_score,
        gaps: FormatPendingMessages(context.messages),
        history: FormatSupervisorHistory(context.supervisor_history)
    }
    
    // Step 2: Invoke Supervisor LLM
    TRY:
        llm ← GetLLM(role="supervisor")
        decision ← AWAIT llm.with_structured_output(SupervisorDecision)
            .ainvoke(supervisor_v1.yaml, observation)
        
        // Register lateral pivot entity if detected
        IF decision.pivot_entity_detected:
            context.add_entity(decision.pivot_entity_detected, is_pivot=True)
        
        // Validate and sanitize decision
        decision ← ValidateDecision(decision, context)
        
        RETURN decision
    
    CATCH Exception:
        // Deterministic heuristic fallback
        RETURN HeuristicFallbackDecision(context)

ALGORITHM HeuristicFallbackDecision(context):
    IF context.entity_graph is EMPTY:
        RETURN Decision(action="gather_evidence", entities=context.entities)
    
    IF context.compressed_events is EMPTY:
        RETURN Decision(action="compress_events")
    
    IF context.rca_findings is EMPTY OR confidence < 0.70:
        RETURN Decision(action="perform_rca")
    
    RETURN Decision(action="finalize_response")

ALGORITHM ValidateDecision(decision, context):
    // Fill missing target entities
    IF decision.action == "gather_evidence" AND no targets:
        decision.target_entities ← AllKnownEntityIDs(context)
    
    // Enforce prerequisite order
    IF decision.action == "perform_rca" AND no compressed_events:
        decision.action ← "compress_events"  // Must compress before RCA
    
    IF decision.action == "finalize_response" AND no rca_findings:
        decision.action ← "perform_rca"      // Must RCA before response
    
    RETURN decision
```

---

## 10. Adaptive Re-Investigation Loop

### Static Mode (Deterministic)

```
ALGORITHM AdaptiveReinvestigation_Static(context):
    WHILE context.needs_reinvestigation():
        // Trigger condition: confidence < 0.70 OR pending REQUEST_EVIDENCE messages
        
        IF context.iteration >= context.max_iterations:
            BREAK
        
        context.iteration += 1
        context.confidence_history.append(context.rca_findings.confidence_score)
        
        // Re-run evidence collection on all entities
        AWAIT EvidenceAgent.execute(context)
        
        // Re-run RCA with expanded evidence
        AWAIT RCAAgent.execute(context)
```

### ReAct Mode (Autonomous)

```
ALGORITHM InvestigationLoop_ReAct(context):
    // Phase 1: Mandatory Triage
    AWAIT TriageAgent.execute(context)
    
    // Phase 2+: Dynamic Supervisor Loop
    WHILE context.iteration < context.max_iterations:
        decision ← AWAIT SupervisorAgent.decide_next_step(context)
        context.record_supervisor_decision(decision)
        
        SWITCH decision.action:
            "gather_evidence"  → AWAIT EvidenceAgent.execute(context)
            "discover_network" → AWAIT DiscoveryAgent.execute(context)
            "compress_events"  → AWAIT CompressionAgent.execute(context)
            "perform_rca"      → AWAIT RCAAgent.execute(context)
            "terminate_benign" → BREAK with early_exit=True
            "finalize_response"→ BREAK
        
        context.iteration += 1
    
    // Final Phase: Response Planning (unless terminated as benign)
    IF NOT early_exit:
        AWAIT ResponsePlannerAgent.execute(context)
```

---

## Complexity Summary

| Algorithm | Time Complexity | Space Complexity |
|:---|:---|:---|
| Alert Normalization | O(1) per alert | O(1) |
| Deduplication (sliding window) | O(1) amortized | O(W) window size |
| Triage Classification | O(1) LLM call | O(T) prompt tokens |
| Entity Grounding | O(E × T) | O(E) entities |
| Evidence Skill Dispatch | O(E × S) entities × skills | O(E × S) |
| Log Ingestion (full scan) | O(F × L) files × lines | O(M) matches |
| 7-Stage Compression | O(N log N) events | O(N) events |
| Causal Graph PageRank | O(V + E) graph nodes/edges | O(V + E) |
| FAISS RAG Retrieval | O(log N) approximate NN | O(N) index |
| Supervisor Decision | O(1) LLM call | O(H) history |
