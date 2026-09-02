# Deep Dive: Ideas from AiSOC → Our AI-Assisted SOC

After reading every architecture doc, concept page, and design document from [beenuar/AiSOC](https://github.com/beenuar/AiSOC), here are **12 concrete ideas** we can bring into our project — organized from **highest impact → lowest effort**.

---

## 1. 🏆 Investigation Ledger (Audit Trail for AI Decisions)

**What AiSOC does:** Every LLM prompt, response, evidence cited, and tool call is logged step-by-step per case in an "Investigation Ledger." Analysts can **replay** any investigation later to understand exactly why the AI made each decision.

**What we have now:** Our `supervisor_history` in `InvestigationContext` tracks `(thought, action, goal)` tuples, but they're **not persisted** to the database and are lost after the investigation ends.

**What to build:**

```python
# NEW: backend/services/investigation_ledger.py
class LedgerEntry:
    step_index: int           # 0, 1, 2, ...
    timestamp: datetime
    agent_name: str           # "supervisor", "triage", "rca_engine"
    phase: str                # "triage", "evidence", "compression", "rca", "response"
    
    # The AI decision
    prompt_sent: str          # Full prompt text sent to LLM
    prompt_hash: str          # SHA256 of prompt for versioning
    llm_response: str         # Raw LLM response
    model_used: str           # "gemini-2.0-flash", "gpt-4o", etc.
    
    # What it decided
    decision: dict            # SupervisorDecision as JSON
    evidence_cited: List[str] # Entity IDs / event IDs referenced
    skills_invoked: List[str] # Which skills were called
    
    # Cost tracking
    tokens_in: int
    tokens_out: int
    latency_ms: int

class InvestigationLedger:
    """Persistent, replayable audit trail for every AI decision."""
    
    def record(self, case_id: str, entry: LedgerEntry) -> None: ...
    def replay(self, case_id: str) -> List[LedgerEntry]: ...
    def get_cost_summary(self, case_id: str) -> dict: ...
```

**Impact:** This directly solves the "why did the AI do that?" question. When the Supervisor runs Evidence 3 times, the Ledger shows exactly what prompt it sent each time and what the LLM returned — making debugging trivial.

> [!IMPORTANT]
> **Your Redundancy Guard fix should also log to this ledger.** When the guard detects "Evidence already returned the same 6 entities twice", it writes a ledger entry saying "SKIPPED: Evidence phase — previously returned identical results."

---

## 2. 🏆 Multi-Model Router (Don't Use LLM When You Don't Need To)

**What AiSOC does:** A 3-tier escalation ladder:
```
deterministic ── confident? ──▶ done (tier=deterministic)
      │ no
      ▼
     ML ──────── confident? ──▶ done (tier=ml)
      │ no
      ▼
     LLM ─────────────────────▶ done (tier=llm)
```

Every decision is **attributed to the tier that produced it.** If a deterministic rule can handle it, the LLM is never called.

**What we have now:** Our `llm_client.py` calls the LLM for everything — triage, RCA, report generation, supervisor decisions. There's no concept of "is this simple enough to handle without AI?"

**What to build:**

```python
# NEW: backend/services/model_router.py
class ModelRouter:
    """3-tier decision router: deterministic → ML → LLM."""
    
    TIERS = ["deterministic", "ml", "llm"]
    
    async def route(self, task: str, context: dict) -> RoutingDecision:
        """Route a task to the cheapest tier that can handle it."""
        
        # Tier 1: Deterministic rules
        if task == "triage" and self._has_known_signature(context):
            return RoutingDecision(tier="deterministic", result=self._rule_triage(context))
        
        if task == "entity_risk" and self._has_threat_intel_match(context):
            return RoutingDecision(tier="deterministic", result={"risk": "high", "source": "threat_intel_db"})
        
        # Tier 2: ML scoring (future - Isolation Forest for anomaly detection)
        # if task == "anomaly_score":
        #     return RoutingDecision(tier="ml", result=self._ml_score(context))
        
        # Tier 3: LLM (last resort)
        return RoutingDecision(tier="llm", result=await self._llm_call(task, context))
```

**Concrete wins for our project:**
| Task | Currently | After Router |
|------|-----------|--------------|
| Triage a known ransomware extension (`.lockbit3`) | LLM call (~2s, ~$0.01) | Deterministic match vs `awesome-lists` ransomware CSV (~0ms, $0) |
| Score risk of a Tor exit node IP | LLM call | Deterministic match vs Tor node list (~0ms, $0) |
| Generate investigation report | LLM call (correct) | LLM call (correct — this needs language generation) |
| Supervisor deciding next phase | LLM call | LLM call (correct — this needs reasoning) |

---

## 3. 🏆 Investigation Swarm (Parallel Hypothesis Agents)

**What AiSOC does:** For complex cases (≥3 entities or ≥3 MITRE techniques), it fans out **3-5 competing hypothesis agents in parallel** — each independently gathering evidence with its own cost budget. A **debate node** then scores the hypotheses and emits a ranked list.

**What we have now:** Our Supervisor runs **one hypothesis at a time, sequentially.** It picks a phase, runs it, observes results, picks the next phase. This is why we get stuck in loops — there's only one theory being tested.

**What to build:**

```python
# NEW: backend/services/hypothesis_swarm.py
class HypothesisAgent:
    """One competing theory about what's happening."""
    hypothesis: str          # e.g. "ransomware_staging"
    supporting_techniques: List[str]  # MITRE technique IDs
    contradicting_signals: List[str]
    confidence: float        # 0.0 - 1.0
    cost_budget_tokens: int  # max tokens this agent can spend

class InvestigationSwarm:
    """Fan out parallel hypotheses, then debate to pick the best one."""
    
    COMPLEXITY_THRESHOLD = 3  # entities or techniques
    
    async def should_swarm(self, context: InvestigationContext) -> bool:
        """Swarm only fires when case is complex enough."""
        entity_count = len(context.entities)
        technique_count = len(set(
            e.get("mitre_technique", "") for e in context.entities if e.get("mitre_technique")
        ))
        return entity_count >= self.COMPLEXITY_THRESHOLD or technique_count >= self.COMPLEXITY_THRESHOLD
    
    async def run_swarm(self, context: InvestigationContext) -> SwarmResult:
        """Run 3-5 hypothesis agents in parallel, then debate."""
        hypotheses = self._generate_hypotheses(context)  # LLM generates competing theories
        
        # Run all hypothesis agents concurrently with budget caps
        results = await asyncio.gather(*[
            self._investigate_hypothesis(h, context) for h in hypotheses
        ])
        
        # Debate node scores each hypothesis
        return await self._debate(results, context)
```

**Why this matters:** Instead of the Supervisor running Evidence → Evidence → Evidence trying to find "how raindrop.ps1 got in", the Swarm would test:
1. **Hypothesis A:** "Ransomware staging via phishing email" → look for email logs
2. **Hypothesis B:** "Lateral movement from compromised peer" → look for SMB/RDP connections
3. **Hypothesis C:** "Insider threat — employee downloaded" → look for browser/download history
4. **Hypothesis D:** "False positive — IT admin legitimately using PowerShell" → check admin activity logs

Each runs in parallel, each gets its own budget, and the debate picks the best-supported theory.

---

## 4. 🏆 Compounding Memory (The SOC That Gets Smarter Over Time)

**What AiSOC does:** A nightly distillation job compresses analyst overrides + verdict history into "institutional memory" — **per-signature priors** (how this alert type has historically resolved) and a **few-shot exemplar bank** (best past cases injected into LLM prompts).

**What we have now:** Every investigation starts from zero. There's no memory of past investigations, past analyst corrections, or past false positives.

**What to build:**

```python
# NEW: backend/services/memory/distillation.py
class CompoundingMemory:
    """Institutional memory that improves verdicts over time."""
    
    def distill(self):
        """Nightly job: compress resolved cases into priors + exemplars."""
        
        # 1. Per-signature priors
        # For each alert signature (category + source + technique),
        # compute: historical FP rate, prior confidence, common resolution
        for signature in self._get_all_signatures():
            resolved_cases = self._get_resolved_cases(signature)
            fp_rate = sum(1 for c in resolved_cases if c.verdict == "false_positive") / len(resolved_cases)
            self._store_prior(signature, fp_rate=fp_rate, sample_size=len(resolved_cases))
        
        # 2. Few-shot exemplar bank
        # Top-N most-evidenced resolved cases per category
        for category in ["ransomware", "phishing", "lateral_movement", "insider_threat"]:
            best_cases = self._get_top_resolved_cases(category, n=5)
            self._store_exemplars(category, best_cases)
    
    def get_memory_verdict_adjustment(self, alert_signature: str) -> float:
        """Bounded adjustment (±0.10 max) based on historical performance."""
        prior = self._get_prior(alert_signature)
        if prior is None:
            return 0.0  # Unknown signature contributes nothing
        
        # Analysts repeatedly confirmed → nudge UP; repeatedly FP'd → nudge DOWN
        adjustment = (1.0 - prior.fp_rate) * 0.10 - prior.fp_rate * 0.10
        return max(-0.10, min(0.10, adjustment))  # Capped at ±0.10
```

**Impact:** After running for a month, the system would automatically know that "Sysmon Event ID 1 with PowerShell" from `UserWorkstation` is usually a false positive (IT admin running scripts), and nudge its triage score down — without any code change.

---

## 5. 🔥 L0-L4 Automation Maturity (Trust Ladder for Response Actions)

**What AiSOC does:** 5 tiers of automation gating, from L0 (agents are advisory-only) to L4 (fully autonomous for whitelisted actions). Each action has a **blast radius** (`MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and the tier determines what's auto-executed vs queued for approval.

**What we have now:** Our Response phase has `simulation_mode: true` hardcoded — everything is simulated. There's no concept of "this action is safe to auto-execute" vs "this needs human approval."

**What to build:**

```python
# NEW: backend/services/response/maturity_gate.py
class BlastRadius(Enum):
    MINIMAL = "minimal"     # Slack notification, ticket creation
    LOW = "low"             # Quarantine file, IOC blocklist
    MEDIUM = "medium"       # Block IP, kill process, reset password
    HIGH = "high"           # Isolate host, disable user
    CRITICAL = "critical"   # Wipe device, revoke all sessions

class AutomationTier(Enum):
    L0_OBSERVE = 0      # All advisory, no auto-execution
    L1_NOTIFY = 1        # Auto: Slack, tickets
    L2_CONTAIN = 2       # Auto: quarantine, blocklist  
    L3_REMEDIATE = 3     # Auto: block IP, kill process
    L4_AUTOMATE = 4      # Auto: isolate host (whitelisted only)

# Map each skill to its blast radius
SKILL_BLAST_RADIUS = {
    "block-ip": BlastRadius.MEDIUM,
    "block-domain": BlastRadius.MEDIUM,
    "isolate-host": BlastRadius.HIGH,
    "kill-process": BlastRadius.MEDIUM,
    "disable-user-account": BlastRadius.HIGH,
    "reset-credentials": BlastRadius.MEDIUM,
    "quarantine-file": BlastRadius.LOW,
    "notify-soc-team": BlastRadius.MINIMAL,
}

class MaturityGate:
    def evaluate(self, skill_name: str, tenant_tier: AutomationTier) -> GateDecision:
        """Should this action auto-execute or queue for approval?"""
        blast = SKILL_BLAST_RADIUS.get(skill_name, BlastRadius.CRITICAL)
        
        if blast.value <= tenant_tier.value:
            return GateDecision(action="auto_execute", reason=f"Blast radius {blast.name} within L{tenant_tier.value} threshold")
        else:
            return GateDecision(action="queue_for_approval", reason=f"Blast radius {blast.name} exceeds L{tenant_tier.value} — requires human approval")
```

**Map to our existing Response skills:**

| Response Skill | Blast Radius | Auto-executes at |
|---|---|---|
| `notify-soc-team` | MINIMAL | L1+ |
| `quarantine-file` | LOW | L2+ |
| `block-ip` | MEDIUM | L3+ |
| `block-domain` | MEDIUM | L3+ |
| `kill-process` | MEDIUM | L3+ |
| `reset-credentials` | MEDIUM | L3+ |
| `isolate-host` | HIGH | L4+ (whitelisted only) |
| `disable-user-account` | HIGH | L4+ (whitelisted only) |

---

## 6. 🔥 Self-Play Purple Team (The SOC That Attacks Itself)

**What AiSOC does:** An LLM-planned campaign engine composes multi-stage attack chains from Atomic Red Team + Caldera, runs them against the live defense, scores detected/missed per technique, and auto-files Detection-as-Code proposals for every miss.

**What we could build (simplified):**

```python
# NEW: backend/services/self_play/purple_team.py
class SelfPlayCampaign:
    """Run attack scenarios against our own detection pipeline to find gaps."""
    
    CANNED_CAMPAIGNS = {
        "ransomware_chain": [
            {"technique": "T1566.001", "stage": "initial-access", "inject": "phishing_email_log"},
            {"technique": "T1059.001", "stage": "execution", "inject": "powershell_download_log"},
            {"technique": "T1547.001", "stage": "persistence", "inject": "registry_run_key_log"},
            {"technique": "T1486", "stage": "impact", "inject": "file_encryption_log"},
        ],
        "credential_theft_chain": [
            {"technique": "T1078", "stage": "initial-access", "inject": "valid_account_login_log"},
            {"technique": "T1003", "stage": "credential-access", "inject": "lsass_dump_log"},
            {"technique": "T1021.001", "stage": "lateral-movement", "inject": "rdp_lateral_log"},
            {"technique": "T1048", "stage": "exfiltration", "inject": "dns_exfil_log"},
        ],
    }
    
    async def run_campaign(self, campaign_name: str) -> CampaignResult:
        """Inject synthetic attack logs and see what our pipeline detects."""
        campaign = self.CANNED_CAMPAIGNS[campaign_name]
        results = []
        
        for step in campaign:
            # Inject synthetic log into our pipeline
            synthetic_log = self._generate_synthetic_log(step)
            detection_result = await self._run_through_pipeline(synthetic_log)
            
            results.append({
                "technique": step["technique"],
                "stage": step["stage"],
                "detected": detection_result.was_detected,
                "detection_time_ms": detection_result.latency_ms,
            })
        
        detected = sum(1 for r in results if r["detected"])
        return CampaignResult(
            total=len(campaign),
            detected=detected,
            missed=[r for r in results if not r["detected"]],
            coverage_pct=detected / len(campaign) * 100,
        )
```

**Impact:** Run `self_play.run_campaign("ransomware_chain")` and immediately see which MITRE techniques our pipeline catches and which it misses — then auto-generate skills/detection rules for the gaps.

---

## 7. 🔥 Playbook Engine (Declarative YAML Workflows)

**What AiSOC does:** Reusable JSON/YAML playbooks with triggers (alert severity, tags, schedule, webhook), ordered steps (`enrich` → `investigate` → `isolate_host` → `notify` → `close_case`), failure handling (`abort`, `continue`, `retry`), and a visual React Flow editor.

**What we have now:** Our orchestrator has a hardcoded pipeline: `triage → evidence → compression → rca → response`. There's no way for a SOC analyst to define "when ransomware is detected, immediately isolate the host, THEN investigate."

**What to build:**

```yaml
# NEW: backend/playbooks/ransomware-response-v1.yaml
id: ransomware-response-v1
name: Ransomware Response
version: "1.0.0"
trigger:
  on: alert
  severity: [critical, high]
  tags: [ransomware, T1486]

steps:
  - id: isolate
    name: Isolate affected host
    type: isolate_host
    params:
      host_field: "{{alert.computer_name}}"
    on_failure: continue   # Don't abort investigation if isolation fails
    timeout_seconds: 30

  - id: investigate
    name: Run full investigation
    type: investigate
    params:
      focus: [forensics, lateral_movement]
    
  - id: notify
    name: Alert SOC team
    type: notify
    params:
      channel: "#soc-critical"
      message: "🚨 Ransomware detected on {{alert.computer_name}} — host isolated, investigation running"

  - id: report
    name: Generate incident report
    type: generate_report
    params:
      format: pdf
```

This is a **big** architectural change but it would transform our project from "a pipeline that processes alerts" into "a SOC platform that orchestrates responses."

---

## 8. Detection-as-Code (Sigma-YAML Rule Format)

**What AiSOC does:** 800+ detection rules in YAML format with positive/negative test fixtures. Every PR that touches a detection rule must pass fixture replay in CI.

**What we have now:** Our `correlation_engine.py` has hardcoded detection logic. No external rule format, no way for users to add their own detections.

**What to build:**

```yaml
# NEW: backend/detections/endpoint/suspicious-powershell-download.yaml
id: det-endpoint-ps-download-001
name: Suspicious PowerShell Download Cradle
severity: high
category: endpoint
tags:
  - mitre.attack.T1059.001
  - mitre.attack.T1105
log_source:
  product: sysmon
detection:
  fields: [process.command_line, process.name]
  condition: >
    process.name IN ["powershell.exe", "pwsh.exe"]
    AND process.command_line MATCHES "(Invoke-WebRequest|wget|curl|DownloadString|DownloadFile|IEX|iex)"
false_positives:
  - IT admin using legitimate PowerShell scripts
  - SCCM/WSUS update processes
playbook: ransomware-response-v1
enabled: true
```

---

## 9. Live Actions Interface (Vendor-Agnostic Response Dispatch)

**What AiSOC does:** A single `POST /api/v1/live-actions/dispatch` endpoint where **capability** (`isolate_host`, `block_ip`) and **vendor** (`crowdstrike`, `defender`, `okta`) are explicit. Executors are pluggable — register a `(vendor_id, capability)` pair and it instantly works.

**What we have now:** Our Response skills model containment commands in SKILL.md files, but execution is simulated. There's no pluggable executor registry.

**What to build:**

```python
# NEW: backend/services/response/live_actions.py
class LiveActionRequest:
    capability: str      # "isolate_host", "block_ip", "disable_user"
    vendor_id: str       # "crowdstrike", "defender", "palo_alto"
    target: str          # hostname, IP, username
    params: dict         # vendor-specific options
    case_id: str
    dry_run: bool = True # Default to simulation

class LiveActionRegistry:
    """Registry of vendor executors for each capability."""
    _executors: Dict[Tuple[str, str], LiveActionExecutor] = {}
    
    def register(self, vendor_id: str, capability: str, executor: LiveActionExecutor):
        self._executors[(vendor_id, capability)] = executor
    
    async def dispatch(self, request: LiveActionRequest) -> LiveActionResult:
        key = (request.vendor_id, request.capability)
        executor = self._executors.get(key)
        
        if request.dry_run:
            return LiveActionResult(status="simulated", summary=f"Would {request.capability} on {request.target} via {request.vendor_id}")
        
        # Check maturity gate BEFORE executing
        gate = MaturityGate()
        decision = gate.evaluate(request.capability, self.tenant_tier)
        if decision.action == "queue_for_approval":
            return LiveActionResult(status="pending_approval", summary=decision.reason)
        
        return await executor.execute(request)
```

---

## 10. LLMOps — Prompt Registry with Version Pinning

**What AiSOC does:** Every production prompt is a named, versioned, content-hashed artifact. A `prompts.lock.json` file pins prompt version → SHA256. CI **fails if a prompt changed without a version bump.**

**What we have now:** Our `prompt_manager.py` loads prompts from YAML templates. No versioning, no hashing, no CI gate.

**What to build:**

```python
# Enhance: backend/services/prompt_manager.py
class VersionedPromptManager:
    def get_prompt(self, name: str) -> PromptArtifact:
        template = self._load_template(name)
        return PromptArtifact(
            name=name,
            version=template.metadata.get("version", "1.0.0"),
            content_hash=hashlib.sha256(template.content.encode()).hexdigest(),
            content=template.content,
        )
    
    def verify_lock(self) -> bool:
        """CI gate: fail if any prompt changed without version bump."""
        lock = json.load(open("prompts.lock.json"))
        for name, locked in lock.items():
            current = self.get_prompt(name)
            if current.content_hash != locked["hash"] and current.version == locked["version"]:
                raise PromptDriftError(f"Prompt '{name}' changed but version still {current.version}")
        return True
```

---

## 11. Entity-Risk Scoring (Risk-Based Alerting)

**What AiSOC does:** Time-decayed entity risk scoring across all alerts. When an entity accumulates enough risk, it's automatically promoted to an incident — even if no single alert was "critical."

**What we have now:** We score individual alerts in Triage but don't track entity risk across multiple alerts over time.

**What to build:**

```python
# NEW: backend/services/entity_risk.py
class EntityRiskTracker:
    """Track cumulative risk per entity with time decay."""
    
    DECAY_HALF_LIFE_HOURS = 24  # Risk halves every 24 hours
    INCIDENT_THRESHOLD = 0.8     # Auto-promote to incident at this level
    
    def update_risk(self, entity_id: str, new_risk_delta: float) -> float:
        """Add risk signal, apply time decay to existing risk, return current total."""
        existing = self._get_current_risk(entity_id)
        decayed = existing * math.exp(-0.693 * hours_since_last / self.DECAY_HALF_LIFE_HOURS)
        new_total = min(1.0, decayed + new_risk_delta)
        
        self._store_risk(entity_id, new_total)
        
        if new_total >= self.INCIDENT_THRESHOLD:
            self._auto_promote_to_incident(entity_id)
        
        return new_total
```

---

## 12. Security Knowledge Graph (Neo4j at Ingest Time)

**What AiSOC does:** Writes a 17-node-label, 14-relationship-type knowledge graph **at ingest time** into Neo4j. Agents walk the graph instead of searching logs — "what can this compromised identity reach right now?" is a graph traversal, not a log search.

**What we have now:** Our investigation is log-file-based. When the Supervisor wants to find "what else is connected to this IP", it runs Evidence collection against the same log file.

**Future direction (not immediate):** This would be a fundamental architecture change — adding Neo4j and building an ingest-time graph materializer. But even without Neo4j, we could build an **in-memory entity graph** during investigation:

```python
# Future: backend/services/knowledge_graph.py
class InvestigationGraph:
    """In-memory entity relationship graph built during investigation."""
    
    def add_relationship(self, source: Entity, relationship: str, target: Entity, evidence: str):
        """e.g. add_relationship(user_john, 'EXECUTED', powershell_proc, 'Sysmon Event 1')"""
        self.graph.add_edge(source.id, target.id, type=relationship, evidence=evidence)
    
    def find_blast_radius(self, entity_id: str, max_hops: int = 3) -> List[Entity]:
        """What can this compromised entity reach?"""
        return list(nx.bfs_tree(self.graph, entity_id, depth_limit=max_hops))
```

---

## Summary: Priority Matrix

| # | Idea | Effort | Impact | Solves What |
|---|------|--------|--------|-------------|
| 1 | **Investigation Ledger** | Medium | 🔴 Critical | "Why did the AI do that?" — auditability |
| 2 | **Multi-Model Router** | Medium | 🔴 Critical | Cost reduction, speed, deterministic decisions |
| 3 | **Investigation Swarm** | High | 🔴 Critical | Eliminates the "3x Evidence loop" problem |
| 4 | **Compounding Memory** | Medium | 🟠 High | SOC gets smarter over time, not just AI |
| 5 | **L0-L4 Automation Maturity** | Low | 🟠 High | Trust ladder for real-world deployment |
| 6 | **Self-Play Purple Team** | High | 🟠 High | Find detection gaps before attackers do |
| 7 | **Playbook Engine** | High | 🟠 High | Custom workflows, trigger-based automation |
| 8 | **Detection-as-Code** | Medium | 🟡 Medium | User-defined detection rules in YAML |
| 9 | **Live Actions Interface** | Medium | 🟡 Medium | Pluggable vendor executors for response |
| 10 | **Prompt Registry + Versioning** | Low | 🟡 Medium | Prevent silent prompt drift, CI safety |
| 11 | **Entity-Risk Scoring** | Low | 🟡 Medium | Cross-alert risk accumulation |
| 12 | **Knowledge Graph** | Very High | 🟡 Medium | Graph-based investigation (future) |

> [!IMPORTANT]
> ## Recommended Implementation Order
> 
> **Sprint 1 (Quick Wins):** #10 Prompt Registry, #5 L0-L4 Gate, #11 Entity-Risk Scoring
> These are low-effort, high-value changes that add production-readiness features.
> 
> **Sprint 2 (Core Upgrades):** #1 Investigation Ledger, #2 Multi-Model Router
> These fundamentally improve auditability and cost efficiency.
> 
> **Sprint 3 (Intelligence):** #4 Compounding Memory, #3 Investigation Swarm
> These make the AI genuinely smarter — not just faster.
> 
> **Sprint 4 (Platform):** #7 Playbook Engine, #8 Detection-as-Code, #9 Live Actions
> These transform the project from "an AI investigation tool" into "an AI SOC platform."

> [!TIP]
> **The single biggest difference between AiSOC and our project:** AiSOC treats the LLM as the **last resort**, not the first call. Their deterministic → ML → LLM escalation ladder means most decisions are fast, cheap, and reproducible. Our project currently sends everything to the LLM. Fixing this (idea #2) would have the highest ROI.
