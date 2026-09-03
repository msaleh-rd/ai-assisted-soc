// === API Base URL ===
const API = '';

// === Navigation ===
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        const page = item.dataset.page;
        if (!page) return;
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        item.classList.add('active');
        document.getElementById(`page-${page}`).classList.add('active');
        
        if (page === 'approvals') {
            loadPendingApprovals();
        } else if (page === 'history') {
            loadInvestigationHistory();
        } else if (page === 'ai-governance') {
            getAIGovernanceOverview();
        }
    });
});

// === Utility Functions ===
async function apiFetch(path, options = {}) {
    const url = `${API}${path}`;
    const res = await fetch(url, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
}

function showResult(elementId, data, isError = false) {
    const el = document.getElementById(elementId);
    el.className = `result-box visible ${isError ? 'error' : 'success'}`;
    el.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

function showInfo(elementId, data) {
    const el = document.getElementById(elementId);
    el.className = 'result-box visible info';
    el.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

// === Alert Templates ===
const ALERT_TEMPLATES = {
    crowdstrike_malware: {
        source: 'crowdstrike',
        alert: {
            event_type: 'DetectionSummaryEvent',
            detection_id: 'det_' + Date.now(),
            severity: 4,
            severity_name: 'High',
            tactic: 'Execution',
            technique: 'T1059',
            technique_id: 'T1059.001',
            computer_name: 'WORKSTATION-042',
            user_name: 'jsmith',
            file_name: 'suspicious.exe',
            file_path: 'C:\\Users\\jsmith\\Downloads\\suspicious.exe',
            sha256: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678',
            parent_process: 'explorer.exe',
            command_line: 'cmd.exe /c suspicious.exe --payload',
            ip_address: '192.168.1.42',
            external_ip: '185.220.101.42',
            mac_address: '00:11:22:33:44:55',
            timestamp: new Date().toISOString(),
            description: 'Malicious executable detected - possible ransomware dropper'
        }
    },
    crowdstrike_lateral: {
        source: 'crowdstrike',
        alert: {
            event_type: 'DetectionSummaryEvent',
            detection_id: 'det_lat_' + Date.now(),
            severity: 5,
            severity_name: 'Critical',
            tactic: 'LateralMovement',
            technique: 'T1021',
            technique_id: 'T1021.002',
            computer_name: 'DC-PRIMARY',
            user_name: 'admin_svc',
            file_name: 'psexec.exe',
            file_path: 'C:\\Windows\\Temp\\psexec.exe',
            sha256: 'b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456789a',
            parent_process: 'services.exe',
            command_line: 'psexec.exe \\\\fileserver01 -u admin_svc -p *** cmd.exe',
            ip_address: '10.0.1.5',
            external_ip: '203.0.113.45',
            mac_address: '00:AA:BB:CC:DD:EE',
            timestamp: new Date().toISOString(),
            description: 'Lateral movement via PsExec to domain controller detected'
        }
    },
    splunk_bruteforce: {
        source: 'splunk',
        alert: {
            search_name: 'Brute Force Login Detection',
            results_link: 'https://splunk.internal/app/search/results/12345',
            result: {
                source: 'WinEventLog:Security',
                sourcetype: 'WinEventLog',
                event_id: 4625,
                user: 'administrator',
                src_ip: '10.0.2.99',
                dest: 'EXCHANGE-01',
                action: 'failure',
                count: 47,
                time_window: '5m',
                first_seen: new Date(Date.now() - 300000).toISOString(),
                last_seen: new Date().toISOString()
            },
            severity: 'high',
            trigger_time: new Date().toISOString(),
            description: '47 failed login attempts from 10.0.2.99 to EXCHANGE-01 in 5 minutes'
        }
    },
    splunk_exfiltration: {
        source: 'splunk',
        alert: {
            search_name: 'Data Exfiltration Detection',
            results_link: 'https://splunk.internal/app/search/results/67890',
            result: {
                source: 'firewall',
                sourcetype: 'palo_alto',
                src_ip: '10.0.1.42',
                dest_ip: '198.51.100.77',
                dest_port: 443,
                bytes_out: 524288000,
                protocol: 'TCP',
                application: 'ssl',
                category: 'unknown',
                user: 'jsmith',
                duration: 3600,
                first_seen: new Date(Date.now() - 3600000).toISOString(),
                last_seen: new Date().toISOString()
            },
            severity: 'critical',
            trigger_time: new Date().toISOString(),
            description: '500MB outbound transfer to unknown external IP 198.51.100.77'
        }
    },
    cam_lds_ransomware: {
        source: 'wazuh',
        task: 'Investigate donotcry ransomware and C2 ingress on linuxshare',
        alert: {
            alert_id: 'cam_ransomware_003',
            source: 'Suricata IDS / Wazuh',
            severity: 5,
            severity_name: 'Critical',
            computer_name: 'linuxshare',
            ip_address: '192.168.100.50',
            user_name: 'root',
            file_name: 'donotcry',
            file_path: '/media/data/Images/donotcry',
            description: 'Ransomware execution detected: install.sh downloaded from 192.42.1.174:8888, encrypting files in /media/data/Images',
            timestamp: new Date().toISOString()
        }
    },
    cam_lds_vnc: {
        source: 'wazuh',
        task: 'Investigate VNC brute force and credential dumping on inetfw',
        alert: {
            alert_id: 'cam_vnc_bruteforce_001',
            source: 'Wazuh SIEM / Auditd',
            severity: 4,
            severity_name: 'High',
            computer_name: 'inetfw',
            ip_address: '192.168.100.23',
            user_name: 'root',
            file_name: 'Xvnc',
            file_path: '/usr/bin/Xvnc',
            description: 'Repeated VNC authentication failures on port 5901 from 192.42.1.174 followed by unauthorized /etc/shadow access',
            timestamp: new Date().toISOString()
        }
    },
    cam_lds_repo: {
        source: 'auditd',
        task: 'Investigate debian package tampering on reposerver',
        alert: {
            alert_id: 'cam_repo_poison_002',
            source: 'Auditd / Wazuh',
            severity: 5,
            severity_name: 'Critical',
            computer_name: 'reposerver',
            ip_address: '192.168.100.15',
            user_name: 'puppet',
            file_name: 'healthcheckd',
            file_path: '/var/packages/debian/healthcheckd.deb',
            description: 'Unauthorized deb package modification and healthcheck_cron.sh script tampering on package repo server',
            timestamp: new Date().toISOString()
        }
    },
    apt29_raindrop: {
        source: 'sysmon',
        task: 'Investigate APT29 phishing and PowerShell execution on UserWorkstation',
        alert: {
            alert_id: 'apt29_step_002',
            source: 'Sysmon / EDR',
            severity: 5,
            severity_name: 'Critical',
            computer_name: 'UserWorkstation',
            ip_address: '192.168.0.4',
            user_name: 'vagrant',
            file_name: 'raindrop.ps1',
            file_path: 'C:\\Users\\vagrant\\raindrop.ps1',
            description: 'PowerShell execution of raindrop.ps1 payload following suspicious email attachment launch from 192.168.0.2',
            timestamp: new Date().toISOString()
        }
    }
};

// Aliases for compatibility
ALERT_TEMPLATES.splunk_exfil = ALERT_TEMPLATES.splunk_exfiltration;

function loadOrchTemplate() {
    const select = document.getElementById('orchAlertTemplate');
    const textarea = document.getElementById('orchAlertJson');
    const taskInput = document.getElementById('orchTask');
    if (!select || !textarea) return;

    const val = select.value;
    const template = ALERT_TEMPLATES[val];
    if (template) {
        textarea.value = JSON.stringify(template.alert, null, 2);
        if (taskInput) {
            taskInput.value = template.task || `Investigate ${template.alert.description || 'security alert and recommend response'}`;
        }
    }
}

// Auto-load template on initial load
document.addEventListener('DOMContentLoaded', () => {
    loadOrchTemplate();
});
setTimeout(loadOrchTemplate, 100);

let _orchEventSource = null;
let _orchStartTime = 0;
let _orchTimerInterval = null;

async function runOrchestration() {
    const startBtn = document.getElementById('orchStartBtn');
    const panel = document.getElementById('orchPanel');
    const statusBadge = document.getElementById('orchStatus');
    const timerSpan = document.getElementById('orchTimer');
    const reasoningDiv = document.getElementById('orchReasoning');
    const dagDiv = document.getElementById('orchDag');
    const logDiv = document.getElementById('orchLog');
    const logCount = document.getElementById('orchLogCount');
    const reportsGrid = document.getElementById('orchReportsGrid');
    const synthesisPanel = document.getElementById('orchSynthesis');
    const synthesisContent = document.getElementById('orchSynthesisContent');
    const pendingBtn = document.getElementById('orchPendingBtn');

    let alertData = {};
    try {
        alertData = JSON.parse(document.getElementById('orchAlertJson').value);
    } catch (e) {
        alert('Invalid JSON in Custom Alert field: ' + e.message);
        return;
    }

    const task = document.getElementById('orchTask').value.trim() || 'Investigate security alert and recommend response';
    const useAIPlanner = document.getElementById('orchUseAIPlanner')?.checked || false;

    // Reset UI state
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth' });
    startBtn.disabled = true;
    startBtn.textContent = 'Running Investigation...';
    statusBadge.textContent = 'Initializing...';
    statusBadge.className = 'orch-status-badge';
    if (pendingBtn) pendingBtn.style.display = 'none';

    reasoningDiv.textContent = '';
    dagDiv.innerHTML = '';
    logDiv.innerHTML = '';
    reportsGrid.innerHTML = '';
    synthesisPanel.style.display = 'none';

    let eventCount = 0;
    _orchStartTime = Date.now();
    clearInterval(_orchTimerInterval);
    _orchTimerInterval = setInterval(() => {
        const elapsed = ((Date.now() - _orchStartTime) / 1000).toFixed(1);
        if (timerSpan) timerSpan.textContent = `${elapsed}s`;
    }, 100);

    function addLogEntry(type, title, detail) {
        eventCount++;
        if (logCount) logCount.textContent = `${eventCount} events`;
        const item = document.createElement('div');
        item.className = 'orch-log-item';
        item.style.cssText = 'padding: 6px 10px; border-bottom: 1px solid #1e293b; font-size: 0.82rem; display: flex; gap: 8px;';
        const timeStr = new Date().toLocaleTimeString();
        item.innerHTML = `
            <span style="color: var(--text-muted); font-family: monospace;">[${timeStr}]</span>
            <strong style="color: #60a5fa;">${title}</strong>
            <span style="color: #cbd5e1; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${detail || ''}</span>
        `;
        logDiv.appendChild(item);
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    function updateAgentCard(taskId, report) {
        let card = document.getElementById(`orch-rep-${taskId}`);
        if (!card) {
            card = document.createElement('div');
            card.id = `orch-rep-${taskId}`;
            card.className = 'report-card';
            reportsGrid.appendChild(card);
        }
        const findings = report.findings || {};
        const confScore = report.confidence !== undefined ? Math.round(report.confidence * 100) : 90;
        
        card.innerHTML = `
            <div class="report-card-header">
                <span class="report-agent-name">${report.agent_name || taskId}</span>
                <span class="report-confidence confidence-${confScore >= 80 ? 'high' : confScore >= 60 ? 'medium' : 'low'}">Conf: ${confScore}%</span>
            </div>
            <div class="report-task">${report.task || ''}</div>
            <div class="report-findings">
                ${findings.root_cause ? `<div style="color: #f8fafc; font-weight: 600; margin-bottom: 4px;">Root Cause: ${findings.root_cause}</div>` : ''}
                ${findings.chain_of_thought_verification ? `<div class="hist-cot-box" style="font-size: 0.78rem;">${findings.chain_of_thought_verification}</div>` : ''}
                <details style="margin-top: 6px;">
                    <summary style="cursor: pointer; color: var(--text-muted); font-size: 0.75rem;">View findings payload</summary>
                    <pre class="code-input" style="font-size: 0.75rem; margin-top: 4px; max-height: 150px; overflow-y: auto;">${JSON.stringify(findings, null, 2)}</pre>
                </details>
            </div>
        `;
    }

    try {
        const response = await fetch('/api/v3/orchestrator/investigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ task, alert_data: alertData, use_ai_planner: useAIPlanner })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        let streamResponse = response;
        const contentType = response.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
            const startData = await response.json();
            const workflowId = startData.workflow_id;
            addLogEntry('temporal_start', 'Temporal Workflow Started', `Workflow ID: ${workflowId}`);
            
            // Connect to the workflow's SSE stream
            streamResponse = await fetch(`/api/v3/orchestrator/investigate/${encodeURIComponent(workflowId)}/stream`);
            if (!streamResponse.ok) {
                throw new Error(`Failed to connect to workflow stream: ${streamResponse.statusText}`);
            }
        }

        const reader = streamResponse.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            const lines = buffer.split('\n');
            buffer = lines.pop(); // keep partial line

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (line.startsWith('event: ')) {
                    const evtType = line.slice(7).trim();
                    let dataLine = lines[i + 1];
                    if (dataLine && dataLine.startsWith('data: ')) {
                        i++;
                        try {
                            const data = JSON.parse(dataLine.slice(6));

                            if (evtType === 'run_start') {
                                statusBadge.textContent = 'Planning...';
                                addLogEntry('run_start', 'Investigation Started', `Run ID: ${data.run_id}`);
                            } else if (evtType === 'plan_created') {
                                statusBadge.textContent = 'Executing Plan...';
                                reasoningDiv.textContent = data.reasoning || '';
                                addLogEntry('plan_created', 'Dynamic Plan Generated', `${data.total_phases} phases, ${data.total_tasks} tasks`);
                                
                                // Render DAG phases
                                dagDiv.innerHTML = '';
                                (data.phases || []).forEach(ph => {
                                    const phCard = document.createElement('div');
                                    phCard.style.cssText = 'background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 10px; min-width: 140px;';
                                    phCard.innerHTML = `
                                        <div style="font-size: 0.75rem; color: #94a3b8; font-weight: bold; margin-bottom: 4px;">Phase ${ph.phase_num}</div>
                                        <div style="display: flex; flex-direction: column; gap: 4px;">
                                            ${(ph.agents || []).map(a => `<span class="badge badge-blue" id="dag-agent-${a}">${a}</span>`).join('')}
                                        </div>
                                    `;
                                    dagDiv.appendChild(phCard);
                                });
                            } else if (evtType === 'phase_start') {
                                addLogEntry('phase_start', `Phase ${data.phase_num} Started`, `Agents: ${(data.agents || []).join(', ')}`);
                            } else if (evtType === 'agent_start') {
                                const badge = document.getElementById(`dag-agent-${data.agent_name}`);
                                if (badge) { badge.className = 'badge badge-purple'; badge.textContent = `${data.agent_name} ⏳`; }
                                addLogEntry('agent_start', `Agent Active: ${data.agent_name}`, data.description || '');
                            } else if (evtType === 'agent_complete') {
                                const badge = document.getElementById(`dag-agent-${data.agent_name}`);
                                if (badge) { badge.className = 'badge badge-green'; badge.textContent = `${data.agent_name} ✓`; }
                                addLogEntry('agent_complete', `Agent Finished: ${data.agent_name}`, `Task ID: ${data.task_id}`);
                                if (data.report) updateAgentCard(data.task_id, data.report);
                            } else if (evtType === 'adaptive_loop_start') {
                                addLogEntry('adaptive_loop_start', `Adaptive Re-Investigation Loop (Iter ${data.iteration})`, data.reason);
                            } else if (evtType === 'synthesis_start') {
                                statusBadge.textContent = 'Synthesizing Findings...';
                                addLogEntry('synthesis_start', 'Synthesizing Final Verdict', 'Reconstructing attack narrative');
                            } else if (evtType === 'pending_approval') {
                                statusBadge.textContent = 'Pending Human Approval Gate';
                                statusBadge.className = 'orch-status-badge orch-status-pending';
                                if (pendingBtn) {
                                    pendingBtn.style.display = 'inline-block';
                                    pendingBtn.onclick = () => {
                                        document.querySelector('.nav-item[data-page="approvals"]')?.click();
                                    };
                                }
                                addLogEntry('pending_approval', 'Human Approval Required', `Workflow ${data.workflow_id} waiting for containment authorization`);
                            } else if (evtType === 'run_complete') {
                                clearInterval(_orchTimerInterval);
                                statusBadge.textContent = 'Completed';
                                statusBadge.className = 'orch-status-badge orch-status-complete';
                                addLogEntry('run_complete', 'Investigation Complete', `Total Duration: ${((data.total_duration_ms || 0) / 1000).toFixed(1)}s`);
                                
                                const synth = data.synthesis || {};
                                synthesisPanel.style.display = 'block';
                                synthesisContent.innerHTML = `
                                    <div style="font-size: 1.1rem; font-weight: bold; color: #f8fafc; margin-bottom: 8px;">${synth.verdict || 'Investigation Complete'}</div>
                                    <p style="color: #cbd5e1; font-size: 0.95rem; line-height: 1.6;">${synth.executive_summary || synth.root_cause || ''}</p>
                                    ${synth.key_findings && synth.key_findings.length ? `
                                        <div style="margin-top: 10px;">
                                            <strong style="color: #94a3b8; font-size: 0.85rem;">Key Findings:</strong>
                                            <ul style="padding-left: 20px; color: #cbd5e1; font-size: 0.88rem; margin-top: 4px;">
                                                ${synth.key_findings.map(f => `<li>${f}</li>`).join('')}
                                            </ul>
                                        </div>
                                    ` : ''}
                                    ${synth.recommended_immediate_actions && synth.recommended_immediate_actions.length ? `
                                        <div style="margin-top: 15px;">
                                            <strong style="color: #34d399; font-size: 0.88rem;">Recommended Immediate Containment Actions:</strong>
                                            <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 6px;">
                                                ${synth.recommended_immediate_actions.map(a => `
                                                    <div style="background: #0f172a; border-left: 3px solid #34d399; padding: 6px 12px; border-radius: 0 4px 4px 0; font-size: 0.85rem;">
                                                        <strong>[${(a.action_type || 'CONTAINMENT').toUpperCase()}]</strong> Target: <code>${a.target}</code> &mdash; ${a.description}
                                                    </div>
                                                `).join('')}
                                            </div>
                                        </div>
                                    ` : ''}
                                `;
                            }
                        } catch (err) {
                            console.error('SSE JSON error', err, dataLine);
                        }
                    }
                }
            }
        }
    } catch (e) {
        clearInterval(_orchTimerInterval);
        statusBadge.textContent = 'Error';
        statusBadge.className = 'orch-status-badge orch-status-failed';
        addLogEntry('error', 'Investigation Failed', e.message);
    } finally {
        startBtn.disabled = false;
        startBtn.innerHTML = '&#9654; Run Agentic Investigation';
    }
}

// === Sample Events for Compression ===
function generateSampleEvents() {
    const now = Date.now();
    const events = [];
    const entities = ['WORKSTATION-042', 'DC-PRIMARY', 'EXCHANGE-01', 'FILESERVER-01', 'DB-PROD-01'];
    const actions = ['login_attempt', 'failed_login', 'successful_login', 'file_access', 'process_execution',
                     'network_connection', 'privilege_escalation', 'lateral_movement', 'data_access', 'registry_modification'];
    const users = ['jsmith', 'admin_svc', 'administrator', 'backup_admin'];

    for (let i = 0; i < 50; i++) {
        events.push({
            timestamp: new Date(now - (50 - i) * 60000).toISOString(),
            event_type: actions[Math.floor(Math.random() * actions.length)],
            entity: entities[Math.floor(Math.random() * entities.length)],
            user: users[Math.floor(Math.random() * users.length)],
            source_ip: `10.0.${Math.floor(Math.random() * 3)}.${Math.floor(Math.random() * 255)}`,
            dest_ip: Math.random() > 0.7 ? `185.220.101.${Math.floor(Math.random() * 255)}` : `10.0.1.${Math.floor(Math.random() * 255)}`,
            risk_score: Math.round(Math.random() * 100) / 100,
            action: actions[Math.floor(Math.random() * actions.length)],
            severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)]
        });
    }
    return events;
}

// === Page: Dashboard ===
async function refreshDashboard() {
    try {
        // Fetch all health and stats endpoints in parallel
        const [health, alertStats, corrStats, rcaHealth] = await Promise.all([
            apiFetch('/health'),
            apiFetch('/api/v1/alerts/stats').catch(() => ({ ok: false, data: {} })),
            apiFetch('/api/v2/correlation/stats').catch(() => ({ ok: false, data: {} })),
            apiFetch('/api/v3/rca/health').catch(() => ({ ok: false, data: {} }))
        ]);

        // Platform status
        document.getElementById('statPlatformStatus').textContent = health.ok ? 'Online' : 'Error';
        document.getElementById('statPlatformStatus').style.color = health.ok ? 'var(--green)' : 'var(--red)';

        // Alert stats
        if (alertStats.ok) {
            document.getElementById('statTrackedAlerts').textContent = alertStats.data.tracked_alerts || 0;
            document.getElementById('statPendingEvidence').textContent = alertStats.data.pending_evidence_collection || 0;
        }

        // Correlation stats
        if (corrStats.ok) {
            document.getElementById('statInvestigations').textContent = corrStats.data.total_investigations || 0;
            document.getElementById('statCompression').textContent = corrStats.data.avg_compression_ratio
                ? corrStats.data.avg_compression_ratio.toFixed(0) + 'x'
                : '0x';
            document.getElementById('statPatterns').textContent = corrStats.data.total_patterns_detected || 0;
        }

        // RCA stats
        if (rcaHealth.ok) {
            document.getElementById('statRCA').textContent = rcaHealth.data.rca_results_count || 0;
            document.getElementById('statIncidents').textContent = rcaHealth.data.incidents_count || 0;
        }

        // Health indicators
        const apiDot = document.getElementById('healthApi');
        apiDot.className = `health-dot ${health.ok ? 'up' : 'down'}`;

        // Health grid
        const healthGrid = document.getElementById('healthDetails');
        const services = [
            { name: 'API Server', endpoint: '/health' },
            { name: 'Phase 1 (Alerts)', endpoint: '/api/v1/alerts/stats' },
            { name: 'Phase 2 (Correlation)', endpoint: '/api/v2/correlation/health' },
            { name: 'Phase 3 (RCA)', endpoint: '/api/v3/rca/health' }
        ];

        healthGrid.innerHTML = '';
        for (const svc of services) {
            try {
                const r = await apiFetch(svc.endpoint);
                healthGrid.innerHTML += `<div class="health-card">
                    <div class="label">${svc.name}</div>
                    <div class="status ${r.ok ? 'up' : 'down'}">${r.ok ? '● Online' : '● Offline'}</div>
                </div>`;
                if (svc.name === 'API Server') {
                    document.getElementById('healthApi').className = `health-dot ${r.ok ? 'up' : 'down'}`;
                }
            } catch {
                healthGrid.innerHTML += `<div class="health-card">
                    <div class="label">${svc.name}</div>
                    <div class="status down">● Offline</div>
                </div>`;
            }
        }

        document.getElementById('healthDb').className = 'health-dot up';
        document.getElementById('healthGraph').className = 'health-dot up';

    } catch (e) {
        console.error('Dashboard refresh error:', e);
    }
}

// === Page: Alerts ===
function loadAlertTemplate() {
    const template = document.getElementById('alertTemplate').value;
    const data = ALERT_TEMPLATES[template];
    if (data) {
        document.getElementById('alertSource').value = data.source;
        document.getElementById('alertPayload').value = JSON.stringify(data.alert, null, 2);
    }
}

async function ingestAlert() {
    const source = document.getElementById('alertSource').value;
    let raw_alert;
    try {
        raw_alert = JSON.parse(document.getElementById('alertPayload').value);
    } catch (e) {
        showResult('alertResult', 'Invalid JSON: ' + e.message, true);
        return;
    }
    const res = await apiFetch('/api/v1/alerts/ingest', {
        method: 'POST',
        body: JSON.stringify({ source, raw_alert })
    });
    showResult('alertResult', res.data, !res.ok);
}

async function ingestBatchAlerts() {
    const alerts = Object.values(ALERT_TEMPLATES).map(t => t.alert);
    const res = await apiFetch('/api/v1/alerts/ingest-batch', {
        method: 'POST',
        body: JSON.stringify({ source: 'crowdstrike', alerts })
    });
    showResult('alertResult', res.data, !res.ok);
}

async function getAlertStats() {
    const res = await apiFetch('/api/v1/alerts/stats');
    showResult('alertStatsResult', res.data, !res.ok);
}

async function getPendingAlerts() {
    const res = await apiFetch('/api/v1/alerts/pending');
    showResult('alertStatsResult', res.data, !res.ok);
}

async function cleanupAlerts() {
    const res = await apiFetch('/api/v1/alerts/cleanup', { method: 'POST' });
    showResult('alertStatsResult', res.data, !res.ok);
}

// === Page: Evidence ===
async function collectEvidence() {
    const investigation_id = document.getElementById('evidenceInvId').value;
    const max_depth = parseInt(document.getElementById('evidenceDepth').value);
    if (!investigation_id) {
        showResult('evidenceResult', 'Please enter an investigation ID', true);
        return;
    }
    const res = await apiFetch('/api/v1/evidence/collect', {
        method: 'POST',
        body: JSON.stringify({ investigation_id, max_depth })
    });
    showResult('evidenceResult', res.data, !res.ok);
}

async function getEvidenceStats() {
    const res = await apiFetch('/api/v1/evidence/stats');
    showResult('evidenceStatsResult', res.data, !res.ok);
}

// === Page: Compression ===
function loadSampleEvents() {
    const events = generateSampleEvents();
    document.getElementById('compressEvents').value = JSON.stringify(events, null, 2);
}

async function compressEvents() {
    const investigation_id = document.getElementById('compressInvId').value;
    const alert_id = document.getElementById('compressAlertId').value;
    let events;
    try {
        events = JSON.parse(document.getElementById('compressEvents').value);
    } catch (e) {
        showResult('compressResult', 'Invalid JSON: ' + e.message, true);
        return;
    }
    const res = await apiFetch('/api/v2/correlation/compress', {
        method: 'POST',
        body: JSON.stringify({
            investigation_id,
            alert_id,
            events,
            incident_time: new Date().toISOString()
        })
    });
    showResult('compressResult', res.data, !res.ok);
}

async function getCompressionStats() {
    const res = await apiFetch('/api/v2/correlation/stats');
    showResult('compressionStatsResult', res.data, !res.ok);
}

async function getCompressedPackage() {
    const id = document.getElementById('retrieveCompressedId').value;
    if (!id) { showResult('compressedPackageResult', 'Enter an investigation ID', true); return; }
    const res = await apiFetch(`/api/v2/correlation/compressed/${id}`);
    showResult('compressedPackageResult', res.data, !res.ok);
}

// === Page: Investigation ===
async function buildInvestigationPackage() {
    const investigation_id = document.getElementById('invPkgInvId').value;
    const compressed_package_id = document.getElementById('invPkgCompId').value;
    const package_type = document.getElementById('invPkgType').value;
    const res = await apiFetch('/api/v2/correlation/investigate', {
        method: 'POST',
        body: JSON.stringify({
            investigation_id,
            compressed_package_id,
            package_type,
            original_alert: { alert_id: 'demo', source: 'crowdstrike', severity: 'high' }
        })
    });
    showResult('invPkgResult', res.data, !res.ok);
}

async function getInvestigationPackage() {
    const id = document.getElementById('retrievePkgId').value;
    if (!id) { showResult('invPkgDetailResult', 'Enter a package ID', true); return; }
    const res = await apiFetch(`/api/v2/correlation/package/${id}`);
    showResult('invPkgDetailResult', res.data, !res.ok);
}

async function getTimeline() {
    const id = document.getElementById('timelineInvId').value;
    if (!id) { showResult('timelineResult', 'Enter an investigation ID', true); return; }
    const res = await apiFetch(`/api/v2/correlation/timeline/${id}`);
    showResult('timelineResult', res.data, !res.ok);
}

async function getAttackGraph() {
    const id = document.getElementById('graphInvId').value;
    if (!id) { showResult('graphResult', 'Enter an investigation ID', true); return; }
    const res = await apiFetch(`/api/v2/correlation/graph/${id}`);
    showResult('graphResult', res.data, !res.ok);
}

// === Page: RCA ===
async function analyzeRCA() {
    const investigation_id = document.getElementById('rcaInvId').value;
    const package_id = document.getElementById('rcaPkgId').value;
    if (!investigation_id || !package_id) {
        showResult('rcaResult', 'Please enter both Investigation ID and Package ID', true);
        return;
    }
    const res = await apiFetch('/api/v3/rca/analyze', {
        method: 'POST',
        body: JSON.stringify({ investigation_id, package_id })
    });
    showResult('rcaResult', res.data, !res.ok);
}

async function getRCADetail() {
    const id = document.getElementById('rcaDetailId').value;
    if (!id) { showResult('rcaDetailResult', 'Enter an RCA ID', true); return; }
    const res = await apiFetch(`/api/v3/rca/rca/${id}`);
    showResult('rcaDetailResult', res.data, !res.ok);
}

async function runAdaptiveLoop() {
    const investigation_id = document.getElementById('adaptiveInvId').value;
    const rca_id = document.getElementById('adaptiveRcaId').value;
    const confidence_threshold = parseFloat(document.getElementById('adaptiveThreshold').value);
    const res = await apiFetch('/api/v3/rca/adaptive-loop', {
        method: 'POST',
        body: JSON.stringify({ investigation_id, rca_id, confidence_threshold, max_iterations: 3 })
    });
    showResult('adaptiveResult', res.data, !res.ok);
}

// === Page: Response ===
async function executeResponse() {
    const investigation_id = document.getElementById('responseInvId').value;
    const rca_id = document.getElementById('responseRcaId').value;
    const auto_approve = document.getElementById('responseAutoApprove').value === 'true';
    const res = await apiFetch('/api/v3/rca/respond', {
        method: 'POST',
        body: JSON.stringify({ investigation_id, rca_id, auto_approve })
    });
    showResult('responseResult', res.data, !res.ok);
}

// === Page: Incidents & Reports ===
async function listIncidents(status) {
    const path = status ? `/api/v3/rca/incidents?status=${status}` : '/api/v3/rca/incidents';
    const res = await apiFetch(path);
    showResult('incidentListResult', res.data, !res.ok);
}

async function getIncidentDetail() {
    const id = document.getElementById('incidentDetailId').value;
    if (!id) { showResult('incidentDetailResult', 'Enter an incident ID', true); return; }
    const res = await apiFetch(`/api/v3/rca/incident/${id}`);
    showResult('incidentDetailResult', res.data, !res.ok);
}

async function closeIncident() {
    const incident_id = document.getElementById('closeIncidentId').value;
    const closure_notes = document.getElementById('closureNotes').value;
    if (!incident_id) { showResult('closeIncidentResult', 'Enter an incident ID', true); return; }
    const res = await apiFetch(`/api/v3/rca/close-incident?incident_id=${encodeURIComponent(incident_id)}&closure_notes=${encodeURIComponent(closure_notes)}`, {
        method: 'POST'
    });
    showResult('closeIncidentResult', res.data, !res.ok);
}

async function generateReports() {
    const incident_id = document.getElementById('reportIncidentId').value;
    if (!incident_id) { showResult('reportGenResult', 'Enter an incident ID', true); return; }
    const checkboxes = document.querySelectorAll('#page-incidents .checkbox-group input:checked');
    const report_types = Array.from(checkboxes).map(cb => cb.value);
    const res = await apiFetch('/api/v3/rca/generate-reports', {
        method: 'POST',
        body: JSON.stringify({ incident_id, report_types })
    });
    showResult('reportGenResult', res.data, !res.ok);
}

async function viewReport() {
    const id = document.getElementById('viewReportId').value;
    const format = document.getElementById('reportFormat').value;
    if (!id) { showResult('viewReportResult', 'Enter a report ID', true); return; }
    const res = await apiFetch(`/api/v3/rca/report/${id}?format=${format}`);
    showResult('viewReportResult', res.data, !res.ok);
}

// === Network Discovery ===

async function loadSkillCatalog() {
    const container = document.getElementById('skillCatalog');
    container.innerHTML = '<div class="loading">Loading skills...</div>';
    try {
        const res = await apiFetch('/api/v3/discovery/skills');
        if (!res.ok) {
            container.innerHTML = '<div class="error-text">Failed to load skills</div>';
            return;
        }
        const skills = res.data;
        if (!skills.length) {
            container.innerHTML = '<div class="empty-text">No skills found</div>';
            return;
        }
        container.innerHTML = skills.map(s => `
            <div class="skill-card">
                <div class="skill-header">
                    <span class="skill-name">${s.name}</span>
                    <span class="badge badge-sm">${s.method}</span>
                    ${s.platform ? `<span class="badge badge-sm badge-outline">${s.platform}</span>` : '<span class="badge badge-sm badge-green">cross-platform</span>'}
                </div>
                <div class="skill-desc">${s.description}</div>
                <div class="skill-collects">
                    <span class="skill-label">Collects:</span>
                    ${s.collects.map(c => `<span class="attr-tag">${c}</span>`).join('')}
                </div>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = `<div class="error-text">Error: ${e.message}</div>`;
    }
}

async function runDiscoveryScan() {
    const btn = document.getElementById('discoveryScanBtn');
    const statusEl = document.getElementById('discoveryScanStatus');
    const targetsRaw = document.getElementById('discoveryTargets').value.trim();
    const timeout = parseInt(document.getElementById('discoveryTimeout').value) || 30;

    if (!targetsRaw) {
        showResult('discoveryScanStatus', 'Enter at least one target IP or hostname', true);
        return;
    }

    const targets = targetsRaw.split('\n').map(t => t.trim()).filter(Boolean);

    // Collect checked attributes
    const checkboxes = document.querySelectorAll('#discoveryAttributes input[type="checkbox"]:checked');
    const attributes = Array.from(checkboxes).map(cb => cb.value);
    if (!attributes.length) {
        showResult('discoveryScanStatus', 'Select at least one attribute to collect', true);
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '&#9203; Scanning...';
    statusEl.className = 'result-box visible info';
    statusEl.textContent = `Scanning ${targets.length} target(s) for ${attributes.length} attribute(s)...`;

    try {
        const res = await apiFetch('/api/v3/discovery/scan', {
            method: 'POST',
            body: JSON.stringify({ targets, attributes, timeout })
        });

        if (!res.ok) {
            showResult('discoveryScanStatus', res.data, true);
            btn.disabled = false;
            btn.innerHTML = '&#9654; Run Discovery Scan';
            return;
        }

        const data = res.data;
        statusEl.className = 'result-box visible success';
        statusEl.textContent = `Scan ${data.scan_id} complete in ${data.duration_seconds.toFixed(1)}s — ${data.skills_used.length} skill(s) used`;

        // Show results panel
        renderDiscoveryResults(data);
    } catch (e) {
        showResult('discoveryScanStatus', `Error: ${e.message}`, true);
    }

    btn.disabled = false;
    btn.innerHTML = '&#9654; Run Discovery Scan';
}

function renderDiscoveryResults(data) {
    const panel = document.getElementById('discoveryResultsPanel');
    const meta = document.getElementById('discoveryMeta');
    const hostsEl = document.getElementById('discoveryHostResults');

    panel.style.display = 'block';

    meta.innerHTML = `
        <div class="discovery-stats">
            <span class="disc-stat"><strong>Scan:</strong> ${data.scan_id}</span>
            <span class="disc-stat"><strong>Skills:</strong> ${data.skills_used.join(', ') || 'none'}</span>
            <span class="disc-stat"><strong>Duration:</strong> ${data.duration_seconds.toFixed(2)}s</span>
        </div>
    `;

    hostsEl.innerHTML = data.hosts.map(host => {
        const statusClass = host.status === 'alive' ? 'status-alive' :
                           host.status === 'unreachable' ? 'status-unreachable' : 'status-unknown';
        const statusIcon = host.status === 'alive' ? '&#9679;' :
                          host.status === 'unreachable' ? '&#9675;' : '&#63;';

        const attrRows = Object.entries(host.attributes).map(([key, val]) => {
            const prov = host.provenance[key] || '';
            const valClass = val === 'unavailable' ? 'attr-unavailable' : 'attr-value';
            return `<tr>
                <td class="attr-key">${key}</td>
                <td class="${valClass}">${val}</td>
                <td class="attr-provenance">${prov}</td>
            </tr>`;
        }).join('');

        const errorHtml = host.errors && host.errors.length
            ? `<div class="host-errors">${host.errors.map(e => `<div class="host-error">&#9888; ${e}</div>`).join('')}</div>`
            : '';

        return `
            <div class="host-result-card">
                <div class="host-header">
                    <span class="host-target">${host.target}</span>
                    <span class="host-status ${statusClass}">${statusIcon} ${host.status}</span>
                </div>
                <table class="attr-table">
                    <thead><tr><th>Attribute</th><th>Value</th><th>Source</th></tr></thead>
                    <tbody>${attrRows}</tbody>
                </table>
                ${errorHtml}
            </div>
        `;
    }).join('');
}

async function enrichTarget() {
    const target = document.getElementById('enrichTarget').value.trim();
    if (!target) {
        showResult('enrichResult', 'Enter a target IP or hostname', true);
        return;
    }
    showInfo('enrichResult', `Enriching ${target}...`);
    try {
        const res = await apiFetch(`/api/v3/discovery/enrich/${encodeURIComponent(target)}`, { method: 'POST' });
        if (!res.ok) {
            showResult('enrichResult', res.data, true);
            return;
        }
        const d = res.data;
        let text = `Target: ${d.target}\nStatus: ${d.status}\nSkills Used: ${(d.skills_used || []).join(', ')}\n\nAttributes:\n`;
        for (const [k, v] of Object.entries(d.attributes || {})) {
            text += `  ${k}: ${v}  (via ${d.provenance[k] || '?'})\n`;
        }
        if (d.errors && d.errors.length) {
            text += `\nErrors:\n${d.errors.map(e => '  ⚠ ' + e).join('\n')}`;
        }
        showResult('enrichResult', text);
    } catch (e) {
        showResult('enrichResult', `Error: ${e.message}`, true);
    }
}

// Load skill catalog on page navigation
document.querySelector('[data-page="discovery"]')?.addEventListener('click', () => {
    // Auto-load skills when navigating to discovery page
    setTimeout(loadSkillCatalog, 100);
});

// === End-to-End Demo ===
let demoRunning = false;

async function runFullDemo() {
    if (demoRunning) return;
    demoRunning = true;
    const btn = document.getElementById('demoStartBtn');
    btn.disabled = true;
    btn.textContent = '⟳ Running Pipeline...';

    // Reset all steps
    for (let i = 1; i <= 7; i++) {
        const step = document.getElementById(`demoStep${i}`);
        step.className = 'demo-step';
        const result = document.getElementById(`demoResult${i}`);
        result.className = 'step-result';
        result.textContent = '';
    }

    let investigationId, compressedPkgId, packageId, rcaId, incidentId;

    try {
        // Step 1: Alert Ingestion
        setDemoStep(1, 'active');
        const alertData = ALERT_TEMPLATES.crowdstrike_malware;
        const alertRes = await apiFetch('/api/v1/alerts/ingest', {
            method: 'POST',
            body: JSON.stringify({ source: alertData.source, raw_alert: alertData.alert })
        });
        investigationId = alertRes.data.investigation_id || 'inv-demo-' + Date.now();
        setDemoStep(1, 'done', `✓ Alert ingested\n  Alert ID: ${alertRes.data.alert_id || 'N/A'}\n  Investigation: ${investigationId}\n  Severity: ${alertRes.data.severity || 'high'}`);

        // Step 2: Evidence Collection
        setDemoStep(2, 'active');
        const evidRes = await apiFetch('/api/v1/evidence/collect', {
            method: 'POST',
            body: JSON.stringify({ investigation_id: investigationId, max_depth: 2 })
        });
        setDemoStep(2, 'done', `✓ Evidence collected\n  Status: ${evidRes.data.status || 'completed'}\n  Entities: ${evidRes.data.entities_count || 0}\n  Relationships: ${evidRes.data.relationships_count || 0}`);

        // Step 3: Event Compression
        setDemoStep(3, 'active');
        const events = generateSampleEvents();
        const compRes = await apiFetch('/api/v2/correlation/compress', {
            method: 'POST',
            body: JSON.stringify({
                investigation_id: investigationId,
                alert_id: alertRes.data.alert_id || 'alert-demo',
                events,
                incident_time: new Date().toISOString()
            })
        });
        compressedPkgId = compRes.data.investigation_id || investigationId;
        setDemoStep(3, 'done', `✓ Events compressed\n  Original: ${compRes.data.original_event_count || events.length} events\n  Compressed: ${compRes.data.compressed_event_count || '?'} events\n  Ratio: ${compRes.data.compression_ratio || '?'}x\n  Risk Score: ${compRes.data.risk_score || '?'}\n  Patterns: ${(compRes.data.detected_patterns || []).length}`);

        // Step 4: Investigation Package
        setDemoStep(4, 'active');
        const invRes = await apiFetch('/api/v2/correlation/investigate', {
            method: 'POST',
            body: JSON.stringify({
                investigation_id: investigationId,
                compressed_package_id: compressedPkgId,
                package_type: 'detailed_rca',
                original_alert: alertData.alert
            })
        });
        packageId = invRes.data.package_id;
        setDemoStep(4, 'done', `✓ Investigation package built\n  Package: ${packageId}\n  Confidence: ${invRes.data.confidence || '?'}\n  Attack Types: ${(invRes.data.suspected_attack_types || []).join(', ')}\n  Impacted: ${(invRes.data.impacted_assets || []).length} assets`);

        // Step 5: RCA
        setDemoStep(5, 'active');
        const rcaRes = await apiFetch('/api/v3/rca/analyze', {
            method: 'POST',
            body: JSON.stringify({ investigation_id: investigationId, package_id: packageId })
        });
        rcaId = rcaRes.data.rca_id;
        setDemoStep(5, 'done', `✓ Root cause identified\n  RCA ID: ${rcaId}\n  Root Cause: ${rcaRes.data.root_cause_service || '?'}\n  Confidence: ${((rcaRes.data.confidence || 0) * 100).toFixed(0)}%\n  Attack Type: ${rcaRes.data.attack_type || '?'}\n  Escalation Required: ${rcaRes.data.requires_escalation ? 'YES' : 'No'}\n  Recommendations: ${rcaRes.data.recommendations_count || 0}`);

        // Step 6: Response
        setDemoStep(6, 'active');
        const respRes = await apiFetch('/api/v3/rca/respond', {
            method: 'POST',
            body: JSON.stringify({ investigation_id: investigationId, rca_id: rcaId, auto_approve: true })
        });
        incidentId = null;
        // Get incident list to find the one just created
        const incList = await apiFetch('/api/v3/rca/incidents');
        if (incList.ok && incList.data.incidents && incList.data.incidents.length > 0) {
            incidentId = incList.data.incidents[incList.data.incidents.length - 1].incident_id;
        }
        setDemoStep(6, 'done', `✓ Response executed\n  Actions Executed: ${respRes.data.actions_executed || 0}\n  Actions Failed: ${respRes.data.actions_failed || 0}\n  Success Rate: ${((respRes.data.success_rate || 0) * 100).toFixed(0)}%\n  Duration: ${respRes.data.duration_seconds || 0}s\n  Incident: ${incidentId || 'N/A'}`);

        // Step 7: Reports
        setDemoStep(7, 'active');
        if (incidentId) {
            const repRes = await apiFetch('/api/v3/rca/generate-reports', {
                method: 'POST',
                body: JSON.stringify({ incident_id: incidentId, report_types: ['executive_summary', 'technical_analysis'] })
            });
            const reportNames = Object.keys(repRes.data || {});
            setDemoStep(7, 'done', `✓ Reports generated\n  Reports: ${reportNames.join(', ')}\n  Incident: ${incidentId}\n\n  ✅ Pipeline complete! All 7 steps executed successfully.`);
        } else {
            setDemoStep(7, 'done', `✓ Skipped (no incident ID available)\n\n  ✅ Pipeline complete! 6/7 steps executed.`);
        }

    } catch (e) {
        console.error('Demo error:', e);
        // Mark current step as error
        for (let i = 1; i <= 7; i++) {
            const step = document.getElementById(`demoStep${i}`);
            if (step.classList.contains('active')) {
                setDemoStep(i, 'error', `✗ Error: ${e.message}`);
                break;
            }
        }
    }

    btn.disabled = false;
    btn.textContent = '▶ Run Full Pipeline Demo';
    demoRunning = false;
}

function setDemoStep(num, state, resultText) {
    const step = document.getElementById(`demoStep${num}`);
    step.className = `demo-step ${state === 'error' ? 'error-step' : state}`;
    if (resultText) {
        const result = document.getElementById(`demoResult${num}`);
        result.className = 'step-result visible';
        result.textContent = resultText;
    }
}

// === Init ===
document.addEventListener('DOMContentLoaded', () => {
    loadAlertTemplate();
    loadOrchTemplate();
    refreshDashboard();
    // Auto-refresh dashboard every 30 seconds
    setInterval(() => {
        if (document.getElementById('page-dashboard').classList.contains('active')) {
            refreshDashboard();
        }
    }, 30000);
});

// === Agent Orchestrator ===
const ORCH_TEMPLATES = ALERT_TEMPLATES;

let orchRunning = false;
let orchTimerInterval = null;
let orchStartTime = null;
let orchEventCount = 0;

function loadOrchTemplate() {
    const select = document.getElementById('orchAlertTemplate');
    const textarea = document.getElementById('orchAlertJson');
    const taskInput = document.getElementById('orchTask');
    if (!select || !textarea) return;

    const templateKey = select.value;
    const template = ALERT_TEMPLATES[templateKey];
    if (template) {
        const alertObj = template.alert || template;
        textarea.value = JSON.stringify(alertObj, null, 2);
        if (taskInput) {
            taskInput.value = template.task || `Investigate ${alertObj.description || 'security alert and recommend response'}`;
        }
    }
}

async function runOrchestration() {
    if (orchRunning) return;
    orchRunning = true;

    const btn = document.getElementById('orchStartBtn');
    btn.disabled = true;
    btn.textContent = '⟳ Orchestrating...';

    const panel = document.getElementById('orchPanel');
    panel.style.display = 'block';

    // Reset UI
    resetOrchUI();

    const task = document.getElementById('orchTask').value || 'Investigate security alert';
    let alertData = null;
    try {
        alertData = JSON.parse(document.getElementById('orchAlertJson').value);
    } catch (e) {
        addOrchLog('error', 'orchestrator', `Invalid JSON Alert Data: ${e.message}`);
        setOrchStatus('failed');
        btn.disabled = false;
        btn.textContent = '▶ Run Agentic Investigation';
        orchRunning = false;
        return;
    }

    // Start timer
    orchStartTime = Date.now();
    orchTimerInterval = setInterval(updateOrchTimer, 100);

    const useAiPlanner = document.getElementById('orchUseAIPlanner')?.checked || false;

    try {
        const response = await fetch('/api/v3/orchestrator/investigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ task, alert_data: alertData, use_ai_planner: useAiPlanner }),
        });
        
        let reader = null;
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            // Temporal mode: got workflow JSON back, need to connect to stream
            const resJson = await response.json();
            const workflowId = resJson.workflow_id;
            addOrchLog('info', 'orchestrator', `Temporal workflow started: ${workflowId}`);
            
            const streamRes = await fetch(`/api/v3/orchestrator/investigate/${workflowId}/stream`);
            reader = streamRes.body.getReader();
        } else {
            // Legacy in-memory mode: stream is returned directly
            reader = response.body.getReader();
        }

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const blocks = buffer.split('\n\n');
            buffer = blocks.pop(); // Keep incomplete block in buffer

            for (const block of blocks) {
                if (!block.trim()) continue;
                let eventType = '';
                let dataStr = '';
                const lines = block.split('\n');
                for (const line of lines) {
                    if (line.startsWith('event: ')) {
                        eventType = line.slice(7).trim();
                    } else if (line.startsWith('data: ')) {
                        dataStr += (dataStr ? '\n' : '') + line.slice(6);
                    }
                }
                if (eventType && dataStr) {
                    try {
                        const data = JSON.parse(dataStr);
                        handleOrchEvent(eventType, data);
                    } catch (e) {
                        console.error('SSE JSON parse error:', e, 'Payload snippet:', dataStr.slice(0, 150));
                    }
                }
            }
        }
    } catch (e) {
        addOrchLog('error', 'orchestrator', `Error: ${e.message}`);
        setOrchStatus('failed');
    }

    clearInterval(orchTimerInterval);
    btn.disabled = false;
    btn.textContent = '▶ Run Agentic Investigation';
    orchRunning = false;
}

function resetOrchUI() {
    orchEventCount = 0;
    document.getElementById('orchLog').innerHTML = '';
    document.getElementById('orchReportsGrid').innerHTML = '';
    document.getElementById('orchReasoning').textContent = '';
    document.getElementById('orchSynthesis').style.display = 'none';
    document.getElementById('orchLogCount').textContent = '0 events';
    document.getElementById('orchDag').innerHTML = '';
    const pendingBtn = document.getElementById('orchPendingBtn');
    if (pendingBtn) pendingBtn.style.display = 'none';
}
// === Agent Orchestrator Dynamic DAG Architecture ===
const AGENT_REGISTRY = {
    'triage_agent': { label: 'Triage & Scope', icon: '🔍', color: '#38bdf8', category: 'Intake' },
    'triage': { label: 'Triage & Scope', icon: '🔍', color: '#38bdf8', category: 'Intake' },
    'triage_activity': { label: 'Triage & Scope', icon: '🔍', color: '#38bdf8', category: 'Intake' },

    'supervisor_agent': { label: 'ReAct Supervisor', icon: '🧠', color: '#c084fc', category: 'Supervision' },
    'supervisor': { label: 'ReAct Supervisor', icon: '🧠', color: '#c084fc', category: 'Supervision' },
    'supervisor_activity': { label: 'ReAct Supervisor', icon: '🧠', color: '#c084fc', category: 'Supervision' },

    'evidence_agent': { label: 'Evidence Collection', icon: '📊', color: '#a78bfa', category: 'Forensics' },
    'gather_evidence': { label: 'Evidence Collection', icon: '📊', color: '#a78bfa', category: 'Forensics' },
    'evidence_activity': { label: 'Evidence Collection', icon: '📊', color: '#a78bfa', category: 'Forensics' },

    'discovery_agent': { label: 'Network Discovery', icon: '🌐', color: '#34d399', category: 'Recon' },
    'discover_network': { label: 'Network Discovery', icon: '🌐', color: '#34d399', category: 'Recon' },
    'discovery_activity': { label: 'Network Discovery', icon: '🌐', color: '#34d399', category: 'Recon' },

    'compression_agent': { label: '7-Stage Compression', icon: '🗜️', color: '#f59e0b', category: 'Analytics' },
    'compress_events': { label: '7-Stage Compression', icon: '🗜️', color: '#f59e0b', category: 'Analytics' },
    'compression_activity': { label: '7-Stage Compression', icon: '🗜️', color: '#f59e0b', category: 'Analytics' },

    'rca_agent': { label: 'Root Cause Analysis', icon: '🔬', color: '#ec4899', category: 'Diagnosis' },
    'perform_rca': { label: 'Root Cause Analysis', icon: '🔬', color: '#ec4899', category: 'Diagnosis' },
    'rca_activity': { label: 'Root Cause Analysis', icon: '🔬', color: '#ec4899', category: 'Diagnosis' },

    'response_agent': { label: 'Response Planning', icon: '⚡', color: '#f97316', category: 'Mitigation' },
    'response_activity': { label: 'Response Planning', icon: '⚡', color: '#f97316', category: 'Mitigation' },
    'finalize_response': { label: 'Response Planning', icon: '⚡', color: '#f97316', category: 'Mitigation' },

    'pending_approval': { label: 'Human Authorization', icon: '🛡️', color: '#ef4444', category: 'Governance' },
    'approve_response': { label: 'Human Authorization', icon: '🛡️', color: '#ef4444', category: 'Governance' },

    'execute_response_activity': { label: 'Active Containment', icon: '🚀', color: '#10b981', category: 'Execution' },
    'execute_response': { label: 'Active Containment', icon: '🚀', color: '#10b981', category: 'Execution' },

    'persist_investigation_results_activity': { label: 'Graph & Audit Store', icon: '💾', color: '#6366f1', category: 'Knowledge' },
    'persist_results': { label: 'Graph & Audit Store', icon: '💾', color: '#6366f1', category: 'Knowledge' }
};

function normalizeAgentKey(name) {
    if (!name) return 'triage_agent';
    const clean = String(name).toLowerCase().replace(/['"]/g, '').trim();
    const aliasMap = {
        'compress_events': 'compression_agent',
        'compression_activity': 'compression_agent',
        'compression': 'compression_agent',
        'gather_evidence': 'evidence_agent',
        'evidence_activity': 'evidence_agent',
        'evidence': 'evidence_agent',
        'perform_rca': 'rca_agent',
        'rca_activity': 'rca_agent',
        'rca': 'rca_agent',
        'discover_network': 'discovery_agent',
        'discovery_activity': 'discovery_agent',
        'discovery': 'discovery_agent',
        'finalize_response': 'response_agent',
        'response_activity': 'response_agent',
        'response': 'response_agent',
        'triage_activity': 'triage_agent',
        'triage': 'triage_agent',
        'supervisor_activity': 'supervisor_agent',
        'supervisor': 'supervisor_agent'
    };
    return aliasMap[clean] || clean;
}

function getAgentMeta(name) {
    const key = normalizeAgentKey(name);
    return AGENT_REGISTRY[key] || { label: String(name).replace(/_/g, ' '), icon: '⚙️', color: '#94a3b8', category: 'Activity' };
}

let activeDagPhases = [];

function renderDynamicDAG(phases) {
    const dagContainer = document.getElementById('orchDag');
    if (!dagContainer) return;
    dagContainer.innerHTML = '';
    activeDagPhases = [];

    (phases || []).forEach(phase => {
        appendOrUpdateDAGPhase(
            phase.phase_num || (activeDagPhases.length + 1),
            phase.agents || (phase.tasks ? phase.tasks.map(t => t.agent) : []),
            phase.parallel,
            phase.status || 'pending'
        );
    });
}

function appendOrUpdateDAGPhase(phaseNum, agents, isParallel = false, initialStatus = 'pending') {
    const dagContainer = document.getElementById('orchDag');
    if (!dagContainer) return;

    const agentList = Array.isArray(agents) && agents.length > 0 ? agents : [];
    if (agentList.length === 0) return;

    let phaseDiv = document.getElementById(`dagPhase${phaseNum}`);
    const primaryAgentKey = normalizeAgentKey(agentList[0]);
    const meta = getAgentMeta(primaryAgentKey);
    const parallelBadge = isParallel ? ' <span class="parallel-badge">PARALLEL</span>' : '';

    if (!phaseDiv) {
        if (dagContainer.children.length > 0) {
            const connector = document.createElement('div');
            connector.className = 'dag-connector';
            connector.innerHTML = `<div class="connector-line"></div><div class="connector-arrow">↓</div>`;
            dagContainer.appendChild(connector);
        }

        phaseDiv = document.createElement('div');
        phaseDiv.className = 'dag-phase';
        phaseDiv.id = `dagPhase${phaseNum}`;

        phaseDiv.innerHTML = `
            <div class="phase-header">
                <span class="phase-tag">PHASE ${phaseNum}</span>
                <span class="phase-title">${meta.category || 'EXECUTION'}${parallelBadge}</span>
            </div>
            <div class="phase-agents" id="phaseAgents${phaseNum}"></div>
        `;
        dagContainer.appendChild(phaseDiv);
        if (!activeDagPhases.includes(phaseNum)) {
            activeDagPhases.push(phaseNum);
        }
    } else {
        const titleEl = phaseDiv.querySelector('.phase-title');
        if (titleEl && meta.category) {
            titleEl.innerHTML = `${meta.category}${parallelBadge}`;
        }
    }

    const agentsDiv = phaseDiv.querySelector(`#phaseAgents${phaseNum}`);
    agentList.forEach((agentName) => {
        const agentKey = normalizeAgentKey(agentName);
        const agentMeta = getAgentMeta(agentKey);
        const nodeId = `node-p${phaseNum}-${agentKey}`;
        
        let nodeDiv = document.getElementById(nodeId);
        if (!nodeDiv) {
            nodeDiv = document.createElement('div');
            nodeDiv.className = `agent-node ${initialStatus}`;
            nodeDiv.id = nodeId;
            nodeDiv.dataset.agent = agentKey;
            nodeDiv.dataset.phase = phaseNum;

            nodeDiv.innerHTML = `
                <div class="node-glow" style="--node-color: ${agentMeta.color}"></div>
                <div class="node-main">
                    <div class="agent-icon-wrapper" style="background: ${agentMeta.color}20; color: ${agentMeta.color}; border: 1px solid ${agentMeta.color}40">
                        <span class="agent-icon">${agentMeta.icon}</span>
                    </div>
                    <div class="agent-info">
                        <div class="agent-label">${agentMeta.label}</div>
                        <div class="agent-subtext" id="subtext-${nodeId}">${initialStatus === 'running' ? 'Executing activity...' : 'Awaiting dispatch'}</div>
                    </div>
                    <div class="agent-status-badge">
                        <span class="status-indicator"></span>
                    </div>
                </div>
                <div class="node-meta-bar" id="meta-${nodeId}" style="display: none;"></div>
            `;
            agentsDiv.appendChild(nodeDiv);
        } else if (initialStatus) {
            nodeDiv.className = `agent-node ${initialStatus}`;
        }
    });
}

function setAgentNodeState(agentName, state, reportData = null) {
    const key = normalizeAgentKey(agentName);
    const matchingNodes = Array.from(document.querySelectorAll(`.agent-node[data-agent="${key}"]`));
    
    let targetNode = null;
    if (state === 'running') {
        targetNode = matchingNodes.find(n => n.classList.contains('pending')) || matchingNodes[matchingNodes.length - 1];
    } else if (state === 'completed' || state === 'failed') {
        targetNode = matchingNodes.find(n => n.classList.contains('running')) || matchingNodes[matchingNodes.length - 1];
    } else {
        targetNode = matchingNodes[matchingNodes.length - 1];
    }

    if (!targetNode) {
        const nextPhase = (activeDagPhases.length || 0) + 1;
        appendOrUpdateDAGPhase(nextPhase, [agentName], false, state);
        targetNode = document.getElementById(`node-p${nextPhase}-${key}`);
    }

    if (targetNode) {
        targetNode.className = `agent-node ${state}`;
        const subtextEl = targetNode.querySelector('.agent-subtext');
        const metaEl = targetNode.querySelector('.node-meta-bar');

        if (state === 'running') {
            if (subtextEl) subtextEl.textContent = 'Executing activity...';
        } else if (state === 'completed') {
            const dur = reportData && reportData.duration_ms ? `${reportData.duration_ms}ms` : 'Completed';
            if (subtextEl) subtextEl.textContent = `✓ ${dur}`;
            
            targetNode.style.cursor = 'pointer';
            targetNode.title = `Click to inspect forensic artifacts for ${formatAgentName(key)}`;
            targetNode.onclick = () => openPhaseInspector(key);

            if (metaEl && reportData && reportData.findings) {
                metaEl.style.display = 'flex';
                let metaHtml = '';
                if (reportData.findings.original_events) {
                    metaHtml += `<span class="meta-pill">${reportData.findings.original_events} → ${reportData.findings.compressed_events} events</span>`;
                }
                if (reportData.findings.iocs_found) {
                    metaHtml += `<span class="meta-pill">${reportData.findings.iocs_found} IOCs</span>`;
                }
                if (reportData.findings.root_cause) {
                    metaHtml += `<span class="meta-pill high-risk">RCA Identified</span>`;
                }
                if (metaHtml) metaEl.innerHTML = metaHtml;
            }
        } else if (state === 'failed') {
            if (subtextEl) subtextEl.textContent = '✗ Execution failed';
        }
    }
}

function handleOrchEvent(type, data) {
    orchEventCount++;
    const countEl = document.getElementById('orchLogCount');
    if (countEl) countEl.textContent = `${orchEventCount} events`;

    switch (type) {
        case 'run_start':
            setOrchStatus('planning');
            addOrchLog(type, 'orchestrator', `Starting investigation: "${data.task}"`);
            break;

        case 'plan_created':
            setOrchStatus('running');
            const reasonEl = document.getElementById('orchReasoning');
            if (reasonEl) reasonEl.textContent = data.reasoning;
            renderDynamicDAG(data.phases || []);
            addOrchLog(type, 'orchestrator', `Plan initialized: ${data.total_tasks || 1} tasks across ${data.total_phases || 1} phases`);
            break;

        case 'phase_start':
            const parallelNote = data.parallel ? ' [PARALLEL]' : '';
            appendOrUpdateDAGPhase(data.phase_num, data.agents || [], data.parallel, 'running');
            addOrchLog(type, 'orchestrator', `Starting Phase ${data.phase_num}${parallelNote}`);
            break;

        case 'pending_approval':
            setOrchStatus('pending_approval');
            const nextP = activeDagPhases.length + 1;
            appendOrUpdateDAGPhase(nextP, ['pending_approval'], false, 'running');
            const approvalNode = document.getElementById(`node-p${nextP}-pending_approval`);
            if (approvalNode) {
                const subtext = approvalNode.querySelector('.agent-subtext');
                if (subtext) subtext.innerHTML = `<span style="color: #ef4444; font-weight: bold;">Authorization Required</span>`;
            }

            const btn = document.getElementById('orchPendingBtn');
            if (btn) {
                btn.style.display = 'inline-block';
                btn.onclick = () => {
                    document.querySelector('.nav-item[data-page="approvals"]').click();
                    setTimeout(() => {
                        const el = document.getElementById(`approval-${data.workflow_id}`);
                        if (el) {
                            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            el.style.transition = 'box-shadow 0.3s ease-in-out';
                            el.style.boxShadow = '0 0 15px var(--accent-red)';
                            setTimeout(() => el.style.boxShadow = 'none', 3000);
                        }
                    }, 200);
                };
            }
            addOrchLog('warning', 'orchestrator', `Workflow paused. Human authorization required for active response.`);
            addPendingApproval(data.workflow_id);
            break;

        case 'supervisor_thought':
            const targets = (data.target_entities || []).join(', ') || 'infrastructure';
            const pivotNote = data.pivot_entity_detected ? ` [🎯 Pivot IOC: ${data.pivot_entity_detected}]` : '';
            if (data.supervisor_assessment) {
                addOrchLog('info', 'supervisor', `📊 Assessment: ${data.supervisor_assessment}`);
            }
            addOrchLog('info', 'supervisor', `Step ${data.iteration} Thought: "${data.thought.slice(0, 140)}..." ➔ Action: ${data.action} on [${targets}]${pivotNote}`);
            break;

        case 'agent_start':
            setAgentNodeState(data.agent_name, 'running');
            addOrchLog(type, data.agent_name, `Started: ${data.description}`);
            break;

        case 'agent_complete':
            const report = data.report;
            const state = report.status === 'completed' ? 'completed' : 'failed';
            setAgentNodeState(data.agent_name, state, report);
            const summary = getAgentLogSummary(report);
            addOrchLog(type, data.agent_name, `Completed (${report.duration_ms}ms) — ${summary}`);
            addAgentReport(report);
            break;

        case 'phase_complete':
            addOrchLog(type, 'orchestrator', `Phase ${data.phase_num} complete`);
            break;

        case 'synthesis_start':
            addOrchLog(type, 'orchestrator', 'Synthesizing findings from all agents...');
            break;

        case 'run_complete':
            setOrchStatus('completed');
            addOrchLog(type, 'orchestrator', `Investigation complete (${data.total_duration_ms}ms)`);
            renderSynthesis(data.synthesis, data.total_duration_ms);
            break;
    }
}

function setOrchStatus(status) {
    const badge = document.getElementById('orchStatus');
    if (!badge) return;
    badge.className = `orch-status-badge ${status}`;
    const labels = { planning: 'Planning...', running: 'Executing', completed: 'Completed', failed: 'Failed', pending_approval: 'Pending Approval' };
    badge.textContent = labels[status] || status;
}

function updateOrchTimer() {
    if (!orchStartTime) return;
    const elapsed = ((Date.now() - orchStartTime) / 1000).toFixed(1);
    const timerEl = document.getElementById('orchTimer');
    if (timerEl) timerEl.textContent = `${elapsed}s`;
}

function addOrchLog(eventType, agent, message) {
    const log = document.getElementById('orchLog');
    const elapsed = orchStartTime ? ((Date.now() - orchStartTime) / 1000).toFixed(2) : '0.00';

    const entry = document.createElement('div');
    entry.className = `log-entry event-${eventType}`;
    entry.innerHTML = `<span class="log-time">${elapsed}s</span><span class="log-agent">${formatAgentName(agent)}</span><span class="log-msg">${escapeHtml(message)}</span>`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

function addAgentReport(report) {
    window.currentPhaseReports = window.currentPhaseReports || {};
    const agentKey = normalizeAgentKey(report.agent_name || '');
    window.currentPhaseReports[agentKey] = report;
    if (report.task_id) window.currentPhaseReports[report.task_id] = report;

    const grid = document.getElementById('orchReportsGrid');
    const confidence = report.confidence || 0;
    const confClass = confidence >= 0.8 ? 'confidence-high' : confidence >= 0.5 ? 'confidence-medium' : 'confidence-low';

    // Pick key findings to display (skip large objects)
    const findings = report.findings || {};
    const displayFindings = Object.entries(findings)
        .filter(([k, v]) => typeof v !== 'object' || Array.isArray(v))
        .filter(([k]) => k !== 'summary' && k !== 'initial_assessment' && k !== 'raw_events' && k !== 'timeline' && k !== 'entity_graph')
        .slice(0, 6);

    const artifactsHtml = (report.artifacts || [])
        .map(a => `<span class="artifact-tag">${a}</span>`).join('');

    const findingsHtml = displayFindings
        .map(([k, v]) => {
            if (k === 'skills_used' && Array.isArray(v)) {
                const badges = v.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:2px 6px; font-size:0.75rem; margin:2px 2px 2px 0; display:inline-block;">⚡ ${escapeHtml(s)}</span>`).join('');
                return `<div class="report-finding-item" style="display:block; margin-top:4px;"><span class="report-finding-key" style="display:block; margin-bottom:2px;">skills_used:</span><div>${badges}</div></div>`;
            }
            const val = Array.isArray(v) ? `[${v.length} items]` : String(v);
            return `<div class="report-finding-item"><span class="report-finding-key">${k}:</span><span class="report-finding-value">${escapeHtml(val)}</span></div>`;
        }).join('');

    const card = document.createElement('div');
    card.className = 'report-card';
    card.innerHTML = `
        <div class="report-card-header">
            <span class="report-agent-name">${formatAgentName(report.agent_name)}</span>
            <span class="report-duration">${report.duration_ms}ms</span>
        </div>
        <div class="report-task">${escapeHtml(report.task)}</div>
        <span class="report-confidence ${confClass}">${(confidence * 100).toFixed(0)}% confidence</span>
        <div class="report-findings">${findingsHtml}</div>
        <div class="report-artifacts">${artifactsHtml}</div>
        <button class="inspect-phase-btn" onclick="openPhaseInspector('${agentKey}')">🔍 Inspect Artifacts & Telemetry ➔</button>
    `;
    grid.appendChild(card);
}

function renderSynthesis(synthesis, totalMs) {
    const el = document.getElementById('orchSynthesis');
    const content = document.getElementById('orchSynthesisContent');
    el.style.display = 'block';

    content.innerHTML = `
        <div class="synthesis-verdict">${escapeHtml(synthesis.verdict)}</div>
        <p style="color:var(--text-secondary);font-size:0.88rem;margin-bottom:1rem;">${escapeHtml(synthesis.executive_summary)}</p>
        <div class="synthesis-stats">
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${synthesis.severity}</div>
                <div class="synthesis-stat-label">Severity</div>
            </div>
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${(synthesis.confidence * 100).toFixed(0)}%</div>
                <div class="synthesis-stat-label">Confidence</div>
            </div>
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${synthesis.blast_radius}</div>
                <div class="synthesis-stat-label">Blast Radius</div>
            </div>
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${synthesis.compression_ratio}</div>
                <div class="synthesis-stat-label">Compression</div>
            </div>
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${synthesis.response_actions}</div>
                <div class="synthesis-stat-label">Actions</div>
            </div>
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${synthesis.agents_used}</div>
                <div class="synthesis-stat-label">Agents Used</div>
            </div>
            <div class="synthesis-stat">
                <div class="synthesis-stat-value">${(totalMs / 1000).toFixed(1)}s</div>
                <div class="synthesis-stat-label">Total Time</div>
            </div>
        </div>
    `;
}

function formatAgentName(name) {
    const key = normalizeAgentKey(name);
    const names = {
        orchestrator: '🎯 Orchestrator',
        supervisor_agent: '🧠 Supervisor',
        supervisor: '🧠 Supervisor',
        triage_agent: '🔍 Triage',
        evidence_agent: '📊 Evidence',
        discovery_agent: '🌐 Discovery',
        compression_agent: '🗜️ Compression',
        rca_agent: '🔬 RCA',
        response_agent: '⚡ Response',
    };
    return names[key] || getAgentMeta(key)?.label || name;
}

function getAgentLogSummary(report) {
    if (!report || !report.findings) return `Done in ${report?.duration_ms || 0}ms`;
    const f = report.findings;
    const name = (report.agent_name || '').toLowerCase();

    // 1. Triage Agent
    if (name.includes('triage')) {
        const mitre = f.technique ? ` • MITRE: ${f.technique}` : '';
        const sev = f.severity ? ` • Severity: ${f.severity}` : '';
        const entCount = f.entity_count !== undefined ? ` • ${f.entity_count} entities extracted` : '';
        const assessment = f.initial_assessment || f.summary || 'Alert triaged and classified.';
        return `${assessment}${mitre}${sev}${entCount}`;
    }

    // 2. Evidence Agent
    if (name.includes('evidence')) {
        const entCount = f.entity_graph_size !== undefined ? f.entity_graph_size : (Object.keys(f.entity_graph || {}).length);
        const relCount = f.relationships_found !== undefined ? f.relationships_found : (f.relationships?.length || 0);
        const skillsCount = f.skills_used?.length || 0;
        
        // Find high risk entities (risk >= 0.6)
        const highRisk = Object.entries(f.entity_graph || {})
            .filter(([_, v]) => (v.risk_score || 0) >= 0.6)
            .map(([k, v]) => `${k.replace(/^(file|host|ip|user):/, '')} (Risk: ${v.risk_score})`);
        
        const riskNote = highRisk.length ? ` • Flagged IOCs: ${highRisk.join(', ')}` : '';
        const skillsList = f.skills_used && f.skills_used.length > 0 ? ` [${f.skills_used.slice(0, 3).join(', ')}${f.skills_used.length > 3 ? '...' : ''}]` : '';
        
        const base = f.summary || f.enrichment_summary || `Expanded into ${entCount} nodes and ${relCount} relationships using ${skillsCount} skills${skillsList}.`;
        return `${base}${riskNote}`;
    }

    // 3. Compression Agent
    if (name.includes('compression')) {
        const orig = f.original_events !== undefined ? f.original_events : 0;
        const comp = f.compressed_events !== undefined ? f.compressed_events : 0;
        const ratio = f.compression_ratio || (orig > 0 ? (orig / (comp || 1)).toFixed(1) + 'x' : '1.0x');
        const patterns = f.patterns_detected && f.patterns_detected.length > 0 ? ` • Patterns: ${f.patterns_detected.length} detected` : '';
        
        const topEvent = f.timeline && f.timeline.length > 0 ? f.timeline[0] : null;
        const topEventNote = topEvent && topEvent.action && topEvent.action !== 'UNKNOWN' ? ` • Milestone: "${topEvent.action.slice(0, 60)}..."` : '';
        
        return f.summary || `Compressed ${orig} raw events down to ${comp} milestones (${ratio} reduction) through 5 agentic skills.${patterns}${topEventNote}`;
    }

    // 4. Discovery Agent
    if (name.includes('discovery')) {
        const scanned = f.targets_scanned !== undefined ? f.targets_scanned : (f.hosts?.length || 0);
        const reachable = (f.hosts || []).filter(h => h.status === 'reachable' || h.status === 'open').length;
        return f.summary || `Network scan completed on ${scanned} target(s). Reachable: ${reachable}.`;
    }

    // 5. RCA Agent
    if (name.includes('rca')) {
        const rootCause = f.root_cause || f.summary || 'Root cause identified.';
        const phases = f.attack_phases && f.attack_phases.length > 0 ? ` • Attack Chain: ${f.attack_phases.length} phases` : '';
        const blast = f.blast_radius ? ` • Blast Radius: ${f.blast_radius} nodes` : '';
        const conf = f.confidence_score !== undefined ? ` • Confidence: ${Math.round(f.confidence_score * 100)}%` : '';
        return `${rootCause}${phases}${blast}${conf}`;
    }

    // 6. Response Agent
    if (name.includes('response')) {
        const actions = f.actions_recommended || [];
        const actionCount = actions.length;
        const topActions = actions.slice(0, 3).map(a => `${a.action_type || a.name || 'action'} (${a.priority || 'Normal'})`).join(', ');
        const actionsSummary = actionCount > 0 ? ` • Playbook [${actionCount} actions: ${topActions}]` : '';
        const challenges = (f.agent_messages || []).filter(m => m.msg_type === 'CHALLENGE');
        const challengeNote = challenges.length ? ` ⚠️ [CHALLENGE: Destructive actions guarded]` : '';
        return `${f.summary || 'Response containment plan generated.'}${actionsSummary}${challengeNote}`;
    }

    // 7. Supervisor Agent
    if (name.includes('supervisor')) {
        return f.thought || f.summary || f.specific_goal || `Forensic step completed.`;
    }

    return f.summary || f.initial_assessment || f.enrichment_summary || f.root_cause || `Done in ${report.duration_ms}ms`;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

// --- Human in the Loop Approvals ---
async function handleApproval(workflowId, decision) {
    try {
        const res = await apiFetch(`/api/v3/orchestrator/investigate/${workflowId}/approve`, {
            method: 'POST',
            body: JSON.stringify({ decision, comment: "Decision from UI" })
        });
        if (res.ok) {
            const el = document.getElementById(`approval-${workflowId}`);
            if (el) el.innerHTML = `<span class="badge badge-green">Decision: ${decision}</span>`;
            
            // update badge
            const badge = document.getElementById('approvalBadge');
            let count = parseInt(badge.textContent);
            if (count > 0) count--;
            badge.textContent = count;
            if (count === 0) badge.style.display = 'none';
        } else {
            alert("Failed to submit approval: " + (typeof res.data === 'object' ? JSON.stringify(res.data) : res.data));
        }
    } catch (e) {
        alert("Error: " + e.message);
    }
}

function addPendingApproval(workflowId, actions = [], confidence = 0, entities = [], summary = "") {
    const list = document.getElementById('approvalsList');
    if (list.innerHTML.includes('No pending approvals')) {
        list.innerHTML = '';
    }
    
    // Don't duplicate
    if (document.getElementById(`approval-${workflowId}`)) return;
    
    // Add badge notification
    const badge = document.getElementById('approvalBadge');
    badge.textContent = (parseInt(badge.textContent) || 0) + 1;
    badge.style.display = 'inline-block';
    
    const card = document.createElement('div');
    card.className = 'agent-card';
    card.id = `approval-${workflowId}`;
    
    let actionsHtml = actions.map(a => {
        if (typeof a === 'string') return `<li>${a}</li>`;
        return `<li><strong>[${(a.action_type || 'UNKNOWN').toUpperCase()}]</strong> Target: <code>${a.target || 'Unknown'}</code><br><span style="font-size: 0.85em; color: var(--text-muted)">${a.description || ''}</span></li>`;
    }).join('');
    let entitiesHtml = entities.map(e => `<span class="badge" style="margin-right:5px; background:var(--bg-lighter)">${e.id} (${e.type})</span>`).join('');
    
    card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div style="flex: 1;">
                <h4 style="margin:0 0 10px 0;">Workflow: ${workflowId} <span class="badge badge-red" style="float:right">Confidence: ${Math.round(confidence * 100)}%</span></h4>
                <div style="font-size:0.9rem; margin-bottom: 10px;"><strong>Summary:</strong> ${summary || 'AI recommends active response. Requires authorization.'}</div>
                ${entities.length > 0 ? `<div style="margin-bottom: 10px;"><strong>Affected Entities:</strong><br>${entitiesHtml}</div>` : ''}
                ${actions.length > 0 ? `<div style="background: var(--bg-darker); padding: 10px; border-radius: 4px; border-left: 3px solid var(--accent-red);"><strong>Recommended Actions:</strong><ul style="margin: 5px 0 0 20px; padding: 0;">${actionsHtml}</ul></div>` : ''}
            </div>
            <div style="display: flex; flex-direction: column; gap: 10px; margin-left: 15px; min-width: 100px;">
                <button class="btn btn-sm btn-primary" onclick="handleApproval('${workflowId}', 'approve')">Approve</button>
                <button class="btn btn-sm" style="background:var(--accent-red); color:white; border:none;" onclick="handleApproval('${workflowId}', 'reject')">Reject</button>
            </div>
        </div>
    `;
    list.appendChild(card);
}

async function loadPendingApprovals() {
    try {
        const list = document.getElementById('approvalsList');
        const badge = document.getElementById('approvalBadge');
        
        list.innerHTML = '<div style="color: var(--text-muted); font-style: italic;">Loading...</div>';
        
        const res = await apiFetch('/api/v3/orchestrator/approvals/pending');
        if (res.ok) {
            list.innerHTML = '';
            const pending = res.data.pending_approvals || [];
            
            if (pending.length === 0) {
                list.innerHTML = '<div style="color: var(--text-muted); font-style: italic;">No pending approvals at this time.</div>';
                badge.style.display = 'none';
                badge.textContent = '0';
                return;
            }
            
            badge.textContent = '0'; // reset before loop
            badge.style.display = 'inline-block';
            
            pending.forEach(p => {
                addPendingApproval(p.workflow_id, p.actions, p.confidence, p.entities, p.summary);
            });
        }
    } catch (e) {
        console.error("Failed to load pending approvals", e);
    }
}

// --- Investigation History Explorer ---
let _historyDebounceTimer = null;
let _currentAttackGraph = null;
let _graphAnimId = null;

function debounceHistorySearch() {
    clearTimeout(_historyDebounceTimer);
    _historyDebounceTimer = setTimeout(() => {
        loadInvestigationHistory();
    }, 300);
}

function clearHistoryFilters() {
    const searchInput = document.getElementById('historySearchInput');
    const statusSelect = document.getElementById('historyStatusFilter');
    const severitySelect = document.getElementById('historySeverityFilter');
    if (searchInput) searchInput.value = '';
    if (statusSelect) statusSelect.value = 'all';
    if (severitySelect) severitySelect.value = 'all';
    loadInvestigationHistory();
}

async function loadInvestigationHistory() {
    try {
        const tbody = document.getElementById('historyTableBody');
        const countSpan = document.getElementById('historyRecordCount');
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 25px; color: var(--text-muted);">&#8987; Fetching investigations...</td></tr>';
        
        const q = (document.getElementById('historySearchInput')?.value || '').trim();
        const status = document.getElementById('historyStatusFilter')?.value || 'all';
        const severity = document.getElementById('historySeverityFilter')?.value || 'all';

        const params = new URLSearchParams();
        if (q) params.append('q', q);
        if (status && status !== 'all') params.append('status', status);
        if (severity && severity !== 'all') params.append('severity', severity);

        const res = await apiFetch(`/api/v3/orchestrator/investigations?${params.toString()}`);
        if (res.ok) {
            const data = res.data;
            const investigations = data.investigations || [];
            const stats = data.stats || {};

            // Update KPI Stats
            const statTotal = document.getElementById('histStatTotal');
            const statCrit = document.getElementById('histStatCritical');
            const statConf = document.getElementById('histStatConfidence');
            const statActs = document.getElementById('histStatActions');

            if (statTotal) statTotal.textContent = stats.total_count !== undefined ? stats.total_count : investigations.length;
            if (statCrit) statCrit.textContent = stats.critical_count !== undefined ? stats.critical_count : 0;
            if (statConf) statConf.textContent = stats.avg_confidence !== undefined ? `${Math.round(stats.avg_confidence * 100)}%` : '--';
            if (statActs) statActs.textContent = stats.total_actions !== undefined ? stats.total_actions : 0;

            if (countSpan) countSpan.textContent = `Showing ${investigations.length} of ${data.total || investigations.length} records`;

            if (investigations.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">No investigations match your query or filters.</td></tr>';
                return;
            }

            tbody.innerHTML = '';
            investigations.forEach(inv => {
                const tr = document.createElement('tr');
                tr.style.borderBottom = '1px solid #1e293b';
                tr.style.transition = 'background 0.15s ease';
                tr.onmouseenter = () => tr.style.background = 'rgba(255,255,255,0.02)';
                tr.onmouseleave = () => tr.style.background = 'transparent';

                const startDateStr = inv.start_time || inv.started_at;
                const date = startDateStr ? new Date(startDateStr).toLocaleString(undefined, {
                    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
                }) : 'Unknown';

                const severity = (inv.severity || 'Medium').toUpperCase();
                let severityBadge = 'badge-blue';
                if (severity === 'CRITICAL') severityBadge = 'badge-red';
                else if (severity === 'HIGH') severityBadge = 'badge-purple';
                else if (severity === 'LOW') severityBadge = 'badge-green';

                const status = (inv.status || 'completed').toLowerCase();
                let statusBadge = 'badge-blue';
                if (status === 'completed') statusBadge = 'badge-green';
                else if (status === 'pending_approval') statusBadge = 'badge-purple';
                else if (status === 'failed') statusBadge = 'badge-red';
                else if (status === 'running') statusBadge = 'badge-blue';

                const confScore = inv.confidence !== undefined ? Math.round(Number(inv.confidence) * 100) : 85;
                const confColor = confScore >= 80 ? '#34d399' : confScore >= 60 ? '#fbbf24' : '#f87171';

                const durationStr = inv.duration_ms ? `${(inv.duration_ms / 1000).toFixed(1)}s` : inv.status === 'running' ? 'Running...' : '--';
                const verdict = inv.verdict || inv.root_cause || 'Security Investigation';

                tr.innerHTML = `
                    <td style="padding: 12px 10px; font-family: monospace; font-size: 0.85rem; color: #93c5fd;">${inv.workflow_id}</td>
                    <td style="padding: 12px 10px; font-size: 0.85rem; color: #cbd5e1;">${date}</td>
                    <td style="padding: 12px 10px;"><span class="badge ${severityBadge}">${severity}</span></td>
                    <td style="padding: 12px 10px; max-width: 280px;">
                        <div style="font-weight: 600; color: #f8fafc; font-size: 0.88rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${verdict}">${verdict}</div>
                        <div style="font-size: 0.78rem; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${inv.root_cause || ''}</div>
                    </td>
                    <td style="padding: 12px 10px;">
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <div style="flex: 1; height: 6px; width: 50px; background: #1e293b; border-radius: 3px; overflow: hidden;">
                                <div style="width: ${confScore}%; height: 100%; background: ${confColor};"></div>
                            </div>
                            <span style="font-size: 0.8rem; font-weight: 600; color: ${confColor};">${confScore}%</span>
                        </div>
                    </td>
                    <td style="padding: 12px 10px; font-family: monospace; font-size: 0.82rem; color: #94a3b8;">${durationStr}</td>
                    <td style="padding: 12px 10px;"><span class="badge ${statusBadge}">${inv.status}</span></td>
                    <td style="padding: 12px 10px; text-align: right;">
                        <button class="btn btn-sm btn-primary" style="padding: 4px 10px; font-size: 0.8rem;" onclick="viewInvestigationDetail('${inv.workflow_id}')">&#128065; Inspect</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--accent-red);">Error loading history: ${res.status}</td></tr>`;
        }
    } catch (e) {
        console.error("Failed to load investigation history", e);
        document.getElementById('historyTableBody').innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--accent-red);">Error: ${e.message}</td></tr>`;
    }
}

function switchHistTab(tabName) {
    document.querySelectorAll('.hist-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.hist-tab-content').forEach(c => c.classList.remove('active'));
    
    const activeBtn = document.getElementById(`histTabBtn-${tabName}`);
    const activeContent = document.getElementById(`histTab-${tabName}`);
    if (activeBtn) activeBtn.classList.add('active');
    if (activeContent) activeContent.classList.add('active');

    if (tabName === 'graph' && _currentAttackGraph) {
        setTimeout(() => initAttackGraphCanvas(_currentAttackGraph), 50);
    }
}

function closeHistoryDetails() {
    const panel = document.getElementById('historyDetailsPanel');
    if (panel) panel.style.display = 'none';
    if (_graphAnimId) cancelAnimationFrame(_graphAnimId);
}

async function viewInvestigationDetail(investigationId) {
    const panel = document.getElementById('historyDetailsPanel');
    const title = document.getElementById('historyDetailsTitle');
    const subtitle = document.getElementById('historyDetailsSubtitle');
    const sevBadge = document.getElementById('historyDetailsSeverityBadge');
    const statusBadge = document.getElementById('historyDetailsStatusBadge');

    panel.style.display = 'block';
    title.textContent = `Investigation: ${investigationId}`;
    subtitle.textContent = `Fetching complete agent logs, reasoning chains, and attack graph...`;
    panel.scrollIntoView({ behavior: 'smooth' });

    try {
        const res = await apiFetch(`/api/v3/orchestrator/investigations/${investigationId}/details`);
        if (!res.ok) {
            subtitle.textContent = `Failed to fetch details: ${res.status}`;
            return;
        }

        const data = res.data;
        subtitle.textContent = `Started: ${data.started_at ? new Date(data.started_at).toLocaleString() : 'N/A'} | Duration: ${data.duration_ms ? (data.duration_ms/1000).toFixed(1)+'s' : 'N/A'}`;

        if (sevBadge) {
            sevBadge.textContent = (data.severity || 'HIGH').toUpperCase();
            sevBadge.className = `badge ${data.severity === 'Critical' ? 'badge-red' : 'badge-purple'}`;
        }
        if (statusBadge) {
            statusBadge.textContent = data.status.toUpperCase();
            statusBadge.className = `badge ${data.status === 'completed' ? 'badge-green' : 'badge-blue'}`;
        }

        // 1. Populate Overview Tab
        const synth = data.synthesis || {};
        document.getElementById('histOverviewVerdict').textContent = synth.verdict || data.severity + ' Incident';
        document.getElementById('histOverviewSummary').textContent = synth.executive_summary || data.root_cause || 'Comprehensive autonomous investigation executed across 5 phases.';

        const findingsUl = document.getElementById('histOverviewFindings');
        findingsUl.innerHTML = '';
        const findingsList = synth.key_findings || (data.attack_phases && data.attack_phases.length ? data.attack_phases : ['Root cause analysis generated and verified against telemetry.']);
        findingsList.forEach(f => {
            const li = document.createElement('li');
            li.textContent = typeof f === 'string' ? f : JSON.stringify(f);
            findingsUl.appendChild(li);
        });

        // Recommended / Executed Actions
        const actionsDiv = document.getElementById('histOverviewActionsList');
        actionsDiv.innerHTML = '';
        const actions = data.actions_recommended || [];
        if (actions.length === 0) {
            actionsDiv.innerHTML = '<div style="color: var(--text-muted); font-style: italic;">No explicit containment actions recorded.</div>';
        } else {
            actions.forEach(a => {
                const actCard = document.createElement('div');
                actCard.style.cssText = 'background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 10px 14px; border-left: 3px solid #34d399;';
                actCard.innerHTML = `
                    <div style="display: flex; justify-content: space-between; font-weight: 600; font-size: 0.88rem; color: #f8fafc;">
                        <span>${(a.action_type || 'CONTAINMENT').toUpperCase()}</span>
                        <span class="badge ${a.priority === 'Critical' ? 'badge-red' : 'badge-blue'}">${a.priority || 'High'}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">Target: <code style="color: #60a5fa;">${a.target || 'N/A'}</code> &mdash; ${a.description || ''}</div>
                `;
                actionsDiv.appendChild(actCard);
            });
        }

        // Audit Trail
        const auditDiv = document.getElementById('histOverviewAuditTrail');
        auditDiv.innerHTML = '';
        const auditList = data.audit_trail || [];
        if (auditList.length === 0) {
            auditDiv.innerHTML = '<div style="color: var(--text-muted); font-style: italic;">No automated or human actions logged in audit trail yet.</div>';
        } else {
            auditList.forEach(aud => {
                const audItem = document.createElement('div');
                audItem.style.cssText = 'padding: 6px 0; border-bottom: 1px solid #1f2937; display: flex; justify-content: space-between; font-size: 0.82rem;';
                audItem.innerHTML = `
                    <span><strong>${aud.action}</strong> by <em>${aud.actor}</em>: ${aud.details}</span>
                    <span style="color: var(--text-muted);">${aud.timestamp ? new Date(aud.timestamp).toLocaleTimeString() : ''}</span>
                `;
                auditDiv.appendChild(audItem);
            });
        }

        // 2. Populate Attack Graph
        _currentAttackGraph = data.attack_graph || { nodes: [], edges: [] };

        // 3. Populate Agent Reasoning & CoT Tab
        const reasoningContainer = document.getElementById('histAgentReasoningContainer');
        reasoningContainer.innerHTML = '';

        const reports = data.reports || {};
        const agentNames = [
            { key: 'task-triage', name: 'Triage Agent', role: 'Alert triage & entity extraction', icon: '&#9888;' },
            { key: 'task-evidence', name: 'Evidence Agent', role: 'Entity graph expansion & data collection', icon: '&#128269;' },
            { key: 'task-discovery', name: 'Discovery Agent', role: 'Network reachability & port scanning', icon: '&#128752;' },
            { key: 'task-compression', name: 'Compression Agent', role: '7-stage event noise reduction', icon: '&#9881;' },
            { key: 'task-rca', name: 'RCA Analyst Agent', role: 'Root cause analysis & CoT verification', icon: '&#128270;' },
            { key: 'task-response', name: 'Response Planner Agent', role: 'Action recommendation & RAG playbook retrieval', icon: '&#9889;' }
        ];

        agentNames.forEach((agentDef, idx) => {
            const report = reports[agentDef.key] || Object.values(reports).find(r => r.agent_name && r.agent_name.includes(agentDef.key.replace('task-', ''))) || null;
            
            const card = document.createElement('div');
            card.className = 'hist-agent-card';
            
            const isCompleted = report && report.status === 'completed';
            const statusColor = isCompleted ? '#34d399' : '#94a3b8';
            const findings = report ? (report.findings || {}) : {};

            let findingsHtml = '';
            if (report) {
                // Special rendering for RCA Chain of Thought
                if (findings.chain_of_thought_verification) {
                    findingsHtml += `
                        <div style="margin-bottom: 12px;">
                            <strong style="color: #a78bfa;">&#129504; Chain-of-Thought Verification (Self-Critique):</strong>
                            <div class="hist-cot-box">${findings.chain_of_thought_verification}</div>
                        </div>
                    `;
                }

                if (findings.root_cause) {
                    findingsHtml += `<div style="margin-bottom: 8px;"><strong>Root Cause:</strong> <span style="color: #f8fafc;">${findings.root_cause}</span></div>`;
                }

                if (findings.entities_identified && findings.entities_identified.length) {
                    findingsHtml += `
                        <div style="margin-bottom: 8px;">
                            <strong>Extracted &amp; Grounded Entities:</strong>
                            <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px;">
                                ${findings.entities_identified.map(e => `<span class="badge badge-blue">${e.type}:${e.id}</span>`).join('')}
                            </div>
                        </div>
                    `;
                }

                if (findings.compression_ratio) {
                    findingsHtml += `<div style="margin-bottom: 8px;"><strong>Compression Ratio:</strong> <span style="color: #60a5fa;">${findings.compression_ratio}</span> (${findings.original_events} &rarr; ${findings.compressed_events} events)</div>`;
                }

                // Generic JSON findings view
                findingsHtml += `
                    <details style="margin-top: 10px;">
                        <summary style="cursor: pointer; color: var(--text-muted); font-size: 0.8rem;">View Full Output Payload JSON</summary>
                        <pre class="code-input" style="font-size: 0.8rem; margin-top: 6px; max-height: 200px; overflow-y: auto;">${JSON.stringify(findings, null, 2)}</pre>
                    </details>
                `;
            } else {
                findingsHtml = '<div style="color: var(--text-muted); font-style: italic;">No execution report recorded for this agent in this investigation.</div>';
            }

            card.innerHTML = `
                <div class="hist-agent-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 1.1rem;">${agentDef.icon}</span>
                        <div>
                            <strong style="color: #f8fafc; font-size: 0.92rem;">${agentDef.name}</strong>
                            <span style="font-size: 0.75rem; color: #94a3b8; margin-left: 8px;">${agentDef.role}</span>
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        ${report && report.confidence !== undefined ? `<span style="font-size: 0.75rem; font-weight: 600; color: #34d399;">Conf: ${Math.round(report.confidence * 100)}%</span>` : ''}
                        ${report && report.duration_ms ? `<span style="font-size: 0.75rem; color: #94a3b8; font-family: monospace;">${report.duration_ms}ms</span>` : ''}
                        <span class="badge" style="background: rgba(52, 211, 153, 0.1); color: ${statusColor};">${report ? report.status : 'SKIPPED'}</span>
                        <span style="font-size: 0.8rem; color: #94a3b8;">&#9662;</span>
                    </div>
                </div>
                <div class="hist-agent-body" style="display: ${idx === 4 || idx === 0 ? 'block' : 'none'};">
                    ${findingsHtml}
                </div>
            `;
            reasoningContainer.appendChild(card);
        });

        // Blackboard Messages
        const blackboard = data.blackboard_messages || [];
        if (blackboard.length > 0) {
            const bbCard = document.createElement('div');
            bbCard.className = 'hist-agent-card';
            bbCard.style.borderLeft = '3px solid #f59e0b';
            bbCard.innerHTML = `
                <div class="hist-agent-header" style="background: #1e293b;" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 1.1rem;">&#128227;</span>
                        <strong style="color: #f59e0b;">Inter-Agent Message Bus (${blackboard.length} messages)</strong>
                    </div>
                    <span style="font-size: 0.8rem; color: #94a3b8;">&#9662;</span>
                </div>
                <div class="hist-agent-body" style="display: block;">
                    ${blackboard.map(msg => `
                        <div class="hist-msg-bubble">
                            <div style="display: flex; justify-content: space-between; font-weight: bold; margin-bottom: 4px; color: #60a5fa;">
                                <span>[${msg.msg_type}] ${msg.source_agent} &rarr; ${msg.target_agent}</span>
                                <span style="font-size: 0.75rem; color: ${msg.resolved ? '#34d399' : '#f87171'};">${msg.resolved ? 'RESOLVED' : 'PENDING'}</span>
                            </div>
                            <div style="color: #cbd5e1; font-size: 0.85rem;">Payload: <code>${JSON.stringify(msg.payload || {})}</code></div>
                        </div>
                    `).join('')}
                </div>
            `;
            reasoningContainer.appendChild(bbCard);
        }

        // 4. Populate Attack Chain Timeline Tab
        const timelineDiv = document.getElementById('histAttackPhasesTimeline');
        timelineDiv.innerHTML = '';
        const phases = data.attack_phases || (synth.key_findings ? synth.key_findings : ['Initial access detected', 'Payload execution confirmed', 'Containment recommended']);
        phases.forEach((ph, i) => {
            const phItem = document.createElement('div');
            phItem.className = 'attack-phase-item';
            phItem.innerHTML = `
                <div style="font-weight: bold; color: #f8fafc; font-size: 0.92rem; margin-bottom: 4px;">Phase ${i + 1}: ${typeof ph === 'string' ? ph : ph.title || JSON.stringify(ph)}</div>
                <div style="font-size: 0.82rem; color: #94a3b8;">Chronological phase identified during multi-agent causal analysis</div>
            `;
            timelineDiv.appendChild(phItem);
        });

        // Switch to Overview tab by default
        switchHistTab('overview');

    } catch (e) {
        console.error("Error inspecting investigation details", e);
        subtitle.textContent = `Error inspecting investigation: ${e.message}`;
    }
}

// --- Interactive Canvas Attack Graph Renderer ---
function initAttackGraphCanvas(graphData) {
    const canvas = document.getElementById('attackGraphCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.clientWidth || 900;
    const height = canvas.clientHeight || 420;
    canvas.width = width;
    canvas.height = height;

    const rawNodes = graphData.nodes || [];
    const rawEdges = graphData.edges || [];

    if (rawNodes.length === 0) {
        ctx.clearRect(0, 0, width, height);
        ctx.fillStyle = '#64748b';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No entities or attack graph available for this investigation.', width / 2, height / 2);
        return;
    }

    // Position nodes circularly or around center host
    const nodes = [];
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) * 0.35;

    rawNodes.forEach((rn, i) => {
        const angle = (i / rawNodes.length) * 2 * Math.PI - Math.PI / 2;
        const isCenter = rn.type === 'host' && i === 0;
        const x = isCenter ? cx : cx + radius * Math.cos(angle);
        const y = isCenter ? cy : cy + radius * Math.sin(angle);

        let color = '#3b82f6'; // default blue
        if (rn.compromised || (rn.risk_score && rn.risk_score >= 0.7) || rn.type === 'malware') color = '#ef4444';
        else if (rn.type === 'user') color = '#10b981';
        else if (rn.type === 'process' || rn.type === 'file') color = '#f59e0b';
        else if (rn.type === 'ip') color = '#38bdf8';

        nodes.push({
            id: rn.id,
            name: rn.name || rn.id,
            type: rn.type || 'entity',
            risk_score: rn.risk_score || 0.5,
            x: x,
            y: y,
            radius: isCenter ? 26 : 20,
            color: color,
            compromised: rn.compromised
        });
    });

    let hoveredNode = null;
    const tooltip = document.getElementById('graphNodeTooltip');

    function draw() {
        ctx.clearRect(0, 0, width, height);

        // Draw grid background lines
        ctx.strokeStyle = '#1e293b';
        ctx.lineWidth = 1;
        for (let x = 0; x < width; x += 40) {
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
        }
        for (let y = 0; y < height; y += 40) {
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
        }

        // Draw Edges
        rawEdges.forEach(e => {
            const src = nodes.find(n => n.id === e.source || n.name === e.source);
            const tgt = nodes.find(n => n.id === e.target || n.name === e.target);
            if (src && tgt) {
                // Line
                ctx.beginPath();
                ctx.moveTo(src.x, src.y);
                ctx.lineTo(tgt.x, tgt.y);
                ctx.strokeStyle = '#475569';
                ctx.lineWidth = 2;
                ctx.stroke();

                // Arrow
                const headlen = 10;
                const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
                const midX = (src.x + tgt.x) / 2;
                const midY = (src.y + tgt.y) / 2;

                ctx.beginPath();
                ctx.moveTo(midX, midY);
                ctx.lineTo(midX - headlen * Math.cos(angle - Math.PI / 6), midY - headlen * Math.sin(angle - Math.PI / 6));
                ctx.moveTo(midX, midY);
                ctx.lineTo(midX - headlen * Math.cos(angle + Math.PI / 6), midY - headlen * Math.sin(angle + Math.PI / 6));
                ctx.strokeStyle = '#94a3b8';
                ctx.stroke();

                // Label
                if (e.label) {
                    ctx.fillStyle = '#64748b';
                    ctx.font = '10px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.fillText(e.label, midX, midY - 6);
                }
            }
        });

        // Draw Nodes
        nodes.forEach(n => {
            // Glow if compromised
            if (n.compromised) {
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius + 6, 0, 2 * Math.PI);
                ctx.fillStyle = 'rgba(239, 68, 68, 0.25)';
                ctx.fill();
            }

            // Node Circle
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
            ctx.fillStyle = n.color;
            ctx.fill();
            ctx.strokeStyle = n === hoveredNode ? '#ffffff' : '#0f172a';
            ctx.lineWidth = n === hoveredNode ? 3 : 2;
            ctx.stroke();

            // Node Icon / Short Text
            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 10px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            const label = n.type ? n.type.toUpperCase().slice(0, 4) : 'ENT';
            ctx.fillText(label, n.x, n.y);

            // Node Name below
            ctx.fillStyle = '#f8fafc';
            ctx.font = '11px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillText(n.name.length > 16 ? n.name.slice(0, 14) + '...' : n.name, n.x, n.y + n.radius + 4);
        });
    }

    draw();

    // Mouse Interaction
    canvas.onmousemove = (evt) => {
        const rect = canvas.getBoundingClientRect();
        const mx = evt.clientX - rect.left;
        const my = evt.clientY - rect.top;

        hoveredNode = nodes.find(n => {
            const dx = mx - n.x;
            const dy = my - n.y;
            return Math.sqrt(dx * dx + dy * dy) <= n.radius + 4;
        });

        if (hoveredNode && tooltip) {
            tooltip.style.display = 'block';
            tooltip.style.left = `${mx + 15}px`;
            tooltip.style.top = `${my + 15}px`;
            tooltip.innerHTML = `
                <div style="font-weight: bold; color: ${hoveredNode.color}; margin-bottom: 2px;">${hoveredNode.name}</div>
                <div style="color: #94a3b8; font-size: 0.75rem;">Type: <strong>${hoveredNode.type}</strong></div>
                <div style="color: #94a3b8; font-size: 0.75rem;">Risk Score: <strong>${hoveredNode.risk_score}</strong></div>
                <div style="color: ${hoveredNode.compromised ? '#ef4444' : '#34d399'}; font-size: 0.75rem; margin-top: 4px;">
                    ${hoveredNode.compromised ? '&#9888; Suspected Compromised' : '&#10003; Monitored'}
                </div>
            `;
            canvas.style.cursor = 'pointer';
        } else {
            if (tooltip) tooltip.style.display = 'none';
            canvas.style.cursor = 'default';
        }

        draw();
    };

    canvas.onmouseleave = () => {
        hoveredNode = null;
        if (tooltip) tooltip.style.display = 'none';
        draw();
    };
}

function resetAttackGraphView() {
    if (_currentAttackGraph) {
        initAttackGraphCanvas(_currentAttackGraph);
    }
}

/* ============================================================
   Interactive Phase Inspector Modal Implementation
   ============================================================ */

let _activeInspectorReport = null;
let _activeInspectorRawLogs = [];

function openPhaseInspector(agentKey) {
    const key = normalizeAgentKey(agentKey || '');
    const report = (window.currentPhaseReports && window.currentPhaseReports[key]) || null;
    
    const modal = document.getElementById('phaseInspectorModal');
    if (!modal) return;

    if (!report) {
        alert(`No forensic artifacts recorded yet for phase: ${formatAgentName(key)}`);
        return;
    }

    _activeInspectorReport = report;
    const findings = report.findings || {};
    _activeInspectorRawLogs = findings.raw_events || [];

    // Header Setup
    const titleEl = document.getElementById('phaseModalTitle');
    const badgeEl = document.getElementById('phaseModalBadge');
    const agentTagEl = document.getElementById('phaseModalAgentTag');
    const durationEl = document.getElementById('phaseModalDuration');

    const meta = getAgentMeta(key);
    if (titleEl) titleEl.textContent = `${meta.label} — Phase Audit & Artifacts`;
    if (badgeEl) {
        const conf = report.confidence || 0;
        badgeEl.textContent = `${(conf * 100).toFixed(0)}% Confidence`;
        badgeEl.className = `badge ${conf >= 0.8 ? 'confidence-high' : conf >= 0.5 ? 'confidence-medium' : 'confidence-low'}`;
    }
    if (agentTagEl) agentTagEl.textContent = key;
    if (durationEl) durationEl.textContent = `${report.duration_ms || 0}ms execution`;

    // Render Tabs & Content based on phase type
    const tabsContainer = document.getElementById('phaseModalTabs');
    const bodyContainer = document.getElementById('phaseModalBody');
    if (!tabsContainer || !bodyContainer) return;

    tabsContainer.innerHTML = '';
    bodyContainer.innerHTML = '';

    if (key === 'compression_agent') {
        renderCompressionInspectorView(report, tabsContainer, bodyContainer);
    } else if (key === 'evidence_agent') {
        renderEvidenceInspectorView(report, tabsContainer, bodyContainer);
    } else if (key === 'discovery_agent') {
        renderDiscoveryInspectorView(report, tabsContainer, bodyContainer);
    } else if (key === 'triage_agent') {
        renderTriageInspectorView(report, tabsContainer, bodyContainer);
    } else if (key === 'rca_agent') {
        renderRCAInspectorView(report, tabsContainer, bodyContainer);
    } else if (key === 'response_agent') {
        renderResponseInspectorView(report, tabsContainer, bodyContainer);
    } else {
        renderGenericInspectorView(report, tabsContainer, bodyContainer);
    }

    modal.style.display = 'flex';
}

function closePhaseInspector() {
    const modal = document.getElementById('phaseInspectorModal');
    if (modal) modal.style.display = 'none';
    _activeInspectorReport = null;
    _activeInspectorRawLogs = [];
}

function switchPhaseModalTab(tabId) {
    document.querySelectorAll('.phase-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.phase-modal-tab-pane').forEach(pane => pane.style.display = 'none');

    const activeBtn = document.getElementById(`phaseTabBtn-${tabId}`);
    const activePane = document.getElementById(`phaseTabPane-${tabId}`);
    if (activeBtn) activeBtn.classList.add('active');
    if (activePane) activePane.style.display = 'block';

    if (tabId === 'subgraph' && _activeInspectorReport) {
        setTimeout(() => initCompressionSubgraphCanvas(_activeInspectorReport), 60);
    }
}

// ------------------------------------------------------------
// 1. Compression Agent Inspector (7-Stage Funnel & Raw Logs)
// ------------------------------------------------------------
function renderCompressionInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const origCount = findings.original_events || (_activeInspectorRawLogs ? _activeInspectorRawLogs.length : 0);
    const compCount = findings.compressed_events || (findings.timeline ? findings.timeline.length : 0);
    const timeline = findings.timeline || [];
    const timelineCount = timeline.length;
    const ratio = findings.compression_ratio || (origCount > 0 && compCount > 0 ? `${(origCount / compCount).toFixed(1)}x` : 'N/A');
    const stages = findings.stages || [];
    const attackGraph = findings.attack_graph || {};

    // Tabs
    tabs.innerHTML = `
        <button class="phase-tab-btn active" id="phaseTabBtn-funnel" onclick="switchPhaseModalTab('funnel')">🗜️ 7-Stage Funnel Breakdown</button>
        <button class="phase-tab-btn" id="phaseTabBtn-rawlogs" onclick="switchPhaseModalTab('rawlogs')">📥 Raw Ingested Logs (${origCount})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-filtered" onclick="switchPhaseModalTab('filtered')">🛡️ Filtered Security Events (${compCount})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-milestones" onclick="switchPhaseModalTab('milestones')">📤 Synthesized Milestones (${timelineCount})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-subgraph" onclick="switchPhaseModalTab('subgraph')">🕸️ Interactive Attack Graph</button>
    `;

    const skillsUsed = (findings.skills_used && findings.skills_used.length > 0) ? findings.skills_used : ["noise-filter", "temporal-clustering", "attack-subgraph-filter", "behavioral-anomaly-filter", "semantic-summarizer"];

    const kpiHtml = `
        <div class="phase-kpi-grid">
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Raw Telemetry Ingested</span>
                <span class="phase-kpi-val" style="color: #60a5fa;">${origCount}</span>
                <span class="phase-kpi-sub">Across Auditd, Suricata, Auth, Wazuh</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Filtered High-Risk Events</span>
                <span class="phase-kpi-val" style="color: #34d399;">${compCount}</span>
                <span class="phase-kpi-sub">${timelineCount} synthesized timeline steps</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Noise Reduction Ratio</span>
                <span class="phase-kpi-val" style="color: #fbbf24;">${ratio}</span>
                <span class="phase-kpi-sub">${origCount > compCount ? `${origCount - compCount} noise events dropped` : 'Baseline'}</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Skills Deployed</span>
                <span class="phase-kpi-val" style="color: #a78bfa;">${skillsUsed.length}</span>
                <span class="phase-kpi-sub">Agentic reduction stages</span>
            </div>
        </div>
    `;

    const skillsBannerHtml = `
        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Agentic Compression Skills Used</span>
                <span class="badge" style="background:rgba(167,139,250,0.15); color:#a78bfa; font-size:0.75rem;">${skillsUsed.length} Reduction Stages</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">🗜️ ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>
    `;

    // Stage Funnel Rows
    let funnelRows = '';
    stages.forEach((stg, idx) => {
        const inC = stg.input || 0;
        const outC = stg.output || 0;
        const pct = origCount > 0 ? Math.round((outC / origCount) * 100) : 100;
        funnelRows += `
            <tr>
                <td><strong style="color:#f8fafc;">${idx + 1}. ${escapeHtml(stg.name)}</strong></td>
                <td><span class="phase-agent-tag">${escapeHtml(stg.skill || '')}</span></td>
                <td>${inC} events</td>
                <td><strong style="color:#34d399;">${outC} events</strong></td>
                <td><span class="badge" style="background: rgba(248,113,113,0.15); color: #f87171;">-${stg.reduction}</span></td>
                <td style="width: 25%;">
                    <div class="funnel-progress-bar">
                        <div class="funnel-progress-fill" style="width: ${pct}%;"></div>
                    </div>
                </td>
            </tr>
        `;
    });

    // Raw Logs Table
    let rawLogRows = '';
    (_activeInspectorRawLogs || []).forEach((log, i) => {
        const src = (log.source || 'general').toLowerCase();
        let srcPill = `<span class="source-pill source-pill-general">${src}</span>`;
        if (src.includes('audit')) srcPill = `<span class="source-pill source-pill-audit">Auditd</span>`;
        else if (src.includes('suricata') || src.includes('ids')) srcPill = `<span class="source-pill source-pill-suricata">Suricata</span>`;
        else if (src.includes('auth') || src.includes('syslog')) srcPill = `<span class="source-pill source-pill-auth">Auth</span>`;
        else if (src.includes('wazuh')) srcPill = `<span class="source-pill source-pill-wazuh">Wazuh</span>`;

        const risk = log.risk_score || 0.1;
        const riskClass = risk >= 0.8 ? 'risk-high' : risk >= 0.5 ? 'risk-med' : 'risk-low';

        rawLogRows += `
            <tr data-source="${src}" class="raw-log-row">
                <td style="color:#64748b; width:40px;">${i + 1}</td>
                <td style="color:#94a3b8; white-space:nowrap;">${escapeHtml(log.timestamp || '')}</td>
                <td>${srcPill}</td>
                <td><strong style="color:#e2e8f0;">${escapeHtml(log.entity || '')}</strong></td>
                <td style="color:#cbd5e1;">${escapeHtml(log.action || log.event_type || '')}</td>
                <td><span class="risk-pill ${riskClass}">${risk}</span></td>
            </tr>
        `;
    });

    // Filtered Events (150 High-Risk Retained Events)
    const filteredEvents = findings.filtered_events || [];
    let filteredEventRows = '';
    filteredEvents.forEach((ev, i) => {
        const risk = ev.risk_score !== undefined ? ev.risk_score : 0.5;
        const riskClass = risk >= 0.8 ? 'risk-high' : risk >= 0.5 ? 'risk-med' : 'risk-low';
        const mitre = ev.mitre_technique_id ? `<span class="mitre-badge">${ev.mitre_technique_id} - ${escapeHtml(ev.mitre_technique_name || ev.mitre_tactic || '')}</span>` : '<span style="color:#64748b; font-size:0.75rem;">—</span>';
        const rawCountBadge = ev.raw_count > 1 ? `<span class="badge" style="background:#1e293b; color:#38bdf8; font-size:0.72rem;">${ev.raw_count} raw logs</span>` : `<span style="color:#64748b; font-size:0.75rem;">1 log</span>`;

        filteredEventRows += `
            <tr class="filtered-event-row">
                <td style="color:#64748b; width:40px;">${i + 1}</td>
                <td style="color:#94a3b8; white-space:nowrap; font-family:var(--mono); font-size:0.8rem;">${escapeHtml(ev.timestamp || '')}</td>
                <td><strong style="color:#e2e8f0;">${escapeHtml(ev.entity || '')}</strong></td>
                <td style="color:#cbd5e1;">${escapeHtml(ev.action || ev.event_type || '')}</td>
                <td>${mitre}</td>
                <td>${rawCountBadge}</td>
                <td><span class="risk-pill ${riskClass}">${risk}</span></td>
            </tr>
        `;
    });

    // Compressed Milestones Cards
    let milestonesHtml = '';
    (timeline || []).forEach((m, i) => {
        const risk = m.risk_score || 0.5;
        const riskClass = risk >= 0.8 ? 'risk-high' : risk >= 0.5 ? 'risk-med' : 'risk-low';
        const mitre = m.mitre_technique_id ? `<span class="mitre-badge">${m.mitre_technique_id} - ${escapeHtml(m.mitre_technique_name || m.mitre_tactic || '')}</span>` : '';

        milestonesHtml += `
            <div class="milestone-card">
                <div class="milestone-card-header">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="color:#64748b; font-size:0.75rem; font-family:var(--mono);">#${i + 1}</span>
                        <span style="color:#38bdf8; font-size:0.8rem; font-family:var(--mono);">${escapeHtml(m.timestamp || '')}</span>
                        <strong style="color:#f8fafc; font-size:0.9rem;">${escapeHtml(m.entity || '')}</strong>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        ${mitre}
                        <span class="risk-pill ${riskClass}">Risk: ${risk}</span>
                    </div>
                </div>
                <div style="font-size:0.85rem; color:#cbd5e1; line-height:1.4;">
                    ${escapeHtml(m.action || m.event_type || '')}
                </div>
            </div>
        `;
    });

    // Subgraph categories
    let subgraphHtml = '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px;">';
    for (const [cat, items] of Object.entries(attackGraph || {})) {
        subgraphHtml += `
            <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:12px;">
                <h4 style="margin-top:0; color:#38bdf8; text-transform:uppercase; font-size:0.78rem; letter-spacing:0.05em;">${escapeHtml(cat.replace(/_/g, ' '))}</h4>
                <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:8px;">
                    ${(Array.isArray(items) ? items : []).map(it => `<span class="artifact-tag" style="background:#1e293b; color:#f8fafc;">${escapeHtml(it)}</span>`).join('')}
                </div>
            </div>
        `;
    }
    subgraphHtml += '</div>';

    body.innerHTML = `
        ${kpiHtml}
        ${skillsBannerHtml}

        <!-- Tab 1: Funnel -->
        <div class="phase-modal-tab-pane" id="phaseTabPane-funnel" style="display: block;">
            <h3 style="margin-bottom:12px; font-size:1rem; color:#f8fafc;">7-Stage Agentic Reduction Pipeline</h3>
            <table class="funnel-table">
                <thead>
                    <tr>
                        <th>Stage Name</th>
                        <th>Applied Skill</th>
                        <th>Input Events</th>
                        <th>Output Events</th>
                        <th>Reduction</th>
                        <th>Retention Funnel</th>
                    </tr>
                </thead>
                <tbody>
                    ${funnelRows || '<tr><td colspan="6" style="text-align:center; color:#64748b;">No stage metrics recorded</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- Tab 2: Raw Logs -->
        <div class="phase-modal-tab-pane" id="phaseTabPane-rawlogs" style="display: none;">
            <div class="log-viewer-search-bar">
                <input type="text" class="log-search-input" id="rawLogSearchInput" placeholder="🔍 Search by entity, process name, command line, or timestamp..." oninput="filterRawLogsInspector()">
                <select class="log-source-filter" id="rawLogSourceFilter" onchange="filterRawLogsInspector()">
                    <option value="all">All Sources (${origCount})</option>
                    <option value="audit">Auditd</option>
                    <option value="suricata">Suricata</option>
                    <option value="auth">Auth / Syslog</option>
                    <option value="wazuh">Wazuh SIEM</option>
                </select>
            </div>
            <div class="log-table-container">
                <table class="log-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Timestamp</th>
                            <th>Source</th>
                            <th>Entity</th>
                            <th>Action / Command</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody id="rawLogTableBody">
                        ${rawLogRows || '<tr><td colspan="6" style="text-align:center; padding:30px; color:#64748b;">No raw logs available in report findings</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 3: Filtered Security Events (150) -->
        <div class="phase-modal-tab-pane" id="phaseTabPane-filtered" style="display: none;">
            <div class="log-viewer-search-bar">
                <input type="text" class="log-search-input" id="filteredLogSearchInput" placeholder="🔍 Search by entity, action, MITRE tactic, or risk..." oninput="filterFilteredEventsInspector()">
            </div>
            <div class="log-table-container">
                <table class="log-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Timestamp</th>
                            <th>Entity / Host</th>
                            <th>Action / Syscall</th>
                            <th>MITRE ATT&CK</th>
                            <th>Rollup Count</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody id="filteredLogTableBody">
                        ${filteredEventRows || '<tr><td colspan="7" style="text-align:center; padding:30px; color:#64748b;">No filtered events recorded</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 4: Milestones -->
        <div class="phase-modal-tab-pane" id="phaseTabPane-milestones" style="display: none;">
            <h3 style="margin-bottom:12px; font-size:1rem; color:#f8fafc;">Synthesized Attack Milestones (${timelineCount})</h3>
            <div style="max-height: 520px; overflow-y: auto;">
                ${milestonesHtml || '<div style="color:#64748b; text-align:center; padding:30px;">No milestones generated</div>'}
            </div>
        </div>

        <!-- Tab 5: Subgraph -->
        <div class="phase-modal-tab-pane" id="phaseTabPane-subgraph" style="display: none;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 style="margin:0; font-size:1rem; color:#f8fafc;">Interactive Causal Attack Graph</h3>
                <button onclick="initCompressionSubgraphCanvas(_activeInspectorReport)" style="background:#1e293b; border:1px solid #475569; color:#94a3b8; padding:3px 10px; border-radius:4px; font-size:0.75rem; cursor:pointer; font-weight:600;">🔄 Reset Layout</button>
            </div>

            <div class="subgraph-canvas-container" id="subgraphCanvasContainer">
                <canvas id="compressionSubgraphCanvas"></canvas>
                <div id="subgraphCanvasTooltip" class="subgraph-canvas-tooltip"></div>
                <div class="subgraph-canvas-legend">
                    <span><span style="color:#ef4444; font-weight:bold;">●</span> Malicious File / Ransomware</span>
                    <span><span style="color:#38bdf8; font-weight:bold;">●</span> Threat Actor / Remote C2</span>
                    <span><span style="color:#a78bfa; font-weight:bold;">●</span> Compromised Host / Network</span>
                    <span><span style="color:#10b981; font-weight:bold;">●</span> SIEM / Monitoring Service</span>
                </div>
            </div>

            <h4 style="margin-top:16px; margin-bottom:10px; font-size:0.85rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em;">Categorized Attack Subgraph Elements</h4>
            ${subgraphHtml}
        </div>
    `;
}

// Interactive Canvas Attack Subgraph Renderer
function initCompressionSubgraphCanvas(report) {
    if (!report || !report.findings) return;
    const canvas = document.getElementById('compressionSubgraphCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const container = document.getElementById('subgraphCanvasContainer');
    const width = container ? container.clientWidth : 850;
    const height = 380;
    canvas.width = width;
    canvas.height = height;

    const attackGraph = report.findings.attack_graph || {};
    const timeline = report.findings.timeline || [];

    // Collect unique entity nodes
    const nodeMap = new Map();
    const addNode = (name, type, risk = 0.5) => {
        if (!name || name === 'unknown') return;
        if (!nodeMap.has(name)) {
            let nType = type;
            let nRisk = risk;
            let icon = '📦';
            let color = '#94a3b8';

            const lower = name.toLowerCase();
            if (lower.includes('donotcry') || lower.includes('ransomware') || lower.includes('malware') || lower.includes('.sh') || lower.includes('.elf')) {
                nType = 'malware';
                nRisk = 0.95;
                icon = '💀';
                color = '#ef4444';
            } else if (lower.includes('192.42.') || lower.includes('c2') || /^\d+\.\d+\.\d+\.\d+$/.test(name)) {
                nType = 'c2_ip';
                nRisk = 0.90;
                icon = '🌐';
                color = '#38bdf8';
            } else if (lower.includes('linuxshare') || lower.includes('host') || lower.includes('srv') || lower.includes('share')) {
                nType = 'host';
                nRisk = 0.80;
                icon = '🖥️';
                color = '#a78bfa';
            } else if (lower.includes('inetfw') || lower.includes('fw') || lower.includes('firewall') || lower.includes('router')) {
                nType = 'firewall';
                nRisk = 0.70;
                icon = '🛡️';
                color = '#f59e0b';
            } else if (lower.includes('wazuh') || lower.includes('suricata') || lower.includes('siem') || lower.includes('audit')) {
                nType = 'security_tool';
                nRisk = 0.20;
                icon = '📡';
                color = '#10b981';
            }

            nodeMap.set(name, { id: name, name, type: nType, risk_score: nRisk, icon, color });
        }
    };

    // Populate nodes from attack categories
    for (const [cat, items] of Object.entries(attackGraph)) {
        (Array.isArray(items) ? items : []).forEach(it => addNode(it, cat));
    }
    // Also include entities from timeline
    timeline.forEach(tl => {
        if (tl.entity) addNode(tl.entity, 'timeline_entity', tl.risk_score || 0.5);
    });

    const nodesList = Array.from(nodeMap.values());
    if (nodesList.length === 0) {
        ctx.fillStyle = '#64748b';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No connected attack nodes discovered in this subgraph.', width / 2, height / 2);
        return;
    }

    // Position nodes radially around center
    const cx = width / 2;
    const cy = height / 2;
    const radiusX = Math.min(width * 0.38, 280);
    const radiusY = Math.min(height * 0.36, 120);

    nodesList.forEach((n, idx) => {
        const angle = (idx / nodesList.length) * 2 * Math.PI - Math.PI / 2;
        n.x = cx + radiusX * Math.cos(angle);
        n.y = cy + radiusY * Math.sin(angle);
        n.radius = 24;
    });

    // Build directed attack edges based on attackGraph categories & flow
    const edges = [];
    const ipNode = nodesList.find(n => n.type === 'c2_ip');
    const malwareNode = nodesList.find(n => n.type === 'malware');
    const hostNode = nodesList.find(n => n.type === 'host');
    const fwNode = nodesList.find(n => n.type === 'firewall');
    const siemNode = nodesList.find(n => n.type === 'security_tool');

    if (ipNode && malwareNode) {
        edges.push({ source: ipNode, target: malwareNode, label: 'C2 Ingress', color: '#f87171' });
    }
    if (ipNode && fwNode) {
        edges.push({ source: ipNode, target: fwNode, label: 'Exfiltration Attempt', color: '#38bdf8' });
    }
    if (fwNode && hostNode) {
        edges.push({ source: fwNode, target: hostNode, label: 'Lateral Movement', color: '#fbbf24' });
    }
    if (malwareNode && hostNode) {
        edges.push({ source: malwareNode, target: hostNode, label: 'Encryption Execution', color: '#ef4444' });
    }
    if (siemNode && hostNode) {
        edges.push({ source: siemNode, target: hostNode, label: 'Telemetry Monitoring', color: '#34d399' });
    }

    // If few edges, connect remaining nodes into a structured ring
    if (edges.length === 0 && nodesList.length > 1) {
        for (let i = 0; i < nodesList.length - 1; i++) {
            edges.push({ source: nodesList[i], target: nodesList[i + 1], label: 'Correlated Link', color: '#64748b' });
        }
    }

    const tooltip = document.getElementById('subgraphCanvasTooltip');
    let hoveredNode = null;

    function renderCanvas() {
        ctx.clearRect(0, 0, width, height);

        // Background subtle grid
        ctx.strokeStyle = 'rgba(51, 65, 85, 0.25)';
        ctx.lineWidth = 1;
        for (let x = 0; x < width; x += 30) {
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
        }
        for (let y = 0; y < height; y += 30) {
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
        }

        // Draw Edges with arrowheads & labels
        edges.forEach(e => {
            const isHovered = hoveredNode && (hoveredNode === e.source || hoveredNode === e.target);
            ctx.beginPath();
            ctx.moveTo(e.source.x, e.source.y);
            ctx.lineTo(e.target.x, e.target.y);
            ctx.strokeStyle = isHovered ? '#f8fafc' : (e.color || '#475569');
            ctx.lineWidth = isHovered ? 3 : 2;
            ctx.stroke();

            // Arrow head
            const angle = Math.atan2(e.target.y - e.source.y, e.target.x - e.source.x);
            const midX = (e.source.x + e.target.x) / 2;
            const midY = (e.source.y + e.target.y) / 2;
            const headlen = 8;
            ctx.beginPath();
            ctx.moveTo(midX, midY);
            ctx.lineTo(midX - headlen * Math.cos(angle - Math.PI / 6), midY - headlen * Math.sin(angle - Math.PI / 6));
            ctx.lineTo(midX - headlen * Math.cos(angle + Math.PI / 6), midY - headlen * Math.sin(angle + Math.PI / 6));
            ctx.fillStyle = isHovered ? '#f8fafc' : (e.color || '#475569');
            ctx.fill();

            // Edge label
            if (e.label) {
                ctx.fillStyle = isHovered ? '#38bdf8' : '#94a3b8';
                ctx.font = '10px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(e.label, midX, midY - 6);
            }
        });

        // Draw Nodes
        nodesList.forEach(n => {
            const isHovered = hoveredNode === n;

            // Outer pulse glow for high risk
            if (n.risk_score >= 0.8) {
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius + 6, 0, 2 * Math.PI);
                ctx.fillStyle = `${n.color}22`;
                ctx.fill();
            }

            // Node Circle
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
            ctx.fillStyle = '#0f172a';
            ctx.fill();
            ctx.strokeStyle = isHovered ? '#ffffff' : n.color;
            ctx.lineWidth = isHovered ? 3 : 2;
            ctx.stroke();

            // Icon & Name
            ctx.font = '14px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(n.icon, n.x, n.y);

            // Label below node
            ctx.font = isHovered ? 'bold 11px sans-serif' : '11px sans-serif';
            ctx.fillStyle = isHovered ? '#f8fafc' : '#cbd5e1';
            ctx.textBaseline = 'top';
            ctx.fillText(n.name, n.x, n.y + n.radius + 5);
        });
    }

    renderCanvas();

    // Mouse movement listener for hover effect & tooltip
    canvas.onmousemove = (evt) => {
        const rect = canvas.getBoundingClientRect();
        const mx = evt.clientX - rect.left;
        const my = evt.clientY - rect.top;

        let found = null;
        for (const n of nodesList) {
            const dist = Math.hypot(n.x - mx, n.y - my);
            if (dist <= n.radius) {
                found = n;
                break;
            }
        }

        if (found !== hoveredNode) {
            hoveredNode = found;
            renderCanvas();

            if (hoveredNode && tooltip) {
                tooltip.style.display = 'block';
                tooltip.style.left = `${mx + 15}px`;
                tooltip.style.top = `${my - 20}px`;
                tooltip.innerHTML = `
                    <div style="font-weight:bold; color:${hoveredNode.color}; margin-bottom:2px;">${hoveredNode.icon} ${escapeHtml(hoveredNode.name)}</div>
                    <div style="color:#94a3b8; font-size:0.7rem;">Type: ${hoveredNode.type}</div>
                    <div style="color:#f87171; font-size:0.7rem;">Risk Score: ${(hoveredNode.risk_score * 100).toFixed(0)}%</div>
                `;
            } else if (tooltip) {
                tooltip.style.display = 'none';
            }
        }
    };

    canvas.onmouseleave = () => {
        if (hoveredNode) {
            hoveredNode = null;
            renderCanvas();
        }
        if (tooltip) tooltip.style.display = 'none';
    };
}

function filterRawLogsInspector() {
    const q = (document.getElementById('rawLogSearchInput')?.value || '').toLowerCase();
    const srcFilter = (document.getElementById('rawLogSourceFilter')?.value || 'all').toLowerCase();

    document.querySelectorAll('.raw-log-row').forEach(row => {
        const rowSrc = (row.dataset.source || '').toLowerCase();
        const text = row.innerText.toLowerCase();
        const matchesQuery = !q || text.includes(q);
        const matchesSrc = srcFilter === 'all' || rowSrc.includes(srcFilter);

        row.style.display = matchesQuery && matchesSrc ? '' : 'none';
    });
}

function filterFilteredEventsInspector() {
    const q = (document.getElementById('filteredLogSearchInput')?.value || '').toLowerCase();

    document.querySelectorAll('.filtered-event-row').forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = !q || text.includes(q) ? '' : 'none';
    });
}

// ------------------------------------------------------------
// 2. Discovery Agent Inspector (Hosts, Ports, Reachability)
// ------------------------------------------------------------
function renderDiscoveryInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const hosts = findings.hosts || [];
    const scanned = findings.targets_scanned !== undefined ? findings.targets_scanned : hosts.length;
    const reachable = hosts.filter(h => h.status === 'alive' || h.status === 'reachable').length;
    const unreachable = hosts.filter(h => h.status === 'unreachable').length;
    const unknown = scanned - reachable - unreachable;
    const skillsUsed = (findings.skills_used && findings.skills_used.length > 0) ? findings.skills_used : ["port-scanner", "service-detector", "subdomain-scanner", "nuclei-vuln-scan"];

    // Collect all open ports across all hosts
    const allPorts = hosts.reduce((acc, h) => {
        const p = (h.attributes || {}).open_ports || '';
        if (p && p !== 'unavailable') p.split(',').map(s => s.trim()).filter(Boolean).forEach(port => acc.add(port));
        return acc;
    }, new Set());

    // Tabs
    tabs.innerHTML = `
        <button class="phase-tab-btn active" id="phaseTabBtn-hosts" onclick="switchPhaseModalTab('hosts')">🖥️ Scanned Hosts (${hosts.length})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-ports" onclick="switchPhaseModalTab('ports')">🔌 Open Ports (${allPorts.size})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-rawscan" onclick="switchPhaseModalTab('rawscan')">📋 Scan Details</button>
    `;

    // KPI Cards
    const kpiHtml = `
        <div class="phase-kpi-grid">
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Hosts Scanned</span>
                <span class="phase-kpi-val" style="color:#60a5fa;">${scanned}</span>
                <span class="phase-kpi-sub">Total targets probed</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Reachable</span>
                <span class="phase-kpi-val" style="color:#34d399;">${reachable}</span>
                <span class="phase-kpi-sub">Responded to probes</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Open Ports Found</span>
                <span class="phase-kpi-val" style="color:#fbbf24;">${allPorts.size}</span>
                <span class="phase-kpi-sub">Across all scanned hosts</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Skills Deployed</span>
                <span class="phase-kpi-val" style="color:#a78bfa;">${skillsUsed.length}</span>
                <span class="phase-kpi-sub">Active discovery tools</span>
            </div>
        </div>
    `;

    const skillsBannerHtml = `
        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Agentic Discovery Skills Deployed</span>
                <span class="badge" style="background:rgba(167,139,250,0.15); color:#a78bfa; font-size:0.75rem;">${skillsUsed.length} Active Probers</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">🌐 ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>
    `;

    // Hosts Table
    let hostRows = '';
    if (hosts.length === 0) {
        hostRows = '<tr><td colspan="6" style="text-align:center; color:#64748b;">No hosts recorded</td></tr>';
    } else {
        hosts.forEach(h => {
            const attr = h.attributes || {};
            const status = h.status || 'unknown';
            const statusColor = status === 'alive' || status === 'reachable' ? '#34d399'
                : status === 'unreachable' ? '#f87171' : '#94a3b8';
            const statusIcon = status === 'alive' || status === 'reachable' ? '✅'
                : status === 'unreachable' ? '❌' : '❓';
            const reach = attr.reachability || status;
            const ports = (attr.open_ports && attr.open_ports !== 'unavailable') ? attr.open_ports : '—';
            const hostname = (attr.hostname && attr.hostname !== 'unavailable') ? attr.hostname : '—';
            const latency = (attr.latency && attr.latency !== 'unavailable') ? attr.latency : '—';
            hostRows += `
                <tr>
                    <td><strong style="color:#f8fafc;">${escapeHtml(h.target || '—')}</strong></td>
                    <td style="color:${statusColor}; font-weight:600;">${statusIcon} ${escapeHtml(status)}</td>
                    <td style="color:#94a3b8;">${escapeHtml(reach)}</td>
                    <td>${escapeHtml(hostname)}</td>
                    <td><code style="color:#fbbf24; font-size:0.8rem;">${escapeHtml(ports)}</code></td>
                    <td style="color:#94a3b8;">${escapeHtml(latency)}</td>
                </tr>
            `;
        });
    }

    // Open Ports breakdown
    let portRows = '';
    if (allPorts.size === 0) {
        portRows = '<tr><td colspan="3" style="text-align:center; color:#64748b;">No open ports detected</td></tr>';
    } else {
        const PORT_SERVICES = {
            '21':'FTP','22':'SSH','23':'Telnet','25':'SMTP','53':'DNS',
            '80':'HTTP','110':'POP3','135':'RPC','139':'NetBIOS','143':'IMAP',
            '443':'HTTPS','445':'SMB','993':'IMAPS','995':'POP3S',
            '1433':'MSSQL','1521':'Oracle DB','3306':'MySQL','3389':'RDP',
            '5432':'PostgreSQL','5900':'VNC','6379':'Redis','8080':'HTTP-Alt',
            '8443':'HTTPS-Alt','27017':'MongoDB'
        };
        const RISKY_PORTS = new Set(['21','23','135','139','445','3389','5900','1433','1521','3306','27017','6379']);
        allPorts.forEach(port => {
            const svc = PORT_SERVICES[port] || 'Unknown';
            const risky = RISKY_PORTS.has(port);
            const hostsWithPort = hosts.filter(h => {
                const p = (h.attributes || {}).open_ports || '';
                return p.split(',').map(s => s.trim()).includes(port);
            }).map(h => h.target).join(', ');
            portRows += `
                <tr>
                    <td><code style="color:#60a5fa; font-weight:700;">${escapeHtml(port)}</code></td>
                    <td><span class="phase-agent-tag">${escapeHtml(svc)}</span></td>
                    <td style="color:${risky ? '#f87171' : '#34d399'}; font-weight:600;">${risky ? '⚠️ High Risk' : '✅ Normal'}</td>
                    <td style="color:#94a3b8; font-size:0.8rem;">${escapeHtml(hostsWithPort)}</td>
                </tr>
            `;
        });
    }

    // Raw scan details — per-host attribute dump
    let rawCards = '';
    if (hosts.length === 0) {
        rawCards = '<div style="color:#64748b; text-align:center;">No scan data available</div>';
    } else {
        hosts.forEach(h => {
            const attr = h.attributes || {};
            const prov = h.provenance || {};
            const attrRows = Object.entries(attr).map(([k, v]) =>
                `<tr><td style="color:#94a3b8; width:40%;">${escapeHtml(k)}</td><td style="color:#e2e8f0;">${escapeHtml(String(v))}</td><td style="color:#475569; font-size:0.75rem;">${escapeHtml(prov[k] || '—')}</td></tr>`
            ).join('');
            rawCards += `
                <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:16px; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                        <h4 style="margin:0; color:#38bdf8; font-size:1rem;">🖥️ ${escapeHtml(h.target)}</h4>
                        <span class="badge" style="background:#1e293b; color:${h.status === 'alive' ? '#34d399' : '#f87171'}">${escapeHtml(h.status || 'unknown')}</span>
                    </div>
                    <table style="width:100%; font-size:0.82rem; border-collapse:collapse;">
                        <thead><tr>
                            <th style="text-align:left; color:#475569; padding:4px 0; border-bottom:1px solid #1f2937;">Attribute</th>
                            <th style="text-align:left; color:#475569; padding:4px 0; border-bottom:1px solid #1f2937;">Value</th>
                            <th style="text-align:left; color:#475569; padding:4px 0; border-bottom:1px solid #1f2937;">Source</th>
                        </tr></thead>
                        <tbody>${attrRows || '<tr><td colspan="3" style="color:#475569;">No attributes collected</td></tr>'}</tbody>
                    </table>
                </div>
            `;
        });
    }

    body.innerHTML = `
        ${kpiHtml}
        ${skillsBannerHtml}
        <div class="phase-modal-tab-pane" id="phaseTabPane-hosts" style="display:block;">
            <table class="funnel-table">
                <thead><tr>
                    <th>Target IP / Host</th>
                    <th>Status</th>
                    <th>Reachability</th>
                    <th>Hostname (DNS)</th>
                    <th>Open Ports</th>
                    <th>Latency</th>
                </tr></thead>
                <tbody>${hostRows}</tbody>
            </table>
        </div>
        <div class="phase-modal-tab-pane" id="phaseTabPane-ports" style="display:none;">
            <table class="funnel-table">
                <thead><tr>
                    <th>Port</th><th>Service</th><th>Risk Level</th><th>Seen On</th>
                </tr></thead>
                <tbody>${portRows}</tbody>
            </table>
        </div>
        <div class="phase-modal-tab-pane" id="phaseTabPane-rawscan" style="display:none;">
            ${rawCards}
        </div>
    `;
}

// ------------------------------------------------------------
// 3. Evidence Agent Inspector (Entity Graph, Sockets, Cron)
// ------------------------------------------------------------
function renderEvidenceInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const entityGraph = findings.entity_graph || {};
    const relationships = findings.relationships || [];
    const skillsUsed = (findings.skills_used && findings.skills_used.length > 0) ? findings.skills_used : ["edr-process-tree", "threat-intel-lookup", "identity-ad-lookup", "network-flow-analyzer", "persistence-auditor", "file-forensics"];

    const entityList = Object.entries(entityGraph);

    tabs.innerHTML = `
        <button class="phase-tab-btn active" id="phaseTabBtn-entities" onclick="switchPhaseModalTab('entities')">📊 Discovered Entities (${entityList.length})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-deepforensics" onclick="switchPhaseModalTab('deepforensics')">🌳 Deep Forensic Profiles</button>
        <button class="phase-tab-btn" id="phaseTabBtn-rels" onclick="switchPhaseModalTab('rels')">🔗 Entity Relationships (${relationships.length})</button>
    `;

    // KPI Cards
    const kpiHtml = `
        <div class="phase-kpi-grid">
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Graph Entities</span>
                <span class="phase-kpi-val" style="color: #60a5fa;">${entityList.length}</span>
                <span class="phase-kpi-sub">Enriched forensic nodes</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Causal Relationships</span>
                <span class="phase-kpi-val" style="color: #34d399;">${relationships.length}</span>
                <span class="phase-kpi-sub">Cross-entity links</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Skills Deployed</span>
                <span class="phase-kpi-val" style="color: #a78bfa;">${skillsUsed.length}</span>
                <span class="phase-kpi-sub">EDR & Network collectors</span>
            </div>
        </div>
    `;

    const skillsBannerHtml = `
        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Agentic Evidence Skills Deployed</span>
                <span class="badge" style="background:rgba(167,139,250,0.15); color:#a78bfa; font-size:0.75rem;">${skillsUsed.length} Forensic Collectors</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">🔍 ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>
    `;

    // Entities Table
    let entityRows = '';
    entityList.forEach(([eid, edata]) => {
        const risk = edata.risk_score || 0.1;
        const riskClass = risk >= 0.8 ? 'risk-high' : risk >= 0.5 ? 'risk-med' : 'risk-low';
        const ti = edata.threat_intel || {};
        const sigs = (ti.suricata_signatures || []).concat(ti.wazuh_rule_ids || []).join(', ') || 'None';

        entityRows += `
            <tr>
                <td><strong style="color:#f8fafc;">${escapeHtml(edata.id || eid)}</strong></td>
                <td><span class="phase-agent-tag">${escapeHtml(edata.type || 'entity')}</span></td>
                <td><span class="risk-pill ${riskClass}">${risk}</span></td>
                <td>${edata.evidence_count || 0} hits</td>
                <td style="color:${ti.is_known_malicious ? '#f87171' : '#34d399'}; font-weight:600;">${ti.is_known_malicious ? '⚠️ Known Malicious' : 'Monitored'}</td>
                <td style="color:#94a3b8; font-size:0.75rem;">${escapeHtml(sigs)}</td>
            </tr>
        `;
    });

    // Deep Forensics Cards
    let forensicsCards = '';
    entityList.forEach(([eid, edata]) => {
        const enr = edata.enrichment || {};
        const sockets = enr.open_sockets ? `<div><strong>Open Sockets:</strong> <code>${enr.open_sockets.join(', ')}</code></div>` : '';
        const beacon = enr.beaconing_detected ? `<div style="color:#f87171; font-weight:bold;">⚠️ Active C2 Beaconing Detected</div>` : '';
        const cron = enr.suspicious_scripts ? `<div><strong>Suspicious Cron/Scripts:</strong> <code>${enr.suspicious_scripts.join(', ')}</code></div>` : '';
        const cmds = enr.access_commands ? `<div><strong>Observed Executions:</strong><pre style="background:#090d16; padding:8px; border-radius:4px; margin-top:4px; font-size:0.75rem;">${escapeHtml(enr.access_commands.join('\n'))}</pre></div>` : '';

        forensicsCards += `
            <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:16px; margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <h4 style="margin:0; color:#38bdf8; font-size:1rem;">${escapeHtml(edata.id || eid)} (${edata.type})</h4>
                    <span class="badge" style="background:#1e293b;">Risk: ${edata.risk_score}</span>
                </div>
                <div style="display:flex; flex-direction:column; gap:8px; font-size:0.85rem; color:#cbd5e1;">
                    ${beacon}
                    ${sockets}
                    ${cron}
                    ${cmds}
                </div>
            </div>
        `;
    });

    // Relationships Table
    let relRows = '';
    relationships.forEach(r => {
        relRows += `
            <tr>
                <td><strong style="color:#38bdf8;">${escapeHtml(r.source)}</strong></td>
                <td><span class="phase-agent-tag" style="color:#fbbf24;">➔ ${escapeHtml(r.type)} ➔</span></td>
                <td><strong style="color:#34d399;">${escapeHtml(r.target)}</strong></td>
            </tr>
        `;
    });

    body.innerHTML = `
        ${kpiHtml}
        ${skillsBannerHtml}
        <div class="phase-modal-tab-pane" id="phaseTabPane-entities" style="display: block;">
            <table class="funnel-table">
                <thead>
                    <tr>
                        <th>Entity Name / IOC</th>
                        <th>Type</th>
                        <th>Risk Score</th>
                        <th>Telemetry Hits</th>
                        <th>Threat Intel Verdict</th>
                        <th>Matching Signatures</th>
                    </tr>
                </thead>
                <tbody>
                    ${entityRows || '<tr><td colspan="6" style="text-align:center;">No entities recorded</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="phase-modal-tab-pane" id="phaseTabPane-deepforensics" style="display: none;">
            ${forensicsCards || '<div style="color:#64748b; text-align:center;">No deep forensic data</div>'}
        </div>

        <div class="phase-modal-tab-pane" id="phaseTabPane-rels" style="display: none;">
            <table class="funnel-table">
                <thead>
                    <tr>
                        <th>Source Node</th>
                        <th>Relationship Type</th>
                        <th>Target Node</th>
                    </tr>
                </thead>
                <tbody>
                    ${relRows || '<tr><td colspan="3" style="text-align:center;">No relationships found</td></tr>'}
                </tbody>
            </table>
        </div>
    `;
}

// === Page: AI Governance (Wave 1-3) ===
async function getAIGovernanceOverview() {
    const res = await apiFetch('/api/v1/ai-governance/overview');
    showResult('aiGovOverviewResult', res.data, !res.ok);
}

async function listDetectionRules() {
    const res = await apiFetch('/api/v1/ai-governance/detections');
    showResult('detectionRulesResult', res.data, !res.ok);
}

async function listEntityRisk() {
    const res = await apiFetch('/api/v1/ai-governance/entity-risk');
    showResult('entityRiskResult', res.data, !res.ok);
}

async function getMaturityGateStatus() {
    const res = await apiFetch('/api/v1/ai-governance/maturity-gate');
    showResult('maturityGateResult', res.data, !res.ok);
}

async function listPlaybooks() {
    const res = await apiFetch('/api/v1/ai-governance/playbooks');
    showResult('playbooksResult', res.data, !res.ok);
}

async function listMemoryPriors() {
    const res = await apiFetch('/api/v1/ai-governance/memory/priors');
    showResult('memoryPriorsResult', res.data, !res.ok);
}

async function runMemoryDistillation() {
    const res = await apiFetch('/api/v1/ai-governance/memory/distill', { method: 'POST' });
    showResult('memoryPriorsResult', res.data, !res.ok);
}

async function runPurpleTeamCampaign() {
    const campaign_name = document.getElementById('purpleTeamCampaign').value;
    const res = await apiFetch('/api/v1/ai-governance/purple-team/run', {
        method: 'POST',
        body: JSON.stringify({ campaign_name })
    });
    showResult('purpleTeamResult', res.data, !res.ok);
}

async function viewInvestigationLedger() {
    const investigation_id = document.getElementById('ledgerInvId').value;
    if (!investigation_id) {
        showResult('ledgerResult', 'Please enter an Investigation ID', true);
        return;
    }
    const res = await apiFetch(`/api/v3/orchestrator/investigations/${encodeURIComponent(investigation_id)}/ledger`);
    showResult('ledgerResult', res.data, !res.ok);
}

async function viewInvestigationLedgerCost() {
    const investigation_id = document.getElementById('ledgerInvId').value;
    if (!investigation_id) {
        showResult('ledgerResult', 'Please enter an Investigation ID', true);
        return;
    }
    const res = await apiFetch(`/api/v3/orchestrator/investigations/${encodeURIComponent(investigation_id)}/ledger/cost`);
    showResult('ledgerResult', res.data, !res.ok);
}

// ------------------------------------------------------------
// 4. Triage Agent Inspector
// ------------------------------------------------------------
function renderTriageInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const entities = findings.entities_identified || [];
    const skillsUsed = (findings.skills_used && findings.skills_used.length > 0) ? findings.skills_used : ["ioc-extractor", "mitre-classifier", "severity-evaluator", "grounding-validator"];

    tabs.innerHTML = `
        <button class="phase-tab-btn active" id="phaseTabBtn-triage" onclick="switchPhaseModalTab('triage')">🎯 Triage Scope & Classification</button>
    `;

    body.innerHTML = `
        <div class="phase-kpi-grid">
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Classification</span>
                <span class="phase-kpi-val" style="color: #f87171;">${escapeHtml(findings.classification || 'Unknown')}</span>
                <span class="phase-kpi-sub">Severity: ${escapeHtml(findings.severity || 'High')}</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Seed Entities</span>
                <span class="phase-kpi-val" style="color: #60a5fa;">${entities.length}</span>
                <span class="phase-kpi-sub">Grounded IOCs</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Skills Deployed</span>
                <span class="phase-kpi-val" style="color: #a78bfa;">${skillsUsed.length}</span>
                <span class="phase-kpi-sub">Triage capabilities</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Immediate Action</span>
                <span class="phase-kpi-val" style="color: ${findings.requires_immediate_action ? '#ef4444' : '#34d399'};">
                    ${findings.requires_immediate_action ? 'REQUIRED' : 'Standard'}
                </span>
                <span class="phase-kpi-sub">Triage priority</span>
            </div>
        </div>

        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Agentic Triage Skills Used</span>
                ${findings.tactic ? `<span class="badge" style="background:rgba(56,189,248,0.15); color:#38bdf8; font-size:0.75rem;">MITRE: ${escapeHtml(findings.tactic)} ${findings.technique ? `(${escapeHtml(findings.technique)})` : ''}</span>` : ''}
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">🔧 ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>

        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:18px; margin-bottom:16px;">
            <h4 style="color:#38bdf8; margin-top:0;">Initial Assessment Reasoning</h4>
            <p style="color:#cbd5e1; font-size:0.9rem; line-height:1.6;">${escapeHtml(findings.initial_assessment || findings.summary || 'No narrative assessment provided.')}</p>
        </div>

        <h4 style="color:#f8fafc; margin-bottom:10px;">Grounded Seed Entities</h4>
        <table class="funnel-table">
            <thead>
                <tr>
                    <th>Entity Identifier</th>
                    <th>Type</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                ${entities.map(e => `
                    <tr>
                        <td><strong style="color:#f8fafc;">${escapeHtml(e.id || e.name || '')}</strong></td>
                        <td><span class="phase-agent-tag">${escapeHtml(e.type || '')}</span></td>
                        <td><span class="risk-pill risk-high">${(e.confidence || 0.9) * 100}%</span></td>
                    </tr>
                `).join('') || '<tr><td colspan="3" style="text-align:center;">No entities grounded</td></tr>'}
            </tbody>
        </table>
    `;
}

// ------------------------------------------------------------
// 5. RCA Agent Inspector
// ------------------------------------------------------------
function renderRCAInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const phases = findings.attack_phases || [];
    const cot = findings.chain_of_thought_verification || findings.reasoning || '';
    const candidates = findings.structural_causal_candidates || [];
    const skillsUsed = (findings.skills_used && findings.skills_used.length > 0) ? findings.skills_used : ["causal-analyzer", "attack-chain-synthesizer", "true-rca-ranker"];

    tabs.innerHTML = `
        <button class="phase-tab-btn active" id="phaseTabBtn-rca" onclick="switchPhaseModalTab('rca')">🔬 Root Cause & Blast Radius</button>
        <button class="phase-tab-btn" id="phaseTabBtn-phases" onclick="switchPhaseModalTab('phases')">⏱️ Attack Chain Phases (${phases.length})</button>
        <button class="phase-tab-btn" id="phaseTabBtn-cot" onclick="switchPhaseModalTab('cot')">🧠 Chain-of-Thought Critique</button>
    `;

    body.innerHTML = `
        <div class="phase-kpi-grid">
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">RCA Confidence</span>
                <span class="phase-kpi-val" style="color: #34d399;">${((report.confidence || 0) * 100).toFixed(0)}%</span>
                <span class="phase-kpi-sub">Validated Causal Graph</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Blast Radius</span>
                <span class="phase-kpi-val" style="color: #ef4444;">${findings.blast_radius || 1} entities</span>
                <span class="phase-kpi-sub">Compromised scope</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Attack Phases</span>
                <span class="phase-kpi-val" style="color: #fbbf24;">${phases.length}</span>
                <span class="phase-kpi-sub">Sequential stages</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Skills Deployed</span>
                <span class="phase-kpi-val" style="color: #a78bfa;">${skillsUsed.length}</span>
                <span class="phase-kpi-sub">Graph RCA engines</span>
            </div>
        </div>

        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Agentic RCA Skills Used</span>
                <span class="badge" style="background:rgba(167,139,250,0.15); color:#a78bfa; font-size:0.75rem;">${skillsUsed.length} Causal Analyzers</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">🔬 ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>

        <div class="phase-modal-tab-pane" id="phaseTabPane-rca">
            <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:18px; margin-bottom:16px;">
                <h4 style="color:#f87171; margin-top:0;">Identified Root Cause</h4>
                <p style="color:#f8fafc; font-size:1.05rem; font-weight:bold; margin-bottom:6px;">${escapeHtml(findings.root_cause || 'Unknown')}</p>
                <p style="color:#94a3b8; font-size:0.85rem; margin:0;">${escapeHtml(findings.summary || '')}</p>
            </div>

            <h4 style="color:#f8fafc; margin-bottom:10px;">Structural Causal Candidates</h4>
            <table class="funnel-table">
                <thead>
                    <tr>
                        <th>Candidate Entity</th>
                        <th>Causal Score</th>
                        <th>Reasoning</th>
                    </tr>
                </thead>
                <tbody>
                    ${candidates.map(c => `
                        <tr>
                            <td><strong style="color:#38bdf8;">${escapeHtml(c.candidate_entity || '')}</strong></td>
                            <td><span class="risk-pill risk-high">${((c.causal_score || 0) * 100).toFixed(0)}%</span></td>
                            <td style="color:#cbd5e1; font-size:0.85rem;">${escapeHtml(c.reasoning || '')}</td>
                        </tr>
                    `).join('') || '<tr><td colspan="3" style="text-align:center;">No candidates scored</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="phase-modal-tab-pane" id="phaseTabPane-phases" style="display: none;">
            <div style="padding-left:20px; position:relative;">
                ${phases.map((p, idx) => `
                    <div class="attack-phase-item">
                        <div style="font-weight:bold; color:#f8fafc; font-size:0.95rem;">Phase ${idx + 1}</div>
                        <div style="color:#cbd5e1; font-size:0.88rem; margin-top:4px;">${escapeHtml(p)}</div>
                    </div>
                `).join('') || '<div style="color:#64748b;">No attack phases reconstructed</div>'}
            </div>
        </div>

        <div class="phase-modal-tab-pane" id="phaseTabPane-cot" style="display: none;">
            <h4 style="color:#a78bfa; margin-top:0;">Chain-of-Thought Self-Verification & Critique</h4>
            <div class="hist-cot-box">${escapeHtml(cot || 'No verification reasoning recorded.')}</div>
        </div>
    `;
}

// ------------------------------------------------------------
// 6. Response Agent Inspector
// ------------------------------------------------------------
function renderResponseInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const actions = findings.actions_recommended || [];
    const skillsUsed = (findings.skills_used && findings.skills_used.length > 0) ? findings.skills_used : ["isolate-host", "block-ip", "reset-credentials", "playbook-executor"];

    tabs.innerHTML = `
        <button class="phase-tab-btn active" id="phaseTabBtn-playbook" onclick="switchPhaseModalTab('playbook')">⚡ Prioritized Containment Playbook (${actions.length})</button>
    `;

    body.innerHTML = `
        <div class="phase-kpi-grid">
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Recommended Actions</span>
                <span class="phase-kpi-val" style="color: #34d399;">${actions.length}</span>
                <span class="phase-kpi-sub">Containment steps</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Critical Actions</span>
                <span class="phase-kpi-val" style="color: #ef4444;">${findings.critical_actions || 0}</span>
                <span class="phase-kpi-sub">Immediate execution</span>
            </div>
            <div class="phase-kpi-card">
                <span class="phase-kpi-label">Skills Deployed</span>
                <span class="phase-kpi-val" style="color: #a78bfa;">${skillsUsed.length}</span>
                <span class="phase-kpi-sub">Remediation playbooks</span>
            </div>
        </div>

        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Response Skills Deployed</span>
                <span class="badge" style="background:rgba(167,139,250,0.15); color:#a78bfa; font-size:0.75rem;">${skillsUsed.length} Playbooks Active</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">🛡️ ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>

        <table class="funnel-table">
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Action</th>
                    <th>Target Entity</th>
                    <th>Execution Command</th>
                    <th>Requires Approval</th>
                    <th>Rollback Procedure</th>
                </tr>
            </thead>
            <tbody>
                ${actions.map(a => `
                    <tr>
                        <td><span class="risk-pill ${a.priority === 1 ? 'risk-high' : 'risk-med'}">P${a.priority || 1}</span></td>
                        <td><strong style="color:#f8fafc;">${escapeHtml(a.action || '')}</strong></td>
                        <td><strong style="color:#38bdf8;">${escapeHtml(a.target_entity || '')}</strong></td>
                        <td><code style="background:#090d16; padding:4px 8px; border-radius:4px; font-size:0.75rem;">${escapeHtml(a.command || 'N/A')}</code></td>
                        <td><span class="badge" style="background:${a.requires_approval ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'}; color:${a.requires_approval ? '#f87171' : '#34d399'};">${a.requires_approval ? 'Required' : 'Auto'}</span></td>
                        <td style="color:#94a3b8; font-size:0.75rem;">${escapeHtml(a.rollback_procedure || 'None')}</td>
                    </tr>
                `).join('') || '<tr><td colspan="6" style="text-align:center;">No actions planned</td></tr>'}
            </tbody>
        </table>
    `;
}

// ------------------------------------------------------------
// Generic Fallback Inspector
// ------------------------------------------------------------
function renderGenericInspectorView(report, tabs, body) {
    const findings = report.findings || {};
    const skillsUsed = findings.skills_used || [];
    tabs.innerHTML = `<button class="phase-tab-btn active">📋 Phase Findings</button>`;
    
    const skillsBannerHtml = skillsUsed.length > 0 ? `
        <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px 18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="color:#a78bfa; font-weight:600; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em;">⚡ Agentic Skills Deployed</span>
                <span class="badge" style="background:rgba(167,139,250,0.15); color:#a78bfa; font-size:0.75rem;">${skillsUsed.length} Skills</span>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:8px;">
                ${skillsUsed.map(s => `<span class="phase-agent-tag" style="background:#1e1b4b; color:#c084fc; border:1px solid #6b21a8; padding:4px 10px; font-size:0.8rem;">⚡ ${escapeHtml(s)}</span>`).join('')}
            </div>
        </div>
    ` : '';

    body.innerHTML = `
        ${skillsBannerHtml}
        <pre style="background:#090d16; padding:16px; border-radius:8px; font-size:0.8rem; overflow-x:auto; color:#cbd5e1;">
${escapeHtml(JSON.stringify(report.findings || {}, null, 2))}
        </pre>
    `;
}

