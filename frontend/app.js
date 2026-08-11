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
    }
};

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
    refreshDashboard();
    // Auto-refresh dashboard every 30 seconds
    setInterval(() => {
        if (document.getElementById('page-dashboard').classList.contains('active')) {
            refreshDashboard();
        }
    }, 30000);
});
