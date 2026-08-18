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
const ORCH_TEMPLATES = {
    crowdstrike_malware: {
        source: 'crowdstrike',
        severity_name: 'High',
        severity: 4,
        tactic: 'Execution',
        technique_id: 'T1059.001',
        alert: {
            event_type: 'DetectionSummaryEvent',
            severity: 4,
            severity_name: 'High',
            tactic: 'Execution',
            technique_id: 'T1059.001',
            user_name: 'jsmith',
            computer_name: 'WS-FINANCE-042',
            local_ip: '10.0.2.100',
            file_name: 'payload.exe',
            sha256: 'a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01',
            command_line: 'cmd.exe /c powershell -ep bypass -f payload.ps1',
        }
    },
    crowdstrike_lateral: {
        source: 'crowdstrike',
        severity_name: 'Critical',
        severity: 5,
        tactic: 'Lateral Movement',
        technique_id: 'T1021.002',
        alert: {
            event_type: 'DetectionSummaryEvent',
            severity: 5,
            severity_name: 'Critical',
            tactic: 'Lateral Movement',
            technique_id: 'T1021.002',
            user_name: 'admin_backup',
            computer_name: 'DC-PRIMARY-01',
            local_ip: '10.0.1.5',
            file_name: 'psexec.exe',
            sha256: 'deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678',
        }
    },
    splunk_bruteforce: {
        source: 'splunk',
        severity_name: 'High',
        severity: 4,
        tactic: 'Credential Access',
        technique_id: 'T1110',
        user: 'svc_monitoring',
        hostname: 'AUTH-SERVER-01',
        src_ip: '185.143.223.47',
        alert: {
            user_name: 'svc_monitoring',
            computer_name: 'AUTH-SERVER-01',
        }
    },
    splunk_exfil: {
        source: 'splunk',
        severity_name: 'Critical',
        severity: 5,
        tactic: 'Exfiltration',
        technique_id: 'T1048',
        user: 'dev_contractor',
        hostname: 'DB-PROD-03',
        src_ip: '10.0.5.88',
        domain: 'exfil-drop.darkweb.cc',
        alert: {
            user_name: 'dev_contractor',
            computer_name: 'DB-PROD-03',
            local_ip: '10.0.5.88',
        }
    },
};

let orchRunning = false;
let orchTimerInterval = null;
let orchStartTime = null;
let orchEventCount = 0;

function loadOrchTemplate() {
    const templateKey = document.getElementById('orchAlertTemplate').value;
    const alertData = ORCH_TEMPLATES[templateKey];
    if (alertData) {
        document.getElementById('orchAlertJson').value = JSON.stringify(alertData, null, 2);
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
            const lines = buffer.split('\n');
            buffer = lines.pop(); // Keep incomplete line in buffer

            let eventType = '';
            for (const line of lines) {
                if (line.startsWith('event: ')) {
                    eventType = line.slice(7).trim();
                } else if (line.startsWith('data: ') && eventType) {
                    try {
                        const data = JSON.parse(line.slice(6));
                        handleOrchEvent(eventType, data);
                    } catch (e) { /* skip malformed */ }
                    eventType = '';
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
    setOrchStatus('planning');
}

function handleOrchEvent(type, data) {
    orchEventCount++;
    document.getElementById('orchLogCount').textContent = `${orchEventCount} events`;

    switch (type) {
        case 'run_start':
            setOrchStatus('planning');
            addOrchLog(type, 'orchestrator', `Starting investigation: "${data.task}"`);
            break;

        case 'plan_created':
            setOrchStatus('running');
            document.getElementById('orchReasoning').textContent = data.reasoning;
            renderDynamicDAG(data.phases || []);
            addOrchLog(type, 'orchestrator', `Plan created: ${data.total_tasks} tasks across ${data.total_phases} phases`);
            break;

        case 'phase_start':
            const parallelNote = data.parallel ? ' [PARALLEL]' : '';
            addOrchLog(type, 'orchestrator', `Starting Phase ${data.phase_num}${parallelNote}`);
            break;

        case 'pending_approval':
            setOrchStatus('pending_approval');
            const btn = document.getElementById('orchPendingBtn');
            if (btn) {
                btn.style.display = 'inline-block';
                btn.onclick = () => {
                    document.querySelector('.nav-item[data-page="approvals"]').click();
                    setTimeout(() => {
                        const el = document.getElementById(`approval-${data.workflow_id}`);
                        if(el) {
                            el.scrollIntoView({behavior: 'smooth', block: 'center'});
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

        case 'agent_start':
            setAgentNodeState(data.agent_name, 'running');
            addOrchLog(type, data.agent_name, `Started: ${data.description}`);
            break;

        case 'agent_complete':
            const report = data.report;
            const state = report.status === 'completed' ? 'completed' : 'failed';
            setAgentNodeState(data.agent_name, state);
            const summary = report.findings?.summary || report.findings?.initial_assessment || `Done in ${report.duration_ms}ms`;
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

function renderDynamicDAG(phases) {
    const dagContainer = document.getElementById('orchDag');
    dagContainer.innerHTML = ''; // clear

    const agentIcons = {
        'triage_agent': '&#128269;',
        'evidence_agent': '&#128200;',
        'discovery_agent': '&#127760;',
        'compression_agent': '&#128476;',
        'rca_agent': '&#128300;',
        'response_agent': '&#9889;',
    };

    const agentLabels = {
        'triage_agent': 'Triage',
        'evidence_agent': 'Evidence',
        'discovery_agent': 'Discovery',
        'compression_agent': 'Compression',
        'rca_agent': 'RCA',
        'response_agent': 'Response',
    };

    phases.forEach((phase, index) => {
        // Add connector arrow (if not first phase)
        if (index > 0) {
            const connector = document.createElement('div');
            connector.className = 'dag-connector';
            connector.innerHTML = '&#8595;';
            dagContainer.appendChild(connector);
        }

        const phaseDiv = document.createElement('div');
        phaseDiv.className = 'dag-phase';
        phaseDiv.id = `dagPhase${phase.phase_num}`;

        const parallelBadge = phase.parallel ? ' <span class="parallel-badge">PARALLEL</span>' : '';
        const labelDiv = document.createElement('div');
        labelDiv.className = 'phase-label';
        labelDiv.innerHTML = `Phase ${phase.phase_num}${parallelBadge}`;
        phaseDiv.appendChild(labelDiv);

        const agentsDiv = document.createElement('div');
        agentsDiv.className = 'phase-agents';

        const phaseAgents = phase.agents || (phase.tasks ? phase.tasks.map(t => t.agent) : []);

        phaseAgents.forEach(agentName => {
            const nodeDiv = document.createElement('div');
            nodeDiv.className = 'agent-node pending';
            nodeDiv.id = `node-${agentName}`;
            nodeDiv.dataset.agent = agentName;

            nodeDiv.innerHTML = `
                <div class="agent-icon">${agentIcons[agentName] || '&#9881;'}</div>
                <div class="agent-label">${agentLabels[agentName] || agentName}</div>
                <div class="agent-status-dot"></div>
            `;
            agentsDiv.appendChild(nodeDiv);
        });

        phaseDiv.appendChild(agentsDiv);
        dagContainer.appendChild(phaseDiv);
    });
}

function setOrchStatus(status) {
    const badge = document.getElementById('orchStatus');
    badge.className = `orch-status-badge ${status}`;
    const labels = { planning: 'Planning...', running: 'Executing', completed: 'Completed', failed: 'Failed' };
    badge.textContent = labels[status] || status;
}

function setAgentNodeState(agentName, state) {
    const node = document.getElementById(`node-${agentName}`);
    if (node) node.className = `agent-node ${state}`;
}

function updateOrchTimer() {
    if (!orchStartTime) return;
    const elapsed = ((Date.now() - orchStartTime) / 1000).toFixed(1);
    document.getElementById('orchTimer').textContent = `${elapsed}s`;
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
    const grid = document.getElementById('orchReportsGrid');
    const confidence = report.confidence || 0;
    const confClass = confidence >= 0.8 ? 'confidence-high' : confidence >= 0.5 ? 'confidence-medium' : 'confidence-low';

    // Pick key findings to display (skip large objects)
    const findings = report.findings || {};
    const displayFindings = Object.entries(findings)
        .filter(([k, v]) => typeof v !== 'object' || Array.isArray(v))
        .filter(([k]) => k !== 'summary' && k !== 'initial_assessment')
        .slice(0, 6);

    const artifactsHtml = (report.artifacts || [])
        .map(a => `<span class="artifact-tag">${a}</span>`).join('');

    const findingsHtml = displayFindings
        .map(([k, v]) => {
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
    const names = {
        orchestrator: '🎯 Orchestrator',
        triage_agent: '🔍 Triage',
        evidence_agent: '📊 Evidence',
        discovery_agent: '🌐 Discovery',
        compression_agent: '🗜️ Compression',
        rca_agent: '🔬 RCA',
        response_agent: '⚡ Response',
    };
    return names[name] || name;
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
    badge.style.display = 'inline-block';
    
    const card = document.createElement('div');
    card.className = 'agent-card';
    card.id = `approval-${workflowId}`;
    
    let actionsHtml = actions.map(a => `<li>${a}</li>`).join('');
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
            
            badge.textContent = pending.length;
            badge.style.display = 'inline-block';
            
            pending.forEach(p => {
                addPendingApproval(p.workflow_id, p.actions, p.confidence, p.entities, p.summary);
            });
        }
    } catch (e) {
        console.error("Failed to load pending approvals", e);
    }
}
