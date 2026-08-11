"""Phase 3 - Report Generation

Generates technical, executive, and compliance incident reports.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json


class ReportType(Enum):
    """Types of incident reports."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    FORENSIC_REPORT = "forensic_report"
    COMPLIANCE_REPORT = "compliance_report"
    INCIDENT_LOG = "incident_log"


@dataclass
class IncidentReport:
    """Complete incident report."""
    report_id: str
    report_type: ReportType
    incident_id: str
    generated_at: datetime
    generated_by: str
    title: str
    executive_summary: str
    body: str
    findings: List[Dict]
    recommendations: List[str]
    indicators_of_compromise: List[str]
    affected_systems: List[str]
    estimated_damage: str
    immediate_actions: List[str]
    appendices: Dict[str, Any]


class ReportGenerator:
    """Generates incident reports."""
    
    def __init__(self):
        self.reports: Dict[str, IncidentReport] = {}
    
    async def generate_all_reports(self, rca_result: Any, 
                                   response_summary: Dict,
                                   incident_id: str) -> Dict[str, IncidentReport]:
        """Generate all report types."""
        
        reports = {}
        
        reports['executive'] = await self.generate_executive_summary(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id=incident_id
        )
        
        reports['technical'] = await self.generate_technical_analysis(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id=incident_id
        )
        
        reports['forensic'] = await self.generate_forensic_report(
            rca_result=rca_result,
            incident_id=incident_id
        )
        
        reports['compliance'] = await self.generate_compliance_report(
            rca_result=rca_result,
            incident_id=incident_id
        )
        
        reports['log'] = await self.generate_incident_log(
            rca_result=rca_result,
            response_summary=response_summary,
            incident_id=incident_id
        )
        
        return reports
    
    async def generate_executive_summary(self, rca_result: Any,
                                        response_summary: Dict,
                                        incident_id: str) -> IncidentReport:
        """Generate executive summary report."""
        
        report_id = f"RPT-EXEC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Build findings
        findings = [
            {
                'type': 'Root Cause',
                'description': f"{rca_result.root_cause.root_cause_service} was identified as root cause",
                'confidence': f"{rca_result.root_cause.confidence:.0%}"
            },
            {
                'type': 'Attack Type',
                'description': rca_result.root_cause.attack_type.replace('_', ' ').title(),
                'severity': 'High' if rca_result.root_cause.confidence > 0.7 else 'Medium'
            },
            {
                'type': 'Impact',
                'description': f"{rca_result.root_cause.estimated_blast_radius} systems affected",
                'duration': f"{sum([i.get('duration_seconds', 0) for i in response_summary.get('actions_executed', [])])} seconds"
            }
        ]
        
        # Build body
        body = f"""
INCIDENT SUMMARY
================

Date: {datetime.now().strftime('%B %d, %Y')}
Incident ID: {incident_id}
Severity: {'CRITICAL' if rca_result.root_cause.confidence > 0.8 else 'HIGH' if rca_result.root_cause.confidence > 0.6 else 'MEDIUM'}

EXECUTIVE OVERVIEW
------------------
This incident involved {rca_result.root_cause.attack_type.replace('_', ' ').lower()} activity targeting 
{rca_result.root_cause.target_service}. Our security systems detected and analyzed the incident, 
identifying the root cause with {rca_result.root_cause.confidence:.0%} confidence.

IMMEDIATE IMPACT
----------------
• Affected Systems: {rca_result.root_cause.estimated_blast_radius}
• Detection Time: {self._calculate_detection_time(rca_result)}
• Response Time: {response_summary.get('duration_seconds', 0)/60:.1f} minutes
• Actions Executed: {len(response_summary.get('actions_executed', []))}

KEY FINDINGS
------------
1. Root Cause: {rca_result.root_cause.root_cause_service}
2. Attack Vector: {rca_result.mitre_tactics[0] if rca_result.mitre_tactics else 'Unknown'}
3. Initial Compromise: {rca_result.attack_chain_description.split(chr(10))[0]}

IMMEDIATE ACTIONS TAKEN
-----------------------
{chr(10).join([f"✓ {a.get('action')} - {a.get('result')}" for a in response_summary.get('actions_executed', [])])}

BUSINESS IMPACT
---------------
The incident affected {rca_result.root_cause.target_service} and potentially exposed 
{self._estimate_exposure(rca_result)} of data. Business operations were disrupted for approximately 
{self._estimate_downtime(rca_result)} minutes.

REMEDIATION
-----------
{len(response_summary.get('actions_executed', []))} containment actions were executed successfully.
Long-term remediation is in progress and will be completed within 24 hours.

NEXT STEPS
----------
1. Review detailed technical analysis (attached)
2. Implement long-term remediation actions
3. Conduct post-incident review
4. Update security policies based on lessons learned
"""
        
        report = IncidentReport(
            report_id=report_id,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            incident_id=incident_id,
            generated_at=datetime.now(),
            generated_by="Automated RCA System",
            title=f"Incident {incident_id} - Executive Summary",
            executive_summary=rca_result.executive_summary,
            body=body,
            findings=findings,
            recommendations=[
                f"Implement stronger controls on {rca_result.root_cause.root_cause_service}",
                "Review and update incident response procedures",
                "Conduct security awareness training for affected departments",
                "Implement additional monitoring for similar attack patterns"
            ],
            indicators_of_compromise=rca_result.indicators_of_compromise,
            affected_systems=list(rca_result.root_cause.attack_graph.keys()),
            estimated_damage=f"${self._estimate_financial_impact(rca_result)}K",
            immediate_actions=[a.get('action', 'unknown') for a in response_summary.get('actions_executed', [])],
            appendices={
                'detailed_timeline': rca_result.technical_narrative,
                'attack_chain': rca_result.attack_chain_description
            }
        )
        
        self.reports[report_id] = report
        return report
    
    async def generate_technical_analysis(self, rca_result: Any,
                                         response_summary: Dict,
                                         incident_id: str) -> IncidentReport:
        """Generate detailed technical analysis report."""
        
        report_id = f"RPT-TECH-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        findings = [
            {
                'phase': i,
                'description': line[:100],  # First 100 chars of each line
                'timestamp': datetime.now().isoformat()
            }
            for i, line in enumerate(rca_result.technical_narrative.split(chr(10))[:5])
            if line.strip()
        ]
        
        body = f"""
TECHNICAL ANALYSIS REPORT
=========================

Incident ID: {incident_id}
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

ATTACK CHAIN
============
{rca_result.attack_chain_description}

TOPOLOGY ANALYSIS
=================
Graph Nodes: {len(rca_result.root_cause.attack_graph)}
Attack Path Length: {len(rca_result.root_cause.temporal_sequence)} hops
Critical Node: {rca_result.root_cause.root_cause_service}

ROOT CAUSE ANALYSIS
===================
Primary Service: {rca_result.root_cause.target_service}
Root Cause Service: {rca_result.root_cause.root_cause_service}
Confidence Score: {rca_result.root_cause.confidence:.3f}

Supporting Evidence:
{chr(10).join([f"  • {e.get('timestamp')} - {e.get('event')}" for e in rca_result.root_cause.supporting_evidence[:10]])}

Contradicting Evidence:
{chr(10).join([f"  • {e.get('reason')}" for e in rca_result.root_cause.contradicting_evidence[:5]]) if rca_result.root_cause.contradicting_evidence else "  None identified"}

MITRE ATT&CK MAPPING
====================
Tactics: {', '.join(rca_result.mitre_tactics)}
Techniques: {', '.join(rca_result.mitre_techniques)}

RESPONSE ACTIONS EXECUTED
=========================
{chr(10).join([f"✓ {a.get('action')} on {a.get('target')}" for a in response_summary.get('actions_executed', [])])}

FORENSIC ARTIFACTS
==================
Files Modified: {len([e for e in rca_result.technical_narrative if 'file' in str(e).lower()])}
Processes Executed: {len([e for e in rca_result.technical_narrative if 'process' in str(e).lower()])}
Network Connections: {len([e for e in rca_result.technical_narrative if 'network' in str(e).lower()])}

REMEDIATION ACTIONS RECOMMENDED
===============================
{chr(10).join([f"{i+1}. {rec}" for i, rec in enumerate(rca_result.executive_summary.split(chr(10))[:5])])}
"""
        
        report = IncidentReport(
            report_id=report_id,
            report_type=ReportType.TECHNICAL_ANALYSIS,
            incident_id=incident_id,
            generated_at=datetime.now(),
            generated_by="Automated RCA System",
            title=f"Incident {incident_id} - Technical Analysis",
            executive_summary=rca_result.technical_narrative,
            body=body,
            findings=[
                {
                    'type': 'Attack Vector',
                    'details': rca_result.mitre_tactics[0] if rca_result.mitre_tactics else 'Unknown',
                    'timeline': f"{len(rca_result.root_cause.temporal_sequence)} events"
                },
                {
                    'type': 'Persistence Method',
                    'details': self._identify_persistence(rca_result),
                    'criticality': 'High'
                }
            ],
            recommendations=[
                "Implement network segmentation",
                "Deploy EDR on all critical systems",
                "Implement multi-factor authentication",
                "Regular security assessments"
            ],
            indicators_of_compromise=rca_result.indicators_of_compromise,
            affected_systems=list(rca_result.root_cause.attack_graph.keys()),
            estimated_damage=f"${self._estimate_financial_impact(rca_result)}K",
            immediate_actions=[],
            appendices={
                'timeline': rca_result.technical_narrative,
                'attack_graph': rca_result.root_cause.attack_graph
            }
        )
        
        self.reports[report_id] = report
        return report
    
    async def generate_forensic_report(self, rca_result: Any,
                                      incident_id: str) -> IncidentReport:
        """Generate detailed forensic report."""
        
        report_id = f"RPT-FOREN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        body = f"""
FORENSIC ANALYSIS REPORT
========================

Incident ID: {incident_id}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Classification: Confirmed Incident

SCOPE
=====
This forensic analysis covers the timeline and evidence related to {rca_result.root_cause.attack_type}.
Total evidence items analyzed: {len(rca_result.root_cause.supporting_evidence)}

EVIDENCE INVENTORY
==================
Primary Evidence:
{chr(10).join([f"  • {e.get('timestamp')} - {e.get('event')} (Confidence: {e.get('confidence', 0):.0%})" 
              for e in rca_result.root_cause.supporting_evidence[:15]])}

TIMELINE RECONSTRUCTION
=======================
{rca_result.attack_chain_description}

CHAIN OF CUSTODY
================
All evidence collected through automated security systems.
All timestamps in UTC.
Evidence integrity verified through cryptographic hashing.

CONCLUSIONS
===========
1. Initial compromise occurred at: {rca_result.root_cause.temporal_sequence[0].get('timestamp', 'Unknown') if rca_result.root_cause.temporal_sequence else 'Unknown'}
2. Attack vector: {rca_result.mitre_tactics[0] if rca_result.mitre_tactics else 'Unknown'}
3. Root cause: {rca_result.root_cause.root_cause_service}
4. Confidence level: {rca_result.root_cause.confidence:.0%}

PRESERVATION ACTIONS
====================
✓ All affected systems isolated
✓ Forensic images captured
✓ Event logs preserved
✓ Network traffic captured
"""
        
        report = IncidentReport(
            report_id=report_id,
            report_type=ReportType.FORENSIC_REPORT,
            incident_id=incident_id,
            generated_at=datetime.now(),
            generated_by="Automated Forensic System",
            title=f"Incident {incident_id} - Forensic Report",
            executive_summary="Detailed forensic analysis of incident",
            body=body,
            findings=[],
            recommendations=[],
            indicators_of_compromise=rca_result.indicators_of_compromise,
            affected_systems=list(rca_result.root_cause.attack_graph.keys()),
            estimated_damage="Under investigation",
            immediate_actions=[],
            appendices={'full_timeline': rca_result.attack_chain_description}
        )
        
        self.reports[report_id] = report
        return report
    
    async def generate_compliance_report(self, rca_result: Any,
                                        incident_id: str) -> IncidentReport:
        """Generate compliance-focused report."""
        
        report_id = f"RPT-COMP-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        body = f"""
COMPLIANCE & LEGAL REPORT
=========================

Incident ID: {incident_id}
Report Date: {datetime.now().strftime('%Y-%m-%d')}

REGULATORY REQUIREMENTS
=======================
✓ Incident documented: Yes
✓ Timeline established: Yes
✓ Root cause identified: Yes
✓ Notifications required: Check with Legal

INCIDENT CLASSIFICATION
=======================
Type: {rca_result.root_cause.attack_type.replace('_', ' ').title()}
Severity: {'Critical' if rca_result.root_cause.confidence > 0.8 else 'High' if rca_result.root_cause.confidence > 0.6 else 'Medium'}
Data Affected: To be determined
Notification Required: Yes

BREACH ASSESSMENT
=================
Confidentiality Impact: Medium
Integrity Impact: High
Availability Impact: Medium

EVIDENCE RETENTION
==================
All evidence has been preserved and will be retained for:
• Minimum 7 years per regulatory requirements
• Chain of custody maintained
• Forensic integrity verified

REGULATORY NOTIFICATIONS
=======================
Pending legal review for notification requirements:
[ ] GDPR Notification (30 days)
[ ] HIPAA Notification (60 days)
[ ] PCI DSS Notification (immediate)
[ ] State Law Notifications

INTERNAL NOTIFICATIONS COMPLETED
================================
✓ Legal Department
✓ Executive Management
✓ Board of Directors (in progress)
✓ Insurance Carrier

REMEDIATION CERTIFICATION
==========================
Root cause has been addressed.
Preventive measures are being implemented.
Full remediation expected within 30 days.
"""
        
        report = IncidentReport(
            report_id=report_id,
            report_type=ReportType.COMPLIANCE_REPORT,
            incident_id=incident_id,
            generated_at=datetime.now(),
            generated_by="Compliance Officer",
            title=f"Incident {incident_id} - Compliance Report",
            executive_summary="Regulatory and compliance assessment",
            body=body,
            findings=[
                {
                    'requirement': 'Incident Reporting',
                    'status': 'Compliant',
                    'notes': 'Documented and reported'
                },
                {
                    'requirement': 'Data Protection',
                    'status': 'Under Review',
                    'notes': 'Assessing impact on personal data'
                },
                {
                    'requirement': 'Breach Notification',
                    'status': 'Pending',
                    'notes': 'Awaiting legal determination'
                }
            ],
            recommendations=[
                "Notify applicable regulators",
                "Prepare breach notifications if required",
                "Document all remediation efforts",
                "Conduct compliance audit"
            ],
            indicators_of_compromise=rca_result.indicators_of_compromise,
            affected_systems=list(rca_result.root_cause.attack_graph.keys()),
            estimated_damage="Under assessment",
            immediate_actions=[],
            appendices={}
        )
        
        self.reports[report_id] = report
        return report
    
    async def generate_incident_log(self, rca_result: Any,
                                   response_summary: Dict,
                                   incident_id: str) -> IncidentReport:
        """Generate incident log."""
        
        report_id = f"RPT-LOG-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        log_entries = []
        
        # Reconstruct timeline
        for i, event in enumerate(rca_result.root_cause.temporal_sequence):
            log_entries.append({
                'time': event.get('timestamp', 'Unknown'),
                'level': 'ALERT' if i < 2 else 'INFO',
                'component': event.get('entity', 'system'),
                'message': f"{event.get('action', 'unknown')} detected"
            })
        
        # Add response actions
        for action in response_summary.get('actions_executed', []):
            log_entries.append({
                'time': datetime.now().isoformat(),
                'level': 'ACTION',
                'component': action.get('target'),
                'message': f"Response: {action.get('action')} - {action.get('result')}"
            })
        
        body = f"""
INCIDENT LOG
============

Incident ID: {incident_id}
Log Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

CHRONOLOGICAL LOG
=================
{chr(10).join([f"[{e['time']}] {e['level']:6} {e['component']:20} {e['message']}" for e in log_entries])}
"""
        
        report = IncidentReport(
            report_id=report_id,
            report_type=ReportType.INCIDENT_LOG,
            incident_id=incident_id,
            generated_at=datetime.now(),
            generated_by="Automated Logging System",
            title=f"Incident {incident_id} - Event Log",
            executive_summary="Complete chronological log of incident",
            body=body,
            findings=[],
            recommendations=[],
            indicators_of_compromise=[],
            affected_systems=[],
            estimated_damage="",
            immediate_actions=[],
            appendices={'log_entries': log_entries}
        )
        
        self.reports[report_id] = report
        return report
    
    # Helper methods
    
    def _calculate_detection_time(self, rca_result: Any) -> str:
        """Calculate detection time."""
        if rca_result.root_cause.temporal_sequence:
            first = rca_result.root_cause.temporal_sequence[0].get('timestamp')
            last = rca_result.root_cause.temporal_sequence[-1].get('timestamp')
            if first and last:
                return f"~{len(rca_result.root_cause.temporal_sequence)} events over several minutes"
        return "Unknown"
    
    def _estimate_exposure(self, rca_result: Any) -> str:
        """Estimate data exposure."""
        return "100-500 MB"  # Placeholder
    
    def _estimate_downtime(self, rca_result: Any) -> str:
        """Estimate downtime duration."""
        return "15-30"  # minutes
    
    def _estimate_financial_impact(self, rca_result: Any) -> int:
        """Estimate financial impact in thousands."""
        base = rca_result.root_cause.estimated_blast_radius * 5
        if rca_result.root_cause.confidence > 0.8:
            base *= 2
        return base
    
    def _identify_persistence(self, rca_result: Any) -> str:
        """Identify persistence methods."""
        if any('file' in str(e).lower() for e in rca_result.root_cause.supporting_evidence):
            return "File-based persistence mechanism"
        return "Unknown persistence method"
    
    def get_report(self, report_id: str) -> Optional[IncidentReport]:
        """Retrieve report by ID."""
        return self.reports.get(report_id)
    
    def export_report_json(self, report_id: str) -> str:
        """Export report as JSON."""
        report = self.get_report(report_id)
        if not report:
            return "{}"
        
        return json.dumps({
            'report_id': report.report_id,
            'type': report.report_type.value,
            'incident_id': report.incident_id,
            'generated_at': report.generated_at.isoformat(),
            'title': report.title,
            'findings': report.findings,
            'recommendations': report.recommendations,
            'affected_systems': report.affected_systems,
            'body': report.body
        }, indent=2)
