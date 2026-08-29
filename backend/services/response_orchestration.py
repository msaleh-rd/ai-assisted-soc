"""Phase 3 - Response Orchestration & Adaptive Investigation

Implements automated response execution, adaptive data collection, and incident lifecycle management.
"""

from typing import List, Dict, Optional, Any, Coroutine
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import uuid


class ActionStatus(Enum):
    """Status of a response action."""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class AdaptiveLoopPhase(Enum):
    """Phases of adaptive investigation loop."""
    INITIAL_ANALYSIS = "initial_analysis"
    GAP_IDENTIFICATION = "gap_identification"
    ADDITIONAL_DATA_COLLECTION = "additional_data_collection"
    RE_ANALYSIS = "re_analysis"
    CONFIDENCE_ASSESSMENT = "confidence_assessment"
    ESCALATION_CHECK = "escalation_check"


@dataclass
class ActionExecutionLog:
    """Log entry for action execution."""
    action_id: str
    action_type: str
    target: str
    timestamp: datetime
    status: ActionStatus
    result: str
    error_message: Optional[str] = None
    duration_seconds: int = 0


@dataclass
class AdaptiveInvestigationIteration:
    """Single iteration of adaptive investigation."""
    iteration_num: int
    started_at: datetime
    ended_at: Optional[datetime]
    phase: AdaptiveLoopPhase
    data_collected: List[Dict]
    gaps_addressed: List[str]
    confidence_improvement: float
    new_findings: List[str]


class ResponseOrchestrator:
    """Orchestrates automated response actions."""
    
    def __init__(self, approval_required: bool = True):
        """
        Initialize response orchestrator.
        
        Args:
            approval_required: Whether to require approval before executing actions
        """
        self.approval_required = approval_required
        self.execution_log: List[ActionExecutionLog] = []
        self.pending_approvals: Dict[str, Dict] = {}
        self.active_actions: Dict[str, Dict] = {}
    
    async def execute_response_plan(self,
                                   rca_result: Any,
                                   approval_callback: Optional[Coroutine] = None) -> Dict[str, Any]:
        """
        Execute full response plan from RCA result.
        
        Args:
            rca_result: RCAResult from RCA engine
            approval_callback: Async callback for approval workflow
            
        Returns:
            Response execution summary
        """
        
        response_summary = {
            'status': 'executing',
            'started_at': datetime.now(),
            'actions_executed': [],
            'actions_failed': [],
            'total_actions': 0,
            'success_rate': 0.0
        }
        
        # Phase 1: Immediate containment actions
        immediate = rca_result.immediate_actions
        response_summary['total_actions'] = len(immediate)
        
        for action in immediate:
            action_result = await self._execute_action(
                action=action,
                approval_callback=approval_callback,
                phase="containment"
            )
            
            if action_result['success']:
                response_summary['actions_executed'].append({
                    'action': action.action.value,
                    'target': action.target,
                    'result': action_result.get('result')
                })
            else:
                response_summary['actions_failed'].append({
                    'action': action.action.value,
                    'target': action.target,
                    'error': action_result.get('error')
                })
        
        # Phase 2: Parallel long-term remediation (with less urgency)
        remediation = rca_result.long_term_remediation
        for action in remediation:
            self._schedule_remediation_action(action)
        
        response_summary['actions_scheduled'] = len(remediation)
        
        # Calculate success rate
        if response_summary['total_actions'] > 0:
            response_summary['success_rate'] = (
                len(response_summary['actions_executed']) / 
                response_summary['total_actions']
            )
        
        response_summary['status'] = 'completed'
        response_summary['completed_at'] = datetime.now()
        response_summary['duration_seconds'] = (
            response_summary['completed_at'] - response_summary['started_at']
        ).total_seconds()
        
        return response_summary
    
    async def _execute_action(self,
                             action: Any,
                             approval_callback: Optional[Coroutine],
                             phase: str) -> Dict[str, Any]:
        """Execute a single response action."""
        
        action_id = str(uuid.uuid4())
        
        try:
            # Check approval if required
            if self.approval_required:
                approval = await self._request_approval(action, approval_callback)
                if not approval:
                    return {
                        'success': False,
                        'error': 'Approval denied'
                    }
            
            # Execute based on action type
            result = await self._execute_by_type(action, action_id)
            
            # Log execution
            self.execution_log.append(ActionExecutionLog(
                action_id=action_id,
                action_type=action.action.value,
                target=action.target,
                timestamp=datetime.now(),
                status=ActionStatus.COMPLETED if result['success'] else ActionStatus.FAILED,
                result=result.get('result', 'No result'),
                error_message=result.get('error'),
                duration_seconds=int(result.get('duration', 0))
            ))
            
            return result
        
        except Exception as e:
            self.execution_log.append(ActionExecutionLog(
                action_id=action_id,
                action_type=action.action.value,
                target=action.target,
                timestamp=datetime.now(),
                status=ActionStatus.FAILED,
                result='Exception during execution',
                error_message=str(e),
                duration_seconds=0
            ))
            
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _execute_by_type(self, action: Any, action_id: str) -> Dict[str, Any]:
        """Execute action based on type via ResponseSkillExecutor."""
        from backend.services.response.skill_handlers import ResponseSkillExecutor
        
        start_time = datetime.now()
        action_name = action.action.value if hasattr(action.action, "value") else str(action.action)
        
        result = await ResponseSkillExecutor.execute_skill(
            skill_name=action_name,
            target=action.target,
            parameters={"description": getattr(action, "description", ""), "priority": getattr(action, "priority", "")}
        )
        
        end_time = datetime.now()
        result['duration'] = (end_time - start_time).total_seconds()
        
        return result
    
    async def _request_approval(self, action: Any, 
                               approval_callback: Optional[Coroutine]) -> bool:
        """Request approval for action."""
        
        approval_request = {
            'action': action.action.value,
            'target': action.target,
            'description': action.description,
            'priority': action.priority,
            'business_impact': action.business_impact,
            'prerequisites': action.prerequisites
        }
        
        self.pending_approvals[str(uuid.uuid4())] = approval_request
        
        if approval_callback:
            approved = await approval_callback(approval_request)
            return approved
        
        # Default: auto-approve critical actions, require approval for others
        return action.priority == "critical"
    
    def _schedule_remediation_action(self, action: Any) -> None:
        """Schedule remediation action for later execution."""
        
        self.active_actions[str(uuid.uuid4())] = {
            'action': action,
            'scheduled_for': datetime.now() + timedelta(hours=1),
            'status': ActionStatus.PENDING
        }
    
    # Action implementations (integrate with actual systems)
    
    async def _isolate_host(self, target: str) -> Dict[str, Any]:
        """Isolate host via EDR API."""
        import os, httpx
        edr_key = os.getenv("EDR_API_KEY")
        if not edr_key:
            # Fallback to simulation if no key
            await asyncio.sleep(0.5)
            return {'success': True, 'result': f'[MOCK] Host {target} isolated from network', 'action_type': 'isolate_host'}
            
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.edr.example.com/v1/hosts/isolate",
                    headers={"Authorization": f"Bearer {edr_key}"},
                    json={"hostname": target}
                )
                response.raise_for_status()
                return {'success': True, 'result': f'Host {target} successfully isolated', 'action_type': 'isolate_host'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'action_type': 'isolate_host'}
    
    async def _reset_credentials(self, target: str) -> Dict[str, Any]:
        """Reset credential via IAM API."""
        import os, httpx
        iam_key = os.getenv("IAM_API_KEY")
        if not iam_key:
            await asyncio.sleep(0.3)
            return {'success': True, 'result': f'[MOCK] Credentials reset for {target}', 'action_type': 'reset_credentials'}
            
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.iam.example.com/v1/users/reset_password",
                    headers={"Authorization": f"Bearer {iam_key}"},
                    json={"username": target}
                )
                response.raise_for_status()
                return {'success': True, 'result': f'Credentials successfully reset for {target}', 'action_type': 'reset_credentials'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'action_type': 'reset_credentials'}
    
    async def _block_ip(self, target: str) -> Dict[str, Any]:
        """Block IP via Firewall API."""
        import os, httpx
        fw_key = os.getenv("FIREWALL_API_KEY")
        if not fw_key:
            await asyncio.sleep(0.2)
            return {'success': True, 'result': f'[MOCK] IP {target} blocked in firewall', 'action_type': 'block_ip'}
            
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.firewall.example.com/v1/rules/block",
                    headers={"Authorization": f"Bearer {fw_key}"},
                    json={"ip": target}
                )
                response.raise_for_status()
                return {'success': True, 'result': f'IP {target} blocked', 'action_type': 'block_ip'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'action_type': 'block_ip'}
    
    async def _block_domain(self, target: str) -> Dict[str, Any]:
        """Simulate domain blocking."""
        await asyncio.sleep(0.2)
        return {
            'success': True,
            'result': f'Domain {target} blocked in DNS'
        }
    
    async def _kill_process(self, target: str) -> Dict[str, Any]:
        """Simulate process termination."""
        await asyncio.sleep(0.3)
        return {
            'success': True,
            'result': f'Process {target} terminated'
        }
    
    async def _revoke_mfa(self, target: str) -> Dict[str, Any]:
        """Simulate MFA revocation."""
        await asyncio.sleep(0.2)
        return {
            'success': True,
            'result': f'MFA devices revoked for {target}'
        }
    
    async def _disable_account(self, target: str) -> Dict[str, Any]:
        """Simulate account disabling."""
        await asyncio.sleep(0.3)
        return {
            'success': True,
            'result': f'Account {target} disabled'
        }
    
    async def _patch_system(self, target: str) -> Dict[str, Any]:
        """Simulate system patching."""
        await asyncio.sleep(2.0)  # Patching takes longer
        return {
            'success': True,
            'result': f'System {target} patched and restarted'
        }
    
    async def _enable_mfa(self, target: str) -> Dict[str, Any]:
        """Simulate MFA enablement."""
        await asyncio.sleep(0.3)
        return {
            'success': True,
            'result': f'MFA enabled for {target}'
        }
    
    async def _update_firewall(self, target: str) -> Dict[str, Any]:
        """Simulate firewall update."""
        await asyncio.sleep(0.5)
        return {
            'success': True,
            'result': f'Firewall rules updated for {target}'
        }


class AdaptiveInvestigationManager:
    """Manages adaptive investigation loops for low-confidence cases."""
    
    def __init__(self, max_iterations: int = 3, confidence_threshold: float = 0.7):
        """
        Initialize adaptive investigation manager.
        
        Args:
            max_iterations: Maximum number of investigation iterations
            confidence_threshold: Target confidence level
        """
        self.max_iterations = max_iterations
        self.confidence_threshold = confidence_threshold
        self.iterations: List[AdaptiveInvestigationIteration] = []
    
    async def run_adaptive_loop(self,
                               investigation_package: Any,
                               rca_result: Any,
                               data_collector: Any) -> Any:
        """
        Run adaptive investigation loop.
        
        If confidence is low, collect additional data and re-analyze.
        
        Args:
            investigation_package: Original investigation package
            rca_result: Initial RCA result
            data_collector: Function to collect additional data
            
        Returns:
            Updated RCA result with improved confidence
        """
        
        current_result = rca_result
        iteration_num = 0
        
        while (iteration_num < self.max_iterations and 
               current_result.root_cause.confidence < self.confidence_threshold):
            
            iteration_num += 1
            print(f"\n🔄 [Adaptive Loop] Iteration {iteration_num}/{self.max_iterations}")
            print(f"   Current confidence: {current_result.root_cause.confidence:.0%}")
            
            # Identify gaps
            gaps = current_result.investigation_gaps
            if not gaps:
                break
            
            print(f"   Identified gaps: {len(gaps)}")
            
            # Collect additional data
            iteration_start = datetime.now()
            
            new_data = await self._collect_additional_data(
                gaps=gaps,
                data_collector=data_collector
            )
            
            print(f"   Collected {len(new_data)} additional events")
            
            # Re-analyze with new data
            enriched_package = self._enrich_investigation_package(
                investigation_package=investigation_package,
                new_data=new_data,
                iteration_num=iteration_num
            )
            
            # Re-run RCA (stub - in production would re-run full pipeline)
            improved_result = self._simulate_re_analysis(
                enriched_package=enriched_package,
                previous_result=current_result
            )
            
            # Log iteration
            self.iterations.append(AdaptiveInvestigationIteration(
                iteration_num=iteration_num,
                started_at=iteration_start,
                ended_at=datetime.now(),
                phase=AdaptiveLoopPhase.RE_ANALYSIS,
                data_collected=new_data,
                gaps_addressed=[g.gap_type for g in gaps],
                confidence_improvement=(
                    improved_result.root_cause.confidence - 
                    current_result.root_cause.confidence
                ),
                new_findings=[f"Confidence improved to {improved_result.root_cause.confidence:.0%}"]
            ))
            
            current_result = improved_result
            
            print(f"   ✅ Confidence improved to {current_result.root_cause.confidence:.0%}")
        
        if current_result.root_cause.confidence >= self.confidence_threshold:
            print(f"\n✅ [Adaptive Loop] Confidence threshold reached: {current_result.root_cause.confidence:.0%}")
        else:
            print(f"\n⚠️  [Adaptive Loop] Max iterations reached. Final confidence: {current_result.root_cause.confidence:.0%}")
        
        return current_result
    
    async def _collect_additional_data(self, gaps: List[Any], 
                                      data_collector: Any) -> List[Dict]:
        """Collect additional data to address identified gaps."""
        
        new_data = []
        
        for gap in gaps:
            print(f"   📊 Collecting data for gap: {gap.gap_type}")
            
            # Query data source
            collected = await data_collector(gap.recommended_query)
            
            new_data.extend(collected)
        
        return new_data
    
    def _enrich_investigation_package(self, investigation_package: Any,
                                     new_data: List[Dict],
                                     iteration_num: int) -> Any:
        """Enrich investigation package with new data."""
        
        # Create enriched copy
        enriched = investigation_package
        
        # Add new events
        for event in new_data:
            enriched.raw_events.append(event)
        
        print(f"   Total events now: {len(enriched.raw_events)}")
        
        return enriched
    
    def _simulate_re_analysis(self, enriched_package: Any,
                            previous_result: Any) -> Any:
        """Simulate re-analysis with new data."""
        
        # Stub: simulate confidence improvement
        improvement = min(0.15, (1.0 - previous_result.root_cause.confidence) * 0.5)
        
        new_confidence = min(
            1.0,
            previous_result.root_cause.confidence + improvement
        )
        
        # Return updated result
        updated_result = previous_result
        updated_result.root_cause.confidence = new_confidence
        
        return updated_result


class IncidentLifecycleManager:
    """Manages incident lifecycle from detection to closure."""
    
    def __init__(self):
        self.incidents: Dict[str, Dict] = {}
    
    async def create_incident(self, rca_result: Any) -> str:
        """Create new incident record."""
        
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        self.incidents[incident_id] = {
            'id': incident_id,
            'created_at': datetime.now(),
            'rca_result': rca_result,
            'status': 'open',
            'severity': self._assess_severity(rca_result),
            'timeline': [],
            'actions_executed': [],
            'actions_pending': [],
            'closed_at': None,
            'closure_notes': None
        }
        
        # Add creation event to timeline
        self._add_timeline_event(incident_id, 'incident_created', 'Incident created and RCA performed')
        
        return incident_id
    
    async def execute_incident_response(self, incident_id: str,
                                       orchestrator: ResponseOrchestrator) -> Dict[str, Any]:
        """Execute response for incident."""
        
        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}
        
        incident = self.incidents[incident_id]
        
        # Execute response plan
        response_summary = await orchestrator.execute_response_plan(
            rca_result=incident['rca_result']
        )
        
        # Update incident
        incident['status'] = 'responding'
        incident['actions_executed'] = response_summary['actions_executed']
        incident['actions_pending'] = response_summary.get('actions_scheduled', 0)
        
        self._add_timeline_event(incident_id, 'response_executed', 
                                f"Executed {len(response_summary['actions_executed'])} actions")
        
        return response_summary
    
    async def close_incident(self, incident_id: str, 
                            closure_notes: str,
                            lessons_learned: Optional[List[str]] = None) -> Dict[str, Any]:
        """Close incident."""
        
        if incident_id not in self.incidents:
            return {'error': 'Incident not found'}
        
        incident = self.incidents[incident_id]
        incident['status'] = 'closed'
        incident['closed_at'] = datetime.now()
        incident['closure_notes'] = closure_notes
        incident['lessons_learned'] = lessons_learned or []
        
        self._add_timeline_event(incident_id, 'incident_closed', closure_notes)
        
        return {
            'incident_id': incident_id,
            'status': 'closed',
            'duration_hours': (incident['closed_at'] - incident['created_at']).total_seconds() / 3600,
            'lessons_learned': lessons_learned
        }
    
    def _assess_severity(self, rca_result: Any) -> str:
        """Assess incident severity."""
        
        if rca_result.root_cause.estimated_blast_radius > 100:
            return 'critical'
        elif rca_result.root_cause.estimated_blast_radius > 50:
            return 'high'
        elif rca_result.root_cause.estimated_blast_radius > 10:
            return 'medium'
        else:
            return 'low'
    
    def _add_timeline_event(self, incident_id: str, event_type: str, 
                           description: str) -> None:
        """Add event to incident timeline."""
        
        self.incidents[incident_id]['timeline'].append({
            'timestamp': datetime.now(),
            'type': event_type,
            'description': description
        })
    
    def get_incident(self, incident_id: str) -> Optional[Dict]:
        """Retrieve incident details."""
        
        return self.incidents.get(incident_id)
    
    def list_incidents(self, status: Optional[str] = None) -> List[Dict]:
        """List incidents, optionally filtered by status."""
        
        incidents = list(self.incidents.values())
        
        if status:
            incidents = [i for i in incidents if i['status'] == status]
        
        return incidents
