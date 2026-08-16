"""Discovery API routes - network/host reconnaissance using pluggable skills."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Dict, Optional, Any
import re

from backend.services.discovery.agent import DiscoveryAgent
from backend.services.discovery.skill_loader import SkillLoader


router = APIRouter(prefix="/api/v3/discovery", tags=["discovery"])

# Shared instances
_loader = SkillLoader()
_agent = DiscoveryAgent()

# Input validation
IPV4_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$')


class DiscoveryScanRequest(BaseModel):
    """Request to run a discovery scan."""
    targets: List[str]
    attributes: List[str] = ["reachability", "hostname", "open_ports"]
    timeout: int = 30

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v):
        if not v:
            raise ValueError("At least one target is required")
        if len(v) > 50:
            raise ValueError("Maximum 50 targets per scan")
        for t in v:
            if not IPV4_RE.match(t) and not HOSTNAME_RE.match(t):
                raise ValueError(f"Invalid target: {t}")
        return v

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, v):
        if not v:
            raise ValueError("At least one attribute is required")
        if len(v) > 20:
            raise ValueError("Maximum 20 attributes per scan")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v < 5 or v > 120:
            raise ValueError("Timeout must be between 5 and 120 seconds")
        return v


class SkillInfo(BaseModel):
    """Skill information for listing."""
    name: str
    description: str
    collects: List[str]
    method: str
    platform: Optional[str]


class DiscoveryHostResult(BaseModel):
    """Result for a single host."""
    target: str
    status: str
    attributes: Dict[str, Any]
    provenance: Dict[str, str]
    errors: List[str]


class DiscoveryScanResponse(BaseModel):
    """Response from a discovery scan."""
    scan_id: str
    targets: List[str]
    requested_attributes: List[str]
    skills_used: List[str]
    hosts: List[DiscoveryHostResult]
    started_at: str
    completed_at: str
    duration_seconds: float


@router.get("/skills", response_model=List[SkillInfo])
async def list_skills():
    """List all available discovery skills."""
    skills = _loader.load_all()
    return [
        SkillInfo(
            name=s.name,
            description=s.description,
            collects=s.collects,
            method=s.method,
            platform=s.platform,
        )
        for s in skills
    ]


@router.get("/skills/{skill_name}", response_model=SkillInfo)
async def get_skill(skill_name: str):
    """Get details about a specific skill."""
    skill = _loader.get_skill(skill_name)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{skill_name}' not found")
    return SkillInfo(
        name=skill.name,
        description=skill.description,
        collects=skill.collects,
        method=skill.method,
        platform=skill.platform,
    )


@router.post("/scan", response_model=DiscoveryScanResponse)
async def run_discovery_scan(request: DiscoveryScanRequest):
    """
    Run a discovery scan against targets.
    
    Matches requested attributes to available skills, executes them
    against each target, and returns collected attributes with provenance.
    """
    result = await _agent.discover(
        targets=request.targets,
        attributes=request.attributes,
        timeout=request.timeout,
    )

    hosts = [
        DiscoveryHostResult(
            target=h.target,
            status=h.status,
            attributes=h.attributes,
            provenance=h.provenance,
            errors=h.errors,
        )
        for h in result.hosts
    ]

    return DiscoveryScanResponse(
        scan_id=result.scan_id,
        targets=result.targets,
        requested_attributes=result.requested_attributes,
        skills_used=result.skills_used,
        hosts=hosts,
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_seconds=result.duration_seconds,
    )


@router.post("/enrich/{target}")
async def enrich_target(target: str, attributes: Optional[List[str]] = None):
    """
    Enrich a single target with all discoverable attributes.
    
    If no attributes specified, collects all available from all skills.
    """
    if not IPV4_RE.match(target) and not HOSTNAME_RE.match(target):
        raise HTTPException(status_code=400, detail=f"Invalid target: {target}")

    if not attributes:
        # Collect all possible attributes from all skills
        all_skills = _loader.load_all()
        attributes = list({attr for s in all_skills for attr in s.collects})

    result = await _agent.discover(
        targets=[target],
        attributes=attributes,
        timeout=30,
    )

    if not result.hosts:
        raise HTTPException(status_code=500, detail="Discovery failed")

    host = result.hosts[0]
    return {
        "target": host.target,
        "status": host.status,
        "attributes": host.attributes,
        "provenance": host.provenance,
        "skills_used": result.skills_used,
        "errors": host.errors,
    }
