"""Data models for AttackMapper."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AttackPhase(str, Enum):
    """Attack phases following the kill chain."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

    @classmethod
    def get_display_name(cls, phase: "AttackPhase") -> str:
        """Get human-readable display name for a phase."""
        display_names = {
            cls.RECONNAISSANCE: "Reconnaissance",
            cls.INITIAL_ACCESS: "Initial Access",
            cls.EXECUTION: "Execution",
            cls.PERSISTENCE: "Persistence",
            cls.PRIVILEGE_ESCALATION: "Privilege Escalation",
            cls.DEFENSE_EVASION: "Defense Evasion",
            cls.CREDENTIAL_ACCESS: "Credential Access",
            cls.DISCOVERY: "Discovery",
            cls.LATERAL_MOVEMENT: "Lateral Movement",
            cls.COLLECTION: "Collection",
            cls.EXFILTRATION: "Exfiltration",
            cls.IMPACT: "Impact",
        }
        return display_names.get(phase, phase.value)

    @classmethod
    def get_order(cls) -> list["AttackPhase"]:
        """Get phases in kill chain order."""
        return [
            cls.RECONNAISSANCE,
            cls.INITIAL_ACCESS,
            cls.EXECUTION,
            cls.PERSISTENCE,
            cls.PRIVILEGE_ESCALATION,
            cls.DEFENSE_EVASION,
            cls.CREDENTIAL_ACCESS,
            cls.DISCOVERY,
            cls.LATERAL_MOVEMENT,
            cls.COLLECTION,
            cls.EXFILTRATION,
            cls.IMPACT,
        ]


class InfrastructureType(str, Enum):
    """Supported infrastructure types."""

    ACTIVE_DIRECTORY = "ad"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    NETWORK = "network"
    ONPREM = "onprem"


class AttackTechnique(BaseModel):
    """Represents a single attack technique."""

    id: str = Field(..., description="Unique technique ID, e.g., AD-CRED-001")
    mitre_id: str = Field(..., description="MITRE ATT&CK ID, e.g., T1558.003")
    name: str = Field(..., description="Human-readable technique name")
    phase: AttackPhase = Field(..., description="Kill chain phase")
    infrastructure: InfrastructureType = Field(..., description="Target infrastructure")
    description: str = Field(..., description="Detailed description of the technique")
    prerequisites: list[str] = Field(default_factory=list, description="Required conditions")
    tools: list[str] = Field(default_factory=list, description="Tools that implement this")
    commands: list[str] = Field(default_factory=list, description="Example exploitation commands")
    detection: str = Field(default="", description="How defenders detect this")
    references: list[str] = Field(default_factory=list, description="External references")
    next_techniques: list[str] = Field(default_factory=list, description="Techniques this enables")
    risk_level: str = Field(default="medium", description="Risk level: low, medium, high, critical")

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "mitre_id": self.mitre_id,
            "name": self.name,
            "phase": self.phase.value,
            "infrastructure": self.infrastructure.value,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "tools": self.tools,
            "commands": self.commands,
            "detection": self.detection,
            "references": self.references,
            "next_techniques": self.next_techniques,
            "risk_level": self.risk_level,
        }


class AttackStep(BaseModel):
    """A single step in an attack path."""

    step_number: int
    technique: AttackTechnique
    description: str = Field(default="", description="Context-specific description")

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "step_number": self.step_number,
            "technique": self.technique.to_dict(),
            "description": self.description,
        }


class AttackPath(BaseModel):
    """Represents a complete attack path from start to goal."""

    id: str = Field(..., description="Unique path ID")
    name: str = Field(..., description="Path name/description")
    infrastructure: InfrastructureType
    start_phase: AttackPhase
    end_phase: AttackPhase
    steps: list[AttackStep] = Field(default_factory=list)
    total_risk_score: float = Field(default=0.0)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "infrastructure": self.infrastructure.value,
            "start_phase": self.start_phase.value,
            "end_phase": self.end_phase.value,
            "steps": [step.to_dict() for step in self.steps],
            "total_risk_score": self.total_risk_score,
        }


class ThreatActor(BaseModel):
    """Represents a known threat actor."""

    name: str = Field(..., description="Threat actor name")
    aliases: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    targeted_infrastructure: list[InfrastructureType] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list, description="List of MITRE technique IDs")
    recent_activity: str = Field(default="")
    references: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "targeted_infrastructure": [i.value for i in self.targeted_infrastructure],
            "ttps": self.ttps,
            "recent_activity": self.recent_activity,
            "references": self.references,
        }


class CVEInfo(BaseModel):
    """Represents CVE vulnerability information."""

    cve_id: str = Field(..., description="CVE identifier, e.g., CVE-2023-23397")
    description: str
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity: str = Field(default="medium")  # low, medium, high, critical
    affected_products: list[str] = Field(default_factory=list)
    affected_infrastructure: list[InfrastructureType] = Field(default_factory=list)
    exploitation_status: str = Field(default="unknown")  # unknown, poc, in-the-wild
    references: list[str] = Field(default_factory=list)
    published_date: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "affected_products": self.affected_products,
            "affected_infrastructure": [i.value for i in self.affected_infrastructure],
            "exploitation_status": self.exploitation_status,
            "references": self.references,
            "published_date": self.published_date,
        }


class ThreatIntelReport(BaseModel):
    """Aggregated threat intelligence report."""

    infrastructure: InfrastructureType
    critical_cves: list[CVEInfo] = Field(default_factory=list)
    active_threat_actors: list[ThreatActor] = Field(default_factory=list)
    trending_techniques: list[str] = Field(default_factory=list)
    last_updated: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "infrastructure": self.infrastructure.value,
            "critical_cves": [cve.to_dict() for cve in self.critical_cves],
            "active_threat_actors": [actor.to_dict() for actor in self.active_threat_actors],
            "trending_techniques": self.trending_techniques,
            "last_updated": self.last_updated,
        }
