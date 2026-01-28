"""Base module class for infrastructure attack modules."""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from attackmapper.core.models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    InfrastructureType,
)
from attackmapper.core.engine import AttackPathEngine


class BaseModule(ABC):
    """Base class for all infrastructure attack modules."""

    def __init__(self):
        self.engine = AttackPathEngine()
        self.techniques: list[AttackTechnique] = []
        self._loaded = False

    @property
    @abstractmethod
    def infrastructure_type(self) -> InfrastructureType:
        """Return the infrastructure type for this module."""
        pass

    @property
    @abstractmethod
    def data_file(self) -> str:
        """Return the filename of the techniques data file."""
        pass

    def load_techniques(self) -> list[AttackTechnique]:
        """Load techniques from the data file."""
        if self._loaded:
            return self.techniques

        data_path = Path(__file__).parent.parent / "data" / self.data_file
        if not data_path.exists():
            raise FileNotFoundError(f"Techniques data file not found: {data_path}")

        with open(data_path) as f:
            data = json.load(f)

        self.techniques = []
        for tech_data in data.get("techniques", []):
            technique = AttackTechnique(
                id=tech_data["id"],
                mitre_id=tech_data["mitre_id"],
                name=tech_data["name"],
                phase=AttackPhase(tech_data["phase"]),
                infrastructure=InfrastructureType(tech_data["infrastructure"]),
                description=tech_data["description"],
                prerequisites=tech_data.get("prerequisites", []),
                tools=tech_data.get("tools", []),
                commands=tech_data.get("commands", []),
                detection=tech_data.get("detection", ""),
                references=tech_data.get("references", []),
                next_techniques=tech_data.get("next_techniques", []),
                risk_level=tech_data.get("risk_level", "medium"),
            )
            self.techniques.append(technique)

        self.engine.load_techniques(self.techniques)
        self._loaded = True
        return self.techniques

    def get_all_techniques(self) -> list[AttackTechnique]:
        """Get all techniques for this infrastructure."""
        if not self._loaded:
            self.load_techniques()
        return self.techniques

    def get_techniques_by_phase(self, phase: AttackPhase) -> list[AttackTechnique]:
        """Get techniques for a specific attack phase."""
        if not self._loaded:
            self.load_techniques()
        return [t for t in self.techniques if t.phase == phase]

    def get_techniques_by_category(self, category: str) -> list[AttackTechnique]:
        """Get techniques by category (phase name as string)."""
        if not self._loaded:
            self.load_techniques()

        # Map common category names to phases
        category_map = {
            "recon": AttackPhase.RECONNAISSANCE,
            "reconnaissance": AttackPhase.RECONNAISSANCE,
            "initial": AttackPhase.INITIAL_ACCESS,
            "initial_access": AttackPhase.INITIAL_ACCESS,
            "execution": AttackPhase.EXECUTION,
            "persistence": AttackPhase.PERSISTENCE,
            "privesc": AttackPhase.PRIVILEGE_ESCALATION,
            "privilege_escalation": AttackPhase.PRIVILEGE_ESCALATION,
            "defense_evasion": AttackPhase.DEFENSE_EVASION,
            "evasion": AttackPhase.DEFENSE_EVASION,
            "credential_access": AttackPhase.CREDENTIAL_ACCESS,
            "credentials": AttackPhase.CREDENTIAL_ACCESS,
            "creds": AttackPhase.CREDENTIAL_ACCESS,
            "discovery": AttackPhase.DISCOVERY,
            "lateral": AttackPhase.LATERAL_MOVEMENT,
            "lateral_movement": AttackPhase.LATERAL_MOVEMENT,
            "collection": AttackPhase.COLLECTION,
            "exfil": AttackPhase.EXFILTRATION,
            "exfiltration": AttackPhase.EXFILTRATION,
            "impact": AttackPhase.IMPACT,
        }

        phase = category_map.get(category.lower())
        if phase:
            return self.get_techniques_by_phase(phase)
        return []

    def get_technique_by_id(self, technique_id: str) -> Optional[AttackTechnique]:
        """Get a specific technique by ID."""
        if not self._loaded:
            self.load_techniques()
        return self.engine.get_technique_by_id(technique_id)

    def search_techniques(self, query: str) -> list[AttackTechnique]:
        """Search techniques by name, description, or MITRE ID."""
        if not self._loaded:
            self.load_techniques()
        return self.engine.search_techniques(query, self.infrastructure_type)

    def generate_full_chain(
        self,
        start_phase: Optional[AttackPhase] = None,
        end_phase: Optional[AttackPhase] = None,
    ) -> AttackPath:
        """Generate a full attack chain."""
        if not self._loaded:
            self.load_techniques()
        return self.engine.generate_full_chain(
            self.infrastructure_type, start_phase, end_phase
        )

    def get_available_phases(self) -> list[AttackPhase]:
        """Get phases that have techniques in this module."""
        if not self._loaded:
            self.load_techniques()
        phases = set(t.phase for t in self.techniques)
        # Return in kill chain order
        return [p for p in AttackPhase.get_order() if p in phases]

    def get_technique_count_by_phase(self) -> dict[AttackPhase, int]:
        """Get count of techniques per phase."""
        if not self._loaded:
            self.load_techniques()
        counts: dict[AttackPhase, int] = {}
        for tech in self.techniques:
            counts[tech.phase] = counts.get(tech.phase, 0) + 1
        return counts
