"""GCP Cloud attack module."""

from attackmapper.core.models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    AttackStep,
    InfrastructureType,
)
from attackmapper.modules.base import BaseModule


class GCPModule(BaseModule):
    """GCP Cloud attack techniques module."""

    @property
    def infrastructure_type(self) -> InfrastructureType:
        return InfrastructureType.GCP

    @property
    def data_file(self) -> str:
        return "gcp_techniques.json"

    def get_service_account_chain(self) -> AttackPath:
        """Get service account privilege escalation chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "GCP-INIT-001",    # Compromised credentials
            "GCP-RECON-002",   # IAM enumeration
            "GCP-PRIVESC-002", # Service account impersonation
            "GCP-PERSIST-001", # SA key creation
            "GCP-DEFENSE-001", # Disable logging
        ]

        steps = []
        step_num = 1
        for tech_id in chain_technique_ids:
            tech = self.get_technique_by_id(tech_id)
            if tech:
                steps.append(AttackStep(
                    step_number=step_num,
                    technique=tech,
                    description=tech.description,
                ))
                step_num += 1

        return AttackPath(
            id="gcp-sa-privesc-chain",
            name="Service Account Privilege Escalation Path",
            infrastructure=InfrastructureType.GCP,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.DEFENSE_EVASION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_metadata_chain(self) -> AttackPath:
        """Get metadata server attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "GCP-INIT-002",    # Exploit public app
            "GCP-CRED-001",    # Metadata credential theft
            "GCP-PRIVESC-001", # IAM policy privesc
            "GCP-COLL-001",    # GCS data collection
            "GCP-EXFIL-001",   # GCS exfiltration
        ]

        steps = []
        step_num = 1
        for tech_id in chain_technique_ids:
            tech = self.get_technique_by_id(tech_id)
            if tech:
                steps.append(AttackStep(
                    step_number=step_num,
                    technique=tech,
                    description=tech.description,
                ))
                step_num += 1

        return AttackPath(
            id="gcp-metadata-chain",
            name="Metadata Server Attack Path",
            infrastructure=InfrastructureType.GCP,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.EXFILTRATION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_gke_chain(self) -> AttackPath:
        """Get GKE cluster compromise chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "GCP-INIT-001",    # Compromised credentials
            "GCP-DISC-002",    # GKE discovery
            "GCP-CRED-003",    # GKE SA token theft
            "GCP-LATERAL-002", # Pod-to-pod movement
            "GCP-COLL-002",    # BigQuery extraction
        ]

        steps = []
        step_num = 1
        for tech_id in chain_technique_ids:
            tech = self.get_technique_by_id(tech_id)
            if tech:
                steps.append(AttackStep(
                    step_number=step_num,
                    technique=tech,
                    description=tech.description,
                ))
                step_num += 1

        return AttackPath(
            id="gcp-gke-chain",
            name="GKE Cluster Compromise Path",
            infrastructure=InfrastructureType.GCP,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.COLLECTION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_predefined_chains(self) -> list[AttackPath]:
        """Get all predefined attack chains for GCP."""
        return [
            self.get_service_account_chain(),
            self.get_metadata_chain(),
            self.get_gke_chain(),
        ]
