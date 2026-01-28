"""Azure Cloud attack module."""

from attackmapper.core.models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    AttackStep,
    InfrastructureType,
)
from attackmapper.modules.base import BaseModule


class AzureModule(BaseModule):
    """Azure Cloud attack techniques module."""

    @property
    def infrastructure_type(self) -> InfrastructureType:
        return InfrastructureType.AZURE

    @property
    def data_file(self) -> str:
        return "azure_techniques.json"

    def get_oauth_consent_chain(self) -> AttackPath:
        """Get OAuth consent phishing attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AZ-RECON-001",   # Tenant enumeration
            "AZ-INIT-001",    # OAuth consent phishing
            "AZ-CRED-001",    # Token theft
            "AZ-PERSIST-001", # Service principal secrets
            "AZ-COLL-002",    # SharePoint data collection
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
            id="azure-oauth-consent-chain",
            name="OAuth Consent Phishing Attack Path",
            infrastructure=InfrastructureType.AZURE,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.COLLECTION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_managed_identity_chain(self) -> AttackPath:
        """Get managed identity abuse attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AZ-INIT-003",    # Compromised credentials
            "AZ-EXEC-002",    # VM Run Command
            "AZ-CRED-002",    # IMDS credential theft
            "AZ-PRIVESC-003", # Managed identity abuse
            "AZ-COLL-001",    # Blob data collection
            "AZ-EXFIL-001",   # Storage exfiltration
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
            id="azure-managed-identity-chain",
            name="Managed Identity Abuse Attack Path",
            infrastructure=InfrastructureType.AZURE,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.EXFILTRATION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_ad_connect_chain(self) -> AttackPath:
        """Get Azure AD Connect compromise attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AZ-INIT-004",    # Azure AD Connect abuse
            "AZ-PRIVESC-002", # Azure AD role assignment
            "AZ-CRED-003",    # Key Vault extraction
            "AZ-PERSIST-004", # Federated identity
            "AZ-IMPACT-001",  # Resource destruction
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
            id="azure-ad-connect-chain",
            name="Azure AD Connect Compromise Attack Path",
            infrastructure=InfrastructureType.AZURE,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.IMPACT,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_predefined_chains(self) -> list[AttackPath]:
        """Get all predefined attack chains for Azure."""
        return [
            self.get_oauth_consent_chain(),
            self.get_managed_identity_chain(),
            self.get_ad_connect_chain(),
        ]
