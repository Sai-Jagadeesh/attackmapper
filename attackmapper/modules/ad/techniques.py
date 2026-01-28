"""Active Directory attack module."""

from typing import Optional

from attackmapper.core.models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    AttackStep,
    InfrastructureType,
)
from attackmapper.modules.base import BaseModule


class ADModule(BaseModule):
    """Active Directory attack techniques module."""

    @property
    def infrastructure_type(self) -> InfrastructureType:
        return InfrastructureType.ACTIVE_DIRECTORY

    @property
    def data_file(self) -> str:
        return "ad_techniques.json"

    def get_kerberoasting_chain(self) -> AttackPath:
        """Get a common Kerberoasting attack chain."""
        if not self._loaded:
            self.load_techniques()

        # Build a typical Kerberoasting path
        chain_technique_ids = [
            "AD-RECON-001",  # LDAP Enumeration
            "AD-INIT-002",   # Password Spraying (or assume creds)
            "AD-CRED-001",   # Kerberoasting
            "AD-PRIVESC-001", # ACL Abuse (if service account has rights)
            "AD-LATERAL-001", # Pass-the-Hash
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
            id="ad-kerberoasting-chain",
            name="Kerberoasting Attack Path",
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.LATERAL_MOVEMENT,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_dcsync_chain(self) -> AttackPath:
        """Get a DCSync attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AD-RECON-003",  # BloodHound Collection
            "AD-INIT-003",   # LLMNR Poisoning
            "AD-INIT-004",   # NTLM Relay
            "AD-PRIVESC-001", # ACL Abuse
            "AD-CRED-004",   # DCSync
            "AD-PERSIST-001", # Golden Ticket
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
            id="ad-dcsync-chain",
            name="DCSync Attack Path",
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.PERSISTENCE,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_adcs_chain(self) -> AttackPath:
        """Get an AD Certificate Services abuse chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AD-RECON-001",  # LDAP Enumeration
            "AD-INIT-002",   # Password Spraying
            "AD-CRED-008",   # AD CS Abuse
            "AD-LATERAL-001", # Pass-the-Hash
            "AD-CRED-004",   # DCSync
            "AD-IMPACT-001", # Domain Takeover
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
            id="ad-adcs-chain",
            name="AD CS Abuse Attack Path",
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.IMPACT,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_predefined_chains(self) -> list[AttackPath]:
        """Get all predefined attack chains for AD."""
        return [
            self.get_kerberoasting_chain(),
            self.get_dcsync_chain(),
            self.get_adcs_chain(),
        ]
