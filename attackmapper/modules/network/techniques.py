"""Network attack module."""

from attackmapper.core.models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    AttackStep,
    InfrastructureType,
)
from attackmapper.modules.base import BaseModule


class NetworkModule(BaseModule):
    """Network attack techniques module."""

    @property
    def infrastructure_type(self) -> InfrastructureType:
        return InfrastructureType.NETWORK

    @property
    def data_file(self) -> str:
        return "network_techniques.json"

    def get_network_pivot_chain(self) -> AttackPath:
        """Get network pivoting attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "NET-RECON-001",   # Network scanning
            "NET-INIT-001",    # Exploit service
            "NET-DISC-001",    # Network discovery
            "NET-LATERAL-001", # Network pivoting
            "NET-RECON-001",   # Scan new segment
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
            id="network-pivot-chain",
            name="Network Pivoting Attack Path",
            infrastructure=InfrastructureType.NETWORK,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.LATERAL_MOVEMENT,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_mitm_chain(self) -> AttackPath:
        """Get man-in-the-middle attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "NET-RECON-003",   # Network sniffing
            "NET-CRED-002",    # Man-in-the-middle
            "NET-COLL-001",    # Traffic capture
            "NET-EXFIL-001",   # Exfiltration
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
            id="network-mitm-chain",
            name="Man-in-the-Middle Attack Path",
            infrastructure=InfrastructureType.NETWORK,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.EXFILTRATION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_device_compromise_chain(self) -> AttackPath:
        """Get network device compromise attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "NET-RECON-002",   # Device discovery
            "NET-CRED-003",    # Brute force
            "NET-EXEC-001",    # Command execution
            "NET-PERSIST-002", # Backdoor account
            "NET-DEFENSE-001", # Firewall modification
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
            id="network-device-chain",
            name="Network Device Compromise Path",
            infrastructure=InfrastructureType.NETWORK,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.DEFENSE_EVASION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_predefined_chains(self) -> list[AttackPath]:
        """Get all predefined attack chains for Network."""
        return [
            self.get_network_pivot_chain(),
            self.get_mitm_chain(),
            self.get_device_compromise_chain(),
        ]
