"""AWS Cloud attack module."""

from attackmapper.core.models import (
    AttackTechnique,
    AttackPath,
    AttackPhase,
    AttackStep,
    InfrastructureType,
)
from attackmapper.modules.base import BaseModule


class AWSModule(BaseModule):
    """AWS Cloud attack techniques module."""

    @property
    def infrastructure_type(self) -> InfrastructureType:
        return InfrastructureType.AWS

    @property
    def data_file(self) -> str:
        return "aws_techniques.json"

    def get_iam_privesc_chain(self) -> AttackPath:
        """Get IAM privilege escalation attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AWS-INIT-001",    # Compromised credentials
            "AWS-RECON-003",   # IAM enumeration
            "AWS-PRIVESC-001", # IAM policy privesc
            "AWS-PERSIST-001", # Access key creation
            "AWS-DEFENSE-001", # Disable CloudTrail
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
            id="aws-iam-privesc-chain",
            name="IAM Privilege Escalation Attack Path",
            infrastructure=InfrastructureType.AWS,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.DEFENSE_EVASION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_s3_exfil_chain(self) -> AttackPath:
        """Get S3 data exfiltration attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AWS-RECON-002",   # S3 bucket enumeration
            "AWS-INIT-003",    # Exploit public app
            "AWS-CRED-001",    # IMDS credential theft
            "AWS-COLL-001",    # S3 data collection
            "AWS-EXFIL-001",   # S3 exfiltration
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
            id="aws-s3-exfil-chain",
            name="S3 Data Exfiltration Attack Path",
            infrastructure=InfrastructureType.AWS,
            start_phase=AttackPhase.RECONNAISSANCE,
            end_phase=AttackPhase.EXFILTRATION,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_lambda_backdoor_chain(self) -> AttackPath:
        """Get Lambda backdoor attack chain."""
        if not self._loaded:
            self.load_techniques()

        chain_technique_ids = [
            "AWS-INIT-001",    # Compromised credentials
            "AWS-PRIVESC-004", # Lambda role abuse
            "AWS-EXEC-002",    # Lambda code injection
            "AWS-PERSIST-002", # Lambda backdoor
            "AWS-CRED-002",    # Extract secrets
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
            id="aws-lambda-backdoor-chain",
            name="Lambda Backdoor Attack Path",
            infrastructure=InfrastructureType.AWS,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.CREDENTIAL_ACCESS,
            steps=steps,
            total_risk_score=sum(
                {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s.technique.risk_level, 2)
                for s in steps
            ),
        )

    def get_predefined_chains(self) -> list[AttackPath]:
        """Get all predefined attack chains for AWS."""
        return [
            self.get_iam_privesc_chain(),
            self.get_s3_exfil_chain(),
            self.get_lambda_backdoor_chain(),
        ]
