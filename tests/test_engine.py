"""Tests for the attack path engine."""

import pytest

from attackmapper.core.engine import AttackPathEngine
from attackmapper.core.models import (
    AttackTechnique,
    AttackPhase,
    InfrastructureType,
)


@pytest.fixture
def sample_techniques():
    """Create sample techniques for testing."""
    return [
        AttackTechnique(
            id="TEST-001",
            mitre_id="T1001",
            name="Test Recon",
            phase=AttackPhase.RECONNAISSANCE,
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            description="Test reconnaissance technique",
            prerequisites=[],
            tools=["tool1"],
            detection="detection method",
            next_techniques=["TEST-002"],
            risk_level="low",
        ),
        AttackTechnique(
            id="TEST-002",
            mitre_id="T1002",
            name="Test Initial Access",
            phase=AttackPhase.INITIAL_ACCESS,
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            description="Test initial access technique",
            prerequisites=["Valid credentials"],
            tools=["tool2"],
            detection="detection method 2",
            next_techniques=["TEST-003"],
            risk_level="medium",
        ),
        AttackTechnique(
            id="TEST-003",
            mitre_id="T1003",
            name="Test Credential Access",
            phase=AttackPhase.CREDENTIAL_ACCESS,
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            description="Test credential access technique",
            prerequisites=["Local admin"],
            tools=["tool3"],
            detection="detection method 3",
            next_techniques=["TEST-004"],
            risk_level="high",
        ),
        AttackTechnique(
            id="TEST-004",
            mitre_id="T1004",
            name="Test Lateral Movement",
            phase=AttackPhase.LATERAL_MOVEMENT,
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            description="Test lateral movement technique",
            prerequisites=["Compromised credentials"],
            tools=["tool4"],
            detection="detection method 4",
            next_techniques=[],
            risk_level="critical",
        ),
    ]


@pytest.fixture
def engine(sample_techniques):
    """Create an engine with sample techniques."""
    engine = AttackPathEngine()
    engine.load_techniques(sample_techniques)
    return engine


class TestAttackPathEngine:
    """Tests for AttackPathEngine."""

    def test_load_techniques(self, engine, sample_techniques):
        """Test loading techniques into the engine."""
        assert len(engine.techniques) == len(sample_techniques)
        assert "TEST-001" in engine.techniques
        assert "TEST-004" in engine.techniques

    def test_get_techniques_by_phase(self, engine):
        """Test getting techniques by phase."""
        recon = engine.get_techniques_by_phase(AttackPhase.RECONNAISSANCE)
        assert len(recon) == 1
        assert recon[0].id == "TEST-001"

        cred = engine.get_techniques_by_phase(AttackPhase.CREDENTIAL_ACCESS)
        assert len(cred) == 1
        assert cred[0].id == "TEST-003"

    def test_get_techniques_by_phase_with_infrastructure(self, engine):
        """Test filtering by phase and infrastructure."""
        techniques = engine.get_techniques_by_phase(
            AttackPhase.RECONNAISSANCE,
            InfrastructureType.ACTIVE_DIRECTORY,
        )
        assert len(techniques) == 1

        # No AWS techniques
        techniques = engine.get_techniques_by_phase(
            AttackPhase.RECONNAISSANCE,
            InfrastructureType.AWS,
        )
        assert len(techniques) == 0

    def test_get_technique_by_id(self, engine):
        """Test getting technique by ID."""
        tech = engine.get_technique_by_id("TEST-002")
        assert tech is not None
        assert tech.name == "Test Initial Access"

        # Non-existent ID
        tech = engine.get_technique_by_id("NONEXISTENT")
        assert tech is None

    def test_get_techniques_by_mitre_id(self, engine):
        """Test getting techniques by MITRE ID."""
        techniques = engine.get_techniques_by_mitre_id("T1003")
        assert len(techniques) == 1
        assert techniques[0].id == "TEST-003"

    def test_search_techniques(self, engine):
        """Test searching techniques."""
        results = engine.search_techniques("credential")
        assert len(results) == 1
        assert results[0].id == "TEST-003"

        results = engine.search_techniques("test")
        assert len(results) == 4

        results = engine.search_techniques("nonexistent")
        assert len(results) == 0

    def test_generate_full_chain(self, engine):
        """Test generating full attack chain."""
        path = engine.generate_full_chain(InfrastructureType.ACTIVE_DIRECTORY)
        assert path is not None
        assert len(path.steps) > 0
        assert path.infrastructure == InfrastructureType.ACTIVE_DIRECTORY

    def test_generate_full_chain_with_phase_range(self, engine):
        """Test generating chain with specific phase range."""
        path = engine.generate_full_chain(
            InfrastructureType.ACTIVE_DIRECTORY,
            start_phase=AttackPhase.INITIAL_ACCESS,
            end_phase=AttackPhase.CREDENTIAL_ACCESS,
        )
        assert path is not None
        assert path.start_phase == AttackPhase.INITIAL_ACCESS
        assert path.end_phase == AttackPhase.CREDENTIAL_ACCESS

    def test_calculate_path_risk(self, engine):
        """Test risk calculation."""
        path = engine.generate_full_chain(InfrastructureType.ACTIVE_DIRECTORY)
        risk = engine.calculate_path_risk(path)

        assert "total_score" in risk
        assert "average_risk" in risk
        assert "max_risk" in risk
        assert "step_count" in risk
        assert risk["step_count"] == len(path.steps)

    def test_get_prerequisites_chain(self, engine):
        """Test getting prerequisites chain."""
        prereqs = engine.get_prerequisites_chain("TEST-003")
        # TEST-002 has TEST-003 in next_techniques
        assert any(t.id == "TEST-002" for t in prereqs)


class TestAttackTechniqueModel:
    """Tests for the AttackTechnique model."""

    def test_technique_to_dict(self, sample_techniques):
        """Test converting technique to dictionary."""
        tech = sample_techniques[0]
        data = tech.to_dict()

        assert data["id"] == "TEST-001"
        assert data["mitre_id"] == "T1001"
        assert data["phase"] == "reconnaissance"
        assert data["infrastructure"] == "ad"

    def test_technique_validation(self):
        """Test technique validation."""
        # Valid technique
        tech = AttackTechnique(
            id="VALID-001",
            mitre_id="T1000",
            name="Valid Technique",
            phase=AttackPhase.RECONNAISSANCE,
            infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
            description="A valid technique",
        )
        assert tech.id == "VALID-001"

        # Missing required fields should raise
        with pytest.raises(Exception):
            AttackTechnique(
                id="INVALID",
                mitre_id="T1000",
                # Missing name
                phase=AttackPhase.RECONNAISSANCE,
                infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
                description="Invalid",
            )
