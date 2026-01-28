"""Tests for the Active Directory module."""

import pytest

from attackmapper.modules.ad import ADModule
from attackmapper.core.models import AttackPhase, InfrastructureType


@pytest.fixture
def ad_module():
    """Create an AD module instance."""
    module = ADModule()
    module.load_techniques()
    return module


class TestADModule:
    """Tests for the AD module."""

    def test_load_techniques(self, ad_module):
        """Test loading AD techniques."""
        techniques = ad_module.get_all_techniques()
        assert len(techniques) > 0
        # All techniques should be AD
        for tech in techniques:
            assert tech.infrastructure == InfrastructureType.ACTIVE_DIRECTORY

    def test_infrastructure_type(self, ad_module):
        """Test infrastructure type property."""
        assert ad_module.infrastructure_type == InfrastructureType.ACTIVE_DIRECTORY

    def test_data_file(self, ad_module):
        """Test data file property."""
        assert ad_module.data_file == "ad_techniques.json"

    def test_get_techniques_by_phase(self, ad_module):
        """Test getting techniques by phase."""
        # Credential access should have multiple techniques
        cred_techniques = ad_module.get_techniques_by_phase(AttackPhase.CREDENTIAL_ACCESS)
        assert len(cred_techniques) > 0

        # All should be credential access
        for tech in cred_techniques:
            assert tech.phase == AttackPhase.CREDENTIAL_ACCESS

    def test_get_techniques_by_category(self, ad_module):
        """Test getting techniques by category string."""
        # Test various category aliases
        categories = [
            ("credential_access", AttackPhase.CREDENTIAL_ACCESS),
            ("creds", AttackPhase.CREDENTIAL_ACCESS),
            ("lateral_movement", AttackPhase.LATERAL_MOVEMENT),
            ("lateral", AttackPhase.LATERAL_MOVEMENT),
            ("recon", AttackPhase.RECONNAISSANCE),
            ("privesc", AttackPhase.PRIVILEGE_ESCALATION),
        ]

        for category, expected_phase in categories:
            techniques = ad_module.get_techniques_by_category(category)
            assert len(techniques) > 0, f"No techniques found for {category}"
            for tech in techniques:
                assert tech.phase == expected_phase

    def test_get_technique_by_id(self, ad_module):
        """Test getting technique by ID."""
        # Should find Kerberoasting
        tech = ad_module.get_technique_by_id("AD-CRED-001")
        assert tech is not None
        assert "Kerberoasting" in tech.name

        # Non-existent ID
        tech = ad_module.get_technique_by_id("NONEXISTENT")
        assert tech is None

    def test_search_techniques(self, ad_module):
        """Test searching techniques."""
        # Search for kerberos
        results = ad_module.search_techniques("kerberos")
        assert len(results) > 0
        # Should find Kerberoasting at minimum

        # Search for DCSync
        results = ad_module.search_techniques("dcsync")
        assert len(results) > 0

        # Search for MITRE ID
        results = ad_module.search_techniques("T1558")
        assert len(results) > 0

    def test_generate_full_chain(self, ad_module):
        """Test generating full attack chain."""
        chain = ad_module.generate_full_chain()
        assert chain is not None
        assert len(chain.steps) > 0
        assert chain.infrastructure == InfrastructureType.ACTIVE_DIRECTORY

    def test_generate_chain_with_phase_range(self, ad_module):
        """Test generating chain with specific phases."""
        chain = ad_module.generate_full_chain(
            start_phase=AttackPhase.CREDENTIAL_ACCESS,
            end_phase=AttackPhase.LATERAL_MOVEMENT,
        )
        assert chain is not None
        assert chain.start_phase == AttackPhase.CREDENTIAL_ACCESS
        assert chain.end_phase == AttackPhase.LATERAL_MOVEMENT

    def test_get_available_phases(self, ad_module):
        """Test getting available phases."""
        phases = ad_module.get_available_phases()
        assert len(phases) > 0
        # Should have at least recon, initial access, credential access, lateral movement
        assert AttackPhase.RECONNAISSANCE in phases
        assert AttackPhase.CREDENTIAL_ACCESS in phases
        assert AttackPhase.LATERAL_MOVEMENT in phases

    def test_get_technique_count_by_phase(self, ad_module):
        """Test getting technique counts by phase."""
        counts = ad_module.get_technique_count_by_phase()
        assert len(counts) > 0
        # Credential access should have several techniques
        assert counts.get(AttackPhase.CREDENTIAL_ACCESS, 0) > 0

    def test_predefined_chains(self, ad_module):
        """Test predefined attack chains."""
        chains = ad_module.get_predefined_chains()
        assert len(chains) >= 3  # Kerberoasting, DCSync, ADCS chains

        # Verify chain structure
        for chain in chains:
            assert len(chain.steps) > 0
            assert chain.infrastructure == InfrastructureType.ACTIVE_DIRECTORY

    def test_kerberoasting_chain(self, ad_module):
        """Test Kerberoasting attack chain."""
        chain = ad_module.get_kerberoasting_chain()
        assert chain is not None
        assert "Kerberoasting" in chain.name
        assert len(chain.steps) > 0

    def test_dcsync_chain(self, ad_module):
        """Test DCSync attack chain."""
        chain = ad_module.get_dcsync_chain()
        assert chain is not None
        assert "DCSync" in chain.name
        assert len(chain.steps) > 0

    def test_adcs_chain(self, ad_module):
        """Test AD CS attack chain."""
        chain = ad_module.get_adcs_chain()
        assert chain is not None
        assert "ADCS" in chain.name or "CS" in chain.name
        assert len(chain.steps) > 0


class TestADTechniquesContent:
    """Tests for specific AD techniques content."""

    def test_kerberoasting_technique(self, ad_module):
        """Test Kerberoasting technique details."""
        tech = ad_module.get_technique_by_id("AD-CRED-001")
        assert tech is not None
        assert tech.mitre_id == "T1558.003"
        assert "Kerberoast" in tech.name
        assert len(tech.tools) > 0
        assert any("Rubeus" in t for t in tech.tools) or any("Impacket" in t for t in tech.tools)
        assert tech.risk_level == "high"

    def test_dcsync_technique(self, ad_module):
        """Test DCSync technique details."""
        tech = ad_module.get_technique_by_id("AD-CRED-004")
        assert tech is not None
        assert tech.mitre_id == "T1003.006"
        assert "DCSync" in tech.name
        assert tech.risk_level == "critical"
        assert "KRBTGT" in tech.description or "hash" in tech.description.lower()

    def test_pass_the_hash_technique(self, ad_module):
        """Test Pass-the-Hash technique details."""
        tech = ad_module.get_technique_by_id("AD-LATERAL-001")
        assert tech is not None
        assert tech.mitre_id == "T1550.002"
        assert "Pass-the-Hash" in tech.name
        assert tech.phase == AttackPhase.LATERAL_MOVEMENT

    def test_golden_ticket_technique(self, ad_module):
        """Test Golden Ticket technique details."""
        tech = ad_module.get_technique_by_id("AD-CRED-006")
        assert tech is not None
        assert "Golden Ticket" in tech.name
        assert tech.risk_level == "critical"

    def test_all_techniques_have_required_fields(self, ad_module):
        """Test that all techniques have required fields."""
        techniques = ad_module.get_all_techniques()
        for tech in techniques:
            assert tech.id, f"Technique missing ID"
            assert tech.mitre_id, f"Technique {tech.id} missing MITRE ID"
            assert tech.name, f"Technique {tech.id} missing name"
            assert tech.description, f"Technique {tech.id} missing description"
            assert tech.phase, f"Technique {tech.id} missing phase"
            assert tech.risk_level in ["low", "medium", "high", "critical"], \
                f"Technique {tech.id} has invalid risk level: {tech.risk_level}"
