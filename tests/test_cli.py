"""Tests for the CLI module."""

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmapper.cli import app


runner = CliRunner()


class TestADCommand:
    """Tests for the 'ad' command."""

    def test_ad_basic(self):
        """Test basic AD command output."""
        result = runner.invoke(app, ["ad"])
        assert result.exit_code == 0
        assert "ACTIVE DIRECTORY" in result.stdout or "Phase:" in result.stdout

    def test_ad_category_credential_access(self):
        """Test filtering by credential access category."""
        result = runner.invoke(app, ["ad", "--category", "credential_access"])
        assert result.exit_code == 0
        assert "Kerberoasting" in result.stdout or "DCSync" in result.stdout

    def test_ad_category_lateral_movement(self):
        """Test filtering by lateral movement category."""
        result = runner.invoke(app, ["ad", "--category", "lateral_movement"])
        assert result.exit_code == 0
        assert "Pass-the-Hash" in result.stdout or "lateral" in result.stdout.lower()

    def test_ad_invalid_category(self):
        """Test with invalid category."""
        result = runner.invoke(app, ["ad", "--category", "nonexistent"])
        assert result.exit_code == 1
        assert "No techniques found" in result.stdout

    def test_ad_search(self):
        """Test search functionality."""
        result = runner.invoke(app, ["ad", "--search", "kerberos"])
        assert result.exit_code == 0
        # Should find Kerberoasting or other Kerberos-related techniques

    def test_ad_export_json(self):
        """Test JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                app, ["ad", "--output", output_path, "--format", "json"]
            )
            assert result.exit_code == 0
            assert "Exported to" in result.stdout

            # Verify JSON structure
            with open(output_path) as f:
                data = json.load(f)
            assert "techniques" in data
            assert len(data["techniques"]) > 0
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_ad_export_html(self):
        """Test HTML export."""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                app, ["ad", "--output", output_path, "--format", "html"]
            )
            assert result.exit_code == 0
            assert "Exported to" in result.stdout

            # Verify HTML content
            with open(output_path) as f:
                content = f.read()
            assert "<html" in content
            assert "AD" in content.upper() and "ATTACK" in content.upper()
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestFullChainCommand:
    """Tests for the 'full-chain' command."""

    def test_full_chain_basic(self):
        """Test basic full-chain command."""
        result = runner.invoke(app, ["full-chain", "--infra", "ad"])
        assert result.exit_code == 0
        assert "Attack Chain" in result.stdout or "-->" in result.stdout

    def test_full_chain_with_phases(self):
        """Test full-chain with specific phase range."""
        result = runner.invoke(
            app,
            ["full-chain", "--infra", "ad", "--from", "initial_access", "--to", "persistence"],
        )
        assert result.exit_code == 0

    def test_full_chain_export_json(self):
        """Test full-chain JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                app,
                ["full-chain", "--infra", "ad", "--output", output_path, "--format", "json"],
            )
            assert result.exit_code == 0

            with open(output_path) as f:
                data = json.load(f)
            assert "attack_path" in data
            assert "steps" in data["attack_path"]
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_full_chain_export_html(self):
        """Test full-chain HTML export."""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                app,
                ["full-chain", "--infra", "ad", "--output", output_path, "--format", "html"],
            )
            assert result.exit_code == 0

            with open(output_path) as f:
                content = f.read()
            assert "<html" in content
            assert "Attack Chain" in content
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestThreatIntelCommand:
    """Tests for the 'threat-intel' command."""

    def test_threat_intel_basic(self):
        """Test basic threat-intel command."""
        result = runner.invoke(app, ["threat-intel", "--infra", "ad"])
        assert result.exit_code == 0
        # Should contain CVE info or threat actors
        assert "CVE" in result.stdout or "Threat" in result.stdout.upper()

    def test_threat_intel_export_json(self):
        """Test threat-intel JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            result = runner.invoke(
                app,
                ["threat-intel", "--infra", "ad", "--output", output_path, "--format", "json"],
            )
            assert result.exit_code == 0

            with open(output_path) as f:
                data = json.load(f)
            assert "threat_intel" in data
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestOtherCommands:
    """Tests for other CLI commands."""

    def test_version(self):
        """Test version command."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "AttackMapper" in result.stdout

    def test_stats(self):
        """Test stats command."""
        result = runner.invoke(app, ["stats"])
        assert result.exit_code == 0
        assert "Active Directory" in result.stdout

    def test_aws_command(self):
        """Test AWS command displays techniques."""
        result = runner.invoke(app, ["aws"])
        assert result.exit_code == 0
        assert "AWS" in result.stdout.upper()
        assert "phase" in result.stdout.lower()

    def test_azure_command(self):
        """Test Azure command displays techniques."""
        result = runner.invoke(app, ["azure"])
        assert result.exit_code == 0
        assert "AZURE" in result.stdout.upper()
        assert "phase" in result.stdout.lower()

    def test_gcp_command(self):
        """Test GCP command displays techniques."""
        result = runner.invoke(app, ["gcp"])
        assert result.exit_code == 0
        assert "GCP" in result.stdout.upper()
        assert "phase" in result.stdout.lower()

    def test_network_command(self):
        """Test Network command displays techniques."""
        result = runner.invoke(app, ["network"])
        assert result.exit_code == 0
        assert "NETWORK" in result.stdout.upper()
        assert "phase" in result.stdout.lower()
