"""Threat intelligence manager coordinating all intel sources."""

import asyncio
from datetime import datetime
from typing import Optional, Callable

import os
from attackmapper.core.models import (
    CVEInfo,
    ThreatActor,
    ThreatIntelReport,
    InfrastructureType,
)
from .cache import IntelCache
from .otx import OTXClient
from .cve import CVEClient
from .cisa_kev import CISAKEVClient
from .custom_feeds import CustomFeedClient
from .sources import BUILTIN_SOURCES, IntelSource, get_default_sources, get_source


class ThreatIntelManager:
    """Coordinates threat intelligence from multiple sources."""

    def __init__(self, cache_path: Optional[str] = None):
        self.cache = IntelCache(cache_path)
        self.otx = OTXClient()
        self.cve_client = CVEClient()
        self.kev_client = CISAKEVClient()
        self.custom_feed_client = CustomFeedClient()

    def _get_builtin_threat_actors(
        self, infrastructure: InfrastructureType
    ) -> list[ThreatActor]:
        """Get built-in threat actor data for when APIs are unavailable."""
        # Built-in threat actors targeting AD
        ad_actors = [
            ThreatActor(
                name="APT29 (Cozy Bear)",
                aliases=["The Dukes", "NOBELIUM", "Midnight Blizzard"],
                description="Russian state-sponsored group known for sophisticated attacks on government and enterprise networks",
                targeted_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY, InfrastructureType.AZURE],
                ttps=["T1558.003", "T1003.006", "T1550.002", "T1484.001"],
                recent_activity="Golden SAML attacks, ADFS token forgery, supply chain compromises",
                references=["https://attack.mitre.org/groups/G0016/"],
            ),
            ThreatActor(
                name="FIN7",
                aliases=["Carbanak", "Carbon Spider"],
                description="Financially motivated threat group targeting retail, hospitality, and financial sectors",
                targeted_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                ttps=["T1059.001", "T1003.001", "T1021.001", "T1550.002"],
                recent_activity="Cobalt Strike deployments, DCSync attacks, lateral movement via WMI",
                references=["https://attack.mitre.org/groups/G0046/"],
            ),
            ThreatActor(
                name="BlackCat/ALPHV",
                aliases=["ALPHV", "Noberus"],
                description="Ransomware-as-a-service operation known for sophisticated AD compromise",
                targeted_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                ttps=["T1486", "T1003.006", "T1484.002", "T1021.002"],
                recent_activity="GPO-based ransomware deployment, domain-wide encryption",
                references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a"],
            ),
            ThreatActor(
                name="Scattered Spider",
                aliases=["UNC3944", "Muddled Libra"],
                description="Threat group specializing in social engineering and identity provider compromise",
                targeted_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY, InfrastructureType.AZURE],
                ttps=["T1566", "T1078", "T1556", "T1098"],
                recent_activity="MFA bypass, help desk social engineering, Azure AD compromise",
                references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"],
            ),
        ]

        aws_actors = [
            ThreatActor(
                name="TeamTNT",
                aliases=[],
                description="Cryptomining and credential stealing group targeting cloud environments",
                targeted_infrastructure=[InfrastructureType.AWS, InfrastructureType.GCP],
                ttps=["T1552.005", "T1496", "T1059.004"],
                recent_activity="Credential harvesting from cloud metadata, cryptominer deployment",
                references=["https://attack.mitre.org/groups/G0139/"],
            ),
        ]

        if infrastructure == InfrastructureType.ACTIVE_DIRECTORY:
            return ad_actors
        elif infrastructure in [InfrastructureType.AWS, InfrastructureType.GCP]:
            return aws_actors
        else:
            return []

    def _get_builtin_cves(
        self, infrastructure: InfrastructureType
    ) -> list[CVEInfo]:
        """Get built-in CVE data for when APIs are unavailable."""
        ad_cves = [
            CVEInfo(
                cve_id="CVE-2024-49113",
                description="Windows LDAP Remote Code Execution Vulnerability (LDAPNightmare)",
                cvss_score=9.8,
                severity="critical",
                affected_products=["Windows Server", "Active Directory"],
                affected_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                exploitation_status="in-the-wild",
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49113"],
                published_date="2024-12-10",
            ),
            CVEInfo(
                cve_id="CVE-2023-23397",
                description="Microsoft Outlook Elevation of Privilege Vulnerability - NTLM relay via calendar invite",
                cvss_score=9.8,
                severity="critical",
                affected_products=["Microsoft Outlook"],
                affected_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                exploitation_status="in-the-wild",
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"],
                published_date="2023-03-14",
            ),
            CVEInfo(
                cve_id="CVE-2022-26923",
                description="Active Directory Domain Services Elevation of Privilege (Certifried)",
                cvss_score=8.8,
                severity="high",
                affected_products=["Active Directory Certificate Services"],
                affected_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                exploitation_status="in-the-wild",
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923"],
                published_date="2022-05-10",
            ),
            CVEInfo(
                cve_id="CVE-2021-42287",
                description="Active Directory Domain Services Elevation of Privilege (sAMAccountName spoofing)",
                cvss_score=8.8,
                severity="high",
                affected_products=["Active Directory"],
                affected_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                exploitation_status="in-the-wild",
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287"],
                published_date="2021-11-09",
            ),
            CVEInfo(
                cve_id="CVE-2020-1472",
                description="Netlogon Elevation of Privilege Vulnerability (Zerologon)",
                cvss_score=10.0,
                severity="critical",
                affected_products=["Windows Server", "Active Directory"],
                affected_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                exploitation_status="in-the-wild",
                references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"],
                published_date="2020-08-11",
            ),
        ]

        if infrastructure == InfrastructureType.ACTIVE_DIRECTORY:
            return ad_cves
        return []

    def _get_trending_techniques(
        self, infrastructure: InfrastructureType
    ) -> list[str]:
        """Get trending attack techniques for an infrastructure type."""
        ad_trending = [
            "AD Certificate Services abuse (ESC1-ESC8)",
            "Shadow Credentials (msDS-KeyCredentialLink manipulation)",
            "Silver Ticket attacks with AES keys",
            "ADCS relay attacks (ESC8/PetitPotam)",
            "Kerberos delegation abuse (constrained/unconstrained)",
            "Group Policy Object (GPO) lateral movement",
            "LAPS password retrieval",
            "Azure AD Connect sync exploitation",
        ]

        aws_trending = [
            "IAM privilege escalation via policy misconfigurations",
            "SSRF to EC2 metadata service (IMDSv1)",
            "Lambda function code injection",
            "S3 bucket enumeration and data exfiltration",
            "Cross-account role assumption abuse",
        ]

        azure_trending = [
            "Managed Identity abuse",
            "Azure AD application consent phishing",
            "Service Principal credential harvesting",
            "Azure Resource Manager template injection",
            "Blob storage SAS token abuse",
        ]

        if infrastructure == InfrastructureType.ACTIVE_DIRECTORY:
            return ad_trending
        elif infrastructure == InfrastructureType.AWS:
            return aws_trending
        elif infrastructure == InfrastructureType.AZURE:
            return azure_trending
        return []

    async def update_intel(
        self,
        progress_callback: Optional[Callable[[str, str, int], None]] = None,
    ) -> dict:
        """Update threat intelligence from all sources."""
        stats = {"cves": 0, "actors": 0, "techniques": 0, "custom_feeds": 0, "errors": []}

        def report_progress(source: str, status: str, count: int = 0):
            if progress_callback:
                progress_callback(source, status, count)

        # Fetch CISA KEV (most reliable source)
        report_progress("CISA KEV Catalog", "fetching")
        try:
            kev_cves = await self.kev_client.get_recent_kev(limit=50)
            for cve in kev_cves:
                self.cache.cache_cve(cve)
            stats["cves"] += len(kev_cves)
            report_progress("CISA KEV Catalog", "success", len(kev_cves))
        except Exception as e:
            stats["errors"].append(f"KEV: {str(e)}")
            report_progress("CISA KEV Catalog", "error")

        # Fetch from NVD
        report_progress("NVD CVE Database", "fetching")
        try:
            for infra in [InfrastructureType.ACTIVE_DIRECTORY, InfrastructureType.AWS]:
                cves = await self.cve_client.get_cves_for_infrastructure(
                    infra, limit=20, days_back=90
                )
                for cve in cves:
                    self.cache.cache_cve(cve)
                stats["cves"] += len(cves)
            report_progress("NVD CVE Database", "success", stats["cves"])
        except Exception as e:
            stats["errors"].append(f"NVD: {str(e)}")
            report_progress("NVD CVE Database", "error")

        # Fetch from OTX if configured
        if self.otx.is_configured():
            report_progress("AlienVault OTX", "fetching")
            try:
                for infra in [InfrastructureType.ACTIVE_DIRECTORY, InfrastructureType.AWS]:
                    actors = await self.otx.get_threat_actors_for_infrastructure(
                        infra, limit=5
                    )
                    for actor in actors:
                        self.cache.cache_threat_actor(actor)
                    stats["actors"] += len(actors)
                report_progress("AlienVault OTX", "success", stats["actors"])
            except Exception as e:
                stats["errors"].append(f"OTX: {str(e)}")
                report_progress("AlienVault OTX", "error")
        else:
            report_progress("AlienVault OTX", "skipped (no API key)")

        # Fetch from enabled built-in sources
        report_progress("Built-in Sources", "starting")
        try:
            builtin_stats = await self.update_from_builtin_sources(progress_callback)
            stats["cves"] += builtin_stats.get("cves", 0)
            stats["actors"] += builtin_stats.get("actors", 0)
            stats["techniques"] += builtin_stats.get("techniques", 0)
            stats["errors"].extend(builtin_stats.get("errors", []))
        except Exception as e:
            stats["errors"].append(f"Built-in sources: {str(e)}")

        # Fetch from custom feeds
        custom_feeds = self.cache.get_custom_feeds(enabled_only=True)
        if custom_feeds:
            for feed in custom_feeds:
                feed_name = feed["name"]
                report_progress(f"Custom: {feed_name}", "fetching")
                try:
                    result = await self.custom_feed_client.fetch_feed(
                        feed["url"],
                        feed["feed_type"]
                    )

                    # Cache CVEs from feed
                    for cve in result.get("cves", []):
                        self.cache.cache_cve(cve)
                    stats["cves"] += len(result.get("cves", []))

                    # Cache threat actors from feed
                    for actor in result.get("threat_actors", []):
                        self.cache.cache_threat_actor(actor)
                    stats["actors"] += len(result.get("threat_actors", []))

                    # Track techniques (stored separately)
                    stats["techniques"] += len(result.get("techniques", []))

                    # Update feed last fetched time
                    self.cache.update_feed_last_fetched(feed_name)
                    stats["custom_feeds"] += 1

                    feed_count = result.get("raw_count", 0)
                    report_progress(f"Custom: {feed_name}", "success", feed_count)
                except Exception as e:
                    stats["errors"].append(f"{feed_name}: {str(e)}")
                    report_progress(f"Custom: {feed_name}", "error")

        # Update last update timestamp
        self.cache.set_last_update()

        total = stats["cves"] + stats["actors"] + stats["techniques"]
        report_progress("Update complete", "complete", total)

        return stats

    def add_custom_feed(
        self,
        name: str,
        url: str,
        feed_type: str = "json",
        infrastructure: Optional[str] = None,
    ) -> bool:
        """Add a custom threat intelligence feed."""
        return self.cache.add_custom_feed(name, url, feed_type, infrastructure)

    def remove_custom_feed(self, name: str) -> bool:
        """Remove a custom feed."""
        return self.cache.remove_custom_feed(name)

    def get_custom_feeds(self) -> list[dict]:
        """Get all configured custom feeds."""
        return self.cache.get_custom_feeds(enabled_only=False)

    def toggle_feed(self, name: str, enabled: bool) -> bool:
        """Enable or disable a custom feed."""
        return self.cache.toggle_feed(name, enabled)

    def get_builtin_sources(self) -> list[dict]:
        """Get all available built-in sources with their status."""
        enabled_sources = self.cache.get_metadata("enabled_builtin_sources")
        enabled_set = set(enabled_sources.split(",")) if enabled_sources else set()

        # Get default sources that should be enabled
        default_sources = {s.name for s in get_default_sources()}

        sources = []
        for name, source in BUILTIN_SOURCES.items():
            # Check if explicitly enabled or if it's a default source
            is_enabled = name in enabled_set or (
                name in default_sources and name not in enabled_set
            )

            sources.append({
                "name": source.name,
                "url": source.url,
                "description": source.description,
                "category": source.category,
                "infrastructure": source.infrastructure,
                "feed_type": source.feed_type,
                "requires_api_key": source.requires_api_key,
                "api_key_env": source.api_key_env,
                "enabled": is_enabled,
                "enabled_by_default": source.enabled_by_default,
            })

        return sources

    def enable_builtin_source(self, name: str) -> bool:
        """Enable a built-in source."""
        if name not in BUILTIN_SOURCES:
            return False

        enabled_sources = self.cache.get_metadata("enabled_builtin_sources")
        enabled_set = set(enabled_sources.split(",")) if enabled_sources else set()
        enabled_set.add(name)
        self.cache.set_metadata("enabled_builtin_sources", ",".join(enabled_set))
        return True

    def disable_builtin_source(self, name: str) -> bool:
        """Disable a built-in source."""
        if name not in BUILTIN_SOURCES:
            return False

        enabled_sources = self.cache.get_metadata("enabled_builtin_sources")
        enabled_set = set(enabled_sources.split(",")) if enabled_sources else set()
        enabled_set.discard(name)
        self.cache.set_metadata("enabled_builtin_sources", ",".join(enabled_set))
        return True

    def get_enabled_builtin_sources(self) -> list[IntelSource]:
        """Get list of enabled built-in sources."""
        enabled_sources = self.cache.get_metadata("enabled_builtin_sources")
        enabled_set = set(enabled_sources.split(",")) if enabled_sources else set()

        # Include default sources unless explicitly disabled
        disabled_sources = self.cache.get_metadata("disabled_builtin_sources")
        disabled_set = set(disabled_sources.split(",")) if disabled_sources else set()

        sources = []
        for name, source in BUILTIN_SOURCES.items():
            if name in enabled_set:
                sources.append(source)
            elif source.enabled_by_default and name not in disabled_set:
                sources.append(source)

        return sources

    async def update_from_builtin_sources(
        self,
        progress_callback: Optional[Callable[[str, str, int], None]] = None,
    ) -> dict:
        """Update from enabled built-in sources."""
        stats = {"techniques": 0, "cves": 0, "actors": 0, "indicators": 0, "errors": []}

        def report_progress(source: str, status: str, count: int = 0):
            if progress_callback:
                progress_callback(source, status, count)

        sources = self.get_enabled_builtin_sources()

        for source in sources:
            source_name = source.name
            report_progress(source_name, "fetching")

            # Check for API key if required
            api_key = None
            if source.requires_api_key and source.api_key_env:
                api_key = os.environ.get(source.api_key_env)
                if not api_key:
                    report_progress(source_name, f"skipped (no {source.api_key_env})")
                    continue

            try:
                result = await self.custom_feed_client.fetch_feed(
                    source.url,
                    source.feed_type,
                    parser=source.parser,
                    api_key=api_key,
                )

                # Cache results
                for cve in result.get("cves", []):
                    self.cache.cache_cve(cve)
                stats["cves"] += len(result.get("cves", []))

                for actor in result.get("threat_actors", []):
                    self.cache.cache_threat_actor(actor)
                stats["actors"] += len(result.get("threat_actors", []))

                stats["techniques"] += len(result.get("techniques", []))
                stats["indicators"] += len(result.get("indicators", []))

                total_items = result.get("raw_count", 0)
                report_progress(source_name, "success", total_items)

            except Exception as e:
                error_msg = str(e)[:100]  # Truncate long errors
                stats["errors"].append(f"{source_name}: {error_msg}")
                report_progress(source_name, "error")

        return stats

    def get_threat_report(
        self,
        infrastructure: InfrastructureType,
        use_cache: bool = True,
    ) -> ThreatIntelReport:
        """Get a threat intelligence report for an infrastructure type."""
        # Try to get from cache first
        cves: list[CVEInfo] = []
        actors: list[ThreatActor] = []

        if use_cache:
            cves = self.cache.get_cves(infrastructure, severity="critical")
            cves.extend(self.cache.get_cves(infrastructure, severity="high"))
            actors = self.cache.get_threat_actors(infrastructure)

        # If cache is empty, use built-in data
        if not cves:
            cves = self._get_builtin_cves(infrastructure)

        if not actors:
            actors = self._get_builtin_threat_actors(infrastructure)

        # Get trending techniques
        trending = self._get_trending_techniques(infrastructure)

        return ThreatIntelReport(
            infrastructure=infrastructure,
            critical_cves=cves[:10],  # Top 10 CVEs
            active_threat_actors=actors[:5],  # Top 5 actors
            trending_techniques=trending,
            last_updated=self.cache.get_last_update(),
        )

    def get_cache_stats(self) -> dict:
        """Get statistics about the cache."""
        return self.cache.get_stats()
