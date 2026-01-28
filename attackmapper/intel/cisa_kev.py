"""CISA Known Exploited Vulnerabilities (KEV) catalog integration."""

from typing import Optional

import httpx

from attackmapper.core.models import CVEInfo, InfrastructureType


class CISAKEVClient:
    """Client for CISA Known Exploited Vulnerabilities catalog."""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Keywords to map CVEs to infrastructure types
    INFRASTRUCTURE_KEYWORDS = {
        InfrastructureType.ACTIVE_DIRECTORY: [
            "active directory", "windows", "microsoft", "exchange", "outlook",
            "kerberos", "ntlm", "ldap", "domain", "smb", "iis",
        ],
        InfrastructureType.AWS: [
            "aws", "amazon", "ec2", "s3",
        ],
        InfrastructureType.AZURE: [
            "azure", "office 365", "sharepoint", "teams", "onedrive",
        ],
        InfrastructureType.GCP: [
            "google cloud", "gcp",
        ],
        InfrastructureType.NETWORK: [
            "cisco", "juniper", "palo alto", "fortinet", "fortigate",
            "router", "firewall", "vpn", "f5", "citrix", "netscaler",
        ],
    }

    def __init__(self):
        self.timeout = 30.0
        self._cache: Optional[list[dict]] = None

    def _detect_infrastructure(self, vendor: str, product: str, description: str) -> list[InfrastructureType]:
        """Detect which infrastructure types a KEV entry affects."""
        combined = f"{vendor} {product} {description}".lower()

        affected = []
        for infra, keywords in self.INFRASTRUCTURE_KEYWORDS.items():
            if any(keyword in combined for keyword in keywords):
                affected.append(infra)

        return affected

    async def fetch_kev_catalog(self) -> list[dict]:
        """Fetch the full KEV catalog."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(self.KEV_URL, timeout=self.timeout)
                response.raise_for_status()
                data = response.json()
                self._cache = data.get("vulnerabilities", [])
                return self._cache
            except Exception:
                return []

    def parse_kev_to_cve(self, kev_entry: dict) -> CVEInfo:
        """Parse a KEV entry into CVEInfo."""
        vendor = kev_entry.get("vendorProject", "")
        product = kev_entry.get("product", "")
        description = kev_entry.get("shortDescription", "")

        affected_infrastructure = self._detect_infrastructure(
            vendor, product, description
        )

        return CVEInfo(
            cve_id=kev_entry.get("cveID", ""),
            description=description,
            cvss_score=9.0,  # KEV doesn't include CVSS, but they're all critical
            severity="critical",
            affected_products=[f"{vendor} {product}"],
            affected_infrastructure=affected_infrastructure,
            exploitation_status="in-the-wild",  # All KEV entries are actively exploited
            references=[
                f"https://nvd.nist.gov/vuln/detail/{kev_entry.get('cveID', '')}"
            ],
            published_date=kev_entry.get("dateAdded", ""),
        )

    async def get_kev_for_infrastructure(
        self,
        infrastructure: InfrastructureType,
        limit: int = 10,
    ) -> list[CVEInfo]:
        """Get KEV entries affecting a specific infrastructure type."""
        if not self._cache:
            await self.fetch_kev_catalog()

        if not self._cache:
            return []

        cves = []
        for entry in self._cache:
            cve = self.parse_kev_to_cve(entry)
            if infrastructure in cve.affected_infrastructure:
                cves.append(cve)
                if len(cves) >= limit:
                    break

        return cves

    async def get_recent_kev(self, limit: int = 20) -> list[CVEInfo]:
        """Get the most recently added KEV entries."""
        if not self._cache:
            await self.fetch_kev_catalog()

        if not self._cache:
            return []

        # KEV catalog is typically ordered by date added (most recent first)
        # but we'll sort to be sure
        sorted_entries = sorted(
            self._cache,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True,
        )

        return [self.parse_kev_to_cve(entry) for entry in sorted_entries[:limit]]

    async def get_all_ad_kev(self) -> list[CVEInfo]:
        """Get all KEV entries related to Active Directory/Windows."""
        return await self.get_kev_for_infrastructure(
            InfrastructureType.ACTIVE_DIRECTORY,
            limit=100,
        )
