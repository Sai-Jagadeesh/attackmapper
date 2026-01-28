"""CVE and vulnerability feed integration."""

from datetime import datetime, timedelta
from typing import Optional

import httpx

from attackmapper.core.models import CVEInfo, InfrastructureType


class CVEClient:
    """Client for fetching CVE data from various sources."""

    # NVD API endpoint
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Keywords to map CVEs to infrastructure types
    INFRASTRUCTURE_KEYWORDS = {
        InfrastructureType.ACTIVE_DIRECTORY: [
            "active directory", "kerberos", "ntlm", "ldap", "domain controller",
            "windows server", "ad cs", "adcs", "certificate services", "krbtgt",
            "dcsync", "mimikatz", "pass-the-hash", "pass-the-ticket",
        ],
        InfrastructureType.AWS: [
            "aws", "amazon web services", "ec2", "s3", "lambda", "iam",
            "eks", "rds", "cloudfront", "cloudwatch",
        ],
        InfrastructureType.AZURE: [
            "azure", "microsoft azure", "entra", "azure ad", "azure active directory",
            "office 365", "o365", "sharepoint online", "teams",
        ],
        InfrastructureType.GCP: [
            "google cloud", "gcp", "gke", "google kubernetes", "bigquery",
            "cloud storage", "compute engine",
        ],
        InfrastructureType.NETWORK: [
            "router", "firewall", "vpn", "cisco", "juniper", "palo alto",
            "fortinet", "fortigate", "network", "switch",
        ],
    }

    def __init__(self):
        self.timeout = 30.0

    def _map_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level."""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    def _detect_infrastructure(self, cve_data: dict) -> list[InfrastructureType]:
        """Detect which infrastructure types a CVE affects based on description."""
        description = ""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "").lower()
                break

        affected = []
        for infra, keywords in self.INFRASTRUCTURE_KEYWORDS.items():
            if any(keyword in description for keyword in keywords):
                affected.append(infra)

        return affected

    def _parse_nvd_cve(self, cve_item: dict) -> Optional[CVEInfo]:
        """Parse NVD CVE data into CVEInfo."""
        try:
            cve_data = cve_item.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Get description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS score
            cvss_score = 0.0
            metrics = cve_data.get("metrics", {})

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    break

            # Detect infrastructure types
            affected_infrastructure = self._detect_infrastructure(cve_data)

            # Get references
            references = []
            for ref in cve_data.get("references", [])[:5]:  # Limit to 5
                references.append(ref.get("url", ""))

            # Get published date
            published = cve_data.get("published", "")
            if published:
                published = published.split("T")[0]

            return CVEInfo(
                cve_id=cve_id,
                description=description[:500] if description else "",
                cvss_score=cvss_score,
                severity=self._map_severity(cvss_score),
                affected_products=[],  # Could parse from configurations
                affected_infrastructure=affected_infrastructure,
                exploitation_status="unknown",
                references=references,
                published_date=published,
            )
        except Exception:
            return None

    async def search_cves(
        self,
        keyword: str,
        limit: int = 20,
        days_back: int = 90,
    ) -> list[CVEInfo]:
        """Search NVD for CVEs matching a keyword."""
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)

        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": limit,
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    self.NVD_API_URL,
                    params=params,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                data = response.json()

                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve = self._parse_nvd_cve(vuln)
                    if cve:
                        cves.append(cve)

                return cves
            except Exception:
                return []

    async def get_cves_for_infrastructure(
        self,
        infrastructure: InfrastructureType,
        limit: int = 10,
        days_back: int = 90,
    ) -> list[CVEInfo]:
        """Get recent CVEs affecting a specific infrastructure type."""
        # Search terms for each infrastructure
        search_terms = {
            InfrastructureType.ACTIVE_DIRECTORY: "active directory",
            InfrastructureType.AWS: "aws",
            InfrastructureType.AZURE: "azure",
            InfrastructureType.GCP: "google cloud",
            InfrastructureType.NETWORK: "network",
        }

        keyword = search_terms.get(infrastructure, infrastructure.value)
        cves = await self.search_cves(keyword, limit * 2, days_back)

        # Filter to only those that actually affect this infrastructure
        filtered = [
            cve for cve in cves
            if infrastructure in cve.affected_infrastructure
        ]

        # Sort by CVSS score descending
        filtered.sort(key=lambda x: x.cvss_score, reverse=True)

        return filtered[:limit]

    async def get_critical_cves(
        self,
        infrastructure: Optional[InfrastructureType] = None,
        limit: int = 10,
        days_back: int = 30,
    ) -> list[CVEInfo]:
        """Get critical CVEs (CVSS >= 9.0)."""
        if infrastructure:
            cves = await self.get_cves_for_infrastructure(
                infrastructure, limit * 3, days_back
            )
        else:
            # Search for general critical CVEs
            cves = await self.search_cves("critical", limit * 3, days_back)

        # Filter to critical only
        critical = [cve for cve in cves if cve.cvss_score >= 9.0]
        return critical[:limit]
