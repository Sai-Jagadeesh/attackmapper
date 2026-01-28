"""AlienVault OTX integration for threat intelligence."""

import os
from typing import Optional

import httpx

from attackmapper.core.models import ThreatActor, InfrastructureType


class OTXClient:
    """Client for AlienVault OTX API."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    # Mapping of OTX tags to our infrastructure types
    TAG_MAPPING = {
        "active directory": InfrastructureType.ACTIVE_DIRECTORY,
        "windows": InfrastructureType.ACTIVE_DIRECTORY,
        "domain controller": InfrastructureType.ACTIVE_DIRECTORY,
        "kerberos": InfrastructureType.ACTIVE_DIRECTORY,
        "aws": InfrastructureType.AWS,
        "amazon": InfrastructureType.AWS,
        "azure": InfrastructureType.AZURE,
        "microsoft cloud": InfrastructureType.AZURE,
        "gcp": InfrastructureType.GCP,
        "google cloud": InfrastructureType.GCP,
        "network": InfrastructureType.NETWORK,
        "firewall": InfrastructureType.NETWORK,
        "router": InfrastructureType.NETWORK,
    }

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OTX_API_KEY")
        self.headers = {}
        if self.api_key:
            self.headers["X-OTX-API-KEY"] = self.api_key

    def is_configured(self) -> bool:
        """Check if OTX API key is configured."""
        return bool(self.api_key)

    async def get_pulses_subscribed(self, limit: int = 10) -> list[dict]:
        """Get subscribed pulses (requires API key)."""
        if not self.is_configured():
            return []

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/pulses/subscribed",
                    headers=self.headers,
                    params={"limit": limit},
                    timeout=30.0,
                )
                response.raise_for_status()
                data = response.json()
                return data.get("results", [])
            except Exception:
                return []

    async def search_pulses(
        self, query: str, limit: int = 10
    ) -> list[dict]:
        """Search for pulses matching a query."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/search/pulses",
                    headers=self.headers,
                    params={"q": query, "limit": limit},
                    timeout=30.0,
                )
                response.raise_for_status()
                data = response.json()
                return data.get("results", [])
            except Exception:
                return []

    async def get_pulses_for_infrastructure(
        self, infrastructure: InfrastructureType, limit: int = 10
    ) -> list[dict]:
        """Get pulses related to a specific infrastructure type."""
        # Search terms for each infrastructure type
        search_terms = {
            InfrastructureType.ACTIVE_DIRECTORY: "active directory OR kerberos OR domain controller",
            InfrastructureType.AWS: "aws OR amazon web services OR ec2",
            InfrastructureType.AZURE: "azure OR microsoft cloud OR entra",
            InfrastructureType.GCP: "google cloud OR gcp OR gke",
            InfrastructureType.NETWORK: "network attack OR lateral movement OR firewall",
        }

        query = search_terms.get(infrastructure, infrastructure.value)
        return await self.search_pulses(query, limit)

    def parse_pulse_to_threat_actor(
        self, pulse: dict, infrastructure: InfrastructureType
    ) -> Optional[ThreatActor]:
        """Parse an OTX pulse into a ThreatActor if it represents one."""
        # OTX pulses aren't always threat actors, but we can extract relevant info
        name = pulse.get("name", "")
        description = pulse.get("description", "")
        tags = pulse.get("tags", [])

        # Try to identify if this is a threat actor-related pulse
        actor_keywords = ["apt", "threat actor", "group", "campaign"]
        is_actor = any(
            keyword in name.lower() or keyword in description.lower()
            for keyword in actor_keywords
        )

        if not is_actor:
            return None

        # Extract MITRE ATT&CK IDs if present
        attack_ids = pulse.get("attack_ids", [])
        ttps = [aid.get("id", "") for aid in attack_ids if aid.get("id")]

        return ThreatActor(
            name=name,
            aliases=[],
            description=description[:500] if description else "",
            targeted_infrastructure=[infrastructure],
            ttps=ttps,
            recent_activity=f"OTX Pulse: {pulse.get('created', 'Unknown date')}",
            references=[f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}"],
        )

    async def get_threat_actors_for_infrastructure(
        self, infrastructure: InfrastructureType, limit: int = 5
    ) -> list[ThreatActor]:
        """Get threat actors targeting a specific infrastructure."""
        pulses = await self.get_pulses_for_infrastructure(infrastructure, limit * 2)

        actors = []
        for pulse in pulses:
            actor = self.parse_pulse_to_threat_actor(pulse, infrastructure)
            if actor and len(actors) < limit:
                actors.append(actor)

        return actors
