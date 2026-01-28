"""Custom threat intelligence feed handler."""

import csv
import io
import httpx
import re
from typing import Optional
from datetime import datetime

from attackmapper.core.models import (
    CVEInfo,
    ThreatActor,
    AttackTechnique,
    AttackPhase,
    InfrastructureType,
)


class CustomFeedClient:
    """Client for fetching and parsing custom threat intelligence feeds."""

    def __init__(self):
        self.timeout = 60.0
        self.headers = {
            "User-Agent": "AttackMapper/1.0 (Threat Intelligence Aggregator)"
        }

    async def fetch_feed(
        self,
        url: str,
        feed_type: str = "json",
        parser: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> dict:
        """Fetch a feed from a URL and return parsed data."""
        headers = self.headers.copy()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            response = await client.get(url, follow_redirects=True)
            response.raise_for_status()

            # Use custom parser if specified
            if parser:
                return await self._parse_with_custom_parser(parser, response, url)

            # Otherwise use standard parsers based on feed_type
            content_type = response.headers.get("content-type", "")

            if feed_type == "csv" or "text/csv" in content_type:
                return self._parse_csv_feed(response.text, url)
            elif feed_type == "stix":
                return self._parse_stix_feed(response.json(), url)
            elif feed_type == "misp":
                return self._parse_misp_feed(response.json(), url)
            elif feed_type == "json" or "application/json" in content_type:
                return self._parse_json_feed(response.json(), url)
            else:
                # Try to parse as text
                return self._parse_text_feed(response.text, url)

    async def _parse_with_custom_parser(
        self, parser: str, response: httpx.Response, url: str
    ) -> dict:
        """Use a specialized parser for specific feed formats."""
        parsers = {
            "lolbas": self._parse_lolbas,
            "gtfobins": self._parse_gtfobins,
            "wadcoms": self._parse_wadcoms,
            "hijacklibs": self._parse_hijacklibs,
            "cisa_kev": self._parse_cisa_kev,
            "atomic_red_team": self._parse_atomic_red_team,
            "stratus": self._parse_stratus,
            "urlhaus": self._parse_urlhaus,
            "threatfox": self._parse_threatfox,
            "malwarebazaar": self._parse_malwarebazaar,
            "feodotracker": self._parse_feodotracker,
            "ransomwatch": self._parse_ransomwatch,
            "lots": self._parse_lots,
            "default_creds": self._parse_default_creds,
            "nuclei": self._parse_nuclei,
        }

        if parser in parsers:
            try:
                if "json" in response.headers.get("content-type", "") or url.endswith(".json"):
                    return parsers[parser](response.json(), url)
                elif "csv" in response.headers.get("content-type", "") or url.endswith(".csv"):
                    return parsers[parser](response.text, url)
                else:
                    return parsers[parser](response.text, url)
            except Exception:
                # Fallback to generic JSON parser
                try:
                    return self._parse_json_feed(response.json(), url)
                except Exception:
                    return {"techniques": [], "cves": [], "threat_actors": [], "indicators": [], "raw_count": 0}

        return self._parse_json_feed(response.json(), url)

    def _parse_json_feed(self, data: dict, source_url: str) -> dict:
        """
        Parse a generic JSON feed.

        Expected formats:
        1. {"techniques": [...]} - Attack techniques
        2. {"cves": [...]} - CVE information
        3. {"threat_actors": [...]} - Threat actor info
        4. {"indicators": [...]} - IOCs (logged but not stored)
        """
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        # Handle techniques
        if "techniques" in data:
            for tech in data.get("techniques", []):
                try:
                    technique = self._parse_technique(tech)
                    if technique:
                        result["techniques"].append(technique)
                except Exception:
                    pass

        # Handle CVEs
        if "cves" in data or "vulnerabilities" in data:
            cve_list = data.get("cves", data.get("vulnerabilities", []))
            for cve_data in cve_list:
                try:
                    cve = self._parse_cve(cve_data, source_url)
                    if cve:
                        result["cves"].append(cve)
                except Exception:
                    pass

        # Handle threat actors
        if "threat_actors" in data or "actors" in data:
            actor_list = data.get("threat_actors", data.get("actors", []))
            for actor_data in actor_list:
                try:
                    actor = self._parse_threat_actor(actor_data, source_url)
                    if actor:
                        result["threat_actors"].append(actor)
                except Exception:
                    pass

        # Handle indicators (IOCs)
        if "indicators" in data or "iocs" in data:
            result["indicators"] = data.get("indicators", data.get("iocs", []))

        result["raw_count"] = len(data) if isinstance(data, list) else sum(
            len(v) for v in data.values() if isinstance(v, list)
        )

        return result

    def _parse_technique(self, data: dict) -> Optional[AttackTechnique]:
        """Parse a technique from feed data."""
        if not data.get("id") or not data.get("name"):
            return None

        # Map infrastructure string to enum
        infra_str = data.get("infrastructure", "").lower()
        infra_map = {
            "ad": InfrastructureType.ACTIVE_DIRECTORY,
            "active_directory": InfrastructureType.ACTIVE_DIRECTORY,
            "aws": InfrastructureType.AWS,
            "azure": InfrastructureType.AZURE,
            "gcp": InfrastructureType.GCP,
            "network": InfrastructureType.NETWORK,
        }
        infrastructure = infra_map.get(infra_str, InfrastructureType.ACTIVE_DIRECTORY)

        # Map phase string to enum
        phase_str = data.get("phase", "execution").lower().replace(" ", "_").replace("-", "_")
        phase_map = {
            "reconnaissance": AttackPhase.RECONNAISSANCE,
            "recon": AttackPhase.RECONNAISSANCE,
            "initial_access": AttackPhase.INITIAL_ACCESS,
            "initial": AttackPhase.INITIAL_ACCESS,
            "execution": AttackPhase.EXECUTION,
            "persistence": AttackPhase.PERSISTENCE,
            "privilege_escalation": AttackPhase.PRIVILEGE_ESCALATION,
            "privesc": AttackPhase.PRIVILEGE_ESCALATION,
            "defense_evasion": AttackPhase.DEFENSE_EVASION,
            "evasion": AttackPhase.DEFENSE_EVASION,
            "credential_access": AttackPhase.CREDENTIAL_ACCESS,
            "credentials": AttackPhase.CREDENTIAL_ACCESS,
            "discovery": AttackPhase.DISCOVERY,
            "lateral_movement": AttackPhase.LATERAL_MOVEMENT,
            "lateral": AttackPhase.LATERAL_MOVEMENT,
            "collection": AttackPhase.COLLECTION,
            "exfiltration": AttackPhase.EXFILTRATION,
            "exfil": AttackPhase.EXFILTRATION,
            "impact": AttackPhase.IMPACT,
        }
        phase = phase_map.get(phase_str, AttackPhase.EXECUTION)

        return AttackTechnique(
            id=data["id"],
            mitre_id=data.get("mitre_id", ""),
            name=data["name"],
            phase=phase,
            infrastructure=infrastructure,
            description=data.get("description", ""),
            prerequisites=data.get("prerequisites", []),
            tools=data.get("tools", []),
            commands=data.get("commands", []),
            detection=data.get("detection", ""),
            references=data.get("references", []),
            next_techniques=data.get("next_techniques", []),
            risk_level=data.get("risk_level", "medium"),
        )

    def _parse_cve(self, data: dict, source_url: str) -> Optional[CVEInfo]:
        """Parse a CVE from feed data."""
        cve_id = data.get("cve_id") or data.get("id") or data.get("cve")
        if not cve_id:
            return None

        # Normalize CVE ID format
        if not cve_id.upper().startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        # Parse affected infrastructure
        affected_infra = []
        infra_data = data.get("affected_infrastructure", data.get("infrastructure", []))
        if isinstance(infra_data, str):
            infra_data = [infra_data]

        infra_map = {
            "ad": InfrastructureType.ACTIVE_DIRECTORY,
            "active_directory": InfrastructureType.ACTIVE_DIRECTORY,
            "windows": InfrastructureType.ACTIVE_DIRECTORY,
            "aws": InfrastructureType.AWS,
            "azure": InfrastructureType.AZURE,
            "gcp": InfrastructureType.GCP,
            "network": InfrastructureType.NETWORK,
            "linux": InfrastructureType.NETWORK,
        }
        for infra in infra_data:
            if isinstance(infra, str):
                mapped = infra_map.get(infra.lower())
                if mapped:
                    affected_infra.append(mapped)

        # Default to AD if no infrastructure specified
        if not affected_infra:
            affected_infra = [InfrastructureType.ACTIVE_DIRECTORY]

        return CVEInfo(
            cve_id=cve_id.upper(),
            description=data.get("description", ""),
            cvss_score=float(data.get("cvss_score", data.get("cvss", 0)) or 0),
            severity=data.get("severity", "medium").lower(),
            affected_products=data.get("affected_products", data.get("products", [])),
            affected_infrastructure=affected_infra,
            exploitation_status=data.get("exploitation_status", "unknown"),
            references=data.get("references", [source_url]),
            published_date=data.get("published_date", data.get("published", "")),
        )

    def _parse_threat_actor(self, data: dict, source_url: str) -> Optional[ThreatActor]:
        """Parse a threat actor from feed data."""
        name = data.get("name") or data.get("actor_name")
        if not name:
            return None

        # Parse targeted infrastructure
        targeted_infra = []
        infra_data = data.get("targeted_infrastructure", data.get("targets", []))
        if isinstance(infra_data, str):
            infra_data = [infra_data]

        infra_map = {
            "ad": InfrastructureType.ACTIVE_DIRECTORY,
            "active_directory": InfrastructureType.ACTIVE_DIRECTORY,
            "windows": InfrastructureType.ACTIVE_DIRECTORY,
            "aws": InfrastructureType.AWS,
            "azure": InfrastructureType.AZURE,
            "gcp": InfrastructureType.GCP,
            "cloud": InfrastructureType.AWS,
            "network": InfrastructureType.NETWORK,
        }
        for infra in infra_data:
            if isinstance(infra, str):
                mapped = infra_map.get(infra.lower())
                if mapped:
                    targeted_infra.append(mapped)

        return ThreatActor(
            name=name,
            aliases=data.get("aliases", []),
            description=data.get("description", ""),
            targeted_infrastructure=targeted_infra,
            ttps=data.get("ttps", data.get("techniques", [])),
            recent_activity=data.get("recent_activity", ""),
            references=data.get("references", [source_url]),
        )

    def _parse_stix_feed(self, data: dict, source_url: str) -> dict:
        """Parse a STIX 2.x format feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        objects = data.get("objects", [])
        result["raw_count"] = len(objects)

        for obj in objects:
            obj_type = obj.get("type", "")

            if obj_type == "attack-pattern":
                # Attack technique
                tech_data = {
                    "id": obj.get("external_references", [{}])[0].get("external_id", obj.get("id", "")),
                    "mitre_id": obj.get("external_references", [{}])[0].get("external_id", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "phase": obj.get("kill_chain_phases", [{}])[0].get("phase_name", "execution") if obj.get("kill_chain_phases") else "execution",
                }
                tech = self._parse_technique(tech_data)
                if tech:
                    result["techniques"].append(tech)

            elif obj_type == "vulnerability":
                # CVE
                cve_data = {
                    "cve_id": obj.get("external_references", [{}])[0].get("external_id", ""),
                    "description": obj.get("description", ""),
                    "references": [ref.get("url") for ref in obj.get("external_references", []) if ref.get("url")],
                }
                cve = self._parse_cve(cve_data, source_url)
                if cve:
                    result["cves"].append(cve)

            elif obj_type == "intrusion-set" or obj_type == "threat-actor":
                # Threat actor
                actor_data = {
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", ""),
                    "references": [ref.get("url") for ref in obj.get("external_references", []) if ref.get("url")],
                }
                actor = self._parse_threat_actor(actor_data, source_url)
                if actor:
                    result["threat_actors"].append(actor)

            elif obj_type == "indicator":
                result["indicators"].append({
                    "pattern": obj.get("pattern", ""),
                    "description": obj.get("description", ""),
                })

        return result

    def _parse_misp_feed(self, data: dict, source_url: str) -> dict:
        """Parse a MISP format feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        events = data.get("response", [data]) if "response" in data else [data]

        for event in events:
            event_data = event.get("Event", event)
            attributes = event_data.get("Attribute", [])
            result["raw_count"] += len(attributes)

            for attr in attributes:
                attr_type = attr.get("type", "")

                if "cve" in attr_type.lower() or attr.get("category") == "External analysis":
                    value = attr.get("value", "")
                    if value.upper().startswith("CVE-"):
                        cve = self._parse_cve({
                            "cve_id": value,
                            "description": attr.get("comment", ""),
                        }, source_url)
                        if cve:
                            result["cves"].append(cve)

        return result

    def _parse_csv_feed(self, content: str, source_url: str) -> dict:
        """Parse a generic CSV feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        result["raw_count"] = len(rows)

        for row in rows:
            # Try to detect what type of data this is
            if any(k.lower() in ["cve", "cve_id", "vulnerability"] for k in row.keys()):
                cve = self._parse_cve(row, source_url)
                if cve:
                    result["cves"].append(cve)
            elif any(k.lower() in ["technique", "attack", "ttp"] for k in row.keys()):
                tech = self._parse_technique(row)
                if tech:
                    result["techniques"].append(tech)

        return result

    def _parse_text_feed(self, content: str, source_url: str) -> dict:
        """Parse a plain text feed (URLs, IPs, etc.)."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        lines = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]
        result["raw_count"] = len(lines)

        for line in lines:
            # Detect CVEs
            cve_match = re.search(r"CVE-\d{4}-\d+", line, re.IGNORECASE)
            if cve_match:
                result["indicators"].append({
                    "type": "cve",
                    "value": cve_match.group(0).upper(),
                })
            # Detect URLs
            elif line.startswith("http://") or line.startswith("https://"):
                result["indicators"].append({
                    "type": "url",
                    "value": line,
                })
            # Detect IPs
            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
                result["indicators"].append({
                    "type": "ip",
                    "value": line.split()[0],
                })

        return result

    # ==========================================================================
    # Specialized Parsers for Red Team Sources
    # ==========================================================================

    def _parse_lolbas(self, data: list, source_url: str) -> dict:
        """Parse LOLBAS (Living Off The Land Binaries and Scripts) feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "tools": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        items = data if isinstance(data, list) else data.get("entries", [])

        for item in items:
            name = item.get("Name", "")
            if not name:
                continue

            # Extract commands from functions
            commands = []
            for func in item.get("Commands", []):
                cmd = func.get("Command", "")
                if cmd:
                    commands.append(f"# {func.get('Description', 'LOLBAS')}\n{cmd}")

            # Map LOLBAS categories to attack phases
            category = item.get("Category", "").lower() if item.get("Category") else ""
            phase_map = {
                "execute": AttackPhase.EXECUTION,
                "ads": AttackPhase.DEFENSE_EVASION,
                "awl bypass": AttackPhase.DEFENSE_EVASION,
                "download": AttackPhase.INITIAL_ACCESS,
                "upload": AttackPhase.EXFILTRATION,
                "copy": AttackPhase.COLLECTION,
                "credentials": AttackPhase.CREDENTIAL_ACCESS,
                "dump": AttackPhase.CREDENTIAL_ACCESS,
                "reconnaissance": AttackPhase.RECONNAISSANCE,
            }

            # Determine primary phase from categories
            primary_phase = AttackPhase.EXECUTION
            for cat in category.split(","):
                cat = cat.strip().lower()
                if cat in phase_map:
                    primary_phase = phase_map[cat]
                    break

            technique = AttackTechnique(
                id=f"LOLBAS-{name}",
                mitre_id=item.get("ATTACKId", ""),
                name=f"LOLBAS: {name}",
                phase=primary_phase,
                infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
                description=item.get("Description", f"Living Off The Land Binary: {name}"),
                prerequisites=[],
                tools=[name],
                commands=commands[:10],  # Limit commands
                detection="; ".join([d.get("Detection", "") for d in item.get("Detection", [])]),
                references=[item.get("URL", source_url)],
                next_techniques=[],
                risk_level="medium",
            )
            result["techniques"].append(technique)

        return result

    def _parse_gtfobins(self, data: dict, source_url: str) -> dict:
        """Parse GTFOBins feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        # GTFOBins uses binary name as key
        items = data if isinstance(data, dict) else {}
        result["raw_count"] = len(items)

        for binary_name, info in items.items():
            if not isinstance(info, dict):
                continue

            functions = info.get("functions", {})
            commands = []

            # Phase mapping for GTFOBins function types
            phase_map = {
                "shell": AttackPhase.EXECUTION,
                "command": AttackPhase.EXECUTION,
                "reverse-shell": AttackPhase.INITIAL_ACCESS,
                "bind-shell": AttackPhase.INITIAL_ACCESS,
                "file-upload": AttackPhase.EXFILTRATION,
                "file-download": AttackPhase.INITIAL_ACCESS,
                "file-write": AttackPhase.PERSISTENCE,
                "file-read": AttackPhase.COLLECTION,
                "sudo": AttackPhase.PRIVILEGE_ESCALATION,
                "suid": AttackPhase.PRIVILEGE_ESCALATION,
                "capabilities": AttackPhase.PRIVILEGE_ESCALATION,
                "limited-suid": AttackPhase.PRIVILEGE_ESCALATION,
            }

            primary_phase = AttackPhase.EXECUTION

            for func_type, func_list in functions.items():
                if func_type in phase_map:
                    primary_phase = phase_map[func_type]

                for func in func_list if isinstance(func_list, list) else []:
                    code = func.get("code", "")
                    if code:
                        commands.append(f"# GTFOBins {func_type}\n{code}")

            if commands:
                technique = AttackTechnique(
                    id=f"GTFO-{binary_name}",
                    mitre_id="",
                    name=f"GTFOBins: {binary_name}",
                    phase=primary_phase,
                    infrastructure=InfrastructureType.NETWORK,
                    description=f"Unix binary exploitation: {binary_name}",
                    prerequisites=[f"{binary_name} binary available"],
                    tools=[binary_name],
                    commands=commands[:10],
                    detection="Monitor for suspicious usage of common Unix binaries",
                    references=[f"https://gtfobins.github.io/gtfobins/{binary_name}/"],
                    next_techniques=[],
                    risk_level="high" if primary_phase == AttackPhase.PRIVILEGE_ESCALATION else "medium",
                )
                result["techniques"].append(technique)

        return result

    def _parse_wadcoms(self, data: list, source_url: str) -> dict:
        """Parse WADComs (Windows/AD Commands) feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        items = data if isinstance(data, list) else []

        for item in items:
            name = item.get("name", "")
            if not name:
                continue

            commands = []
            for cmd in item.get("commands", []):
                if isinstance(cmd, dict):
                    commands.append(f"# {cmd.get('description', '')}\n{cmd.get('command', '')}")
                elif isinstance(cmd, str):
                    commands.append(cmd)

            # Map WADComs categories to phases
            category = item.get("category", "").lower()
            phase_map = {
                "reconnaissance": AttackPhase.RECONNAISSANCE,
                "enumeration": AttackPhase.DISCOVERY,
                "credential access": AttackPhase.CREDENTIAL_ACCESS,
                "lateral movement": AttackPhase.LATERAL_MOVEMENT,
                "privilege escalation": AttackPhase.PRIVILEGE_ESCALATION,
                "persistence": AttackPhase.PERSISTENCE,
                "execution": AttackPhase.EXECUTION,
            }
            phase = phase_map.get(category, AttackPhase.EXECUTION)

            technique = AttackTechnique(
                id=f"WAD-{name.replace(' ', '-')}",
                mitre_id=item.get("mitre_id", ""),
                name=f"WADComs: {name}",
                phase=phase,
                infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
                description=item.get("description", ""),
                prerequisites=item.get("prerequisites", []),
                tools=item.get("tools", []),
                commands=commands[:15],
                detection=item.get("detection", ""),
                references=item.get("references", [source_url]),
                next_techniques=[],
                risk_level="high",
            )
            result["techniques"].append(technique)

        return result

    def _parse_hijacklibs(self, data: list, source_url: str) -> dict:
        """Parse HijackLibs (DLL Hijacking) feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        items = data if isinstance(data, list) else []

        for item in items:
            name = item.get("name", "") or item.get("Name", "")
            if not name:
                continue

            dll = item.get("dll", "") or item.get("VulnerableDLL", "")
            exe = item.get("executable", "") or item.get("VulnerableExecutable", "")

            commands = []
            if dll and exe:
                commands.append(f"# DLL Hijacking\n# Place malicious DLL as: {dll}\n# Trigger via: {exe}")

            technique = AttackTechnique(
                id=f"HIJACK-{name.replace(' ', '-')}",
                mitre_id="T1574.001",
                name=f"DLL Hijack: {name}",
                phase=AttackPhase.PERSISTENCE,
                infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
                description=f"DLL hijacking opportunity in {exe} via {dll}",
                prerequisites=["Write access to DLL search path"],
                tools=["msfvenom", "Visual Studio"],
                commands=commands,
                detection="Monitor for DLL loading from unusual paths",
                references=[source_url],
                next_techniques=[],
                risk_level="high",
            )
            result["techniques"].append(technique)

        return result

    def _parse_cisa_kev(self, data: dict, source_url: str) -> dict:
        """Parse CISA Known Exploited Vulnerabilities catalog."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        vulnerabilities = data.get("vulnerabilities", [])
        result["raw_count"] = len(vulnerabilities)

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            # Determine affected infrastructure from vendor/product
            vendor = vuln.get("vendorProject", "").lower()
            product = vuln.get("product", "").lower()

            affected_infra = []
            if "microsoft" in vendor or "windows" in product or "active directory" in product:
                affected_infra.append(InfrastructureType.ACTIVE_DIRECTORY)
            if "amazon" in vendor or "aws" in product:
                affected_infra.append(InfrastructureType.AWS)
            if "azure" in product or "microsoft" in vendor and "azure" in product:
                affected_infra.append(InfrastructureType.AZURE)
            if "google" in vendor or "gcp" in product:
                affected_infra.append(InfrastructureType.GCP)
            if not affected_infra:
                affected_infra.append(InfrastructureType.NETWORK)

            cve = CVEInfo(
                cve_id=cve_id,
                description=vuln.get("shortDescription", vuln.get("vulnerabilityName", "")),
                cvss_score=0.0,  # KEV doesn't include CVSS
                severity="critical",  # If it's in KEV, it's actively exploited
                affected_products=[f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}"],
                affected_infrastructure=affected_infra,
                exploitation_status="in-the-wild",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                published_date=vuln.get("dateAdded", ""),
            )
            result["cves"].append(cve)

        return result

    def _parse_atomic_red_team(self, content: str, source_url: str) -> dict:
        """Parse Atomic Red Team CSV index."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        result["raw_count"] = len(rows)

        for row in rows:
            technique_id = row.get("Technique #", "") or row.get("Technique", "")
            name = row.get("Technique Name", "") or row.get("Test Name", "")

            if not technique_id or not name:
                continue

            # Map tactic to phase
            tactic = row.get("Tactic", "").lower()
            phase_map = {
                "reconnaissance": AttackPhase.RECONNAISSANCE,
                "initial-access": AttackPhase.INITIAL_ACCESS,
                "execution": AttackPhase.EXECUTION,
                "persistence": AttackPhase.PERSISTENCE,
                "privilege-escalation": AttackPhase.PRIVILEGE_ESCALATION,
                "defense-evasion": AttackPhase.DEFENSE_EVASION,
                "credential-access": AttackPhase.CREDENTIAL_ACCESS,
                "discovery": AttackPhase.DISCOVERY,
                "lateral-movement": AttackPhase.LATERAL_MOVEMENT,
                "collection": AttackPhase.COLLECTION,
                "exfiltration": AttackPhase.EXFILTRATION,
                "impact": AttackPhase.IMPACT,
            }
            phase = phase_map.get(tactic.replace(" ", "-"), AttackPhase.EXECUTION)

            technique = AttackTechnique(
                id=f"ART-{technique_id}",
                mitre_id=technique_id,
                name=f"Atomic: {name}",
                phase=phase,
                infrastructure=InfrastructureType.ACTIVE_DIRECTORY,
                description=row.get("Test Description", row.get("Description", "")),
                prerequisites=[],
                tools=["Atomic Red Team"],
                commands=[f"# Run with Invoke-AtomicTest\nInvoke-AtomicTest {technique_id}"],
                detection="",
                references=[f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{technique_id}/{technique_id}.md"],
                next_techniques=[],
                risk_level="medium",
            )
            result["techniques"].append(technique)

        return result

    def _parse_stratus(self, data: list, source_url: str) -> dict:
        """Parse Stratus Red Team techniques."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        items = data if isinstance(data, list) else []

        for item in items:
            name = item.get("name", "") or item.get("id", "")
            if not name:
                continue

            # Map platform to infrastructure
            platform = item.get("platform", "").lower()
            infra_map = {
                "aws": InfrastructureType.AWS,
                "azure": InfrastructureType.AZURE,
                "gcp": InfrastructureType.GCP,
                "kubernetes": InfrastructureType.NETWORK,
            }
            infrastructure = infra_map.get(platform, InfrastructureType.AWS)

            # Map tactic to phase
            tactics = item.get("mitreTactics", [])
            phase = AttackPhase.EXECUTION
            if tactics:
                tactic = tactics[0].lower().replace("-", "_")
                phase_map = {
                    "initial_access": AttackPhase.INITIAL_ACCESS,
                    "execution": AttackPhase.EXECUTION,
                    "persistence": AttackPhase.PERSISTENCE,
                    "privilege_escalation": AttackPhase.PRIVILEGE_ESCALATION,
                    "defense_evasion": AttackPhase.DEFENSE_EVASION,
                    "credential_access": AttackPhase.CREDENTIAL_ACCESS,
                    "discovery": AttackPhase.DISCOVERY,
                    "lateral_movement": AttackPhase.LATERAL_MOVEMENT,
                    "exfiltration": AttackPhase.EXFILTRATION,
                }
                phase = phase_map.get(tactic, AttackPhase.EXECUTION)

            commands = []
            if item.get("id"):
                commands.append(f"# Run with Stratus Red Team\nstratus detonate {item['id']}")

            technique = AttackTechnique(
                id=f"STRATUS-{item.get('id', name)}",
                mitre_id=", ".join(item.get("mitreAttackTechniques", [])),
                name=f"Stratus: {name}",
                phase=phase,
                infrastructure=infrastructure,
                description=item.get("description", ""),
                prerequisites=[],
                tools=["Stratus Red Team"],
                commands=commands,
                detection=item.get("detection", ""),
                references=[f"https://stratus-red-team.cloud/attack-techniques/{platform}/{item.get('id', '')}"],
                next_techniques=[],
                risk_level="high",
            )
            result["techniques"].append(technique)

        return result

    def _parse_urlhaus(self, data: dict, source_url: str) -> dict:
        """Parse abuse.ch URLhaus feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        urls = data.get("urls", []) if isinstance(data, dict) else data
        result["raw_count"] = len(urls) if isinstance(urls, list) else 0

        for entry in urls[:1000]:  # Limit to prevent memory issues
            if isinstance(entry, dict):
                result["indicators"].append({
                    "type": "url",
                    "value": entry.get("url", ""),
                    "threat_type": entry.get("threat", ""),
                    "tags": entry.get("tags", []),
                })

        return result

    def _parse_threatfox(self, data: dict, source_url: str) -> dict:
        """Parse abuse.ch ThreatFox feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        iocs = data.get("data", []) if isinstance(data, dict) else data
        result["raw_count"] = len(iocs) if isinstance(iocs, list) else 0

        for entry in iocs[:1000]:
            if isinstance(entry, dict):
                result["indicators"].append({
                    "type": entry.get("ioc_type", "unknown"),
                    "value": entry.get("ioc", ""),
                    "threat_type": entry.get("threat_type", ""),
                    "malware": entry.get("malware", ""),
                    "confidence": entry.get("confidence_level", 0),
                })

        return result

    def _parse_malwarebazaar(self, data: dict, source_url: str) -> dict:
        """Parse abuse.ch MalwareBazaar feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        samples = data.get("data", []) if isinstance(data, dict) else data
        result["raw_count"] = len(samples) if isinstance(samples, list) else 0

        for entry in samples[:500]:
            if isinstance(entry, dict):
                result["indicators"].append({
                    "type": "hash",
                    "value": entry.get("sha256_hash", ""),
                    "md5": entry.get("md5_hash", ""),
                    "filename": entry.get("file_name", ""),
                    "file_type": entry.get("file_type", ""),
                    "signature": entry.get("signature", ""),
                })

        return result

    def _parse_feodotracker(self, data: list, source_url: str) -> dict:
        """Parse abuse.ch Feodo Tracker feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        for entry in data[:500] if isinstance(data, list) else []:
            if isinstance(entry, dict):
                result["indicators"].append({
                    "type": "ip",
                    "value": entry.get("ip_address", ""),
                    "port": entry.get("port", ""),
                    "malware": entry.get("malware", ""),
                    "status": entry.get("status", ""),
                })

        return result

    def _parse_ransomwatch(self, data: list, source_url: str) -> dict:
        """Parse ransomwatch leak site posts."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        # Extract unique threat actors from ransomware groups
        actors_seen = set()
        for entry in data if isinstance(data, list) else []:
            group = entry.get("group_name", "")
            if group and group not in actors_seen:
                actors_seen.add(group)
                actor = ThreatActor(
                    name=group,
                    aliases=[],
                    description=f"Ransomware group: {group}",
                    targeted_infrastructure=[InfrastructureType.ACTIVE_DIRECTORY],
                    ttps=["T1486", "T1490", "T1003"],  # Common ransomware TTPs
                    recent_activity=f"Active leak site with {len([e for e in data if e.get('group_name') == group])} posts",
                    references=[source_url],
                )
                result["threat_actors"].append(actor)

        return result

    def _parse_lots(self, data: list, source_url: str) -> dict:
        """Parse LOTS (Living Off Trusted Sites) project feed."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": len(data) if isinstance(data, list) else 0,
        }

        for item in data if isinstance(data, list) else []:
            name = item.get("name", "") or item.get("site", "")
            if not name:
                continue

            # Determine what the site can be used for
            uses = item.get("uses", []) or item.get("categories", [])
            commands = []
            for use in uses:
                if isinstance(use, dict):
                    commands.append(f"# {use.get('type', 'Usage')}\n{use.get('example', '')}")

            technique = AttackTechnique(
                id=f"LOTS-{name.replace('.', '-')}",
                mitre_id="T1102",  # Web Service
                name=f"LOTS: {name}",
                phase=AttackPhase.EXFILTRATION,  # Most LOTS are for exfil/C2
                infrastructure=InfrastructureType.NETWORK,
                description=f"Trusted site that can be abused: {name}",
                prerequisites=["Internet access"],
                tools=[],
                commands=commands[:5],
                detection="Monitor for unusual traffic to legitimate sites",
                references=[source_url],
                next_techniques=[],
                risk_level="medium",
            )
            result["techniques"].append(technique)

        return result

    def _parse_default_creds(self, content: str, source_url: str) -> dict:
        """Parse default credentials cheat sheet."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        result["raw_count"] = len(rows)

        # Group by product for techniques
        products = {}
        for row in rows:
            product = row.get("Product", row.get("product", "Unknown"))
            if product not in products:
                products[product] = []
            products[product].append(row)

        for product, creds in list(products.items())[:50]:  # Limit
            commands = []
            for cred in creds[:5]:
                username = cred.get("Username", cred.get("username", ""))
                password = cred.get("Password", cred.get("password", ""))
                if username and password:
                    commands.append(f"# Default credentials for {product}\nUsername: {username}\nPassword: {password}")

            if commands:
                technique = AttackTechnique(
                    id=f"DEFCRED-{product.replace(' ', '-')[:20]}",
                    mitre_id="T1078.001",
                    name=f"Default Creds: {product}",
                    phase=AttackPhase.INITIAL_ACCESS,
                    infrastructure=InfrastructureType.NETWORK,
                    description=f"Default credentials for {product}",
                    prerequisites=[f"Access to {product} login"],
                    tools=[],
                    commands=commands,
                    detection="Monitor for authentication with default credentials",
                    references=[source_url],
                    next_techniques=[],
                    risk_level="high",
                )
                result["techniques"].append(technique)

        return result

    def _parse_nuclei(self, data: dict, source_url: str) -> dict:
        """Parse Nuclei templates CVE information."""
        result = {
            "techniques": [],
            "cves": [],
            "threat_actors": [],
            "indicators": [],
            "raw_count": 0,
        }

        # Nuclei exports CVE info in various formats
        if isinstance(data, dict):
            cves = data.get("cves", []) or data.get("templates", [])
        else:
            cves = data if isinstance(data, list) else []

        result["raw_count"] = len(cves)

        for item in cves[:200]:
            if isinstance(item, dict):
                cve_id = item.get("ID", "") or item.get("cve-id", "") or item.get("id", "")
                if not cve_id or not cve_id.upper().startswith("CVE-"):
                    continue

                cve = CVEInfo(
                    cve_id=cve_id.upper(),
                    description=item.get("description", item.get("info", {}).get("description", "")),
                    cvss_score=float(item.get("cvss-score", 0) or 0),
                    severity=item.get("severity", "medium").lower(),
                    affected_products=item.get("products", []),
                    affected_infrastructure=[InfrastructureType.NETWORK],
                    exploitation_status="poc-available",
                    references=item.get("reference", []) or [source_url],
                    published_date=item.get("published", ""),
                )
                result["cves"].append(cve)

        return result
