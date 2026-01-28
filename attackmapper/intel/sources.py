"""Pre-configured threat intelligence and red team sources."""

from typing import Optional
from dataclasses import dataclass


@dataclass
class IntelSource:
    """A pre-configured intelligence source."""
    name: str
    url: str
    description: str
    feed_type: str  # json, stix, misp, csv, custom
    category: str  # threat_intel, red_team, exploits, techniques, iocs
    infrastructure: Optional[str]  # ad, aws, azure, gcp, network, or None for all
    requires_api_key: bool = False
    api_key_env: Optional[str] = None  # Environment variable name for API key
    enabled_by_default: bool = False
    parser: Optional[str] = None  # Custom parser name if needed


# Pre-configured sources organized by category
BUILTIN_SOURCES = {
    # ==========================================================================
    # MITRE ATT&CK Framework Sources
    # ==========================================================================
    "mitre-attack-enterprise": IntelSource(
        name="mitre-attack-enterprise",
        url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        description="MITRE ATT&CK Enterprise Matrix - Full technique database",
        feed_type="stix",
        category="techniques",
        infrastructure=None,
        enabled_by_default=True,
    ),
    "mitre-attack-ics": IntelSource(
        name="mitre-attack-ics",
        url="https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        description="MITRE ATT&CK for ICS - Industrial Control Systems techniques",
        feed_type="stix",
        category="techniques",
        infrastructure="network",
    ),
    "mitre-attack-mobile": IntelSource(
        name="mitre-attack-mobile",
        url="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        description="MITRE ATT&CK Mobile Matrix",
        feed_type="stix",
        category="techniques",
        infrastructure=None,
    ),

    # ==========================================================================
    # Red Team Technique Resources
    # ==========================================================================
    "atomic-red-team": IntelSource(
        name="atomic-red-team",
        url="https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-CSV/index.csv",
        description="Atomic Red Team - Library of tests mapped to MITRE ATT&CK",
        feed_type="csv",
        category="red_team",
        infrastructure=None,
        parser="atomic_red_team",
        enabled_by_default=True,
    ),
    "lolbas": IntelSource(
        name="lolbas",
        url="https://lolbas-project.github.io/api/lolbas.json",
        description="LOLBAS - Living Off The Land Binaries and Scripts (Windows)",
        feed_type="json",
        category="red_team",
        infrastructure="ad",
        parser="lolbas",
        enabled_by_default=True,
    ),
    "gtfobins": IntelSource(
        name="gtfobins",
        url="https://gtfobins.github.io/gtfobins.json",
        description="GTFOBins - Unix binaries for privilege escalation and security bypass",
        feed_type="json",
        category="red_team",
        infrastructure="network",
        parser="gtfobins",
        enabled_by_default=True,
    ),
    "hijacklibs": IntelSource(
        name="hijacklibs",
        url="https://hijacklibs.net/api/hijacklibs.json",
        description="HijackLibs - DLL Hijacking database for Windows",
        feed_type="json",
        category="red_team",
        infrastructure="ad",
        parser="hijacklibs",
    ),
    "wadcoms": IntelSource(
        name="wadcoms",
        url="https://wadcoms.github.io/api/wadcoms.json",
        description="WADComs - Windows/AD offensive command reference",
        feed_type="json",
        category="red_team",
        infrastructure="ad",
        parser="wadcoms",
        enabled_by_default=True,
    ),
    "lots-project": IntelSource(
        name="lots-project",
        url="https://lots-project.com/api/lots.json",
        description="LOTS Project - Living Off Trusted Sites for C2/exfil",
        feed_type="json",
        category="red_team",
        infrastructure=None,
        parser="lots",
    ),
    "malapi": IntelSource(
        name="malapi",
        url="https://malapi.io/api/win32",
        description="MalAPI - Windows APIs commonly used by malware",
        feed_type="json",
        category="red_team",
        infrastructure="ad",
        parser="malapi",
    ),
    "filesec": IntelSource(
        name="filesec",
        url="https://filesec.io/api/files.json",
        description="FileSec - File extension security analysis",
        feed_type="json",
        category="red_team",
        infrastructure=None,
        parser="filesec",
    ),

    # ==========================================================================
    # Cloud Security Resources
    # ==========================================================================
    "stratus-red-team": IntelSource(
        name="stratus-red-team",
        url="https://raw.githubusercontent.com/DataDog/stratus-red-team/main/docs/attack-techniques/list.json",
        description="Stratus Red Team - Cloud attack simulation library by DataDog",
        feed_type="json",
        category="red_team",
        infrastructure=None,  # Covers AWS, Azure, GCP
        parser="stratus",
        enabled_by_default=True,
    ),
    "aws-security-tools": IntelSource(
        name="aws-security-tools",
        url="https://raw.githubusercontent.com/toniblyx/my-arsenal-of-aws-security-tools/master/README.md",
        description="AWS Security Tools Arsenal",
        feed_type="custom",
        category="red_team",
        infrastructure="aws",
        parser="markdown_tools",
    ),
    "cloudlist": IntelSource(
        name="cloudlist",
        url="https://raw.githubusercontent.com/projectdiscovery/cloudlist/main/README.md",
        description="Cloud asset discovery tool reference",
        feed_type="custom",
        category="red_team",
        infrastructure=None,
        parser="markdown_tools",
    ),

    # ==========================================================================
    # Vulnerability & Exploit Sources
    # ==========================================================================
    "cisa-kev": IntelSource(
        name="cisa-kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="CISA Known Exploited Vulnerabilities Catalog",
        feed_type="json",
        category="exploits",
        infrastructure=None,
        parser="cisa_kev",
        enabled_by_default=True,
    ),
    "nuclei-cves": IntelSource(
        name="nuclei-cves",
        url="https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
        description="Nuclei CVE Templates - Exploitable vulnerabilities",
        feed_type="json",
        category="exploits",
        infrastructure=None,
        parser="nuclei",
    ),
    "exploitdb": IntelSource(
        name="exploitdb",
        url="https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
        description="Exploit-DB - Public exploits database",
        feed_type="csv",
        category="exploits",
        infrastructure=None,
        parser="exploitdb",
    ),
    "poc-in-github": IntelSource(
        name="poc-in-github",
        url="https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md",
        description="PoC-in-GitHub - CVE Proof of Concepts from GitHub",
        feed_type="custom",
        category="exploits",
        infrastructure=None,
        parser="github_pocs",
    ),

    # ==========================================================================
    # Threat Intelligence Feeds
    # ==========================================================================
    "abuse-urlhaus": IntelSource(
        name="abuse-urlhaus",
        url="https://urlhaus.abuse.ch/downloads/json/",
        description="URLhaus - Malicious URL database by abuse.ch",
        feed_type="json",
        category="iocs",
        infrastructure=None,
        parser="urlhaus",
    ),
    "abuse-threatfox": IntelSource(
        name="abuse-threatfox",
        url="https://threatfox.abuse.ch/export/json/recent/",
        description="ThreatFox - IOC database by abuse.ch",
        feed_type="json",
        category="iocs",
        infrastructure=None,
        parser="threatfox",
    ),
    "abuse-malwarebazaar": IntelSource(
        name="abuse-malwarebazaar",
        url="https://bazaar.abuse.ch/export/json/recent/",
        description="MalwareBazaar - Malware sample database",
        feed_type="json",
        category="iocs",
        infrastructure=None,
        parser="malwarebazaar",
    ),
    "abuse-feodotracker": IntelSource(
        name="abuse-feodotracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        description="Feodo Tracker - Botnet C2 IP blocklist",
        feed_type="json",
        category="iocs",
        infrastructure=None,
        parser="feodotracker",
    ),
    "openphish": IntelSource(
        name="openphish",
        url="https://openphish.com/feed.txt",
        description="OpenPhish - Phishing URL feed",
        feed_type="custom",
        category="iocs",
        infrastructure=None,
        parser="text_urls",
    ),
    "phishtank": IntelSource(
        name="phishtank",
        url="http://data.phishtank.com/data/online-valid.json",
        description="PhishTank - Community phishing verification",
        feed_type="json",
        category="iocs",
        infrastructure=None,
        parser="phishtank",
        requires_api_key=True,
        api_key_env="PHISHTANK_API_KEY",
    ),
    "alienvault-otx": IntelSource(
        name="alienvault-otx",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        description="AlienVault OTX - Open Threat Exchange",
        feed_type="json",
        category="threat_intel",
        infrastructure=None,
        parser="otx",
        requires_api_key=True,
        api_key_env="OTX_API_KEY",
    ),

    # ==========================================================================
    # Active Directory Specific
    # ==========================================================================
    "bloodhound-techniques": IntelSource(
        name="bloodhound-techniques",
        url="https://raw.githubusercontent.com/SpecterOps/BloodHound/main/packages/javascript/bh-shared-ui/src/components/HelpTexts/index.tsx",
        description="BloodHound attack techniques and abuse info",
        feed_type="custom",
        category="red_team",
        infrastructure="ad",
        parser="bloodhound",
    ),
    "ad-security-tools": IntelSource(
        name="ad-security-tools",
        url="https://raw.githubusercontent.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet/master/README.md",
        description="Active Directory Exploitation Cheat Sheet",
        feed_type="custom",
        category="red_team",
        infrastructure="ad",
        parser="markdown_techniques",
    ),
    "impacket-examples": IntelSource(
        name="impacket-examples",
        url="https://api.github.com/repos/fortra/impacket/contents/examples",
        description="Impacket tools reference",
        feed_type="json",
        category="red_team",
        infrastructure="ad",
        parser="github_contents",
    ),

    # ==========================================================================
    # Threat Actor Intelligence
    # ==========================================================================
    "malpedia": IntelSource(
        name="malpedia",
        url="https://malpedia.caad.fkie.fraunhofer.de/api/list/actors",
        description="Malpedia - Threat actor and malware database",
        feed_type="json",
        category="threat_intel",
        infrastructure=None,
        parser="malpedia",
    ),
    "mitre-groups": IntelSource(
        name="mitre-groups",
        url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        description="MITRE ATT&CK Threat Groups",
        feed_type="stix",
        category="threat_intel",
        infrastructure=None,
        parser="mitre_groups",
    ),
    "ransomwatch": IntelSource(
        name="ransomwatch",
        url="https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
        description="Ransomwatch - Ransomware group leak site monitoring",
        feed_type="json",
        category="threat_intel",
        infrastructure=None,
        parser="ransomwatch",
    ),

    # ==========================================================================
    # Detection & Defense (useful for understanding what to evade)
    # ==========================================================================
    "sigma-rules": IntelSource(
        name="sigma-rules",
        url="https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1",
        description="Sigma Rules - Generic detection signatures",
        feed_type="json",
        category="techniques",
        infrastructure=None,
        parser="sigma_rules",
    ),
    "elastic-detection-rules": IntelSource(
        name="elastic-detection-rules",
        url="https://api.github.com/repos/elastic/detection-rules/git/trees/main?recursive=1",
        description="Elastic Detection Rules",
        feed_type="json",
        category="techniques",
        infrastructure=None,
        parser="detection_rules",
    ),
    "splunk-security-content": IntelSource(
        name="splunk-security-content",
        url="https://api.github.com/repos/splunk/security_content/git/trees/develop?recursive=1",
        description="Splunk Security Content - Detection analytics",
        feed_type="json",
        category="techniques",
        infrastructure=None,
        parser="splunk_detections",
    ),

    # ==========================================================================
    # Offensive Security Tools Reference
    # ==========================================================================
    "hacktricks": IntelSource(
        name="hacktricks",
        url="https://api.github.com/repos/HackTricks-wiki/hacktricks/git/trees/master?recursive=1",
        description="HackTricks - Pentesting/red team techniques wiki",
        feed_type="json",
        category="red_team",
        infrastructure=None,
        parser="hacktricks",
    ),
    "payloads-all-the-things": IntelSource(
        name="payloads-all-the-things",
        url="https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/git/trees/master?recursive=1",
        description="PayloadsAllTheThings - Payload repository",
        feed_type="json",
        category="red_team",
        infrastructure=None,
        parser="payloads",
    ),
    "seclists": IntelSource(
        name="seclists",
        url="https://api.github.com/repos/danielmiessler/SecLists/git/trees/master?recursive=1",
        description="SecLists - Security testing wordlists",
        feed_type="json",
        category="red_team",
        infrastructure=None,
        parser="seclists",
    ),

    # ==========================================================================
    # Network Security
    # ==========================================================================
    "default-credentials": IntelSource(
        name="default-credentials",
        url="https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv",
        description="Default Credentials Cheat Sheet",
        feed_type="csv",
        category="red_team",
        infrastructure="network",
        parser="default_creds",
    ),
    "public-dns-resolvers": IntelSource(
        name="public-dns-resolvers",
        url="https://public-dns.info/nameservers.json",
        description="Public DNS resolvers list",
        feed_type="json",
        category="red_team",
        infrastructure="network",
        parser="dns_resolvers",
    ),
}


def get_sources_by_category(category: str) -> list[IntelSource]:
    """Get all sources in a specific category."""
    return [s for s in BUILTIN_SOURCES.values() if s.category == category]


def get_sources_by_infrastructure(infrastructure: str) -> list[IntelSource]:
    """Get all sources relevant to a specific infrastructure."""
    return [
        s for s in BUILTIN_SOURCES.values()
        if s.infrastructure is None or s.infrastructure == infrastructure
    ]


def get_default_sources() -> list[IntelSource]:
    """Get sources that are enabled by default."""
    return [s for s in BUILTIN_SOURCES.values() if s.enabled_by_default]


def get_source(name: str) -> Optional[IntelSource]:
    """Get a specific source by name."""
    return BUILTIN_SOURCES.get(name)


def list_all_sources() -> list[IntelSource]:
    """Get all available sources."""
    return list(BUILTIN_SOURCES.values())
