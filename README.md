<h1 align="center">AttackMapper</h1>

<p align="center">
  <strong>Attack Path Visualization & Threat Intelligence Platform</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-integrated-red.svg" alt="MITRE ATT&CK">
</p>

---

## Overview

AttackMapper is a powerful CLI tool for red team operations that generates attack paths, maps techniques to the MITRE ATT&CK framework, and integrates real-time threat intelligence. Generate beautiful, interactive HTML reports with attack flow visualizations.

## Features

### Attack Path Visualization
- **Kill Chain Mapping** - Visualize complete attack paths from reconnaissance to impact
- **Interactive Graph Views** - Force-directed, radial, and flow-based visualizations
- **Phase-based Organization** - Techniques organized by MITRE ATT&CK tactics

### Threat Intelligence Integration
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **AlienVault OTX** - Open Threat Exchange feeds
- **CVE Tracking** - Real-time vulnerability intelligence
- **Threat Actor Profiles** - Active adversary group tracking

### Multi-Infrastructure Support
| Infrastructure | Description |
|---------------|-------------|
| **Active Directory** | Domain attacks, Kerberos, ADCS, Group Policy |
| **AWS** | IAM, S3, Lambda, EC2, privilege escalation |
| **Azure** | Entra ID, Key Vault, managed identities |
| **GCP** | IAM, Cloud Functions, service accounts |
| **Network** | Traditional network attack paths |

### Enterprise Reporting
- **Interactive HTML Reports** - Modern, responsive dashboard UI
- **Threat Intelligence Dashboard** - CVEs, threat actors, trending TTPs
- **Attack Flow Graphs** - Multiple visualization modes
- **Export Options** - HTML, JSON formats

## Installation

### Requirements
- Python 3.9+
- pip

### Install from source

```bash
git clone https://github.com/Sai-Jagadeesh/attackmapper.git
cd attackmapper
pip install -e .
```

### Verify installation

```bash
attackmapper --help
```

## Quick Start

### View Attack Paths

```bash
# Active Directory attack paths
attackmapper ad

# AWS cloud attack paths
attackmapper aws

# Azure cloud attack paths
attackmapper azure

# GCP cloud attack paths
attackmapper gcp

# Network attack paths
attackmapper network
```

### Filter by Attack Phase

```bash
# View only credential access techniques
attackmapper ad --category credential_access

# View privilege escalation techniques
attackmapper aws --category privilege_escalation
```

### Generate Reports

```bash
# Generate interactive HTML report
attackmapper full-chain --infra ad --output report.html --format html

# Generate JSON export
attackmapper full-chain --infra ad --output report.json --format json
```

### Threat Intelligence

```bash
# Update threat intelligence feeds
attackmapper update-intel

# View threat intel for specific infrastructure
attackmapper threat-intel --infra ad
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `attackmapper ad` | Active Directory attack paths |
| `attackmapper aws` | AWS cloud attack paths |
| `attackmapper azure` | Azure cloud attack paths |
| `attackmapper gcp` | GCP cloud attack paths |
| `attackmapper network` | Network attack paths |
| `attackmapper full-chain` | Generate complete attack chain |
| `attackmapper threat-intel` | View threat intelligence |
| `attackmapper update-intel` | Update threat intel database |

### Options

```
--category, -c    Filter by attack phase
--output, -o      Output file path
--format, -f      Output format (html, json)
--help            Show help message
```

## Configuration

### Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```env
# AlienVault OTX API Key (free)
OTX_API_KEY=your_api_key_here
```

### Getting API Keys

#### AlienVault OTX (Free)
1. Sign up at [AlienVault OTX](https://otx.alienvault.com/)
2. Go to Settings → API Integration
3. Copy your API key

## Project Structure

```
attackmapper/
├── attackmapper/
│   ├── core/           # Core engine and models
│   ├── modules/        # Infrastructure modules
│   │   ├── ad/         # Active Directory
│   │   ├── aws/        # AWS Cloud
│   │   ├── azure/      # Azure Cloud
│   │   ├── gcp/        # GCP Cloud
│   │   └── network/    # Network
│   ├── intel/          # Threat intelligence
│   ├── templates/      # Report templates
│   └── data/           # Technique databases
├── tests/              # Test suite
└── docs/               # Documentation
```

## MITRE ATT&CK Coverage

AttackMapper maps techniques across the full kill chain:

- **Reconnaissance** - Target identification and information gathering
- **Initial Access** - Entry point techniques
- **Execution** - Running malicious code
- **Persistence** - Maintaining access
- **Privilege Escalation** - Gaining higher permissions
- **Defense Evasion** - Avoiding detection
- **Credential Access** - Stealing credentials
- **Discovery** - Environment exploration
- **Lateral Movement** - Moving through the network
- **Collection** - Gathering target data
- **Exfiltration** - Stealing data
- **Impact** - Disruption and destruction

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) - Framework and technique mappings
- [AlienVault OTX](https://otx.alienvault.com/) - Threat intelligence feeds
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Vulnerability catalog

---

<p align="center">
  <strong>Built for Red Team Operations</strong>
</p>
