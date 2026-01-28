# AttackMapper

A CLI Attack Path Visualizer for Red Team Operations.

## Features

- **Attack Path Visualization**: Generate comprehensive attack paths for various infrastructure types
- **MITRE ATT&CK Integration**: All techniques mapped to MITRE ATT&CK framework
- **Threat Intelligence**: Integrated threat intel from AlienVault OTX, CISA KEV, and CVE feeds
- **Multiple Infrastructure Support**: Active Directory, AWS, Azure, GCP, and Network
- **Rich CLI Output**: Beautiful terminal output with attack phase highlighting
- **Export Options**: JSON and HTML report generation

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# View Active Directory attack paths
attackmapper ad

# View specific attack category
attackmapper ad --category credential_access

# Generate full attack chain
attackmapper full-chain --infra ad

# Update threat intelligence
attackmapper update-intel

# View threat intelligence for AD
attackmapper threat-intel --infra ad

# Export to HTML report
attackmapper full-chain --infra ad --output report.html --format html
```

## Commands

- `attackmapper ad` - Active Directory attack paths
- `attackmapper aws` - AWS cloud attack paths
- `attackmapper azure` - Azure cloud attack paths
- `attackmapper gcp` - GCP cloud attack paths
- `attackmapper network` - Network attack paths
- `attackmapper threat-intel` - View threat intelligence
- `attackmapper update-intel` - Update threat intelligence database
- `attackmapper full-chain` - Generate full attack chain

## Configuration

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

### AlienVault OTX

Get a free API key from [AlienVault OTX](https://otx.alienvault.com/) to enable threat intelligence features.

## License

MIT License
