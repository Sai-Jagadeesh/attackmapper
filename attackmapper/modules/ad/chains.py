"""Predefined attack chains for Active Directory."""

# Common AD attack chain templates
AD_CHAIN_TEMPLATES = {
    "kerberoasting": {
        "name": "Kerberoasting Attack",
        "description": "Classic Kerberoasting attack to obtain service account credentials",
        "phases": ["reconnaissance", "initial_access", "credential_access", "lateral_movement"],
        "technique_ids": ["AD-RECON-001", "AD-INIT-002", "AD-CRED-001", "AD-LATERAL-001"],
    },
    "dcsync": {
        "name": "DCSync Domain Compromise",
        "description": "Obtain DCSync rights and dump all domain credentials",
        "phases": ["reconnaissance", "initial_access", "privilege_escalation", "credential_access", "persistence"],
        "technique_ids": ["AD-RECON-003", "AD-INIT-003", "AD-PRIVESC-001", "AD-CRED-004", "AD-PERSIST-001"],
    },
    "adcs": {
        "name": "AD Certificate Services Abuse",
        "description": "Abuse misconfigured AD CS for domain compromise",
        "phases": ["reconnaissance", "credential_access", "privilege_escalation", "impact"],
        "technique_ids": ["AD-RECON-001", "AD-CRED-008", "AD-PRIVESC-001", "AD-IMPACT-001"],
    },
    "ntlm_relay": {
        "name": "NTLM Relay Attack",
        "description": "Capture and relay NTLM authentication for unauthorized access",
        "phases": ["initial_access", "credential_access", "lateral_movement"],
        "technique_ids": ["AD-INIT-003", "AD-INIT-004", "AD-LATERAL-001"],
    },
    "golden_ticket": {
        "name": "Golden Ticket Persistence",
        "description": "Achieve persistent domain access via Golden Ticket",
        "phases": ["credential_access", "persistence", "lateral_movement"],
        "technique_ids": ["AD-CRED-004", "AD-CRED-006", "AD-PERSIST-001", "AD-LATERAL-001"],
    },
    "shadow_credentials": {
        "name": "Shadow Credentials Attack",
        "description": "Abuse msDS-KeyCredentialLink for authentication",
        "phases": ["reconnaissance", "privilege_escalation", "credential_access"],
        "technique_ids": ["AD-RECON-003", "AD-PRIVESC-005", "AD-CRED-002"],
    },
    "gpo_abuse": {
        "name": "GPO Abuse for Lateral Movement",
        "description": "Abuse GPO write permissions for code execution",
        "phases": ["reconnaissance", "privilege_escalation", "execution", "lateral_movement"],
        "technique_ids": ["AD-RECON-003", "AD-PRIVESC-002", "AD-EXEC-001", "AD-LATERAL-001"],
    },
    "ransomware": {
        "name": "Domain-Wide Ransomware",
        "description": "Full domain compromise leading to ransomware deployment",
        "phases": ["initial_access", "credential_access", "privilege_escalation", "lateral_movement", "impact"],
        "technique_ids": ["AD-INIT-001", "AD-CRED-002", "AD-PRIVESC-003", "AD-LATERAL-001", "AD-IMPACT-001"],
    },
}

# Step descriptions for common attack chains
STEP_DESCRIPTIONS = {
    "kerberoasting": [
        "Enumerate domain via LDAP to find service accounts with SPNs",
        "Obtain valid domain credentials via password spraying or phishing",
        "Request TGS tickets for SPNs and crack offline to get service account passwords",
        "Use compromised service account for lateral movement",
    ],
    "dcsync": [
        "Run BloodHound to map attack paths to Domain Admin",
        "Capture NTLM hashes via LLMNR/NBT-NS poisoning",
        "Abuse ACLs to grant DCSync rights or escalate to DA",
        "Perform DCSync to extract all domain password hashes including KRBTGT",
        "Create Golden Ticket for persistent domain access",
    ],
    "adcs": [
        "Enumerate AD CS configuration and certificate templates",
        "Exploit misconfigured template (ESC1-ESC8) to obtain privileged certificate",
        "Use certificate for authentication as privileged user",
        "Achieve full domain compromise",
    ],
}
