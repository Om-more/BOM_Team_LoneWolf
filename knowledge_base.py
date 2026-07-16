"""
Tiny static retrieval layer -- no vector DB needed for 10-15 entries.
Maps each Context_Tag your correlation engine already produces to real MITRE
ATT&CK technique(s) + a bank-specific SOP line. The LLM is instructed to cite
these verbatim instead of inventing technique IDs from memory.
"""

KNOWLEDGE_BASE = {
    "MULTI_DOMAIN_CORRELATED_ATTACK": [
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "TA0001 Initial Access",
            "description": "Adversary uses compromised legitimate credentials to access the account, "
                            "consistent with simultaneous fraud + cyber signal agreement.",
            "sop": "Freeze account immediately, force step-up re-authentication, escalate to Tier 2 analyst.",
        },
    ],
    "QUANTUM_HARVEST_CONFIRMED": [
        {
            "technique_id": "T1020",
            "technique_name": "Automated Exfiltration",
            "tactic": "TA0010 Exfiltration",
            "description": "Large encrypted payload transfer paired with cyber-confirmed anomalous flow, "
                            "consistent with harvest-now-decrypt-later (HNDL) staging behavior.",
            "sop": "Block source IP, quarantine affected session, flag data for crypto-agility review.",
        },
    ],
    "FINANCIAL_QUANTUM_THREAT": [
        {
            "technique_id": "T1657",
            "technique_name": "Financial Theft",
            "tactic": "TA0040 Impact",
            "description": "High fraud score co-occurring with quantum-risk exfiltration signal; "
                            "suggests financially motivated data harvesting ahead of a future decrypt attempt.",
            "sop": "Freeze account, block source IP, notify fraud + crypto-risk teams jointly.",
        },
    ],
    "QUANTUM_EXFIL_SUSPECTED": [
        {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "TA0010 Exfiltration",
            "description": "Elevated payload entropy and transfer volume outside normal baseline, "
                            "isolated to the quantum-risk model without corroborating fraud/cyber signal.",
            "sop": "Log and monitor; escalate only if repeated within 24h from same source.",
        },
    ],
    "FRAUD_ONLY_ANOMALY": [
        {
            "technique_id": "T1657",
            "technique_name": "Financial Theft",
            "tactic": "TA0040 Impact",
            "description": "Transaction-level anomaly isolated to the fraud model; no corroborating "
                            "network or exfiltration signal.",
            "sop": "Hold transaction for manual review; do not auto-freeze on a single-domain signal.",
        },
    ],
    "CYBER_ONLY_ANOMALY": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "TA0006 Credential Access",
            "description": "Network telemetry anomaly (login/flow pattern) isolated to the cyber model; "
                            "no corroborating transactional signal yet.",
            "sop": "Rate-limit source IP; notify SOC; do not freeze account on network signal alone.",
        },
    ],
    "MULTIPLE_MILD_SIGNALS": [
        {
            "technique_id": "T1589",
            "technique_name": "Gather Victim Identity Information",
            "tactic": "TA0043 Reconnaissance",
            "description": "Several domains show mild, sub-threshold anomalies simultaneously -- "
                            "consistent with early-stage reconnaissance rather than active attack.",
            "sop": "Add to watchlist; re-evaluate if any single score crosses 70 within the next window.",
        },
    ],
    "LOW_RISK_WATCH": [
        {
            "technique_id": "T1589",
            "technique_name": "Gather Victim Identity Information",
            "tactic": "TA0043 Reconnaissance",
            "description": "One mild signal in isolation; low confidence, likely benign variance.",
            "sop": "No action required; log for trend analysis only.",
        },
    ],
    "NORMAL": [],
}

DEFAULT_ENTRY = [{
    "technique_id": "N/A",
    "technique_name": "No matching technique",
    "tactic": "N/A",
    "description": "No specific ATT&CK technique matched this context tag.",
    "sop": "Handle per standard triage procedure.",
}]


def retrieve(context_tag: str):
    """Returns the KB entries for a given Context_Tag (empty/default-safe)."""
    return KNOWLEDGE_BASE.get(context_tag, DEFAULT_ENTRY)
