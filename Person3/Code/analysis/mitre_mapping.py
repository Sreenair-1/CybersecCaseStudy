"""MITRE ATT&CK Mapping for Incident-Grounded Simulation.

Maps documented incident characteristics to simulation behaviors and MITRE ATT&CK techniques.
Each mapping is explicitly labeled with its analytical evidence status:
- 'incident-supported': Documented in public incident disclosures.
- 'analytical/inferred': Plausible technique inferred from attacker outcomes.
- 'simulation-only': Modeling abstraction used for synthetic experimentation.
"""

from typing import Dict, List


MITRE_MAPPING: List[Dict[str, str]] = [
    {
        "incident_characteristic": "Machine-speed API and service endpoint enumeration",
        "simulation_stage": "Resource Discovery",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1087 / T1083 (Account / File / Service Discovery)",
        "simulation_actions": "DISCOVER, REQUEST_RESOURCE",
        "evidence_status": "incident-supported",
        "note": "Synthetic enumeration of simulated platform resources; no real network scanning.",
    },
    {
        "incident_characteristic": "Platform token, key, and secret harvesting",
        "simulation_stage": "Credential Attempt",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552 / T1555 (Unsecured Credentials / Credentials from Vault)",
        "simulation_actions": "ACCESS_CREDENTIAL",
        "evidence_status": "incident-supported",
        "note": "Uses synthetic credential objects; no real credential harvesting.",
    },
    {
        "incident_characteristic": "Unauthorized service execution and scope expansion",
        "simulation_stage": "Unauthorized Access",
        "mitre_tactic": "Privilege Escalation / Defense Evasion",
        "mitre_technique": "T1078 (Valid Accounts / Permission Overreach)",
        "simulation_actions": "READ, WRITE, EXECUTE, REQUEST_RESOURCE",
        "evidence_status": "analytical/inferred",
        "note": "Represents authorization violations within the synthetic permission engine.",
    },
    {
        "incident_characteristic": "Cross-zone pivoting across platform infrastructure",
        "simulation_stage": "Lateral Movement",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021 / T1090 (Remote Services / Proxy Redirection)",
        "simulation_actions": "MOVE",
        "evidence_status": "analytical/inferred",
        "note": "Evaluated by synthetic network segmentation policies across 6 zones.",
    },
    {
        "incident_characteristic": "Targeting of proprietary model weights, datasets, and ground-truth",
        "simulation_stage": "Sensitive Resource Access",
        "mitre_tactic": "Collection / Impact Proxy",
        "mitre_technique": "T1530 / T1565 (Data from Cloud Storage / Data Manipulation)",
        "simulation_actions": "READ, WRITE, EXECUTE",
        "evidence_status": "incident-supported",
        "note": "Terminal synthetic objective (customer_pii/sensitive store); no data leaves the system.",
    },
    {
        "incident_characteristic": "AI anomaly detection & automated session blocking",
        "simulation_stage": "Detection and Containment",
        "mitre_tactic": "Defense Evasion Countermeasures",
        "mitre_technique": "M1038 / M1040 (Execution Prevention / Behavior Monitoring)",
        "simulation_actions": "BLOCK_AGENT",
        "evidence_status": "simulation-only",
        "note": "Simulated behavioral threshold and automated containment delay engine.",
    },
]

