MITRE_MAPPING = [
    {
        "simulation_stage": "Resource Discovery",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1087/T1083-style discovery abstraction",
        "simulation_actions": "DISCOVER, REQUEST_RESOURCE",
        "note": "Synthetic enumeration of simulated resources only.",
    },
    {
        "simulation_stage": "Credential Attempt",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Credential store access abstraction",
        "simulation_actions": "ACCESS_CREDENTIAL",
        "note": "Uses fake credential objects; no real credential collection occurs.",
    },
    {
        "simulation_stage": "Unauthorized Access",
        "mitre_tactic": "Defense Evasion / Privilege Abuse",
        "mitre_technique": "Policy violation abstraction",
        "simulation_actions": "READ, WRITE, EXECUTE, REQUEST_RESOURCE",
        "note": "Represents permission violations in the synthetic policy engine.",
    },
    {
        "simulation_stage": "Lateral Movement",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "Remote service movement abstraction",
        "simulation_actions": "MOVE",
        "note": "Synthetic zone transitions evaluated by segmentation policy.",
    },
    {
        "simulation_stage": "Sensitive Resource Access",
        "mitre_tactic": "Collection / Exfiltration Impact Proxy",
        "mitre_technique": "Sensitive data access abstraction",
        "simulation_actions": "READ, WRITE, EXECUTE",
        "note": "Counts successful access to synthetic sensitive resources; no data leaves the simulation.",
    },
]

