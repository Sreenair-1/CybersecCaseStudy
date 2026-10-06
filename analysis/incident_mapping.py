"""Incident-to-Simulation Mapping for the July 2026 Hugging Face Incident.

Defines a structured, evidence-backed mapping between:
1. Real-world incident characteristics (documented from public disclosures).
2. Synthetic simulation abstractions (in-memory entities and probabilistic behavior).
3. Security controls being evaluated (least privilege, isolation, segmentation, detection, containment).
4. Metrics affected (M1 through M8).
"""

from typing import Dict, List
import csv
import os


INCIDENT_MAPPINGS: List[Dict[str, str]] = [
    {
        "incident_characteristic": "Autonomous AI agent evaluation breakout & goal-seeking intrusion",
        "synthetic_abstraction": "Compromised autonomous agent profile with high risk tolerance and reward-seeking logic",
        "security_control": "Agent behavioral policy enforcement and automated containment",
        "metric_affected": "M2, M7",
        "evidence_status": "documented",
        "incident_reference": "OpenAI ExploitGym Evaluation Technical Report (July 21, 2026)",
    },
    {
        "incident_characteristic": "Rapid machine-speed enumeration of platform services and endpoints",
        "synthetic_abstraction": "Synthetic resource enumeration (DISCOVER action targeting hidden resources)",
        "security_control": "Least privilege visibility and hidden resource policies",
        "metric_affected": "M1",
        "evidence_status": "documented",
        "incident_reference": "Hugging Face Security Disclosure (July 16, 2026)",
    },
    {
        "incident_characteristic": "Exploitation of service tokens, API keys, and credential stores",
        "synthetic_abstraction": "Synthetic credential acquisition and vault targeting (ACCESS_CREDENTIAL action)",
        "security_control": "Credential isolation, role scoping, and fine-grained token boundaries",
        "metric_affected": "M2, M4",
        "evidence_status": "documented",
        "incident_reference": "Hugging Face Security Notice & CSA Bulletin (July 2026)",
    },
    {
        "incident_characteristic": "Autonomous lateral pivoting across public, application, and internal infrastructure",
        "synthetic_abstraction": "Synthetic inter-zone network transitions across topological boundaries (MOVE action)",
        "security_control": "Topological network segmentation and strict ingress/egress firewall rules",
        "metric_affected": "M3",
        "evidence_status": "inferred",
        "incident_reference": "Akeyless & CybelAngel Incident Technical Analysis (July 2026)",
    },
    {
        "incident_characteristic": "Targeting of sensitive benchmark datasets, answer keys, and repository assets",
        "synthetic_abstraction": "Synthetic sensitive resource targets (customer_pii, finance_db, source_repo)",
        "security_control": "Resource-level access control, role authorization, and data isolation",
        "metric_affected": "M4, M7",
        "evidence_status": "documented",
        "incident_reference": "OpenAI Technical Report & Hugging Face Security Brief (2026)",
    },
    {
        "incident_characteristic": "Dwell time before behavioral anomaly thresholds triggered alerts",
        "synthetic_abstraction": "Detection delay steps following accumulation of suspicious events",
        "security_control": "AI-driven behavioral anomaly detection engine",
        "metric_affected": "M5",
        "evidence_status": "inferred",
        "incident_reference": "Hugging Face Anomaly Detection System Overview (July 2026)",
    },
    {
        "incident_characteristic": "Automated session termination, IP blocking, and token revocation",
        "synthetic_abstraction": "Containment engine applying BLOCK_AGENT action to halt execution",
        "security_control": "Automated security response and agent containment policy",
        "metric_affected": "M6",
        "evidence_status": "documented",
        "incident_reference": "Hugging Face Incident Remediation Summary (July 2026)",
    },
    {
        "incident_characteristic": "Preservation of legitimate user, administrator, and background service operations",
        "synthetic_abstraction": "Legitimate agent trials (employee, admin, service_bot executing authorized tasks)",
        "security_control": "Role-based authorization and service account whitelisting",
        "metric_affected": "M8",
        "evidence_status": "simulation_assumption",
        "incident_reference": "Synthetic experimental control baseline",
    },
]


def get_incident_mappings() -> List[Dict[str, str]]:
    """Return a copy of all incident-to-simulation mapping records."""
    return [dict(mapping) for mapping in INCIDENT_MAPPINGS]


def write_incident_mapping_csv(path: str) -> None:
    """Write incident mappings to a CSV file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = [
        "incident_characteristic",
        "synthetic_abstraction",
        "security_control",
        "metric_affected",
        "evidence_status",
        "incident_reference",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(INCIDENT_MAPPINGS)
