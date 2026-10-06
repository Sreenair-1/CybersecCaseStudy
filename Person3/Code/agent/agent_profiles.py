"""Synthetic Agent Profiles for Incident-Grounded Simulation.

Profiles represent identities/roles relevant to the July 2026 Hugging Face threat model:
- 'compromised': Primary adversarial autonomous agent model (analogous to the escaped
                eval agent exhibiting high risk tolerance, exploratory discovery,
                and credential harvesting).
- 'curious': Lower-capability exploratory / overreaching identity modeling policy misuse.
- 'employee', 'admin', 'service_bot': Legitimate operational profiles used to measure
                                      collateral impact, policy false positives, and
                                      legitimate task availability (M8).
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class AgentProfile:
    profile_id: str
    display_name: str
    role: str
    legitimate_objective: str
    resource_interests: List[str]
    action_probabilities: Dict[str, float]
    risk_tolerance: float
    unauthorized_willingness: float
    starting_zone: str


def build_agent_profiles() -> Dict[str, AgentProfile]:
    """Construct the five synthetic agent profiles for the simulation."""
    return {
        "employee": AgentProfile(
            "employee",
            "Normal employee",
            "employee",
            "complete_hr_task",
            ["public_docs", "hr_portal"],
            {"DISCOVER": 0.18, "READ": 0.36, "REQUEST_RESOURCE": 0.16, "LEGITIMATE_TASK": 0.30},
            0.10,
            0.03,
            "public",
        ),
        "admin": AgentProfile(
            "admin",
            "Privileged administrator",
            "admin",
            "administer_services",
            ["admin_console", "ops_runbooks", "app_service"],
            {"DISCOVER": 0.18, "READ": 0.20, "EXECUTE": 0.20, "MOVE": 0.18, "LEGITIMATE_TASK": 0.24},
            0.22,
            0.08,
            "admin",
        ),
        "curious": AgentProfile(
            "curious",
            "Curious overreaching employee",
            "employee",
            "complete_hr_task",
            ["hr_portal", "finance_db", "customer_pii", "credential_vault"],
            {"DISCOVER": 0.26, "READ": 0.20, "ACCESS_CREDENTIAL": 0.14, "MOVE": 0.20, "REQUEST_RESOURCE": 0.10, "LEGITIMATE_TASK": 0.10},
            0.55,
            0.42,
            "public",
        ),
        "compromised": AgentProfile(
            "compromised",
            "Compromised account",
            "employee",
            "reach_sensitive_data",
            ["credential_vault", "finance_db", "customer_pii", "source_repo", "admin_console"],
            {"DISCOVER": 0.24, "READ": 0.16, "ACCESS_CREDENTIAL": 0.22, "MOVE": 0.25, "EXECUTE": 0.08, "REQUEST_RESOURCE": 0.05},
            0.90,
            0.85,
            "public",
        ),
        "service_bot": AgentProfile(
            "service_bot",
            "Service automation",
            "service",
            "process_orders",
            ["app_service", "internal_api", "orders_db"],
            {"DISCOVER": 0.08, "READ": 0.20, "WRITE": 0.16, "EXECUTE": 0.14, "LEGITIMATE_TASK": 0.42},
            0.08,
            0.02,
            "application",
        ),
    }
