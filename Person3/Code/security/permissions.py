from dataclasses import dataclass
from typing import Iterable, Optional

from agent.action_policy import Action
from agent.agent_profiles import AgentProfile
from environment.credentials import Credential
from environment.resources import Resource


@dataclass(frozen=True)
class PermissionResult:
    authorized: bool
    blocked: bool
    reason: str
    credential_id: str = ""


def _matching_credential(credentials: Iterable[Credential], target: Resource) -> Optional[Credential]:
    for credential in credentials:
        if target.resource_id in credential.resource_access or credential.credential_id == target.required_credential:
            return credential
    return None


def evaluate_permission(
    environment: str,
    action: Action,
    agent: AgentProfile,
    target: Resource,
    available_credentials: Iterable[Credential],
) -> PermissionResult:
    if action == Action.DISCOVER:
        if target.discoverable or environment == "baseline":
            return PermissionResult(True, False, "discoverable")
        return PermissionResult(False, environment == "protected", "hidden_resource")

    if action == Action.REQUEST_RESOURCE:
        allowed = agent.role == target.required_role or target.resource_id in agent.resource_interests
        return PermissionResult(allowed, False, "request_allowed" if allowed else "request_denied")

    credential = _matching_credential(available_credentials, target)
    if action == Action.LEGITIMATE_TASK and credential and target.resource_id in agent.resource_interests:
        return PermissionResult(True, False, "legitimate_task_authorized", credential.credential_id)
    role_match = agent.role == target.required_role
    if credential and (role_match or environment == "baseline" or not credential.isolated):
        return PermissionResult(True, False, "credential_authorized", credential.credential_id)

    if environment == "protected":
        return PermissionResult(False, True, "least_privilege_block")
    return PermissionResult(False, False, "unauthorized_but_attempted")
