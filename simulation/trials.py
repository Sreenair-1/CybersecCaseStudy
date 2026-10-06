from typing import Dict, List, Set
import random

from agent.action_policy import Action
from agent.agent_profiles import AgentProfile, build_agent_profiles
from agent.decision_engine import DecisionEngine
from config import ExperimentConfig
from environment.credentials import Credential, build_credentials
from environment.resources import Resource, build_resources, is_sensitive
from security.containment import ContainmentEngine, ContainmentState
from security.detection import DetectionEngine, DetectionState
from security.permissions import evaluate_permission
from security.segmentation import evaluate_transition
from simulation.events import Event


ATTACK_SUCCESS_RESOURCE = "customer_pii"


def initial_credentials(profile: AgentProfile, credentials: Dict[str, Credential]) -> List[Credential]:
    mapping = {
        "employee": ["employee_basic"],
        "curious": ["employee_basic"],
        "compromised": ["employee_basic"],
        "admin": ["admin_ops"],
        "service_bot": ["svc_app", "svc_db"],
    }
    return [credentials[item] for item in mapping.get(profile.profile_id, []) if item in credentials]


def run_environment_trials(environment: str, config: ExperimentConfig) -> List[Event]:
    seed_offset = 0 if environment == "baseline" else 10_000
    rng = random.Random(config.seed + seed_offset)
    profiles = build_agent_profiles()
    events: List[Event] = []
    attack_profiles = [profiles["compromised"], profiles["curious"]]
    legit_profiles = [profiles["employee"], profiles["admin"], profiles["service_bot"]]

    for index in range(config.attack_trials_per_environment):
        profile = attack_profiles[index % len(attack_profiles)]
        events.extend(run_single_trial(environment, "attack", f"{environment}-attack-{index:04d}", profile, config, rng))

    for index in range(config.legitimate_trials_per_environment):
        profile = legit_profiles[index % len(legit_profiles)]
        events.extend(run_single_trial(environment, "legitimate", f"{environment}-legit-{index:04d}", profile, config, rng))
    return events


def run_single_trial(
    environment: str,
    trial_kind: str,
    trial_id: str,
    profile: AgentProfile,
    config: ExperimentConfig,
    rng: random.Random,
) -> List[Event]:
    resources = build_resources()
    credentials = build_credentials(environment)
    held_credentials = initial_credentials(profile, credentials)
    decision_engine = DecisionEngine(rng)
    detection_engine = DetectionEngine(environment)
    containment_engine = ContainmentEngine(environment)
    detection_state = DetectionState()
    containment_state = ContainmentState()

    current_resource = "public_docs" if profile.starting_zone == "public" else "app_service"
    if profile.starting_zone == "admin":
        current_resource = "admin_console"
    current_zone = profile.starting_zone
    discovered: Set[str] = {rid for rid, resource in resources.items() if resource.discoverable}
    trial_events: List[Event] = []

    for timestamp in range(1, config.max_steps + 1):
        if containment_state.contained:
            break

        action, target = decision_engine.choose_action(profile, trial_kind, environment, current_zone, resources, discovered)
        source_resource = current_resource
        source_zone = current_zone
        event_type = "action"
        reason = ""
        authorized = False
        successful = False

        if action == Action.MOVE:
            segment = evaluate_transition(environment, current_zone, target)
            authorized = segment.allowed
            successful = segment.allowed
            reason = segment.reason
            event_type = "transition"
            if successful:
                current_zone = target.network_zone
                current_resource = target.resource_id
                discovered.add(target.resource_id)
        else:
            permission = evaluate_permission(environment, action, profile, target, held_credentials)
            authorized = permission.authorized
            blocked = permission.blocked
            successful = authorized and not blocked
            reason = permission.reason
            if action == Action.DISCOVER and (successful or environment == "baseline"):
                discovered.add(target.resource_id)
                successful = True
            if action == Action.REQUEST_RESOURCE and successful:
                discovered.add(target.resource_id)
            if action == Action.ACCESS_CREDENTIAL and successful:
                gained = credentials.get(target.required_credential)
                if gained and (environment == "baseline" or not gained.isolated or profile.role == gained.role):
                    held_credentials.append(gained)
            if action == Action.LEGITIMATE_TASK and successful:
                reason = f"completed:{profile.legitimate_objective}"

        detection_state = detection_engine.observe(
            detection_state,
            timestamp,
            action.value,
            target,
            authorized,
            successful,
            source_zone,
        )
        containment_state = containment_engine.apply(containment_state, timestamp, detection_state.detected)
        suspicious = detection_state.first_suspicious_time == timestamp or (not authorized) or (successful and is_sensitive(target))

        trial_events.append(
            Event(
                trial_id=trial_id,
                trial_kind=trial_kind,
                environment=environment,
                agent_id=profile.profile_id,
                timestamp=timestamp,
                action=action.value,
                source_resource=source_resource,
                target_resource=target.resource_id,
                source_zone=source_zone,
                target_zone=target.network_zone,
                authorized=authorized,
                successful=successful,
                suspicious=suspicious,
                detected=detection_state.detected,
                contained=containment_state.contained,
                event_type=event_type,
                reason=reason,
            )
        )

        if trial_kind == "attack" and target.resource_id == ATTACK_SUCCESS_RESOURCE and successful:
            break
        if trial_kind == "legitimate" and action == Action.LEGITIMATE_TASK and successful:
            break

    return trial_events


def classify_attack_success(events: List[dict]) -> bool:
    return any(
        event["trial_kind"] == "attack"
        and event["target_resource"] == ATTACK_SUCCESS_RESOURCE
        and str(event["successful"]) == "True"
        for event in events
    )


def classify_legitimate_success(events: List[dict]) -> bool:
    return any(
        event["trial_kind"] == "legitimate"
        and event["action"] == "LEGITIMATE_TASK"
        and str(event["successful"]) == "True"
        for event in events
    )
