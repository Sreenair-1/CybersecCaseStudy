import math
import random

from agent.agent_profiles import build_agent_profiles
from agent.decision_engine import DecisionEngine
from config import ExperimentConfig
from environment.credentials import build_credentials
from environment.resources import build_resources
from security.containment import ContainmentEngine, ContainmentState
from security.detection import DetectionEngine, DetectionState
from security.permissions import evaluate_permission
from security.segmentation import evaluate_transition
from agent.action_policy import Action
from analysis.metrics import calculate_metrics
from simulation.trials import classify_attack_success, classify_legitimate_success, initial_visible_resources, run_single_trial


def test_permission_evaluation_blocks_protected_unauthorized_access():
    resources = build_resources()
    credentials = build_credentials("protected")
    profile = build_agent_profiles()["employee"]
    result = evaluate_permission("protected", Action.READ, profile, resources["customer_pii"], [credentials["employee_basic"]])
    assert not result.authorized
    assert result.blocked


def test_segmentation_differs_between_environments():
    resources = build_resources()
    assert evaluate_transition("baseline", "public", resources["internal_api"]).allowed
    assert not evaluate_transition("protected", "public", resources["internal_api"]).allowed


def test_credential_isolation_differs():
    baseline = build_credentials("baseline")["employee_basic"]
    protected = build_credentials("protected")["employee_basic"]
    assert not baseline.isolated
    assert protected.isolated


def test_detection_triggers_on_protected_unauthorized_action():
    resources = build_resources()
    engine = DetectionEngine("protected", detection_delay_steps=2)
    state = engine.observe(DetectionState(), 1, "READ", resources["customer_pii"], False, False, "public")
    assert not state.detected
    assert state.detection_trigger_time == 1
    state = engine.observe(state, 3, "READ", resources["public_docs"], True, True, "public")
    assert state.detected
    assert state.detection_time == 3


def test_no_suspicious_events_have_no_detection():
    resources = build_resources()
    engine = DetectionEngine("baseline", detection_delay_steps=4)
    state = engine.observe(DetectionState(), 1, "READ", resources["public_docs"], True, True, "public")
    assert not state.detected
    assert state.first_suspicious_time is None


def test_containment_only_in_protected():
    protected = ContainmentEngine("protected", containment_delay_steps=2)
    state = protected.apply(ContainmentState(), 2, 2)
    assert not state.contained
    state = protected.apply(state, 4, 2)
    assert state.contained
    assert not ContainmentEngine("baseline", containment_delay_steps=2).apply(ContainmentState(), 4, 2).contained


def test_decision_engine_returns_legitimate_task_after_discovery_and_location():
    resources = build_resources()
    profile = build_agent_profiles()["employee"]
    engine = DecisionEngine(random.Random(1))
    action, target = engine.choose_action(profile, "legitimate", "protected", "application", resources, set(resources))
    assert action == Action.LEGITIMATE_TASK
    assert target.resource_id == "hr_portal"


def test_attack_success_classification():
    events = [{"trial_kind": "attack", "action": "READ", "target_resource": "customer_pii", "successful": "True"}]
    assert classify_attack_success(events)


def test_attack_success_requires_access_not_movement():
    events = [{"trial_kind": "attack", "action": "MOVE", "target_resource": "customer_pii", "successful": "True"}]
    assert not classify_attack_success(events)


def test_legitimate_success_classification():
    events = [{"trial_kind": "legitimate", "action": "LEGITIMATE_TASK", "successful": "True"}]
    assert classify_legitimate_success(events)


def test_metric_edge_cases_no_transitions_or_detection():
    rows = calculate_metrics(
        [
            {
                "trial_id": "t1",
                "trial_kind": "legitimate",
                "environment": "baseline",
                "timestamp": "1",
                "action": "READ",
                "target_resource": "public_docs",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            }
        ]
    )
    lateral = [row for row in rows if row["metric"] == "M3_lateral_movement_success_rate_percent"][0]
    assert lateral["sample_size"] == 0
    assert math.isnan(lateral["mean"])


def test_initial_visibility_is_not_counted_as_discovery():
    resources = build_resources()
    profile = build_agent_profiles()["employee"]
    visible = initial_visible_resources("baseline", profile, resources)
    assert "public_docs" in visible
    rows = calculate_metrics(
        [
            {
                "trial_id": "t1",
                "trial_kind": "legitimate",
                "environment": "baseline",
                "timestamp": "1",
                "action": "READ",
                "target_resource": "public_docs",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            }
        ]
    )
    discovery = [row for row in rows if row["metric"] == "M1_unique_resources_discovered_per_trial"][0]
    assert discovery["mean"] == 0.0


def test_only_successful_discovery_increases_m1_and_repeats_are_unique():
    rows = calculate_metrics(
        [
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "baseline",
                "timestamp": "1",
                "action": "DISCOVER",
                "target_resource": "internal_api",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "baseline",
                "timestamp": "2",
                "action": "DISCOVER",
                "target_resource": "internal_api",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "baseline",
                "timestamp": "3",
                "action": "DISCOVER",
                "target_resource": "finance_db",
                "authorized": "False",
                "successful": "False",
                "suspicious": "True",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
        ]
    )
    discovery = [row for row in rows if row["metric"] == "M1_unique_resources_discovered_per_trial"][0]
    assert discovery["mean"] == 1.0


def test_legitimate_movement_is_excluded_from_lmsr():
    rows = calculate_metrics(
        [
            {
                "trial_id": "t1",
                "trial_kind": "legitimate",
                "environment": "protected",
                "timestamp": "1",
                "action": "MOVE",
                "target_resource": "hr_portal",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "False",
                "contained": "False",
                "event_type": "transition",
                "movement_type": "legitimate",
            }
        ]
    )
    lateral = [row for row in rows if row["metric"] == "M3_lateral_movement_success_rate_percent"][0]
    assert lateral["sample_size"] == 0
    assert math.isnan(lateral["mean"])


def test_lateral_movement_rate_uses_lateral_attempts_only():
    base = {
        "trial_id": "t1",
        "trial_kind": "attack",
        "environment": "baseline",
        "action": "MOVE",
        "target_resource": "internal_api",
        "authorized": "True",
        "suspicious": "False",
        "detected": "False",
        "contained": "False",
        "event_type": "transition",
    }
    rows = calculate_metrics(
        [
            {**base, "timestamp": "1", "successful": "True", "movement_type": "lateral"},
            {**base, "timestamp": "2", "successful": "False", "movement_type": "lateral"},
            {**base, "timestamp": "3", "successful": "True", "movement_type": "legitimate"},
        ]
    )
    lateral = [row for row in rows if row["metric"] == "M3_lateral_movement_success_rate_percent"][0]
    assert lateral["mean"] == 50.0


def test_detection_and_containment_order_metrics():
    rows = calculate_metrics(
        [
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "protected",
                "timestamp": "2",
                "action": "READ",
                "target_resource": "finance_db",
                "authorized": "False",
                "successful": "False",
                "suspicious": "True",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "protected",
                "timestamp": "4",
                "action": "READ",
                "target_resource": "public_docs",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "True",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
                "detection_time": "4",
            },
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "protected",
                "timestamp": "6",
                "action": "READ",
                "target_resource": "public_docs",
                "authorized": "True",
                "successful": "True",
                "suspicious": "False",
                "detected": "True",
                "contained": "True",
                "event_type": "action",
                "movement_type": "none",
                "detection_time": "4",
                "containment_time": "6",
            },
        ]
    )
    detection = [row for row in rows if row["metric"] == "M5_detection_time_steps"][0]
    containment = [row for row in rows if row["metric"] == "M6_containment_time_steps"][0]
    assert detection["mean"] == 2.0
    assert containment["mean"] == 2.0


def test_multiple_sensitive_resources_are_unique_successful_exposures():
    rows = calculate_metrics(
        [
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "baseline",
                "timestamp": "1",
                "action": "READ",
                "target_resource": "customer_pii",
                "authorized": "True",
                "successful": "True",
                "suspicious": "True",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "baseline",
                "timestamp": "2",
                "action": "READ",
                "target_resource": "customer_pii",
                "authorized": "True",
                "successful": "True",
                "suspicious": "True",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
            {
                "trial_id": "t1",
                "trial_kind": "attack",
                "environment": "baseline",
                "timestamp": "3",
                "action": "READ",
                "target_resource": "finance_db",
                "authorized": "False",
                "successful": "False",
                "suspicious": "True",
                "detected": "False",
                "contained": "False",
                "event_type": "action",
                "movement_type": "none",
            },
        ]
    )
    exposure = [row for row in rows if row["metric"] == "M4_unique_sensitive_resources_exposed_per_trial"][0]
    assert exposure["mean"] == 1.0


def test_run_trial_is_deterministic_for_same_seed():
    config = ExperimentConfig(seed=7, attack_trials_per_environment=1, legitimate_trials_per_environment=1, max_steps=5)
    profile = build_agent_profiles()["compromised"]
    first = run_single_trial("baseline", "attack", "a", profile, config, random.Random(7))
    second = run_single_trial("baseline", "attack", "a", profile, config, random.Random(7))
    assert first == second
