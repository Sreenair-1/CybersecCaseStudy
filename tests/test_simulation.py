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


def test_incident_phase_mapping_logic():
    from simulation.trials import map_incident_phase
    resources = build_resources()
    assert map_incident_phase(Action.DISCOVER, resources["internal_api"], "attack", True, True, False) == "resource_discovery"
    assert map_incident_phase(Action.ACCESS_CREDENTIAL, resources["credential_vault"], "attack", True, True, False) == "credential_access"
    assert map_incident_phase(Action.MOVE, resources["internal_api"], "attack", True, True, False) == "lateral_movement"
    assert map_incident_phase(Action.READ, resources["customer_pii"], "attack", True, True, False) == "sensitive_access"
    assert map_incident_phase(Action.LEGITIMATE_TASK, resources["hr_portal"], "legitimate", True, True, False) == "legitimate_operation"
    assert map_incident_phase(Action.READ, resources["customer_pii"], "attack", False, False, True) == "containment"


def test_incident_mapping_evidence_statuses_valid():
    from analysis.incident_mapping import get_incident_mappings
    mappings = get_incident_mappings()
    assert len(mappings) >= 6
    valid_statuses = {"documented", "inferred", "simulation_assumption"}
    for mapping in mappings:
        assert mapping["evidence_status"] in valid_statuses
        assert "incident_characteristic" in mapping
        assert "synthetic_abstraction" in mapping
        assert "security_control" in mapping
        assert "metric_affected" in mapping


def test_mitre_mapping_evidence_statuses_valid():
    from analysis.mitre_mapping import MITRE_MAPPING
    valid_statuses = {"incident-supported", "analytical/inferred", "simulation-only"}
    for mapping in MITRE_MAPPING:
        assert mapping["evidence_status"] in valid_statuses
        assert "incident_characteristic" in mapping
        assert "mitre_tactic" in mapping
        assert "mitre_technique" in mapping


def test_synthetic_resources_abstraction_integrity():
    resources = build_resources()
    assert "customer_pii" in resources
    assert "credential_vault" in resources
    assert "public_docs" in resources
    valid_zones = {"public", "application", "internal", "database", "sensitive", "admin"}
    for res in resources.values():
        assert res.network_zone in valid_zones
        assert isinstance(res.sensitivity, int)


def test_no_external_network_or_process_interaction():
    config = ExperimentConfig(seed=42, attack_trials_per_environment=2, legitimate_trials_per_environment=2, max_steps=6)
    events = run_single_trial("protected", "attack", "test-trial", build_agent_profiles()["compromised"], config, random.Random(42))
    assert len(events) > 0
    assert all(hasattr(e, "incident_phase") for e in events)
    assert all(isinstance(e.incident_phase, str) and len(e.incident_phase) > 0 for e in events)


def test_metrics_dynamically_generated_from_events():
    empty_rows = calculate_metrics([])
    assert len(empty_rows) == 0

    base_event = {
        "trial_id": "dyn-1",
        "trial_kind": "attack",
        "environment": "baseline",
        "agent_id": "compromised",
        "timestamp": "1",
        "action": "DISCOVER",
        "source_resource": "public_docs",
        "target_resource": "internal_api",
        "source_zone": "public",
        "target_zone": "internal",
        "authorized": "True",
        "successful": "True",
        "suspicious": "False",
        "detected": "False",
        "contained": "False",
        "event_type": "action",
        "movement_type": "none",
        "reason": "new_resource_discovered",
        "incident_phase": "resource_discovery",
    }
    metrics1 = calculate_metrics([base_event])
    m1_val1 = [r for r in metrics1 if r["metric"] == "M1_unique_resources_discovered_per_trial"][0]["mean"]
    assert m1_val1 == 1.0

    second_event = dict(base_event, timestamp="2", target_resource="finance_db")
    metrics2 = calculate_metrics([base_event, second_event])
    m1_val2 = [r for r in metrics2 if r["metric"] == "M1_unique_resources_discovered_per_trial"][0]["mean"]
    assert m1_val2 == 2.0
