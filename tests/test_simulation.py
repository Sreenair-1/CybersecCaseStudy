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
from simulation.trials import classify_attack_success, classify_legitimate_success, run_single_trial


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
    engine = DetectionEngine("protected")
    state = engine.observe(DetectionState(), 1, "READ", resources["customer_pii"], False, False, "public")
    assert state.detected
    assert state.detection_time == 1


def test_no_suspicious_events_have_no_detection():
    resources = build_resources()
    engine = DetectionEngine("baseline")
    state = engine.observe(DetectionState(), 1, "READ", resources["public_docs"], True, True, "public")
    assert not state.detected
    assert state.first_suspicious_time is None


def test_containment_only_in_protected():
    assert ContainmentEngine("protected").apply(ContainmentState(), 2, True).contained
    assert not ContainmentEngine("baseline").apply(ContainmentState(), 2, True).contained


def test_decision_engine_returns_legitimate_task_after_discovery_and_location():
    resources = build_resources()
    profile = build_agent_profiles()["employee"]
    engine = DecisionEngine(random.Random(1))
    action, target = engine.choose_action(profile, "legitimate", "protected", "application", resources, set(resources))
    assert action == Action.LEGITIMATE_TASK
    assert target.resource_id == "hr_portal"


def test_attack_success_classification():
    events = [{"trial_kind": "attack", "target_resource": "customer_pii", "successful": "True"}]
    assert classify_attack_success(events)


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
            }
        ]
    )
    lateral = [row for row in rows if row["metric"] == "M3_lateral_movement_success_rate_percent"][0]
    assert lateral["sample_size"] == 0
    assert math.isnan(lateral["mean"])


def test_run_trial_is_deterministic_for_same_seed():
    config = ExperimentConfig(seed=7, attack_trials_per_environment=1, legitimate_trials_per_environment=1, max_steps=5)
    profile = build_agent_profiles()["compromised"]
    first = run_single_trial("baseline", "attack", "a", profile, config, random.Random(7))
    second = run_single_trial("baseline", "attack", "a", profile, config, random.Random(7))
    assert first == second
