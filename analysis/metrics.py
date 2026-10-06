from collections import defaultdict
from statistics import mean, median, stdev
from typing import Dict, Iterable, List
import csv
import math
import os

from simulation.trials import classify_attack_success, classify_legitimate_success


def _bool(value) -> bool:
    return value is True or str(value) == "True"


def _summary(values: List[float]) -> Dict[str, float]:
    clean = [value for value in values if value is not None and not math.isnan(value)]
    if not clean:
        return {"value": math.nan, "mean": math.nan, "median": math.nan, "std": math.nan, "min": math.nan, "max": math.nan, "sample_size": 0}
    return {
        "value": mean(clean),
        "mean": mean(clean),
        "median": median(clean),
        "std": stdev(clean) if len(clean) > 1 else 0.0,
        "min": min(clean),
        "max": max(clean),
        "sample_size": len(clean),
    }


def group_by_trial(events: Iterable[dict]) -> Dict[str, List[dict]]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for event in events:
        grouped[event["trial_id"]].append(event)
    return grouped


def calculate_metrics(events: List[dict]) -> List[dict]:
    by_environment: Dict[str, List[dict]] = defaultdict(list)
    for event in events:
        by_environment[event["environment"]].append(event)

    rows: List[dict] = []
    for environment, env_events in sorted(by_environment.items()):
        trials = group_by_trial(env_events)
        discovery_counts = []
        unauthorized_counts = []
        lateral_rates = []
        sensitive_counts = []
        detection_times = []
        containment_times = []
        attack_successes = []
        legitimate_successes = []
        detection_flags = []
        containment_flags = []

        for trial_events in trials.values():
            discovered = {event["target_resource"] for event in trial_events if event["action"] == "DISCOVER" and _bool(event["successful"])}
            unauthorized = [event for event in trial_events if not _bool(event["authorized"])]
            transitions = [event for event in trial_events if event["event_type"] == "transition"]
            successful_transitions = [event for event in transitions if _bool(event["successful"])]
            sensitive = {event["target_resource"] for event in trial_events if _bool(event["successful"]) and event["target_resource"] in {"customer_pii", "credential_vault", "finance_db"}}

            discovery_counts.append(float(len(discovered)))
            unauthorized_counts.append(float(len(unauthorized)))
            lateral_rates.append((len(successful_transitions) / len(transitions) * 100.0) if transitions else math.nan)
            sensitive_counts.append(float(len(sensitive)))

            suspicious_times = [int(event["timestamp"]) for event in trial_events if _bool(event["suspicious"])]
            detection_events = [event for event in trial_events if _bool(event["detected"])]
            containment_events = [event for event in trial_events if _bool(event["contained"])]
            detection_flags.append(1.0 if detection_events else 0.0)
            containment_flags.append(1.0 if containment_events else 0.0)
            if suspicious_times and detection_events:
                detection_times.append(float(int(detection_events[0]["timestamp"]) - suspicious_times[0]))
            if detection_events and containment_events:
                containment_times.append(float(int(containment_events[0]["timestamp"]) - int(detection_events[0]["timestamp"])))

            if trial_events[0]["trial_kind"] == "attack":
                attack_successes.append(1.0 if classify_attack_success(trial_events) else 0.0)
            if trial_events[0]["trial_kind"] == "legitimate":
                legitimate_successes.append(1.0 if classify_legitimate_success(trial_events) else 0.0)

        metric_values = {
            "M1_unique_resources_discovered_per_trial": discovery_counts,
            "M2_unauthorized_actions_per_trial": unauthorized_counts,
            "M3_lateral_movement_success_rate_percent": lateral_rates,
            "M4_unique_sensitive_resources_exposed_per_trial": sensitive_counts,
            "M5_detection_time_steps": detection_times,
            "M6_containment_time_steps": containment_times,
            "M7_attack_success_rate_percent": [value * 100.0 for value in attack_successes],
            "M8_legitimate_task_success_percent": [value * 100.0 for value in legitimate_successes],
            "detection_rate_percent": [value * 100.0 for value in detection_flags],
            "containment_rate_percent": [value * 100.0 for value in containment_flags],
        }
        for metric, values in metric_values.items():
            summary = _summary(values)
            rows.append({"environment": environment, "metric": metric, **summary})

    validate_metrics(rows)
    return rows


def validate_metrics(rows: List[dict]) -> None:
    bounded = {
        "M3_lateral_movement_success_rate_percent",
        "M7_attack_success_rate_percent",
        "M8_legitimate_task_success_percent",
        "detection_rate_percent",
        "containment_rate_percent",
    }
    for row in rows:
        value = row["mean"]
        if row["metric"] in bounded and not math.isnan(value) and not (0 <= value <= 100):
            raise ValueError(f"{row['metric']} outside 0..100: {value}")
        if row["metric"] in {"M5_detection_time_steps", "M6_containment_time_steps"} and not math.isnan(value) and value < 0:
            raise ValueError(f"{row['metric']} cannot be negative: {value}")


def write_metrics_csv(rows: List[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = ["environment", "metric", "value", "sample_size", "mean", "median", "std", "min", "max"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_metrics_csv(path: str) -> List[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

