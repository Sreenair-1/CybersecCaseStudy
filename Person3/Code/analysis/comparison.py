from typing import Dict, List
import csv
import math
import os


def compare_environments(metric_rows: List[dict]) -> List[dict]:
    by_metric: Dict[str, Dict[str, dict]] = {}
    for row in metric_rows:
        by_metric.setdefault(row["metric"], {})[row["environment"]] = row

    comparisons = []
    for metric, env_rows in sorted(by_metric.items()):
        if "baseline" not in env_rows or "protected" not in env_rows:
            continue
        baseline = float(env_rows["baseline"]["mean"])
        protected = float(env_rows["protected"]["mean"])
        absolute = protected - baseline
        percentage = math.nan if baseline == 0 or math.isnan(baseline) else (absolute / baseline) * 100.0
        comparisons.append(
            {
                "metric": metric,
                "baseline_mean": baseline,
                "protected_mean": protected,
                "absolute_difference": absolute,
                "percentage_change": percentage,
                "assumption": "Independent deterministic simulation trials; descriptive comparison.",
            }
        )
    return comparisons


def write_comparison_csv(comparisons: List[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = [
        "metric",
        "baseline_mean",
        "protected_mean",
        "absolute_difference",
        "percentage_change",
        "assumption",
    ]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(comparisons)
