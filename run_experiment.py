import argparse
import os

from analysis.attack_graph import plot_attack_graph, write_attack_graph_csv
from analysis.comparison import compare_environments, write_comparison_csv
from analysis.figures import generate_metric_figures
from analysis.metrics import calculate_metrics, read_metrics_csv, write_metrics_csv
from config import ExperimentConfig
from simulation.baseline import run_baseline
from simulation.events import read_events_csv, write_events_csv
from simulation.protected import run_protected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the synthetic cybersecurity case study simulation.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--attack-trials", type=int, default=100)
    parser.add_argument("--legitimate-trials", type=int, default=100)
    parser.add_argument("--max-steps", type=int, default=18)
    parser.add_argument("--baseline-detection-delay", type=int, default=4)
    parser.add_argument("--protected-detection-delay", type=int, default=2)
    parser.add_argument("--containment-delay", type=int, default=2)
    parser.add_argument("--output-dir", default="output")
    return parser.parse_args()


def format_value(value: float) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "NaN"
    if number != number:
        return "NaN"
    return f"{number:.2f}"


def main() -> None:
    args = parse_args()
    config = ExperimentConfig(
        seed=args.seed,
        attack_trials_per_environment=args.attack_trials,
        legitimate_trials_per_environment=args.legitimate_trials,
        max_steps=args.max_steps,
        baseline_detection_delay_steps=args.baseline_detection_delay,
        protected_detection_delay_steps=args.protected_detection_delay,
        protected_containment_delay_steps=args.containment_delay,
        output_dir=args.output_dir,
    )
    events = run_baseline(config) + run_protected(config)
    events_path = os.path.join(config.output_dir, "events.csv")
    metrics_path = os.path.join(config.output_dir, "metrics.csv")
    comparison_path = os.path.join(config.output_dir, "comparison.csv")
    figures_dir = os.path.join(config.output_dir, "figures")

    write_events_csv(events, events_path)
    event_rows = read_events_csv(events_path)
    metrics = calculate_metrics(event_rows)
    write_metrics_csv(metrics, metrics_path)
    metric_rows = read_metrics_csv(metrics_path)
    generate_metric_figures(metric_rows, figures_dir)
    write_attack_graph_csv(event_rows, os.path.join(figures_dir, "attack_graph_edges.csv"))
    plot_attack_graph(event_rows, os.path.join(figures_dir, "attack_graph.png"))
    comparisons = compare_environments(metric_rows)
    write_comparison_csv(comparisons, comparison_path)

    by_env_metric = {(row["environment"], row["metric"]): row for row in metric_rows}
    labels = [
        ("Resource Discovery", "M1_unique_resources_discovered_per_trial"),
        ("Unauthorized Actions", "M2_unauthorized_actions_per_trial"),
        ("Lateral Movement Success Rate", "M3_lateral_movement_success_rate_percent"),
        ("Sensitive Resource Exposure", "M4_unique_sensitive_resources_exposed_per_trial"),
        ("Detection Time", "M5_detection_time_steps"),
        ("Containment Time", "M6_containment_time_steps"),
        ("Attack Success Rate", "M7_attack_success_rate_percent"),
        ("Legitimate Task Success", "M8_legitimate_task_success_percent"),
    ]

    print("Cybersecurity Agent Simulation")
    print("==============================")
    print()
    print("Configuration")
    print("-------------")
    print(f"Seed: {config.seed}")
    print(f"Attack trials/environment: {config.attack_trials_per_environment}")
    print(f"Legitimate trials/environment: {config.legitimate_trials_per_environment}")
    print(f"Maximum steps: {config.max_steps}")
    print(f"Baseline detection delay: {config.baseline_detection_delay_steps}")
    print(f"Protected detection delay: {config.protected_detection_delay_steps}")
    print(f"Containment delay: {config.protected_containment_delay_steps}")
    for environment, title in [("baseline", "Environment A - Baseline"), ("protected", "Environment B - Protected")]:
        print()
        print(title)
        print("-" * len(title))
        for label, metric in labels:
            row = by_env_metric[(environment, metric)]
            suffix = "%" if "percent" in metric else ""
            print(f"{label}: {format_value(row['mean'])}{suffix}")
        print()
        print(f"Detection Rate: {format_value(by_env_metric[(environment, 'detection_rate_percent')]['mean'])}%")
        print(f"Containment Rate: {format_value(by_env_metric[(environment, 'containment_rate_percent')]['mean'])}%")
    print()
    print("Comparison")
    print("----------")
    for comparison in comparisons:
        if comparison["metric"].startswith("M"):
            print(
                f"{comparison['metric']}: protected-baseline = "
                f"{format_value(comparison['absolute_difference'])}; change = "
                f"{format_value(comparison['percentage_change'])}%"
            )
    print()
    print("Output")
    print("------")
    print(events_path)
    print(metrics_path)
    print(comparison_path)
    print(figures_dir)


if __name__ == "__main__":
    main()
