from typing import Dict, List
import math
import os


FIGURE_METRICS = [
    ("figure_1_resource_discovery.png", "M1_unique_resources_discovered_per_trial", "Unique resources discovered per trial"),
    ("figure_2_unauthorized_actions.png", "M2_unauthorized_actions_per_trial", "Unauthorized actions per trial"),
    ("figure_3_lateral_movement.png", "M3_lateral_movement_success_rate_percent", "Lateral movement success rate (%)"),
    ("figure_4_sensitive_exposure.png", "M4_unique_sensitive_resources_exposed_per_trial", "Unique sensitive resources exposed per trial"),
    ("figure_5_detection_time.png", "M5_detection_time_steps", "Detection time (steps)"),
    ("figure_6_containment_time.png", "M6_containment_time_steps", "Containment time (steps)"),
    ("figure_7_attack_success.png", "M7_attack_success_rate_percent", "Attack success rate (%)"),
    ("figure_8_legitimate_success.png", "M8_legitimate_task_success_percent", "Legitimate task success (%)"),
]


def generate_metric_figures(metric_rows: List[dict], figures_dir: str) -> None:
    import matplotlib.pyplot as plt

    os.makedirs(figures_dir, exist_ok=True)
    lookup: Dict[tuple, dict] = {(row["environment"], row["metric"]): row for row in metric_rows}
    for filename, metric, ylabel in FIGURE_METRICS:
        environments = ["baseline", "protected"]
        values = []
        for environment in environments:
            row = lookup.get((environment, metric), {})
            value = float(row.get("mean", math.nan))
            values.append(0 if math.isnan(value) else value)

        fig, ax = plt.subplots(figsize=(6.4, 4.2))
        bars = ax.bar(["Baseline", "Protected"], values, color=["#b84a62", "#287c76"])
        ax.set_ylabel(ylabel)
        ax.set_title(ylabel + ": Baseline vs Protected")
        ax.bar_label(bars, fmt="%.2f", padding=3)
        ax.margins(y=0.18)
        ax.grid(axis="y", alpha=0.25)
        fig.tight_layout()
        fig.savefig(os.path.join(figures_dir, filename), dpi=180)
        plt.close(fig)

