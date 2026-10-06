from collections import Counter, defaultdict
from typing import List, Tuple
import csv
import os


def build_attack_edges(events: List[dict]) -> List[Tuple[str, str, str, int]]:
    counters = defaultdict(Counter)
    for event in events:
        if event["trial_kind"] == "attack" and event["event_type"] == "transition":
            key = (event["source_zone"], event["target_zone"])
            counters[event["environment"]][key] += 1
    edges = []
    for environment, counter in counters.items():
        for (source, target), count in counter.items():
            edges.append((environment, source, target, count))
    return edges


def write_attack_graph_csv(events: List[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["environment", "source_zone", "target_zone", "transition_attempts"])
        writer.writerows(build_attack_edges(events))


def plot_attack_graph(events: List[dict], path: str) -> None:
    import matplotlib.pyplot as plt

    edges = build_attack_edges(events)
    zones = ["public", "application", "internal", "database", "sensitive", "admin"]
    positions = {zone: (index, 0) for index, zone in enumerate(zones)}
    offsets = {"baseline": 0.18, "protected": -0.18}
    colors = {"baseline": "#b84a62", "protected": "#287c76"}

    fig, ax = plt.subplots(figsize=(11, 4.8))
    for zone, (x, y) in positions.items():
        ax.scatter([x], [y], s=1200, color="#f5f5f5", edgecolor="#333333", zorder=3)
        ax.text(x, y, zone.replace("_", " ").title(), ha="center", va="center", fontsize=9, zorder=4)

    max_count = max([edge[3] for edge in edges], default=1)
    for environment, source, target, count in edges:
        sx, sy = positions[source]
        tx, ty = positions[target]
        offset = offsets.get(environment, 0)
        width = 0.5 + 4.0 * (count / max_count)
        ax.annotate(
            "",
            xy=(tx, ty + offset),
            xytext=(sx, sy + offset),
            arrowprops=dict(arrowstyle="->", lw=width, color=colors[environment], alpha=0.75),
        )

    handles = [plt.Line2D([0], [0], color=color, lw=3, label=env.title()) for env, color in colors.items()]
    ax.legend(handles=handles, loc="upper center", ncol=2)
    ax.set_title("Attack Graph: Transition Attempts by Environment")
    ax.set_axis_off()
    fig.tight_layout()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path, dpi=180)
    plt.close(fig)

