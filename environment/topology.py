from typing import Dict, List, Set, Tuple


ZONES = ["public", "application", "internal", "database", "sensitive", "admin"]

BASELINE_EDGES: Set[Tuple[str, str]] = {
    ("public", "application"),
    ("application", "internal"),
    ("internal", "database"),
    ("database", "sensitive"),
    ("public", "internal"),
    ("application", "database"),
    ("internal", "admin"),
    ("database", "admin"),
    ("admin", "database"),
    ("admin", "sensitive"),
}

PROTECTED_EDGES: Set[Tuple[str, str]] = {
    ("public", "application"),
    ("application", "internal"),
    ("internal", "database"),
    ("database", "sensitive"),
    ("admin", "admin"),
    ("admin", "application"),
}


def allowed_edges(environment: str) -> Set[Tuple[str, str]]:
    edges = BASELINE_EDGES if environment == "baseline" else PROTECTED_EDGES
    with_reverse = set(edges)
    with_reverse.update((target, source) for source, target in edges if environment == "baseline")
    with_reverse.update((zone, zone) for zone in ZONES)
    return with_reverse


def is_transition_allowed(environment: str, source_zone: str, target_zone: str) -> bool:
    return (source_zone, target_zone) in allowed_edges(environment)


def adjacent_zones(environment: str, source_zone: str) -> List[str]:
    return sorted(target for source, target in allowed_edges(environment) if source == source_zone)

