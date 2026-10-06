from dataclasses import dataclass

from environment.resources import Resource
from environment.topology import is_transition_allowed


@dataclass(frozen=True)
class SegmentationResult:
    allowed: bool
    reason: str


def evaluate_transition(environment: str, current_zone: str, target: Resource) -> SegmentationResult:
    if is_transition_allowed(environment, current_zone, target.network_zone):
        return SegmentationResult(True, "transition_allowed")
    return SegmentationResult(False, f"blocked_by_segmentation:{current_zone}->{target.network_zone}")

