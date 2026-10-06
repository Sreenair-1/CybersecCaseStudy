from dataclasses import dataclass, field
from typing import Dict, Optional

from environment.resources import Resource, is_sensitive


@dataclass
class DetectionState:
    unauthorized_count: int = 0
    lateral_count: int = 0
    first_suspicious_time: Optional[int] = None
    detected: bool = False
    detection_time: Optional[int] = None
    detection_reason: str = ""
    seen_zones: set = field(default_factory=set)


class DetectionEngine:
    def __init__(self, environment: str):
        self.environment = environment
        self.unauthorized_threshold = 3 if environment == "baseline" else 1
        self.lateral_threshold = 3 if environment == "baseline" else 2

    def observe(
        self,
        state: DetectionState,
        timestamp: int,
        action: str,
        target: Resource,
        authorized: bool,
        successful: bool,
        current_zone: str,
    ) -> DetectionState:
        suspicious = False
        reason = ""
        if not authorized:
            state.unauthorized_count += 1
            suspicious = True
            reason = "unauthorized_action"
        if action == "MOVE" and successful and target.network_zone != current_zone and not authorized:
            state.lateral_count += 1
            state.seen_zones.add(target.network_zone)
            if state.lateral_count >= self.lateral_threshold:
                suspicious = True
                reason = "lateral_movement"
        if successful and is_sensitive(target) and action in {"READ", "WRITE", "EXECUTE", "ACCESS_CREDENTIAL"}:
            suspicious = True
            reason = "sensitive_resource_access"

        if suspicious and state.first_suspicious_time is None:
            state.first_suspicious_time = timestamp

        should_detect = (
            state.unauthorized_count >= self.unauthorized_threshold
            or state.lateral_count >= self.lateral_threshold
            or (self.environment == "protected" and successful and is_sensitive(target) and action in {"READ", "WRITE", "EXECUTE", "ACCESS_CREDENTIAL"})
        )
        if should_detect and not state.detected:
            state.detected = True
            state.detection_time = timestamp
            state.detection_reason = reason or "policy_threshold"
        return state
