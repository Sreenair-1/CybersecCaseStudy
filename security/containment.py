from dataclasses import dataclass
from typing import Optional


@dataclass
class ContainmentState:
    contained: bool = False
    containment_trigger_time: Optional[int] = None
    containment_time: Optional[int] = None
    containment_action: str = ""


class ContainmentEngine:
    def __init__(self, environment: str, containment_delay_steps: int):
        self.environment = environment
        self.containment_delay_steps = containment_delay_steps

    def apply(self, state: ContainmentState, timestamp: int, detection_time: Optional[int]) -> ContainmentState:
        if self.environment == "protected" and detection_time is not None and state.containment_trigger_time is None:
            state.containment_trigger_time = detection_time
        if (
            self.environment == "protected"
            and state.containment_trigger_time is not None
            and not state.contained
            and timestamp >= state.containment_trigger_time + self.containment_delay_steps
        ):
            state.contained = True
            state.containment_time = timestamp
            state.containment_action = "BLOCK_AGENT"
        return state
