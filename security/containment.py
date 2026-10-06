from dataclasses import dataclass
from typing import Optional


@dataclass
class ContainmentState:
    contained: bool = False
    containment_time: Optional[int] = None
    containment_action: str = ""


class ContainmentEngine:
    def __init__(self, environment: str):
        self.environment = environment

    def apply(self, state: ContainmentState, timestamp: int, detected: bool) -> ContainmentState:
        if self.environment == "protected" and detected and not state.contained:
            state.contained = True
            state.containment_time = timestamp
            state.containment_action = "BLOCK_AGENT"
        return state

