from dataclasses import asdict, dataclass
from typing import Iterable, List
import csv
import os


@dataclass(frozen=True)
class Event:
    trial_id: str
    trial_kind: str
    environment: str
    agent_id: str
    timestamp: int
    action: str
    source_resource: str
    target_resource: str
    source_zone: str
    target_zone: str
    authorized: bool
    successful: bool
    suspicious: bool
    detected: bool
    contained: bool
    event_type: str
    reason: str


FIELDNAMES = list(Event.__dataclass_fields__.keys())


def write_events_csv(events: Iterable[Event], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = [asdict(event) for event in events]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def read_events_csv(path: str) -> List[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

