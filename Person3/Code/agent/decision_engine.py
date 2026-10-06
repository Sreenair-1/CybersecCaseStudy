from typing import Dict, List, Sequence, Set
import random

from agent.action_policy import Action
from agent.agent_profiles import AgentProfile
from environment.resources import Resource, is_sensitive
from environment.topology import adjacent_zones, is_transition_allowed


class DecisionEngine:
    def __init__(self, rng: random.Random):
        self.rng = rng

    def choose_action(
        self,
        profile: AgentProfile,
        trial_kind: str,
        environment: str,
        current_zone: str,
        resources: Dict[str, Resource],
        known_resources: Set[str],
    ) -> tuple[Action, Resource]:
        if trial_kind == "attack":
            action = self._weighted_action(profile)
            target = self._attack_target(profile, action, environment, current_zone, resources, known_resources)
            return action, target

        target = self._legitimate_target(profile, resources, known_resources)
        if target.resource_id not in known_resources:
            return Action.REQUEST_RESOURCE, target
        if current_zone != target.network_zone:
            if not is_transition_allowed(environment, current_zone, target.network_zone):
                intermediary = self._routing_target(environment, current_zone, target, resources, known_resources)
                if intermediary is not None:
                    return Action.MOVE, intermediary
            return Action.MOVE, target
        return Action.LEGITIMATE_TASK, target

    def _weighted_action(self, profile: AgentProfile) -> Action:
        actions = list(profile.action_probabilities.keys())
        weights = [profile.action_probabilities[action] for action in actions]
        return Action(self.rng.choices(actions, weights=weights, k=1)[0])

    def _attack_target(
        self,
        profile: AgentProfile,
        action: Action,
        environment: str,
        current_zone: str,
        resources: Dict[str, Resource],
        known_resources: Set[str],
    ) -> Resource:
        interested = [resources[item] for item in profile.resource_interests if item in resources]
        visible = [resources[item] for item in sorted(known_resources) if item in resources]
        sensitive = [resource for resource in resources.values() if is_sensitive(resource)]

        if action == Action.DISCOVER:
            candidates = [resource for resource in resources.values() if resource.resource_id not in known_resources]
            return self.rng.choice(candidates or list(resources.values()))

        if action == Action.MOVE:
            zones = set(adjacent_zones(environment, current_zone))
            candidates = [resource for resource in interested + sensitive if resource.network_zone in zones]
            return self.rng.choice(candidates or interested or list(resources.values()))

        if action == Action.ACCESS_CREDENTIAL:
            vault = resources.get("credential_vault")
            return vault if vault else self.rng.choice(list(resources.values()))

        candidates = [resource for resource in interested if resource.resource_id in known_resources] or visible or interested
        if self.rng.random() < profile.risk_tolerance:
            candidates = candidates + sensitive
        return self.rng.choice(candidates or list(resources.values()))

    def _legitimate_target(
        self,
        profile: AgentProfile,
        resources: Dict[str, Resource],
        known_resources: Set[str],
    ) -> Resource:
        preferred = [resources[item] for item in profile.resource_interests if item in resources]
        undiscovered = [resource for resource in preferred if resource.resource_id not in known_resources]
        return undiscovered[0] if undiscovered else preferred[-1]

    def _routing_target(
        self,
        environment: str,
        current_zone: str,
        target: Resource,
        resources: Dict[str, Resource],
        known_resources: Set[str],
    ) -> Resource | None:
        for resource_id in sorted(known_resources):
            resource = resources[resource_id]
            if (
                resource.network_zone in adjacent_zones(environment, current_zone)
                and is_transition_allowed(environment, resource.network_zone, target.network_zone)
            ):
                return resource
        return None
