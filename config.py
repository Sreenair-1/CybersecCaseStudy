from dataclasses import dataclass


@dataclass(frozen=True)
class ExperimentConfig:
    seed: int = 42
    attack_trials_per_environment: int = 100
    legitimate_trials_per_environment: int = 100
    max_steps: int = 18
    output_dir: str = "output"

