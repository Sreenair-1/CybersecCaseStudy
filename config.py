from dataclasses import dataclass


@dataclass(frozen=True)
class ExperimentConfig:
    seed: int = 42
    attack_trials_per_environment: int = 100
    legitimate_trials_per_environment: int = 100
    max_steps: int = 18
    baseline_detection_delay_steps: int = 4
    protected_detection_delay_steps: int = 2
    protected_containment_delay_steps: int = 2
    output_dir: str = "output"
