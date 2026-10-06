from dataclasses import dataclass


CASE_STUDY_TITLE = "Analysis of an Autonomous AI Agent Cyberattack on Hugging Face (July 2026)"
CASE_STUDY_MODE = "incident_grounded_synthetic"
INCIDENT_NAME = "Hugging Face Autonomous AI Agent Evaluation Escape"
INCIDENT_DATE = "July 2026"
INCIDENT_ORGANIZATION = "Hugging Face / OpenAI ExploitGym Evaluation"


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
