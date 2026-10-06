from config import ExperimentConfig
from simulation.trials import run_environment_trials


def run_protected(config: ExperimentConfig):
    return run_environment_trials("protected", config)

