# AI Agent Cyberattack Simulation & Zero Trust Defense

A synthetic, incident-grounded cybersecurity simulation framework that models the attack lifecycle of autonomous AI agents escaping sandboxes and evaluates the efficacy of Zero Trust Architecture (ZTA) defensive controls (least privilege visibility, credential isolation, network zone segmentation, and automated anomaly containment).

---

## How to Execute

### 1. Install Dependencies
Ensure Python 3.10+ is installed, then install the required dependencies:

```bash
pip install -r requirements.txt
```

### 2. Run the Simulation Experiment
Execute the full deterministic simulation pipeline:

```bash
python run_experiment.py
```

#### Optional CLI Arguments
You can customize the simulation parameters:
```bash
python run_experiment.py --seed 42 --attack-trials 100 --legitimate-trials 100 --max-steps 18
```

### 3. Run Unit Tests (Optional)
To verify test suites across agents, security controls, and environments:

```bash
pytest -q
```

---

## Output Artifacts

Running the experiment produces generated artifacts in the `output/` directory:
- `output/events.csv`: Detailed event logs across all simulation trials.
- `output/metrics.csv`: Aggregated summary statistics for evaluation metrics (M1–M8).
- `output/comparison.csv`: Baseline vs. Protected environment comparative analysis.
- `output/incident_mapping.csv`: Mappings between real-world incident stages and synthetic actions.
- `output/figures/`: Publication-quality metric visualization plots and attack graph diagrams.
