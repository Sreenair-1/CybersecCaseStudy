# Synthetic Cybersecurity Case Study

This project runs a deterministic, non-destructive cybersecurity simulation comparing a baseline environment with weak controls against a protected environment with least privilege, credential isolation, segmentation, detection, and containment.

The simulation is fully synthetic. It does not scan networks, exploit systems, use real credentials, run malware, or contact external services.

## Research Objective

Measure how security architecture changes simulated agent behavior, unauthorized activity, lateral movement, sensitive-resource exposure, detection, containment, attack success, and legitimate task completion.

## Hypothesis

The protected environment should reduce unauthorized access, lateral movement, sensitive-resource exposure, and attack success while preserving most legitimate task success.

## Architecture

The code follows the requested module layout:

- `agent/`: profiles, action probabilities, and decision engine.
- `environment/`: synthetic resources, credentials, services, and topology.
- `security/`: permission, segmentation, detection, and containment logic.
- `simulation/`: baseline/protected trial orchestration and event records.
- `analysis/`: metrics, comparison, attack graph, and figures.
- `output/`: generated CSV files and figures.

## Environment Models

Baseline uses broader credentials, weak segmentation, greater initial resource visibility, and slower detection. Protected uses least privilege, isolated credentials, restricted initial visibility, strict zone transitions, policy enforcement, faster detection, and delayed containment.

## Agent Model

Five profiles are implemented: normal employee, privileged administrator, curious employee, compromised account, and service automation. Each has different objectives, interests, action probabilities, risk tolerance, and willingness to attempt unauthorized actions.

## Metric Definitions

- M1: unique resources actively discovered per trial. Initial visibility is not counted as discovery.
- M2: unauthorized action attempts per trial.
- M3: successful adversarial lateral-movement attempts divided by total adversarial lateral-movement attempts. Legitimate movement is excluded.
- M4: unique sensitive resources successfully exposed per trial. Attempted or blocked access is not exposure.
- M5: simulated detection timestamp minus first suspicious action timestamp.
- M6: simulated containment timestamp minus detection timestamp.
- M7: attack trials that successfully access `customer_pii`.
- M8: legitimate trials that complete a `LEGITIMATE_TASK`.

Missing detection and containment times remain missing rather than being replaced by arbitrary values.

## Trial Methodology

By default, each environment runs 100 attack trials and 100 legitimate trials with seed `42`. The same seed and configuration produce the same `events.csv`, `metrics.csv`, `comparison.csv`, and figures. Detection and containment delays are experimental inputs, not measured outputs chosen after the run.

## Run

```bash
python run_experiment.py
```

Optional arguments:

```bash
python run_experiment.py --seed 42 --attack-trials 100 --legitimate-trials 100 --max-steps 18
```

Delay parameters can also be changed:

```bash
python run_experiment.py --baseline-detection-delay 4 --protected-detection-delay 2 --containment-delay 2
```

## Outputs

- `output/events.csv`: complete event log.
- `output/metrics.csv`: calculated metric summaries.
- `output/comparison.csv`: baseline/protected descriptive comparison.
- `output/figures/figure_*.png`: metric figures generated from metrics.
- `output/figures/attack_graph.png`: attack transition visualization generated from events.
- `output/figures/attack_graph_edges.csv`: transition counts used for the graph.

## Person 3 Packaging

After running the experiment, package the implementation deliverable with:

```bash
python package_person3.py
```

This creates `Person3/` with `Section_8_Implementation.docx`, source code, results CSV files, MITRE mapping, and renamed figures for the case-study submission.

## Scientific Integrity

Experimental inputs are configuration, topology, permissions, credentials, detection rules, containment policy, seed, and trial count. Experimental outputs are generated events, metric values, comparisons, and figures. No metric values are hard-coded.

## Limitations

This is an explanatory model, not a real security assessment. It abstracts away real attacker tooling, human workflows, system vulnerabilities, asset heterogeneity, and operational response delays.
