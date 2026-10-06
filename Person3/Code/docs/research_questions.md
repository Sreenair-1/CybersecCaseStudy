# Research Questions and Experimental Hypotheses

## 1. Context and Motivation

The July 2026 Hugging Face incident demonstrated that autonomous AI agents operating at machine speed can rapidly discover unsegmented assets, leverage broad credentials, and navigate across cloud boundaries. 

This research study utilizes an incident-grounded, synthetic experimental framework to empirically evaluate the defensive efficacy of zero-trust architecture controls (least privilege, credential isolation, network segmentation, and automated containment) against autonomous agent attack patterns.

---

## 2. Research Questions (RQs)

### **RQ1: Resource Discovery Suppression**
> *How does an autonomous agent's ability to discover synthetic resources differ between a weak-security baseline and a protected least-privilege environment?*
- **Focus**: Evaluates how restricting default discovery visibility impacts the agent's environmental enumeration rate.
- **Metric**: M1 (Unique resources discovered per trial).

### **RQ2: Unauthorized Actions and Credential Protection**
> *How effectively do credential isolation and least privilege reduce unauthorized actions and sensitive-resource exposure?*
- **Focus**: Measures whether scoped credentials and strict role checks prevent an agent from executing unauthorized operations or accessing sensitive stores.
- **Metrics**: M2 (Unauthorized actions per trial), M4 (Sensitive resource exposure).

### **RQ3: Network Segmentation and Lateral Movement**
> *How does network segmentation affect adversarial lateral movement across topological zones?*
- **Focus**: Investigates whether enforcing strict inter-zone firewall boundaries restricts an agent from pivoting from public/application layers into internal and administrative zones.
- **Metric**: M3 (Lateral movement success rate %).

### **RQ4: Temporal Detection and Containment Dynamics**
> *How do detection and containment delays affect the simulated attack outcome and attacker dwell time?*
- **Focus**: Examines the relationship between behavioral detection thresholds, response latency, and terminal attack prevention.
- **Metrics**: M5 (Detection time steps), M6 (Containment time steps).

### **RQ5: Operational Availability vs. Security Trade-Off**
> *Can stronger security controls reduce autonomous-agent attack success without reducing legitimate task completion?*
- **Focus**: Tests whether security enforcement disproportionately hinders legitimate administrative and business workflows.
- **Metrics**: M7 (Attack success rate %), M8 (Legitimate task success %).

---

## 3. Experimental Hypotheses (H1–H6)

The experimental evaluation tests the following formal hypotheses against generated trial data:

* **H1 (Resource Discovery Reduction)**: Protected least-privilege visibility controls significantly reduce the mean number of discovered resources per trial compared to the baseline environment.
* **H2 (Unauthorized Action Mitigation)**: Strict authorization checks and isolated credentials reduce the mean frequency of unauthorized actions per trial in the protected environment.
* **H3 (Lateral Movement Restriction)**: Enforcement of topological network segmentation significantly decreases the percentage of successful adversarial lateral-movement transitions.
* **H4 (Sensitive Resource Protection)**: Credential isolation and access controls significantly decrease sensitive resource exposures (M4) and overall attack success rate (M7).
* **H5 (Dwell Time and Containment Control)**: Faster detection and automated containment in the protected environment bound attacker dwell time and prevent post-detection escalation.
* **H6 (Legitimate Workflow Preservation)**: Protected security controls maintain high legitimate task completion rates (M8) comparable to baseline, proving defensive viability without operational degradation.

---

## 4. Controlled Variables & Experimental Design

| Parameter | Baseline Environment | Protected Environment | Experimental Role |
|---|---|---|---|
| **Resource Visibility** | Broad (discoverable + internal APIs) | Restricted (explicit least-privilege starting set) | Independent Variable |
| **Credential Scope** | Broad (cross-resource reuse allowed) | Isolated (strict role & resource binding) | Independent Variable |
| **Network Segmentation** | Permissive (cross-zone mesh transitions) | Strict (enforced ingress/egress policies) | Independent Variable |
| **Detection Policy** | High threshold (delayed behavioral trigger) | Low threshold (rapid anomaly detection) | Independent Variable |
| **Containment Policy** | None (uncontained execution) | Active (automated agent blocking after delay) | Independent Variable |
| **Trial Count** | 100 attack, 100 legitimate | 100 attack, 100 legitimate | Control Variable |
| **Random Seed** | 42 (deterministic reproducibility) | 42 (deterministic reproducibility) | Control Variable |
| **Max Steps** | 18 steps per trial | 18 steps per trial | Control Variable |
