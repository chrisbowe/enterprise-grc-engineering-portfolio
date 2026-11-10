# Lab 1: Quantitative Cyber Risk Modeling (FAIR™ Framework)

## 📌 Overview
This lab implements the **Factor Analysis of Information Risk (FAIR™)** standard, the international standard quantitative model for information security and operational risk.

Instead of subjective, ambiguous qualitative risk matrices (High/Medium/Low), this engine uses Monte Carlo simulations (100,000 iterations per scenario by default) to generate probabilistic financial loss distributions ($ USD).

## 📊 Key Output Metrics
* **ALE (Annualized Loss Exposure / Expectancy):** The average expected financial loss per year.
* **10th Percentile (Optimistic):** Expected loss in favorable threat conditions.
* **50th Percentile (Median):** Expected loss baseline.
* **90th Percentile (Pessimistic / Tail Risk):** Severe loss scenario for capital reserve planning and cyber insurance adequacy.
* **99th Percentile:** Extreme tail loss scenario.

## 🛠️ Usage

```bash
# Install dependencies
pip install numpy

# Execute the simulation engine with default 100,000 iterations
python fair_engine.py

# Execute with custom iterations and reproducible random seed
python fair_engine.py --iterations 100000 --seed 42
```

## 📋 Scenario Schema (`scenarios.json`)
Each threat scenario models:
1. `threat_event_frequency_range`: PERT distribution (or triangular) `[min, mode, max]` attempts per year.
2. `vulnerability_prob`: Probability that threat capability overcomes resistance strength.
3. `primary_loss_range`: Direct response costs (incident triage, forensics, downtime).
4. `secondary_loss_prob`: Probability of secondary stakeholder reactions (SLEF).
5. `secondary_loss_range`: Secondary loss magnitude per event.
