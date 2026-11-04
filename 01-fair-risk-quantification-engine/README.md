# Lab 1: Quantitative Cyber Risk Modeling (FAIR™ Framework)

## 📌 Overview
This lab implements the **Factor Analysis of Information Risk (FAIR™)** standard, the only international standard quantitative model for information security and operational risk.

Instead of subjective, ambiguous qualitative risk matrices (High/Medium/Low), this engine uses Monte Carlo simulations (10,000 iterations per scenario) to generate probabilistic financial loss distributions ($ USD).

## 📊 Key Output Metrics
* **ALE (Annualized Loss Expectancy):** The average expected financial loss per year.
* **10th Percentile (Optimistic):** Expected loss in favorable threat conditions.
* **50th Percentile (Median):** Expected loss baseline.
* **90th Percentile (Pessimistic / Tail Risk):** Severe loss scenario for capital reserve planning and cyber insurance adequacy.

## 🛠️ Usage

```bash
# Install dependencies
pip install numpy

# Execute the simulation engine
python fair_engine.py
```

## 📋 Scenario Schema (`scenarios.json`)
Each threat scenario models:
1. `threat_event_frequency_range`: Triangular distribution `[min, mode, max]` attempts per year.
2. `vulnerability_prob`: Probability that threat capability overcomes resistance strength.
3. `primary_loss_range`: Direct response costs (incident triage, forensics, downtime).
4. `secondary_loss_prob`: Probability of secondary stakeholder reactions.
5. `secondary_loss_range`: Fines, litigation, customer churn.
