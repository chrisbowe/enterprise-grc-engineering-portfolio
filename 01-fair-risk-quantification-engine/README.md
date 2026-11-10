# Lab 1: Quantitative Cyber Risk Modeling (Open FAIR™ Framework)

## 📌 Overview
This lab implements the **Open FAIR™** (Factor Analysis of Information Risk) framework, an Open Group technical standard for quantitative risk analysis in information security and operational risk.

Instead of subjective, ambiguous qualitative risk matrices (High/Medium/Low), this engine uses Monte Carlo simulations (100,000 iterations per scenario by default) with Poisson-thinned event frequencies and PERT distributions to generate decision-useful financial loss distributions ($ USD).

## 📊 Key Output Metrics
* **ALE (Annualized Loss Exposure / Expectancy):** The average expected financial loss per year.
* **10th Percentile (Optimistic):** Expected loss in favorable conditions (90% of years are at or above).
* **50th Percentile (Median):** Expected loss baseline.
* **90th Percentile (1-in-10-year loss / Tail Risk):** Severe loss scenario for capital reserve planning and cyber insurance adequacy.
* **99th Percentile (1-in-100-year loss):** Extreme catastrophic tail risk.

## 🛠️ Usage

```bash
# Install dependencies from repository root
pip install -r ../requirements.txt

# Execute the simulation engine with default 100,000 iterations
python fair_engine.py

# Execute with custom iterations and reproducible random seed
python fair_engine.py --iterations 100000 --seed 42
```

## 📋 Scenario Schema (`scenarios.json`)
Each threat scenario models:
1. `id`, `name`, `asset`, `threat_community`: Scenario metadata.
2. `threat_event_frequency_range`: PERT range `[min, mode, max]` threat events per year (a rate).
3. `vulnerability_prob`: Constant probability `0..1` OR PERT range `[min, mode, max]` within `0..1` that threat capability overcomes resistance strength.
4. `primary_loss_range`: PERT range `[min, mode, max]` in USD per loss event (direct response, forensics, downtime).
5. `secondary_loss_prob`: Probability `0..1` that secondary stakeholder reactions occur (SLEF).
6. `secondary_loss_range`: PERT range `[min, mode, max]` in USD per secondary loss event.
7. `distribution`: *(Optional)* `"pert"` (default) or `"triangular"`.
