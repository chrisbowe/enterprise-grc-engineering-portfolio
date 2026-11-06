# Enterprise Cybersecurity & GRC Engineering Portfolio

A reference implementation demonstrating practical expertise in **Quantitative Cyber Risk Modeling (Open FAIR™)**, **Automated Compliance-as-Code Guardrails (OPA & Rego v1)**, **Tier-Scaled Third-Party Risk Management (TPRM)**, and **Regulatory Incident Materiality Screening (SEC Form 8-K & EU DORA)**.

---

## 🏛️ Executive Summary

Modern cybersecurity leaders and Governance, Risk, and Compliance (GRC) teams face a transition from static, annual compliance checklists to **continuous assurance** and **financially-quantified decision making**. 

This repository provides four complete, hands-on engineering labs designed to solve real-world enterprise risk challenges:

| # | Lab Directory | Core Domain | Industry Standards | Key Deliverable |
|---|---------------|-------------|--------------------|-----------------|
| **01** | [`01-fair-risk-quantification-engine`](./01-fair-risk-quantification-engine) | Quantitative Risk Modeling | Open FAIR™ Standard, ISO/IEC 27005 | Implements Poisson-thinned loss event counts and independent per-event PERT loss draws to generate scenario-based loss estimates ($) and Annualized Loss Exposure (ALE). |
| **02** | [`02-compliance-as-code-pipeline`](./02-compliance-as-code-pipeline) | Continuous Control Monitoring | NIST CSF 2.0, CIS Controls v8, OPA | Policy unit-tested in CI against Terraform plan fixtures; illustrates shift-left policy gates failing plan checks on non-compliant configurations. |
| **03** | [`03-third-party-risk-tprm-scoring`](./03-third-party-risk-tprm-scoring) | Vendor & Supply Chain Risk | ISO/IEC 27001, SOC 2 Type II, NIST CSF 2.0 GV.SC | Scores structured assessment data, classifies vendors into Tiers 1–4, audits date-calculated SOC 2 recency, and generates remediation recommendations. |
| **04** | [`04-sec-dora-incident-disclosure`](./04-sec-dora-incident-disclosure) | Regulatory Incident Screening | SEC Item 1.05 Form 8-K, EU DORA | Decision-support materiality screening aid calculating quantitative/qualitative thresholds and tracking separate SEC, DORA, and NIS2 regulatory reporting clocks. |

---

## 🚀 Lab Walkthroughs & Architecture

### Lab 1: Open FAIR™ Quantitative Risk Modeling Engine
* **Directory:** [`./01-fair-risk-quantification-engine`](./01-fair-risk-quantification-engine)
* **Stack:** Python 3, NumPy
* **Problem:** Subjective qualitative heatmaps (Red/Yellow/Green) fail to provide executives with the data required for capital allocation.
* **Solution:** Simulates 100,000 iterations of Threat Event Frequency (TEF rate) and Vulnerability using Poisson thinning, drawing independent per-event Primary and Secondary losses via PERT distributions to produce decision-useful Annualized Loss Exposure (ALE) distributions (Mean, P10, P50, P90, P99).

### Lab 2: Compliance-as-Code & Continuous Assurance Pipeline
* **Directory:** [`./02-compliance-as-code-pipeline`](./02-compliance-as-code-pipeline)
* **Stack:** Open Policy Agent (OPA), Rego v1, Terraform, GitHub Actions
* **Problem:** Cloud misconfigurations often bypass manual reviews, causing compliance drift between annual audit cycles.
* **Solution:** A shift-left CI/CD policy-as-code gate unit-tested against Terraform plan fixtures. Shows how pipelines enforce explicit S3 encryption configuration (CIS 3.11 / NIST PR.DS-01), restrict public IP exposure with tag-based exceptions (CIS 12.2 / NIST PR.IR-01), and require MFA on wildcard IAM admin policies (CIS 6.5 / NIST PR.AA-03/05).

### Lab 3: Third-Party Risk Management (TPRM) Scoring Engine
* **Directory:** [`./03-third-party-risk-tprm-scoring`](./03-third-party-risk-tprm-scoring)
* **Stack:** Python, JSON
* **Problem:** Third-party SaaS vendors and sub-processors introduce blind spots into enterprise perimeter security.
* **Solution:** Automatically scores structured assessment data into Tier 1–4 risk buckets, audits technical prerequisites (date-calculated SOC 2 recency <12 months, SAML SSO, phishing-resistant MFA, tier-scaled breach SLAs: 24h for Tier 1, 48h for Tier 2, 72h for Tier 3), and outputs executive procurement dossiers and remediation recommendations.

### Lab 4: SEC & DORA Incident Materiality Assessment Screening Aid
* **Directory:** [`./04-sec-dora-incident-disclosure`](./04-sec-dora-incident-disclosure)
* **Stack:** Python, Decision Logic
* **Problem:** Stringent regulatory reporting requirements—including the U.S. SEC Form 8-K Item 1.05 (four business days after a materiality determination in Eastern Time) and EU DORA (major incident initial notification within 4 hours of classification, 24-hour outer limit unless classified late)—require rapid, defensible incident screening.
* **Solution:** An automated decision-support screening aid that balances direct revenue loss and response costs against qualitative indicators (critical service disruption, brand harm, mass PII exposure). Tracks distinct SEC, DORA, and NIS2 reporting timelines alongside internal escalation targets.
* **Disclaimer:** *This screening aid provides internal decision support and does not constitute formal legal determination or legal advice. Calibrate all financial thresholds and qualitative factors with corporate legal counsel.*

---

## ⚙️ Quick Start

Clone this repository and explore any lab:

```bash
git clone https://github.com/chrisbowe/enterprise-grc-engineering-portfolio.git
cd enterprise-grc-engineering-portfolio
pip install -r requirements.txt

# Run Lab 1 (Open FAIR Simulation with 100,000 iterations & seed)
cd 01-fair-risk-quantification-engine
python fair_engine.py --iterations 100000 --seed 42

# Run Lab 2 (Rego Compliance Policy Suite)
cd ../02-compliance-as-code-pipeline
bash run_policy_tests.sh

# Run Lab 3 (Vendor Risk Evaluator)
cd ../03-third-party-risk-tprm-scoring
python vendor_evaluator.py

# Run Lab 4 (Materiality Screening Aid)
cd ../04-sec-dora-incident-disclosure
python materiality_calculator.py

# Run Python Unit Test Suite
cd ..
pytest tests/
```

---

## 📜 Standards & Frameworks Referenced
* **NIST Cybersecurity Framework (CSF) 2.0:** Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)
* **CIS Critical Security Controls v8:** Controls 3 (Data Protection), 6 (Access Control Management), 12 (Network Infrastructure Management)
* **ISO/IEC 27001:2022:** Information Security Management System (ISMS)
* **Open FAIR™:** Risk Taxonomy & Risk Analysis Technical Standards
* **U.S. SEC Regulation S-K / Form 8-K (Item 1.05):** Cybersecurity Risk Management, Strategy, Governance, and Incident Disclosure
* **EU Digital Operational Resilience Act (DORA):** Regulation (EU) 2022/2554, RTS (EU) 2024/1772, Delegated Regulation (EU) 2025/301
* **EU NIS2 Directive:** Directive (EU) 2022/2555
