# Enterprise Cybersecurity & GRC Engineering Portfolio

A production-grade portfolio demonstrating expertise in **Quantitative Cyber Risk Modeling (FAIR)**, **Automated Compliance-as-Code Guardrails (OPA & Rego)**, **Third-Party Risk Management (TPRM)**, and **Regulatory Incident Governance (SEC Form 8-K & EU DORA)**.

---

## 🏛️ Executive Summary

Modern cybersecurity leaders and Governance, Risk, and Compliance (GRC) teams face a transition from static, annual compliance checklists to **continuous assurance** and **financially-quantified decision making**. 

This repository provides four complete, hands-on engineering labs designed to solve real-world enterprise risk challenges:

| # | Lab Directory | Core Domain | Industry Standards | Key Deliverable |
|---|---------------|-------------|--------------------|-----------------|
| **01** | [`01-fair-risk-quantification-engine`](./01-fair-risk-quantification-engine) | Quantitative Risk Modeling | FAIR™ Framework, Open FAIR | Translates technical CVEs into annualized financial loss distributions ($) via Monte Carlo simulations for Board presentation. |
| **02** | [`02-compliance-as-code-pipeline`](./02-compliance-as-code-pipeline) | Continuous Control Monitoring | NIST CSF 2.0, CIS v8, OPA | Enforces automated security guardrails in CI/CD, preventing non-compliant infrastructure from ever provisioning. |
| **03** | [`03-third-party-risk-tprm-scoring`](./03-third-party-risk-tprm-scoring) | Vendor & Supply Chain Risk | ISO/IEC 27001, SOC 2 Type II, SIG | Dynamically categorizes vendors by data criticality, audits subprocessor controls, and generates automated remediation notices. |
| **04** | [`04-sec-dora-incident-disclosure`](./04-sec-dora-incident-disclosure) | Regulatory Incident Response | SEC Item 1.05 Form 8-K, EU DORA | Programmatic calculation of operational and qualitative materiality thresholds with automated disclosure trigger runbooks. |

---

## 🚀 Lab Walkthroughs & Architecture

### Lab 1: FAIR Quantitative Risk Quantification Engine
* **Directory:** [`./01-fair-risk-quantification-engine`](./01-fair-risk-quantification-engine)
* **Stack:** Python 3, NumPy, SciPy, Matplotlib
* **Problem:** Subjective qualitative heatmaps (Red/Yellow/Green) fail to provide executives with the data required for capital allocation.
* **Solution:** Simulates 10,000 iterations of Threat Event Frequency (TEF), Vulnerability, Primary Loss (forensics, downtime), and Secondary Loss (litigation, fines) to produce 10th, 50th, and 90th percentile Annualized Loss Expectancies (ALE).

### Lab 2: Compliance-as-Code & Continuous Assurance Pipeline
* **Directory:** [`./02-compliance-as-code-pipeline`](./02-compliance-as-code-pipeline)
* **Stack:** Open Policy Agent (OPA), Rego, Terraform, GitHub Actions
* **Problem:** Cloud misconfigurations often bypass manual reviews, causing compliance drift between annual audit cycles.
* **Solution:** A shift-left CI/CD policy-as-code gate that inspects Terraform plans before merge. Rejects resources lacking encryption (CIS 3.3), exposing public IPs (CIS 4.1), or granting wildcard IAM privileges without MFA (CIS 5.2).

### Lab 3: Third-Party Risk Management (TPRM) Scoring Engine
* **Directory:** [`./03-third-party-risk-tprm-scoring`](./03-third-party-risk-tprm-scoring)
* **Stack:** Python, JSON Schema
* **Problem:** Third-party SaaS vendors and AI sub-processors introduce blind spots into enterprise perimeter security.
* **Solution:** Automatically maps vendor questionnaires into Tier 1–4 risk buckets, audits technical prerequisites (SOC 2 recency, SAML SSO, phishing-resistant MFA, subprocessor breach SLAs), and outputs executive procurement verdicts.

### Lab 4: SEC & DORA Incident Materiality Assessment Calculator
* **Directory:** [`./04-sec-dora-incident-disclosure`](./04-sec-dora-incident-disclosure)
* **Stack:** Python, Markdown Incident Playbooks
* **Problem:** New regulatory rules (SEC 4-day disclosure under Item 1.05 and DORA's 24-hour initial reporting) create personal legal liability for security executives who fail to determine materiality quickly.
* **Solution:** An automated decision calculator that evaluates downtime, revenue loss per hour, PII exposure counts, and reputation multipliers against enterprise revenue materiality baselines.

---

## ⚙️ Quick Start

Clone this repository and explore any lab:

```bash
git clone https://github.com/chrisbowe/enterprise-grc-engineering-portfolio.git
cd enterprise-grc-engineering-portfolio

# Run Lab 1 (FAIR Simulation)
cd 01-fair-risk-quantification-engine
python fair_engine.py

# Run Lab 3 (Vendor Risk Evaluator)
cd ../03-third-party-risk-tprm-scoring
python vendor_evaluator.py

# Run Lab 4 (Materiality Calculator)
cd ../04-sec-dora-incident-disclosure
python materiality_calculator.py
```

---

## 📜 Standards & Frameworks Referenced
* **NIST Cybersecurity Framework (CSF) 2.0:** Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)
* **CIS Critical Security Controls v8:** Controls 3 (Data Protection), 4 (Secure Configuration), 5 (Account Management)
* **ISO/IEC 27001:2022:** Information Security Management System (ISMS)
* **Open FAIR™:** Risk Taxonomy & Risk Analysis Technical Standards
* **U.S. SEC Regulation S-K / Form 8-K (Item 1.05):** Cybersecurity Risk Management, Strategy, Governance, and Incident Disclosure
* **EU Digital Operational Resilience Act (DORA):** Regulation (EU) 2022/2554
