# Lab 4: SEC & DORA Incident Materiality Assessment Calculator

## 📌 Overview
Under modern regulatory standards—including the **U.S. SEC 4-day disclosure rule (Item 1.05 of Form 8-K)** and the **European Union Digital Operational Resilience Act (DORA)**—determining whether an active security incident is **"Material"** is a critical legal and governance mandate.

This lab provides:
1. **`materiality_calculator.py`**: A programmatic materiality assessment engine balancing quantitative financial impact against qualitative customer impact.
2. **`incident_response_runbook.md`**: An executive incident response protocol mapping detection, containment, board briefing, and regulatory filing clocks.

## ⏱️ Regulatory Filing Triggers
* **SEC Form 8-K (Item 1.05):** Mandates public disclosure within **four (4) business days** once an incident is determined to be material.
* **EU DORA:** Requires initial notification of a major ICT-related incident within **24 hours**, an intermediate report within **72 hours**, and a final root-cause report within **1 month**.

## 🛠️ Usage

```bash
# Execute the materiality assessment
python materiality_calculator.py
```
