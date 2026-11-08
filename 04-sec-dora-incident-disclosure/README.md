# Lab 4: SEC & DORA Incident Materiality Assessment Screening Aid

## 📌 Overview
Under modern regulatory standards—including the **U.S. SEC 4-day disclosure rule (Item 1.05 of Form 8-K)** and the **European Union Digital Operational Resilience Act (DORA)**—determining whether an active security incident is **"Material"** is a critical legal and governance mandate.

This lab provides:
1. **`materiality_calculator.py`**: A programmatic materiality screening aid balancing quantitative financial impact against qualitative customer impact.
2. **`incident_response_runbook.md`**: An executive incident response protocol mapping detection, containment, board briefing, and regulatory filing clocks.

## ⏱️ Regulatory Filing Triggers
* **SEC Form 8-K (Item 1.05):** Mandates public disclosure within **four (4) business days** once an incident is determined to be material. Calculations exclude weekends and US federal holidays (5 U.S.C. 6103) evaluated in US Eastern Time.
* **EU DORA (RTS (EU) 2025/301 Art. 5):** Major ICT-related incident initial notification within **4 hours** of classification and no later than **24 hours** after becoming aware of the incident; intermediate report within **72 hours** of initial notification; final root-cause report within **1 month** after the latest intermediate report.

> **Limitation Note:** Weekend and Member State bank-holiday relief under DORA RTS (EU) 2025/301 Art. 5(4)–(6) is unmodeled in this screening aid. Under Art. 5(5), such relief is explicitly unavailable to credit institutions, CCPs, trading venues, and NIS2 essential/important entities for initial and intermediate reports, and competent authorities may disapply it for significant entities (Art. 5(6)). Align local supervisory filing procedures with corporate legal counsel.

## 🛠️ Usage

```bash
# Execute the materiality assessment
python materiality_calculator.py
```
