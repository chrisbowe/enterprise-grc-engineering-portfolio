# Lab 4: Regulatory Incident Materiality & Notification Screening Aid

## 📌 Overview
Under modern cybersecurity regulations—including **U.S. SEC Form 8-K Item 1.05**, the **EU Digital Operational Resilience Act (DORA)**, and the **EU NIS2 Directive**—incident response teams must evaluate regulatory reporting triggers under strict, regime-specific clocks:
* **U.S. SEC Form 8-K Item 1.05:** Public disclosure required within **four (4) business days** after the registrant determines an incident is **material**, with the determination required without unreasonable delay following technical discovery.
* **EU DORA (Regulation (EU) 2022/2554 & RTS (EU) 2025/301 Art. 5):** Mandatory reporting for financial entities when an ICT-related incident is classified as **major**. Initial notification is due within **4 hours** of classification and no later than **24 hours** after becoming aware of the incident.
* **EU NIS2 (Directive (EU) 2022/2555 Art. 23):** Early warning required within **24 hours** of becoming aware of a **significant incident**, followed by incident notification within **72 hours**.

This lab provides:
1. **`materiality_calculator.py`**: A programmatic materiality screening aid balancing quantitative financial impact (direct loss + incident response costs) against qualitative SEC factors, evaluating Eastern Time business days with federal holiday exclusion (5 U.S.C. 6103), and calculating distinct DORA and NIS2 notification timelines.
2. **`incident_response_runbook.md`**: An operational cross-functional incident triage protocol mapping technical discovery, SEC materiality determination, DORA/NIS2 classification, and executive escalation workflows.

## ⏱️ Regulatory Filing Triggers & Clocks
* **SEC Form 8-K (Item 1.05):** Mandates public disclosure within **four (4) business days** once an incident is determined to be material. Calculations exclude weekends and US federal holidays (5 U.S.C. 6103) evaluated in US Eastern Time. Tracks discovery-to-determination elapsed time for legal counsel review.
* **EU DORA (RTS (EU) 2025/301 Art. 5):** Major ICT-related incident initial notification within **4 hours** of classification and no later than **24 hours** after becoming aware of the incident; intermediate report within **72 hours** of initial notification; final root-cause report within **1 month** after the latest intermediate report. (If classified after the 24-hour mark, initial notification is due within 4 hours of classification).
* **EU NIS2 (Directive (EU) 2022/2555 Art. 23):** For in-scope essential and important entities, early warning within **24 hours** of becoming aware of a significant incident; incident notification within **72 hours**; final report within **1 month** of the incident notification. *(DORA serves as sector-specific lex specialis for in-scope financial entities).*

> **Limitation Note:** Weekend and Member State bank-holiday relief under DORA RTS (EU) 2025/301 Art. 5(4)–(6) is unmodeled in this screening aid. Under Art. 5(5), such relief is explicitly unavailable to credit institutions, CCPs, trading venues, and NIS2 essential/important entities for initial and intermediate reports, and competent authorities may disapply it for significant entities (Art. 5(6)). Align local supervisory filing procedures with corporate legal counsel.

> **Disclaimer:** *This screening aid provides internal decision support and does not constitute formal legal determination or legal advice. Calibrate all financial thresholds and qualitative factors with corporate legal counsel.*

## 🛠️ Usage

```bash
# Execute the materiality assessment
python materiality_calculator.py
```
