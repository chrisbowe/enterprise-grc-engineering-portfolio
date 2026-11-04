# Lab 3: Automated Third-Party Risk Management (TPRM)

## 📌 Overview
Supply chain vulnerabilities and unvetted SaaS applications represent one of the most common vectors for enterprise data compromise. 

This lab implements an automated **Third-Party Risk Management (TPRM)** intake pipeline that programmatically classifies vendor engagements by risk criticality and evaluates their technical compliance against ISO 27001 and SOC 2 Trust Services Criteria.

## 🏢 Vendor Criticality Classification
* **Tier 1 (Critical):** Direct production database access, PII, financial data processing.
* **Tier 2 (High):** Confidential business records, enterprise API / network peering.
* **Tier 3 (Moderate):** Internal communication tools, non-sensitive workforce SaaS.
* **Tier 4 (Low):** Public collateral, marketing tools without corporate network connectivity.

## 🛠️ Usage

```bash
# Execute vendor security evaluation
python vendor_evaluator.py
```
