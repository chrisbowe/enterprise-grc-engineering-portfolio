# Lab 3: Automated Third-Party Risk Management (TPRM) Intake Engine

## 📌 Overview
Supply chain vulnerabilities and unvetted third-party software represent significant vectors for enterprise data compromise and regulatory non-compliance. 

This lab implements an automated **Third-Party Risk Management (TPRM)** intake pipeline that programmatically classifies vendor engagements into criticality tiers based on data access, evaluates independent assurance evidence (SOC 2 Type II recency within 12 months or active ISO/IEC 27001 certification), audits tier-scaled security controls, and generates executive procurement dossiers with four distinct verdict states.

## 🏢 Tier-Scaled Criticality Classification
Vendors are classified into four risk tiers based on access scope:
* **Tier 1 (Critical Enterprise Risk):** Production database access (`has_prod_db_access`), PII handling (`has_pii`), financial data processing (`handles_financials`), corporate network peering (`network_peering`), or business-critical service dependency (`business_critical`).
* **Tier 2 (High Operational Risk):** Access to confidential internal documentation or intellectual property (`has_internal_docs`).
* **Tier 3 (Moderate Risk):** Corporate email or non-sensitive workforce communications access (`employee_email_access`).
* **Tier 4 (Low / Public Risk):** Public marketing collateral or non-connected tools with no access to non-public enterprise assets.

## 🛡️ Tier-Scaled Control Requirements & SLA Limits
Controls are audited as policy-as-data with tier-scaled severity ratings:
* **Independent Assurance:** Requires a current SOC 2 Type II report with period end date within 365 days (`soc2_report_period_end`), active self-attestation fallback (`soc2_type_2_current`), or an unexpired ISO/IEC 27001 certificate (`iso27001_cert_expiry`). Missing assurance is **CRITICAL** for Tier 1, **HIGH** for Tier 2, and **MEDIUM** for Tier 3. *(Note: The engine validates report recency and certificate currency; it does not audit individual Trust Services Criteria).*
* **Phishing-Resistant MFA:** Requires FIDO2/WebAuthn or PIV/smart card authentication (`phishing_resistant_mfa_enforced`). Missing is **HIGH** for Tier 1, **MEDIUM** for Tier 2, and not required for Tiers 3–4.
* **Breach Notification SLAs:** Requires binding contractual notification commitments (`vendor_breach_notification_hours` or `subprocessor_breach_notification_hours`) that allow the enterprise to meet its own regulatory deadlines (GDPR 72h, SEC Item 1.05, DORA/NIS2):
  * **Tier 1:** $\le$ **24 hours** (missing or exceeding SLA is **HIGH** severity).
  * **Tier 2:** $\le$ **48 hours** (missing or exceeding SLA is **MEDIUM** severity).
  * **Tier 3:** $\le$ **72 hours** (missing or exceeding SLA is **LOW** severity).
* **Enterprise Identity (SSO):** Requires SAML 2.0 / OIDC identity federation (`enforces_saml_sso`). Missing is **MEDIUM** for Tiers 1–2, **LOW** for Tier 3.

## 📋 Procurement Verdict States
The engine synthesizes findings into one of four definitive procurement statuses:
1. **`REJECTED - REMEDIATE BEFORE PROCUREMENT`**: Triggered by any **CRITICAL** finding (e.g. Tier 1 vendor lacking independent assurance).
2. **`CONDITIONAL - EXECUTIVE RISK ACCEPTANCE AND REMEDIATION PLAN REQUIRED`**: Triggered by any **HIGH** finding (e.g. missing phishing-resistant MFA or inadequate breach SLA).
3. **`APPROVED WITH CONDITIONS - TRACK FINDINGS TO CLOSURE`**: Triggered when only **MEDIUM** or **LOW** findings exist.
4. **`APPROVED FOR PROCUREMENT`**: Zero findings; vendor meets all tier-mandated security prerequisites.

## 🛠️ Usage

```bash
# Execute evaluation on default sample assessment (sample_vendor_assessment.json)
python vendor_evaluator.py

# Evaluate a custom vendor assessment file
python vendor_evaluator.py /path/to/assessment.json
```
