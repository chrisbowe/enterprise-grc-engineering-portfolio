#!/usr/bin/env python3
"""
Third-Party Risk Management (TPRM) & Vendor Intake Scoring Engine
Classifies vendors into criticality tiers and generates automated risk audits.
"""

import json
import os
import sys

class VendorRiskEvaluator:
    def __init__(self, assessment_data):
        self.data = assessment_data

    def calculate_tier(self):
        """Calculates Vendor Criticality Tier based on data sensitivity & access scope."""
        data_scope = self.data.get("data_access", {})
        
        if data_scope.get("has_pii") or data_scope.get("has_prod_db_access") or data_scope.get("handles_financials"):
            return "Tier 1 (Critical Enterprise Risk)"
        elif data_scope.get("has_internal_docs") or data_scope.get("network_peering"):
            return "Tier 2 (High Operational Risk)"
        elif data_scope.get("employee_email_access"):
            return "Tier 3 (Moderate Risk)"
        return "Tier 4 (Low / Public Risk)"

    def audit_security_controls(self):
        """Validates reported technical controls against enterprise minimum standards."""
        findings = []
        controls = self.data.get("security_controls", {})

        # Control 1: Independent SOC 2 Type II assurance
        if not controls.get("soc2_type_2_current"):
            findings.append({
                "severity": "CRITICAL",
                "control": "SOC 2 Type II Recency",
                "finding": "Vendor lacks a valid, current (<12 months) SOC 2 Type II audit report.",
                "remediation": "Require vendor to provide current auditor report or execute a formal security addendum."
            })

        # Control 2: Phishing-resistant MFA
        if not controls.get("phishing_resistant_mfa_enforced"):
            findings.append({
                "severity": "HIGH",
                "control": "Administrative MFA Strength",
                "finding": "Vendor engineers with access to production data do not enforce FIDO2/Passkey MFA.",
                "remediation": "Mandate hardware key / WebAuthn MFA enforcement for all support and ops personnel."
            })

        # Control 3: Subprocessor breach notification SLA
        notification_sla = controls.get("subprocessor_breach_notification_hours", 999)
        if notification_sla > 72:
            findings.append({
                "severity": "MEDIUM",
                "control": "Breach Notification SLA",
                "finding": f"Vendor commits to {notification_sla}h breach notification, which exceeds enterprise 72-hour regulatory threshold.",
                "remediation": "Amend Data Protection Addendum (DPA) to enforce a mandatory 48-hour incident notification window."
            })

        # Control 4: Enterprise Identity Integration
        if not controls.get("enforces_saml_sso"):
            findings.append({
                "severity": "MEDIUM",
                "control": "Enterprise Identity (SSO)",
                "finding": "Vendor platform does not support SAML 2.0 / OIDC identity federation.",
                "remediation": "Upgrade subscription tier or mandate strict SCIM lifecycle provisioning."
            })

        return findings

    def generate_procurement_dossier(self):
        tier = self.calculate_tier()
        findings = self.audit_security_controls()
        
        has_critical = any(f["severity"] == "CRITICAL" for f in findings)
        status = "REJECTED - CONDITIONAL REMEDIATION REQUIRED" if has_critical else "APPROVED FOR PROCUREMENT"

        return {
            "vendor_name": self.data.get("vendor_name"),
            "vendor_id": self.data.get("vendor_id"),
            "business_owner": self.data.get("business_owner"),
            "criticality_tier": tier,
            "procurement_status": status,
            "total_risk_findings": len(findings),
            "findings": findings
        }

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "sample_vendor_assessment.json")

    if not os.path.exists(file_path):
        print(f"Error: Assessment file not found at {file_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "r", encoding="utf-8-sig") as f:
        assessment = json.load(f)

    evaluator = VendorRiskEvaluator(assessment)
    dossier = evaluator.generate_procurement_dossier()

    print("\n" + "=" * 80)
    print("  THIRD-PARTY RISK MANAGEMENT (TPRM) EXECUTIVE PROCUREMENT DOSSIER")
    print("=" * 80)
    print(f"Vendor Name:        {dossier['vendor_name']} ({dossier['vendor_id']})")
    print(f"Business Sponsor:   {dossier['business_owner']}")
    print(f"Calculated Tier:    {dossier['criticality_tier']}")
    print(f"Procurement Status: {dossier['procurement_status']}")
    print(f"Total Findings:     {dossier['total_risk_findings']}")
    print("-" * 80)
    
    for idx, finding in enumerate(dossier["findings"], 1):
        print(f"\nFinding #{idx} [{finding['severity']}]: {finding['control']}")
        print(f"  Issue:       {finding['finding']}")
        print(f"  Remediation: {finding['remediation']}")
    
    print("\n" + "=" * 80 + "\n")
