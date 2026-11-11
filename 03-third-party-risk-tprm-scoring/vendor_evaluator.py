#!/usr/bin/env python3
"""
Third-Party Risk Management (TPRM) & Vendor Intake Scoring Engine

Input JSON (keys marked * are optional additions)
-------------------------------------------------
vendor_name, vendor_id, business_owner
data_access: has_pii, has_prod_db_access, handles_financials, network_peering,
             business_critical*, has_internal_docs, employee_email_access
security_controls:
    soc2_report_period_end*  "YYYY-MM-DD"      (preferred over the boolean below)
    soc2_type_2_current      bool              (self-attested fallback)
    iso27001_cert_expiry*    "YYYY-MM-DD"      (accepted as alternative assurance)
    phishing_resistant_mfa_enforced  bool      (FIDO2/WebAuthn, PIV/smart card)
    vendor_breach_notification_hours* number   (legacy key accepted:
                                                subprocessor_breach_notification_hours)
    enforces_saml_sso        bool              (SAML 2.0 / OIDC federation)
"""

import json
import os
import sys
from datetime import date, datetime

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Policy-as-data: severity of a missing control per tier (None = not required).
TIER_REQUIREMENTS = {
    1: {"label": "Tier 1 (Critical Enterprise Risk)", "assurance": "CRITICAL",
        "phishing_mfa": "HIGH", "sso": "MEDIUM", "max_breach_hours": 24, "breach_severity": "HIGH"},
    2: {"label": "Tier 2 (High Operational Risk)", "assurance": "HIGH",
        "phishing_mfa": "MEDIUM", "sso": "MEDIUM", "max_breach_hours": 48, "breach_severity": "MEDIUM"},
    3: {"label": "Tier 3 (Moderate Risk)", "assurance": "MEDIUM",
        "phishing_mfa": None, "sso": "LOW", "max_breach_hours": 72, "breach_severity": "LOW"},
    4: {"label": "Tier 4 (Low / Public Risk)", "assurance": None,
        "phishing_mfa": None, "sso": None, "max_breach_hours": None, "breach_severity": None},
}


def _flag(value, name):
    """Strict boolean: JSON strings like "false" are truthy in Python, so reject them."""
    if value is None or isinstance(value, bool):
        return bool(value)
    raise ValueError(f"'{name}' must be a JSON boolean (true/false), got {value!r}")


def _parse_date(value, name):
    if value in (None, ""):
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"'{name}' must be YYYY-MM-DD, got {value!r}")


RECOGNIZED_DATA_ACCESS_KEYS = {
    "has_pii", "has_prod_db_access", "handles_financials", "network_peering",
    "business_critical", "has_internal_docs", "employee_email_access"
}
RECOGNIZED_CONTROL_KEYS = {
    "soc2_report_period_end", "soc2_type_2_current", "iso27001_cert_expiry",
    "phishing_resistant_mfa_enforced", "vendor_breach_notification_hours",
    "subprocessor_breach_notification_hours", "enforces_saml_sso"
}


class VendorRiskEvaluator:
    def __init__(self, assessment_data, as_of=None):
        self.data = assessment_data
        self.as_of = as_of or date.today()
        da = assessment_data.get("data_access")
        if not isinstance(da, dict) or not da:
            raise ValueError("'data_access' section is required: refusing to default an unassessed vendor to Tier 4.")

        sc = assessment_data.get("security_controls")
        if sc is not None and not isinstance(sc, dict):
            raise ValueError("'security_controls' must be a dict when provided.")
        sc = sc or {}

        # Track unrecognized schema fields to alert callers to schema drift
        self.unknown_fields = []
        da_unknown = set(da.keys()) - RECOGNIZED_DATA_ACCESS_KEYS
        if da_unknown:
            for k in sorted(da_unknown):
                self.unknown_fields.append(f"data_access.{k}")
            sys.stderr.write(f"Warning: unrecognized 'data_access' fields ignored: {sorted(da_unknown)}\n")
        ctrl_unknown = set(sc.keys()) - RECOGNIZED_CONTROL_KEYS
        if ctrl_unknown:
            for k in sorted(ctrl_unknown):
                self.unknown_fields.append(f"security_controls.{k}")
            sys.stderr.write(f"Warning: unrecognized 'security_controls' fields ignored: {sorted(ctrl_unknown)}\n")

    # ------------------------------------------------------------------ tiering
    def calculate_tier_number(self):
        d = self.data["data_access"]
        f = lambda k: _flag(d.get(k), k)
        if (f("has_pii") or f("has_prod_db_access") or f("handles_financials")
                or f("network_peering") or f("business_critical")):
            return 1
        if f("has_internal_docs"):
            return 2
        if f("employee_email_access"):
            return 3
        return 4

    def calculate_tier(self):
        return TIER_REQUIREMENTS[self.calculate_tier_number()]["label"]

    # ------------------------------------------------------------------ evidence helpers
    def _assurance_status(self, controls):
        """Returns (satisfied, evidence description)."""
        end = _parse_date(controls.get("soc2_report_period_end"), "soc2_report_period_end")
        if end:
            if end > self.as_of:
                soc2_note = f"SOC 2 Type II period end {end} is in the future; verify"
            else:
                age = (self.as_of - end).days
                if 0 <= age <= 365:
                    return True, f"SOC 2 Type II period ended {end} ({age} days ago)"
                soc2_note = f"SOC 2 Type II period ended {end} ({age} days ago, outside 12 months)"
        elif "soc2_type_2_current" in controls:
            if _flag(controls["soc2_type_2_current"], "soc2_type_2_current"):
                return True, "SOC 2 Type II self-attested by vendor (no report date supplied; verify the report)"
            soc2_note = "vendor reports no current SOC 2 Type II"
        else:
            soc2_note = "no SOC 2 Type II evidence provided"

        iso = _parse_date(controls.get("iso27001_cert_expiry"), "iso27001_cert_expiry")
        if iso and iso >= self.as_of:
            return True, f"ISO/IEC 27001 certificate valid until {iso}"
        return False, soc2_note

    @staticmethod
    def _breach_hours(controls):
        for key in ("vendor_breach_notification_hours", "subprocessor_breach_notification_hours"):
            v = controls.get(key)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                return float(v)
        return None

    # ------------------------------------------------------------------ audit
    def audit_security_controls(self):
        """Validates reported controls against the minimums for the vendor's tier."""
        findings = []
        controls = self.data.get("security_controls") or {}
        req = TIER_REQUIREMENTS[self.calculate_tier_number()]

        def add(severity, control, finding, remediation):
            findings.append({"severity": severity, "control": control,
                             "finding": finding, "remediation": remediation})

        # 1. Independent assurance (SOC 2 Type II or ISO 27001)
        if req["assurance"]:
            ok, evidence = self._assurance_status(controls)
            if not ok:
                add(req["assurance"], "Independent Assurance (SOC 2 Type II / ISO 27001)",
                    f"No valid independent assurance: {evidence}. A SOC 2 Type II period should have ended within 12 months.",
                    "Obtain a current SOC 2 Type II report (or valid ISO/IEC 27001 certificate with Statement of Applicability), "
                    "or execute a formal security addendum with a dated remediation plan.")

        # 2. Phishing-resistant MFA
        if req["phishing_mfa"] and not _flag(controls.get("phishing_resistant_mfa_enforced"), "phishing_resistant_mfa_enforced"):
            add(req["phishing_mfa"], "Administrative MFA Strength",
                "Vendor personnel with access to our data do not enforce phishing-resistant MFA (FIDO2/WebAuthn or PIV).",
                "Mandate hardware-key / WebAuthn MFA for all support and operations personnel.")

        # 3. Breach notification SLA (must beat our own regulatory clocks)
        if req["max_breach_hours"]:
            hours = self._breach_hours(controls)
            limit = req["max_breach_hours"]
            if hours is None:
                add(req["breach_severity"], "Breach Notification SLA",
                    "Vendor has not stated a breach-notification commitment.",
                    f"Amend the DPA to require notification within {limit} hours of discovery.")
            elif hours > limit:
                add(req["breach_severity"], "Breach Notification SLA",
                    f"Vendor commits to {hours:g}h notification; this tier requires <= {limit}h so that we can meet our own "
                    "regulatory deadlines (e.g., GDPR 72h, SEC 8-K, DORA/NIS2 early notification).",
                    f"Amend the Data Protection Addendum (DPA) to require notification within {limit} hours, "
                    "with flow-down to the vendor's own subprocessors.")

        # 4. Enterprise identity integration
        if req["sso"] and not _flag(controls.get("enforces_saml_sso"), "enforces_saml_sso"):
            add(req["sso"], "Enterprise Identity (SSO)",
                "Vendor platform does not support SAML 2.0 / OIDC identity federation.",
                "Upgrade subscription tier to enable SSO, or require SCIM lifecycle provisioning with MFA.")

        findings.sort(key=lambda x: -SEVERITY_ORDER[x["severity"]])
        return findings

    # ------------------------------------------------------------------ verdict
    @staticmethod
    def _status(findings):
        severities = {f["severity"] for f in findings}
        if "CRITICAL" in severities:
            return "REJECTED - REMEDIATE BEFORE PROCUREMENT"
        if "HIGH" in severities:
            return "CONDITIONAL - EXECUTIVE RISK ACCEPTANCE AND REMEDIATION PLAN REQUIRED"
        if findings:
            return "APPROVED WITH CONDITIONS - TRACK FINDINGS TO CLOSURE"
        return "APPROVED FOR PROCUREMENT"

    def generate_procurement_dossier(self):
        findings = self.audit_security_controls()
        return {
            "vendor_name": self.data.get("vendor_name"),
            "vendor_id": self.data.get("vendor_id"),
            "business_owner": self.data.get("business_owner"),
            "assessment_date": self.as_of.isoformat(),
            "tier_number": self.calculate_tier_number(),
            "criticality_tier": self.calculate_tier(),
            "procurement_status": self._status(findings),
            "total_risk_findings": len(findings),
            "findings": findings,
        }


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    strict = False
    if "--strict" in argv:
        strict = True
        argv.remove("--strict")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = argv[0] if argv else os.path.join(script_dir, "sample_vendor_assessment.json")

    if not os.path.exists(file_path):
        print(f"Error: Assessment file not found at {file_path}", file=sys.stderr)
        return 1
    with open(file_path, "r", encoding="utf-8-sig") as f:
        assessment = json.load(f)

    try:
        evaluator = VendorRiskEvaluator(assessment)
        if strict and evaluator.unknown_fields:
            print(f"Input error: strict mode rejected unrecognized fields: {evaluator.unknown_fields}", file=sys.stderr)
            return 2
        dossier = evaluator.generate_procurement_dossier()
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    print("\n" + "=" * 80)
    print("  THIRD-PARTY RISK MANAGEMENT (TPRM) EXECUTIVE PROCUREMENT DOSSIER")
    print("=" * 80)
    print(f"Vendor Name:        {dossier['vendor_name']} ({dossier['vendor_id']})")
    print(f"Business Sponsor:   {dossier['business_owner']}")
    print(f"Assessment Date:    {dossier['assessment_date']}")
    print(f"Calculated Tier:    {dossier['criticality_tier']}")
    print(f"Procurement Status: {dossier['procurement_status']}")
    print(f"Total Findings:     {dossier['total_risk_findings']}")
    print("-" * 80)
    for idx, finding in enumerate(dossier["findings"], 1):
        print(f"\nFinding #{idx} [{finding['severity']}]: {finding['control']}")
        print(f"  Issue:       {finding['finding']}")
        print(f"  Remediation: {finding['remediation']}")
    print("\n" + "=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
