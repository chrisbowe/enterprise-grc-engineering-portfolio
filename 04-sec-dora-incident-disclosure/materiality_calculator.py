#!/usr/bin/env python3
"""
Regulatory Incident Governance & Materiality Decision Engine
Calculates quantitative and qualitative materiality thresholds under U.S. SEC Form 8-K (Item 1.05) and EU DORA.
"""

from datetime import datetime, timezone
import json
import sys

class IncidentMaterialityAssessment:
    def __init__(self, incident_name, rev_impact_per_hour, downtime_hours, records_exposed, reputation_factor, is_critical_service_down):
        self.incident_name = incident_name
        self.rev_impact_per_hour = rev_impact_per_hour
        self.downtime_hours = downtime_hours
        self.records_exposed = records_exposed
        self.reputation_factor = reputation_factor  # 1.0 (minimal) to 3.0 (severe public brand impact)
        self.is_critical_service_down = is_critical_service_down

    def evaluate_materiality(self, annual_revenue_baseline=100000000):
        """
        Determines quantitative and qualitative materiality.
        SEC standard: Total impact > 0.5% of annual revenue, critical service disruption, or mass customer PII exfiltration.
        """
        direct_revenue_loss = self.rev_impact_per_hour * self.downtime_hours
        forensics_and_legal_estimate = 250000 + (self.records_exposed * 18.50)
        total_estimated_impact = (direct_revenue_loss + forensics_and_legal_estimate) * self.reputation_factor

        materiality_threshold = annual_revenue_baseline * 0.005 # 0.5% threshold ($500,000 on $100M revenue)

        quantitative_trigger = total_estimated_impact >= materiality_threshold
        qualitative_trigger = self.records_exposed >= 100000 or self.is_critical_service_down

        is_material = quantitative_trigger or qualitative_trigger

        actions = []
        if is_material:
            actions.append("SEC Form 8-K (Item 1.05): File formal disclosure within four (4) business days of this determination.")
            actions.append("EU DORA / NIS2 Mandate: Submit initial major incident notification to national competent authority within 24 hours.")
            actions.append("Convene Board Audit & Cyber Risk Committee within 12 hours.")
            actions.append("Preserve all forensic logs, communication channels, and chain of custody for regulatory review.")
        else:
            actions.append("Log in internal security incident register. No mandatory external regulatory disclosure at this threshold.")
            actions.append("Maintain continuous monitoring; re-assess materiality if blast radius or exfiltration scope expands.")

        return {
            "incident_name": self.incident_name,
            "assessment_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "direct_revenue_loss": round(direct_revenue_loss, 2),
            "forensics_legal_estimate": round(forensics_and_legal_estimate, 2),
            "total_estimated_financial_impact": round(total_estimated_impact, 2),
            "materiality_financial_threshold": round(materiality_threshold, 2),
            "quantitative_materiality_exceeded": quantitative_trigger,
            "qualitative_materiality_triggered": qualitative_trigger,
            "final_determination": "MATERIAL" if is_material else "NON-MATERIAL",
            "regulatory_mandates": actions
        }

if __name__ == "__main__":
    incident = IncidentMaterialityAssessment(
        incident_name="Unauthorized Cloud Data Lake Exfiltration (Customer PII)",
        rev_impact_per_hour=25000,
        downtime_hours=8,
        records_exposed=140000,
        reputation_factor=1.4,
        is_critical_service_down=True
    )

    assessment = incident.evaluate_materiality(annual_revenue_baseline=100000000)

    print("\n" + "=" * 80)
    print("  EXECUTIVE CYBER INCIDENT MATERIALITY DETERMINATION (SEC & DORA)")
    print("=" * 80)
    print(f"Incident:                 {assessment['incident_name']}")
    print(f"Timestamp:                {assessment['assessment_timestamp']}")
    print(f"Estimated Total Impact:   ${assessment['total_estimated_financial_impact']:,.2f}")
    print(f"Materiality Threshold:    ${assessment['materiality_financial_threshold']:,.2f}")
    print(f"Quantitative Triggered:   {assessment['quantitative_materiality_exceeded']}")
    print(f"Qualitative Triggered:    {assessment['qualitative_materiality_triggered']}")
    print(f"FINAL DETERMINATION:      >>> {assessment['final_determination']} <<<")
    print("-" * 80)
    print("MANDATORY REGULATORY ACTIONS:")
    for a in assessment["regulatory_mandates"]:
        print(f"  • {a}")
    print("=" * 80 + "\n")
