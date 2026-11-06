#!/usr/bin/env python3
"""
Cyber Incident Materiality SCREENING Aid & Regulatory Clock Tracker

IMPORTANT - what this tool is and is not
----------------------------------------
* It is a SCREENING AID. It never declares an incident "material" or "non-material".
  Under SEC Form 8-K Item 1.05, materiality is determined by the registrant (typically
  its disclosure committee with counsel) using the "substantial likelihood a reasonable
  investor would consider it important" standard. The SEC deliberately set NO numeric
  threshold, so the revenue percentage and record-count trigger below are INTERNAL
  HEURISTICS, configurable in `Assumptions`, and should be calibrated with counsel.
* SEC materiality, DORA "major incident" classification and NIS2 "significant incident"
  are three SEPARATE tests with separate clocks. A "material" SEC screen does not by
  itself trigger DORA or NIS2 reporting, and vice versa. They are modelled separately.
* Reputation is treated as a QUALITATIVE factor (as the SEC release does), not as a
  multiplier on cost.
* Cost inputs are PLACEHOLDERS. Replace `fixed_response_cost` and `cost_per_record`
  with figures you can source (e.g., your own incident history or a cited breach-cost study).

Regulatory references (verify against current text before relying on them)
-------------------------------------------------------------------------
* SEC: Form 8-K Item 1.05 - file within four business days after the registrant
  determines the incident is material; determination must be made without unreasonable
  delay after discovery. Delay only on a U.S. Attorney General national-security /
  public-safety determination. Business-day count here skips weekends only; pass
  `holidays` for U.S. federal holidays.
* DORA (Reg. (EU) 2022/2554; classification RTS (EU) 2024/1772; reporting RTS (EU) 2025/301):
  for incidents classified as MAJOR: initial notification within 4 hours of classification
  and no later than 24 hours after becoming aware; intermediate report within 72 hours of
  the initial notification; final report within one month after the latest intermediate
  report. Applies to in-scope EU financial entities only.
* NIS2 (Directive (EU) 2022/2555): for SIGNIFICANT incidents: early warning within 24 hours of
  awareness; incident notification within 72 hours; final report within one month of the
  incident notification. DORA is the sector-specific regime for financial entities and
  takes precedence for them.
"""

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Dict, Optional

# Qualitative factors named in the SEC's adopting release for Item 1.05.
SEC_QUALITATIVE_FACTORS = (
    "reputational_harm",
    "customer_or_vendor_relationship_harm",
    "competitive_harm",
    "litigation_or_regulatory_action_likely",
)


@dataclass
class Assumptions:
    fixed_response_cost: float = 250_000.0        # PLACEHOLDER: forensics, counsel, notifications
    cost_per_record: float = 18.50                # PLACEHOLDER: replace with a sourced figure
    quantitative_pct_of_revenue: float = 0.005    # internal screening heuristic, NOT an SEC rule
    mass_exposure_records: int = 100_000          # internal screening heuristic, NOT an SEC rule


@dataclass
class IncidentFacts:
    incident_name: str
    rev_impact_per_hour: float
    downtime_hours: float
    records_exposed: int
    critical_service_down: bool = False
    qualitative_factors: Dict[str, bool] = field(default_factory=dict)
    awareness_time: Optional[datetime] = None          # when the entity became aware
    determination_time: Optional[datetime] = None      # when materiality WAS DETERMINED (SEC clock)
    dora_classification_time: Optional[datetime] = None  # when classified major (DORA clock)


@dataclass
class EntityProfile:
    annual_revenue: float
    is_sec_registrant: bool = False
    is_dora_entity: bool = False
    is_nis2_entity: bool = False
    dora_major_incident: Optional[bool] = None         # None = not yet classified
    nis2_significant_incident: Optional[bool] = None   # None = not yet assessed


def add_business_days(start: date, days: int, holidays=frozenset()) -> date:
    d = start
    while days > 0:
        d += timedelta(days=1)
        if d.weekday() < 5 and d not in holidays:
            days -= 1
    return d



def _require_tz(dt: Optional[datetime], name: str):
    if dt is not None and dt.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware (pass a tz-aware datetime)")

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


class IncidentMaterialityScreen:
    def __init__(self, facts: IncidentFacts, profile: EntityProfile,
                 assumptions: Optional[Assumptions] = None, holidays=frozenset()):
        self.f, self.p, self.a, self.holidays = facts, profile, assumptions or Assumptions(), holidays
        self._validate()

    def _validate(self):
        for name in ("rev_impact_per_hour", "downtime_hours", "records_exposed"):
            if getattr(self.f, name) < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.p.annual_revenue <= 0:
            raise ValueError("annual_revenue must be positive")
        unknown = set(self.f.qualitative_factors) - set(SEC_QUALITATIVE_FACTORS)
        if unknown:
            raise ValueError(f"Unknown qualitative factors {sorted(unknown)}; allowed: {SEC_QUALITATIVE_FACTORS}")

    # ------------------------------------------------------------ screening
    def screen(self):
        f, p, a = self.f, self.p, self.a
        direct_revenue_loss = f.rev_impact_per_hour * f.downtime_hours
        response_cost = a.fixed_response_cost + f.records_exposed * a.cost_per_record
        total_cost = direct_revenue_loss + response_cost             # no reputation multiplier
        threshold = p.annual_revenue * a.quantitative_pct_of_revenue
        quantitative = total_cost >= threshold

        indicators = [k for k in SEC_QUALITATIVE_FACTORS if f.qualitative_factors.get(k)]
        if f.critical_service_down:
            indicators.append("critical_service_disruption")
        if f.records_exposed >= a.mass_exposure_records:
            indicators.append("large_scale_data_exposure (heuristic)")

        if (quantitative and indicators) or len(indicators) >= 2:
            level = "ESCALATE NOW - convene disclosure committee and counsel to make the materiality determination"
        elif quantitative or len(indicators) == 1:
            level = "REVIEW REQUIRED - counsel to assess; re-screen as facts develop"
        else:
            level = "NO SCREENING INDICATORS TRIGGERED - document rationale; keep monitoring (this is not a materiality determination)"

        return {
            "incident_name": f.incident_name,
            "screen_timestamp": _iso(datetime.now(timezone.utc)),
            "direct_revenue_loss": round(direct_revenue_loss, 2),
            "response_cost_estimate": round(response_cost, 2),
            "total_estimated_cost": round(total_cost, 2),
            "quantitative_threshold": round(threshold, 2),
            "quantitative_indicator": quantitative,
            "qualitative_indicators": indicators,
            "screening_result": level,
            "assumption_warning": "Cost inputs and thresholds are internal placeholders/heuristics; calibrate with counsel.",
            "regulatory_regimes": self._regimes(),
            "internal_playbook_actions": self._internal_actions(),
        }

    # ------------------------------------------------------------ regulatory regimes (separate tests, separate clocks)
    def _regimes(self):
        f, p = self.f, self.p
        regimes = []

        if p.is_sec_registrant:
            due = None
            if f.determination_time:
                _require_tz(f.determination_time, "determination_time")
                ny_date = f.determination_time.astimezone(ZoneInfo("America/New_York")).date()
                due = add_business_days(ny_date, 4, self.holidays).isoformat()
            regimes.append({
                "regime": "SEC Form 8-K Item 1.05",
                "test": "Registrant determines the incident is MATERIAL (decision by registrant, not this tool).",
                "obligation": "File Item 1.05 8-K within four business days after the materiality determination.",
                "filing_due_date": due or "Clock starts at the determination: record the determination timestamp.",
                "also": "Determination must be made without unreasonable delay after discovery.",
            })

        if p.is_dora_entity:
            entry = {"regime": "EU DORA major-incident reporting",
                     "test": "Classify under the DORA criteria (clients/transactions affected, duration, data loss, "
                             "geographic spread, criticality of services, economic impact). Independent of SEC materiality."}
            if p.dora_major_incident is None:
                entry["status"] = "CLASSIFICATION PENDING - classify now; if aware of a potential major incident the 24-hour outer limit is already running."
            elif p.dora_major_incident:
                entry["obligation"] = ("Initial notification within 4h of classification and no later than 24h after awareness; "
                                       "intermediate report within 72h of the initial notification; final report within one month "
                                       "after the latest intermediate report.")
                if f.awareness_time:
                    _require_tz(f.awareness_time, "awareness_time")
                    _require_tz(f.dora_classification_time, "dora_classification_time")
                    outer = f.awareness_time + timedelta(hours=24)
                    inner = f.dora_classification_time + timedelta(hours=4) if f.dora_classification_time else None
                    if inner and f.dora_classification_time > outer:
                        initial_due = inner  # late classification: 24h cap no longer applies per RTS
                    else:
                        initial_due = min(outer, inner) if inner else outer
                    entry["initial_notification_due"] = _iso(initial_due)
            else:
                entry["status"] = "Classified NOT major - no DORA major-incident notification; keep records."
            regimes.append(entry)

        if p.is_nis2_entity:
            entry = {"regime": "EU NIS2 significant-incident reporting",
                     "test": "Assess whether the incident is SIGNIFICANT under NIS2 / national law."}
            if p.is_dora_entity:
                entry["note"] = "Financial entities in DORA scope follow DORA instead (lex specialis)."
            if p.nis2_significant_incident is None:
                entry["status"] = "ASSESSMENT PENDING"
            elif p.nis2_significant_incident:
                entry["obligation"] = ("Early warning within 24h of awareness; incident notification within 72h; "
                                       "final report within one month of the incident notification.")
                if f.awareness_time:
                    entry["early_warning_due"] = _iso(f.awareness_time + timedelta(hours=24))
                    entry["incident_notification_due"] = _iso(f.awareness_time + timedelta(hours=72))
            else:
                entry["status"] = "Assessed NOT significant - no NIS2 notification; keep records."
            regimes.append(entry)

        if not regimes:
            regimes.append({"regime": "None selected",
                            "status": "No regime flagged for this entity profile. Confirm applicability (SEC registrant, DORA, NIS2, state/sector rules, contracts)."})
        return regimes

    @staticmethod
    def _internal_actions():
        # Internal policy / good practice, NOT regulatory mandates.
        return [
            "Convene the disclosure committee / cyber risk committee (internal target: within 12 hours).",
            "Preserve forensic logs, communications and chain of custody (litigation hold).",
            "Record timestamps for awareness, classification and determination: regulatory clocks depend on them.",
            "Re-run this screen whenever scope, exfiltration volume or service impact changes.",
        ]


def print_report(r):
    print("\n" + "=" * 80)
    print("  CYBER INCIDENT MATERIALITY SCREEN (decision support - not a legal determination)")
    print("=" * 80)
    print(f"Incident:                  {r['incident_name']}")
    print(f"Screen timestamp:          {r['screen_timestamp']}")
    print(f"Direct revenue loss:       ${r['direct_revenue_loss']:,.2f}")
    print(f"Response cost estimate:    ${r['response_cost_estimate']:,.2f}")
    print(f"Total estimated cost:      ${r['total_estimated_cost']:,.2f}")
    print(f"Screening threshold:       ${r['quantitative_threshold']:,.2f}   (exceeded: {r['quantitative_indicator']})")
    print(f"Qualitative indicators:    {', '.join(r['qualitative_indicators']) or 'none'}")
    print(f"SCREENING RESULT:          >>> {r['screening_result']} <<<")
    print(f"Note:                      {r['assumption_warning']}")
    print("-" * 80)
    print("REGULATORY REGIMES (separate tests, separate clocks):")
    for reg in r["regulatory_regimes"]:
        print(f"\n  [{reg['regime']}]")
        for k, v in reg.items():
            if k != "regime":
                print(f"    {k.replace('_', ' ')}: {v}")
    print("\nINTERNAL PLAYBOOK ACTIONS (policy, not regulation):")
    for a in r["internal_playbook_actions"]:
        print(f"  - {a}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    now = datetime.now(timezone.utc)
    facts = IncidentFacts(
        incident_name="Unauthorized Cloud Data Lake Exfiltration (Customer PII)",
        rev_impact_per_hour=25_000,
        downtime_hours=8,
        records_exposed=140_000,
        critical_service_down=True,
        qualitative_factors={"reputational_harm": True, "litigation_or_regulatory_action_likely": True},
        awareness_time=now - timedelta(hours=6),
        determination_time=now,
    )
    profile = EntityProfile(annual_revenue=100_000_000, is_sec_registrant=True)
    print_report(IncidentMaterialityScreen(facts, profile).screen())
