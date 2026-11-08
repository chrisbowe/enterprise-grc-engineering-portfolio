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

Timestamp Definitions across Regulatory Regimes
-----------------------------------------------
* `discovery_time` (SEC Item 1.05): When the registrant first detects or discovers technical
  evidence that a cybersecurity incident has occurred. Triggers the obligation to reach a
  materiality determination "without unreasonable delay."
* `awareness_time` (EU DORA Art. 19(4) & RTS (EU) 2025/301 Art. 5): When the financial entity
  becomes aware of the ICT-related incident itself (prior to and independent of whether it is
  major). Starts the 24-hour outer limit for submitting the initial notification.
* `dora_classification_time` (DORA RTS (EU) 2024/1772): When the entity classifies the incident
  as "major" under the criteria (clients affected, downtime, data loss, criticality). Triggers
  the 4-hour initial notification deadline (capped by the 24-hour awareness outer limit, unless
  classified late after the 24-hour mark).
* `awareness_time` (EU NIS2 Art. 23(4)(a)): When the in-scope entity becomes aware that an
  incident is *significant*, starting the 24-hour early warning clock.
* `determination_time` (SEC Item 1.05): When the registrant determines the incident is material.
  Starts the strict four-business-day Form 8-K filing deadline.

Regulatory references (verify against current text before relying on them)
-------------------------------------------------------------------------
* SEC: Form 8-K Item 1.05 - file within four business days after the registrant
  determines the incident is material; determination must be made without unreasonable
  delay after discovery. Delay only on a U.S. Attorney General national-security /
  public-safety determination. Business-day count automatically excludes weekends
  and U.S. federal holidays (5 U.S.C. 6103) evaluated in Eastern Time; custom
  holiday sets may also be passed.
* DORA (Reg. (EU) 2022/2554; classification RTS (EU) 2024/1772; reporting RTS (EU) 2025/301):
  for incidents classified as MAJOR: initial notification within 4 hours of classification
  and no later than 24 hours after becoming aware of the incident; intermediate report within
  72 hours of the initial notification; final report within one month after the latest intermediate
  report (Article 5). Applies to in-scope EU financial entities only.
  Weekend/bank-holiday relief (RTS 2025/301 Art. 5(4)-(6)) is NOT modeled: where permitted, a deadline
  falling on a weekend or Member State bank holiday may be met by noon of the next working day. It is
  unavailable to credit institutions, CCPs, trading venues and NIS2 essential/important entities for
  initial and intermediate reports (Art. 5(5)), and authorities may disapply it for significant entities (Art. 5(6)).
* NIS2 (Directive (EU) 2022/2555): for SIGNIFICANT incidents: early warning within 24 hours of
  awareness of significance; incident notification within 72 hours; final report within one month
  of the incident notification. DORA is the sector-specific regime for financial entities and
  takes precedence for them.
"""

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Dict, Optional, Union, Iterable

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
    discovery_time: Optional[datetime] = None          # when incident was discovered (SEC delay clock)
    awareness_time: Optional[datetime] = None          # when entity became aware of incident (DORA) / significance (NIS2)
    determination_time: Optional[datetime] = None      # when materiality WAS DETERMINED (SEC clock)
    dora_classification_time: Optional[datetime] = None  # when classified major under DORA criteria


@dataclass
class EntityProfile:
    annual_revenue: float
    is_sec_registrant: bool = False
    is_dora_entity: bool = False
    is_nis2_entity: bool = False
    dora_major_incident: Optional[bool] = None         # None = not yet classified
    nis2_significant_incident: Optional[bool] = None   # None = not yet assessed


# ---------------------------------------------------------------------------
# US Federal Holidays (5 U.S.C. 6103) & Business Day Calendar
# ---------------------------------------------------------------------------
def _nth_weekday_of_month(year: int, month: int, weekday: int, n: int) -> date:
    d = date(year, month, 1)
    days_ahead = (weekday - d.weekday()) % 7
    d += timedelta(days=days_ahead)
    return d + timedelta(weeks=n - 1)


def _last_weekday_of_month(year: int, month: int, weekday: int) -> date:
    if month == 12:
        d = date(year + 1, 1, 1) - timedelta(days=1)
    else:
        d = date(year, month + 1, 1) - timedelta(days=1)
    days_behind = (d.weekday() - weekday) % 7
    return d - timedelta(days=days_behind)


def _observe(d: date) -> date:
    if d.weekday() == 5:    # Saturday -> Friday
        return d - timedelta(days=1)
    elif d.weekday() == 6:  # Sunday -> Monday
        return d + timedelta(days=1)
    return d


def get_us_federal_holidays(year: int) -> set:
    """
    Returns US federal holidays observed in the specified calendar year (5 U.S.C. 6103).
    All returned dates have d.year == year.
    Correctly includes Dec 31 when Jan 1 of year+1 falls on a Saturday.
    """
    h = set()
    # New Year's Day for this year (if not observed in the preceding year)
    ny = _observe(date(year, 1, 1))
    if ny.year == year:
        h.add(ny)
    # Next year's New Year's Day if observed on Dec 31 of this year (when Jan 1 falls on Saturday)
    ny_next = _observe(date(year + 1, 1, 1))
    if ny_next.year == year:
        h.add(ny_next)

    h.add(_nth_weekday_of_month(year, 1, 0, 3))        # Martin Luther King Jr. Day (3rd Mon Jan)
    h.add(_nth_weekday_of_month(year, 2, 0, 3))        # Washington's Birthday (3rd Mon Feb)
    h.add(_last_weekday_of_month(year, 5, 0))          # Memorial Day (last Mon May)
    h.add(_observe(date(year, 6, 19)))                 # Juneteenth (June 19)
    h.add(_observe(date(year, 7, 4)))                  # Independence Day (July 4)
    h.add(_nth_weekday_of_month(year, 9, 0, 1))        # Labor Day (1st Mon Sep)
    h.add(_nth_weekday_of_month(year, 10, 0, 2))       # Columbus Day (2nd Mon Oct)
    h.add(_observe(date(year, 11, 11)))                # Veterans Day (Nov 11)
    h.add(_nth_weekday_of_month(year, 11, 3, 4))       # Thanksgiving Day (4th Thu Nov)
    h.add(_observe(date(year, 12, 25)))                # Christmas Day (Dec 25)
    return h


def default_us_holidays(years: Optional[Union[int, Iterable[int]]] = None) -> frozenset:
    """
    Returns US federal holidays for the given years (iterable or single year).
    If omitted, defaults to surrounding 4 years of the current calendar year.
    """
    if years is None:
        cy = date.today().year
        years = range(cy - 1, cy + 3)
    elif isinstance(years, int):
        years = [years]
    try:
        import holidays as pyholidays
        return frozenset(pyholidays.country_holidays("US", years=years).keys())
    except ImportError:
        h = set()
        for y in years:
            h.update(get_us_federal_holidays(y))
        return frozenset(h)


def add_business_days(start: date, days: int, holidays: Optional[frozenset] = None) -> date:
    if holidays is None:
        # Dynamically anchor holiday calendar window to the start date
        holidays = default_us_holidays(range(start.year - 1, start.year + 2))
    d = start
    while days > 0:
        d += timedelta(days=1)
        if d.weekday() < 5 and d not in holidays:
            days -= 1
    return d


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


class IncidentMaterialityScreen:
    def __init__(self, facts: IncidentFacts, profile: EntityProfile,
                 assumptions: Optional[Assumptions] = None, holidays: Optional[frozenset] = None):
        self.f = facts
        self.p = profile
        self.a = assumptions or Assumptions()
        self._validate()
        if holidays is not None:
            self.holidays = frozenset(holidays)
        else:
            # Anchor holiday window to the determination date or incident facts, avoiding dependency on execution year
            ref_dt = self.f.determination_time or self.f.discovery_time or self.f.awareness_time
            anchor_year = ref_dt.year if ref_dt else date.today().year
            self.holidays = default_us_holidays(range(anchor_year - 1, anchor_year + 3))

    def _validate(self):
        for name in ("rev_impact_per_hour", "downtime_hours", "records_exposed"):
            if getattr(self.f, name) < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.p.annual_revenue <= 0:
            raise ValueError("annual_revenue must be positive")
        unknown = set(self.f.qualitative_factors) - set(SEC_QUALITATIVE_FACTORS)
        if unknown:
            raise ValueError(f"Unknown qualitative factors {sorted(unknown)}; allowed: {SEC_QUALITATIVE_FACTORS}")

        # Validate timezone awareness on all four datetime fields
        for dt_name in ("discovery_time", "awareness_time", "determination_time", "dora_classification_time"):
            dt_val = getattr(self.f, dt_name, None)
            if dt_val is not None:
                if not isinstance(dt_val, datetime):
                    raise TypeError(f"{dt_name} must be a datetime instance, got {type(dt_val).__name__}")
                if dt_val.tzinfo is None:
                    raise ValueError(f"{dt_name} must be timezone-aware (pass a tz-aware datetime)")

        # Validate that determination_time cannot precede discovery_time
        if self.f.discovery_time and self.f.determination_time:
            if self.f.determination_time < self.f.discovery_time:
                raise ValueError("determination_time cannot precede discovery_time")

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
                ny_date = f.determination_time.astimezone(ZoneInfo("America/New_York")).date()
                due = add_business_days(ny_date, 4, self.holidays).isoformat()

            sec_entry = {
                "regime": "SEC Form 8-K Item 1.05",
                "test": "Registrant determines the incident is MATERIAL (decision by registrant, not this tool).",
                "obligation": "File Item 1.05 8-K within four business days after the materiality determination.",
                "filing_due_date": due or "Clock starts at the determination: record the determination timestamp.",
                "also": "Determination must be made without unreasonable delay after discovery.",
            }

            if f.discovery_time:
                sec_entry["discovery_time"] = _iso(f.discovery_time)
                if f.determination_time:
                    delta = f.determination_time - f.discovery_time
                    days = delta.days
                    hours = delta.seconds // 3600
                    mins = (delta.seconds % 3600) // 60
                    sec_entry["discovery_to_determination_elapsed"] = f"{days}d {hours}h {mins}m"
                    sec_entry["discovery_to_determination_note"] = "Elapsed window recorded for legal counsel review against the SEC 'without unreasonable delay' standard."
                else:
                    sec_entry["discovery_to_determination_status"] = "Determination pending; evaluate without unreasonable delay with counsel."

            regimes.append(sec_entry)

        if p.is_dora_entity:
            entry = {"regime": "EU DORA major-incident reporting",
                     "test": "Classify under the DORA criteria (clients/transactions affected, duration, data loss, "
                             "geographic spread, criticality of services, economic impact). Independent of SEC materiality."}
            if p.dora_major_incident is None:
                entry["status"] = "CLASSIFICATION PENDING - classify now; if aware of a potential major incident the 24-hour outer limit is already running."
            elif p.dora_major_incident:
                entry["obligation"] = ("Initial notification within 4h of classification and no later than 24h after awareness of the incident; "
                                       "intermediate report within 72h of the initial notification; final report within one month "
                                       "after the latest intermediate report (RTS 2025/301 Art. 5).")
                if f.awareness_time:
                    outer = f.awareness_time + timedelta(hours=24)
                    inner = f.dora_classification_time + timedelta(hours=4) if f.dora_classification_time else None
                    if inner and f.dora_classification_time > outer:
                        initial_due = inner  # late classification: 24h cap no longer applies per RTS
                    else:
                        initial_due = min(outer, inner) if inner else outer
                    entry["initial_notification_due"] = _iso(initial_due)
                elif f.dora_classification_time:
                    entry["status_note"] = "awareness_time not recorded; unable to assess the 24-hour outer limit against the 4-hour post-classification deadline."
                else:
                    entry["status_note"] = "Record awareness_time to track the DORA initial notification deadline."
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
        discovery_time=now - timedelta(hours=14),
        awareness_time=now - timedelta(hours=14),
        determination_time=now,
    )
    profile = EntityProfile(annual_revenue=100_000_000, is_sec_registrant=True)
    print_report(IncidentMaterialityScreen(facts, profile).screen())
