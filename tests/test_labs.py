import os
import sys
from datetime import date, datetime, timezone, timedelta
from zoneinfo import ZoneInfo
import numpy as np

try:
    import pytest
except ImportError:
    pytest = None

# Construct absolute paths relative to this test file so tests run from any directory
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "01-fair-risk-quantification-engine"))
sys.path.insert(0, os.path.join(REPO_ROOT, "03-third-party-risk-tprm-scoring"))
sys.path.insert(0, os.path.join(REPO_ROOT, "04-sec-dora-incident-disclosure"))

from fair_engine import analyze_scenario, run_monte_carlo_fair, summarize, _draw, main as fair_main
from vendor_evaluator import VendorRiskEvaluator
from materiality_calculator import IncidentMaterialityScreen, IncidentFacts, EntityProfile, get_us_federal_holidays

# -----------------------------------------------------------------------------
# Lab 1: FAIR Quantitative Risk Quantification Engine
# -----------------------------------------------------------------------------
def test_fair_engine_reproducibility():
    scenario = {
        "id": "TEST-01",
        "name": "Test Scenario",
        "asset": "Database",
        "threat_community": "Attackers",
        "threat_event_frequency_range": [1, 2, 3],
        "vulnerability_prob": 0.5,
        "primary_loss_range": [10000, 20000, 30000],
        "secondary_loss_prob": 0.2,
        "secondary_loss_range": [5000, 10000, 15000]
    }
    rng1 = np.random.default_rng(12345)
    rng2 = np.random.default_rng(12345)
    loss1, ev1 = run_monte_carlo_fair(scenario, 1000, rng1)
    loss2, ev2 = run_monte_carlo_fair(scenario, 1000, rng2)
    assert np.array_equal(loss1, loss2)
    assert np.array_equal(ev1, ev2)


def test_fair_portfolio_event_accumulation():
    sc1 = {
        "id": "SC-1", "name": "Scenario 1", "asset": "Server", "threat_community": "Threats",
        "threat_event_frequency_range": [2, 4, 6], "vulnerability_prob": 1.0,
        "primary_loss_range": [1000, 2000, 3000], "secondary_loss_prob": 0.0,
        "secondary_loss_range": [0, 0, 0]
    }
    rng = np.random.default_rng(42)
    res, losses, events = analyze_scenario(sc1, 1000, rng)
    assert len(events) == 1000
    assert np.mean(events) > 0.0
    summary = summarize(losses, events)
    assert summary["mean_loss_events"] > 0.0


def test_fair_simulated_mean_matches_analytic_expectation():
    """
    Validates that per-event sampling converges to compound Poisson analytic expectation:
      E[Loss] = E[Events] * (E[Primary] + P(Secondary) * E[Secondary])
    """
    scenario = {
        "id": "ANALYTIC-01",
        "name": "Analytic Convergence Test",
        "asset": "Server Cluster",
        "threat_community": "Threat Actors",
        "threat_event_frequency_range": [2, 4, 6],
        "vulnerability_prob": 0.5,
        "primary_loss_range": [10000, 20000, 30000],
        "secondary_loss_prob": 0.5,
        "secondary_loss_range": [10000, 20000, 30000]
    }
    rng = np.random.default_rng(42)
    losses, events = run_monte_carlo_fair(scenario, iterations=50_000, rng=rng)

    # Analytic expectation calculation:
    mean_tef = (2 + 4 * 4 + 6) / 6.0                  # 4.0
    mean_events = mean_tef * 0.5                       # 2.0
    mean_prim = (10000 + 4 * 20000 + 30000) / 6.0      # 20000.0
    mean_sec = (10000 + 4 * 20000 + 30000) / 6.0       # 20000.0
    mean_loss_per_event = mean_prim + 0.5 * mean_sec   # 30000.0
    expected_annual_loss = mean_events * mean_loss_per_event  # 60000.0

    simulated_mean = float(np.mean(losses))
    rel_err = abs(simulated_mean - expected_annual_loss) / expected_annual_loss
    assert rel_err < 0.02, f"Expected ~{expected_annual_loss}, got {simulated_mean} (rel_err {rel_err:.4f})"


def test_fair_variance_matches_compound_poisson():
    """
    Validates that per-event loss sampling matches compound Poisson variance:
      Var[Loss] = E[N] * E[X^2] = lambda * E[X^2]
    For fixed TEF rate 4 with vulnerability 0.5, N ~ Poisson(2).
    A buggy one-loss-draw-per-year implementation yields a variance ratio ~1.60;
    the correct independent per-event sampling yields a ratio ~1.00.
    """
    base_scenario = {
        "id": "VAR-01",
        "name": "Compound Poisson Variance Validation",
        "asset": "Core Infrastructure",
        "threat_community": "External Adversaries",
        "threat_event_frequency_range": [4, 4, 4],
        "vulnerability_prob": 0.5,
        "primary_loss_range": [1000, 5000, 50000],
        "secondary_loss_prob": 0.0,
        "secondary_loss_range": [0, 0, 0]
    }
    loss, _ = run_monte_carlo_fair(base_scenario, 200_000, np.random.default_rng(1))
    x = _draw(np.random.default_rng(2), (1000, 5000, 50000), 1_000_000)
    expected_var = 2.0 * float(np.mean(x**2))
    simulated_var = float(loss.var())
    ratio = simulated_var / expected_var
    assert abs(ratio - 1.0) < 0.05, f"Expected variance ratio ~1.0, got {ratio:.4f}"


def test_fair_main_cli_smoke():
    """
    Smoke tests fair_engine.py CLI execution across the full scenarios portfolio.
    Ensures argument parsing, scenario loading, child RNG seeding, and report generation succeed.
    """
    scenarios_path = os.path.join(REPO_ROOT, "01-fair-risk-quantification-engine", "scenarios.json")
    ret = fair_main(["--scenarios", scenarios_path, "--iterations", "1000", "--seed", "1"])
    assert ret == 0


# -----------------------------------------------------------------------------
# Lab 3: Third-Party Risk Management (TPRM) Scoring Engine
# -----------------------------------------------------------------------------
def test_vendor_evaluator_tier_scaling():
    t1_vendor = {
        "vendor_name": "CloudCo", "vendor_id": "V-1", "business_owner": "CTO",
        "data_access": {"has_pii": True},
        "security_controls": {
            "soc2_type_2_current": True,
            "phishing_resistant_mfa_enforced": True,
            "vendor_breach_notification_hours": 24,
            "enforces_saml_sso": True
        }
    }
    evaluator = VendorRiskEvaluator(t1_vendor)
    assert evaluator.calculate_tier() == "Tier 1 (Critical Enterprise Risk)"
    findings = evaluator.audit_security_controls()
    assert len(findings) == 0


def test_vendor_evaluator_finding_generation():
    noncompliant_vendor = {
        "vendor_name": "InsecureVendor", "vendor_id": "V-2", "business_owner": "VP Sales",
        "data_access": {"has_pii": True},
        "security_controls": {
            "soc2_type_2_current": False,
            "phishing_resistant_mfa_enforced": False,
            "vendor_breach_notification_hours": 96,
            "enforces_saml_sso": False
        }
    }
    evaluator = VendorRiskEvaluator(noncompliant_vendor)
    findings = evaluator.audit_security_controls()
    assert len(findings) == 4
    dossier = evaluator.generate_procurement_dossier()
    assert dossier["procurement_status"] == "REJECTED - REMEDIATE BEFORE PROCUREMENT"


def test_vendor_soc2_recency_boundaries():
    """
    Tests exact boundary conditions for date-calculated SOC 2 recency:
      - 364 days ago: compliant across tiers
      - 365 days ago: compliant at 12-month boundary
      - 366 days ago: non-compliant (assurance expired > 365 days)
      - Verifies tier-scaled finding severity:
          Tier 1 -> CRITICAL
          Tier 2 -> HIGH
          Tier 3 -> MEDIUM
    """
    as_of = date(2026, 6, 1)

    def make_vendor(tier_number, period_end_date):
        data_access = {}
        if tier_number == 1:
            data_access = {"has_pii": True}
        elif tier_number == 2:
            data_access = {"has_internal_docs": True}
        elif tier_number == 3:
            data_access = {"employee_email_access": True}
        return {
            "vendor_name": f"CloudSaaS-T{tier_number}",
            "vendor_id": f"V-RECENCY-T{tier_number}",
            "business_owner": "CISO",
            "data_access": data_access,
            "security_controls": {
                "soc2_report_period_end": period_end_date.isoformat(),
                "phishing_resistant_mfa_enforced": True,
                "vendor_breach_notification_hours": 24,
                "enforces_saml_sso": True
            }
        }

    # 364 days ago: within 12 months -> compliant
    v1_364 = make_vendor(1, as_of - timedelta(days=364))
    eval_364 = VendorRiskEvaluator(v1_364, as_of=as_of)
    assert len(eval_364.audit_security_controls()) == 0

    # 365 days ago: exactly on 365-day boundary -> compliant
    v1_365 = make_vendor(1, as_of - timedelta(days=365))
    eval_365 = VendorRiskEvaluator(v1_365, as_of=as_of)
    assert len(eval_365.audit_security_controls()) == 0

    # 366 days ago: expired (> 365 days) -> tier-scaled severity
    # Tier 1 -> CRITICAL
    v1_366 = make_vendor(1, as_of - timedelta(days=366))
    f1 = VendorRiskEvaluator(v1_366, as_of=as_of).audit_security_controls()
    assert len(f1) == 1
    assert f1[0]["severity"] == "CRITICAL"
    assert "outside 12 months" in f1[0]["finding"]

    # Tier 2 -> HIGH
    v2_366 = make_vendor(2, as_of - timedelta(days=366))
    f2 = VendorRiskEvaluator(v2_366, as_of=as_of).audit_security_controls()
    assert len(f2) == 1
    assert f2[0]["severity"] == "HIGH"

    # Tier 3 -> MEDIUM
    v3_366 = make_vendor(3, as_of - timedelta(days=366))
    f3 = VendorRiskEvaluator(v3_366, as_of=as_of).audit_security_controls()
    assert len(f3) == 1
    assert f3[0]["severity"] == "MEDIUM"


# -----------------------------------------------------------------------------
# Lab 4: SEC & DORA Regulatory Incident Materiality Screening Aid
# -----------------------------------------------------------------------------
def test_sec_due_date_uses_eastern_time_and_holidays():
    """
    Thu 9 PM ET = Fri 2 AM UTC.
    In ET (Nov 5) with Veterans Day (Nov 11) skipped:
      Fri Nov 6 (1), Mon Nov 9 (2), Tue Nov 10 (3), Wed Nov 11 (HOLIDAY), Thu Nov 12 (4).
    A UTC-based calculation starts Fri Nov 6 and yields Fri Nov 13.
    """
    ET = ZoneInfo("America/New_York")
    det = datetime(2026, 11, 5, 21, 0, tzinfo=ET)
    vets_day = frozenset({date(2026, 11, 11)})
    facts = IncidentFacts(
        incident_name="SEC Eastern Time & Holiday Test",
        rev_impact_per_hour=1000.0,
        downtime_hours=1.0,
        records_exposed=10,
        determination_time=det
    )
    profile = EntityProfile(annual_revenue=100_000_000.0, is_sec_registrant=True)
    screen = IncidentMaterialityScreen(facts, profile, holidays=vets_day).screen()
    sec = next(r for r in screen["regulatory_regimes"] if "SEC" in r["regime"])
    assert sec["filing_due_date"] == "2026-11-12"


def test_sec_due_date_default_federal_holidays():
    """Validates that default holiday calendar automatically includes US Federal holidays (e.g. Veterans Day)."""
    ET = ZoneInfo("America/New_York")
    det = datetime(2026, 11, 5, 21, 0, tzinfo=ET)
    facts = IncidentFacts(
        incident_name="SEC Default Holiday Test",
        rev_impact_per_hour=1000.0,
        downtime_hours=1.0,
        records_exposed=10,
        determination_time=det
    )
    profile = EntityProfile(annual_revenue=100_000_000.0, is_sec_registrant=True)
    screen = IncidentMaterialityScreen(facts, profile).screen()
    sec = next(r for r in screen["regulatory_regimes"] if "SEC" in r["regime"])
    assert sec["filing_due_date"] == "2026-11-12"


def test_sec_discovery_to_determination_reporting_and_validation():
    """
    Verifies that discovery_time is tracked, validated, and reported:
      - When discovery_time and determination_time are both provided, elapsed time is reported for counsel review.
      - When only discovery_time is provided, 'Determination pending; evaluate without unreasonable delay with counsel' is reported.
      - If determination_time precedes discovery_time, ValueError is raised.
    """
    ET = ZoneInfo("America/New_York")
    disc = datetime(2026, 11, 1, 9, 0, tzinfo=ET)
    det = datetime(2026, 11, 3, 14, 30, tzinfo=ET)

    facts = IncidentFacts(
        incident_name="Discovery-to-Determination Window Test",
        rev_impact_per_hour=100.0,
        downtime_hours=1.0,
        records_exposed=10,
        discovery_time=disc,
        determination_time=det
    )
    profile = EntityProfile(annual_revenue=10_000_000.0, is_sec_registrant=True)
    screen = IncidentMaterialityScreen(facts, profile).screen()
    sec = next(r for r in screen["regulatory_regimes"] if "SEC" in r["regime"])
    assert sec["discovery_to_determination_elapsed"] == "2d 5h 30m"
    assert "counsel review" in sec["discovery_to_determination_note"].lower()

    # Only discovery_time provided
    facts_pending = IncidentFacts(
        incident_name="Discovery Pending Test",
        rev_impact_per_hour=100.0,
        downtime_hours=1.0,
        records_exposed=10,
        discovery_time=disc
    )
    screen_pending = IncidentMaterialityScreen(facts_pending, profile).screen()
    sec_pending = next(r for r in screen_pending["regulatory_regimes"] if "SEC" in r["regime"])
    assert "pending" in sec_pending["discovery_to_determination_status"].lower()

    # Determination preceding discovery raises ValueError
    facts_invalid = IncidentFacts(
        incident_name="Invalid Time Order",
        rev_impact_per_hour=100.0,
        downtime_hours=1.0,
        records_exposed=10,
        discovery_time=det,
        determination_time=disc
    )
    try:
        IncidentMaterialityScreen(facts_invalid, profile)
        assert False, "Expected ValueError when determination_time precedes discovery_time"
    except ValueError as e:
        assert "cannot precede discovery_time" in str(e)


def test_fallback_us_federal_holidays_2026_and_2027():
    """
    Directly exercises get_us_federal_holidays() independently of the `holidays` package.
    Asserts:
      - 2026 matches the expected federal holiday set (including observed Friday July 3 and actual July 4).
      - 2027 correctly includes Dec 31, 2027 (observed for New Year's Day Jan 1, 2028).
      - 2028 does NOT duplicate Dec 31, 2027 (which strictly belongs to the 2027 calendar year).
      - All dates strictly fall within their respective calendar years.
    """
    h_2026 = get_us_federal_holidays(2026)
    assert date(2026, 1, 1) in h_2026
    assert date(2026, 7, 3) in h_2026   # July 4 is Sat -> observed Fri July 3
    assert date(2026, 7, 4) in h_2026   # Actual calendar date
    assert date(2026, 11, 11) in h_2026 # Veterans Day
    assert date(2026, 12, 25) in h_2026 # Christmas Day
    assert all(d.year == 2026 for d in h_2026)

    h_2027 = get_us_federal_holidays(2027)
    assert date(2027, 12, 31) in h_2027  # Jan 1, 2028 is Sat -> observed Fri Dec 31, 2027
    assert all(d.year == 2027 for d in h_2027)

    h_2028 = get_us_federal_holidays(2028)
    assert date(2027, 12, 31) not in h_2028  # Dec 31, 2027 belongs strictly to 2027 set
    assert all(d.year == 2028 for d in h_2028)


def test_holiday_library_cross_check_2026_to_2028():
    """
    Cross-checks the built-in fallback calendar against the `holidays` PyPI package
    for calendar years 2026, 2027, and 2028.
    Ensures identical set membership across both implementations.
    """
    try:
        import holidays as pyholidays
    except ImportError:
        if pytest:
            pytest.skip("holidays library not installed; skipping cross-check")
        return

    for year in (2026, 2027, 2028):
        fallback = get_us_federal_holidays(year)
        lib = set(pyholidays.country_holidays("US", years=year).keys())
        assert fallback == lib, f"Mismatch in {year}: fallback={fallback - lib}, lib={lib - fallback}"


def test_rejects_naive_datetime_on_all_fields():
    """Verifies that _validate() strictly rejects naive datetimes on all four datetime attributes."""
    for field_name in ("discovery_time", "awareness_time", "determination_time", "dora_classification_time"):
        kwargs = {
            "incident_name": "Naive Test",
            "rev_impact_per_hour": 100.0,
            "downtime_hours": 1.0,
            "records_exposed": 10
        }
        kwargs[field_name] = datetime(2026, 11, 6, 12, 0)  # naive datetime!
        facts = IncidentFacts(**kwargs)
        profile = EntityProfile(annual_revenue=100_000_000.0, is_sec_registrant=True, is_dora_entity=True, is_nis2_entity=True)
        try:
            IncidentMaterialityScreen(facts, profile)
            assert False, f"Expected ValueError for naive datetime in {field_name}"
        except ValueError as e:
            assert "must be timezone-aware" in str(e)


def test_dora_classification_within_24h_normal_and_capped_paths():
    """
    Tests EU DORA major incident initial notification deadlines within the 24h awareness window:
      - Path 1: Classified at +2h -> initial notification due within 4h of classification (+6h from awareness).
      - Path 2: Classified at +22h -> 4h from classification would be +26h, but is capped by the 24h outer limit.
    """
    now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    profile = EntityProfile(annual_revenue=50_000_000.0, is_dora_entity=True, dora_major_incident=True)

    # Path 1: Classified 2h after awareness -> due at +6h
    f1 = IncidentFacts(
        incident_name="DORA Normal +2h",
        rev_impact_per_hour=1000.0, downtime_hours=1.0, records_exposed=50,
        awareness_time=now,
        dora_classification_time=now + timedelta(hours=2)
    )
    s1 = IncidentMaterialityScreen(f1, profile).screen()
    dora1 = next(r for r in s1["regulatory_regimes"] if "DORA" in r["regime"])
    expected_due_1 = (now + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert dora1["initial_notification_due"] == expected_due_1

    # Path 2: Classified 22h after awareness -> 22h + 4h = 26h, capped at 24h outer limit
    f2 = IncidentFacts(
        incident_name="DORA Capped +22h",
        rev_impact_per_hour=1000.0, downtime_hours=1.0, records_exposed=50,
        awareness_time=now,
        dora_classification_time=now + timedelta(hours=22)
    )
    s2 = IncidentMaterialityScreen(f2, profile).screen()
    dora2 = next(r for r in s2["regulatory_regimes"] if "DORA" in r["regime"])
    expected_due_2 = (now + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert dora2["initial_notification_due"] == expected_due_2


def test_dora_late_classification():
    """Under EU DORA RTS, if classification occurs after 24h of awareness, initial notification is due within 4h of classification."""
    now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    awareness = now
    classification = now + timedelta(hours=30)  # classified at 30h (> 24h outer limit)
    facts = IncidentFacts(
        incident_name="DORA Incident Test",
        rev_impact_per_hour=5000.0,
        downtime_hours=4.0,
        records_exposed=1000,
        awareness_time=awareness,
        dora_classification_time=classification
    )
    profile = EntityProfile(annual_revenue=100_000_000.0, is_dora_entity=True, dora_major_incident=True)
    assessment = IncidentMaterialityScreen(facts, profile)
    screen = assessment.screen()
    dora_regime = [r for r in screen["regulatory_regimes"] if "DORA" in r["regime"]][0]
    expected_due = (classification + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert dora_regime["initial_notification_due"] == expected_due


def test_dora_classification_without_awareness_status_note():
    """
    Verifies that when dora_classification_time is provided without awareness_time,
    a status_note is reported rather than silently omitting due dates.
    """
    now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    facts = IncidentFacts(
        incident_name="DORA Classification Without Awareness",
        rev_impact_per_hour=1000.0,
        downtime_hours=1.0,
        records_exposed=100,
        dora_classification_time=now
    )
    profile = EntityProfile(annual_revenue=10_000_000.0, is_dora_entity=True, dora_major_incident=True)
    screen = IncidentMaterialityScreen(facts, profile).screen()
    dora = next(r for r in screen["regulatory_regimes"] if "DORA" in r["regime"])
    assert "status_note" in dora
    assert "awareness_time not recorded" in dora["status_note"]


if __name__ == '__main__':
    test_fair_engine_reproducibility()
    test_fair_portfolio_event_accumulation()
    test_fair_simulated_mean_matches_analytic_expectation()
    test_fair_variance_matches_compound_poisson()
    test_fair_main_cli_smoke()
    test_vendor_evaluator_tier_scaling()
    test_vendor_evaluator_finding_generation()
    test_vendor_soc2_recency_boundaries()
    test_sec_due_date_uses_eastern_time_and_holidays()
    test_sec_due_date_default_federal_holidays()
    test_sec_discovery_to_determination_reporting_and_validation()
    test_fallback_us_federal_holidays_2026_and_2027()
    test_holiday_library_cross_check_2026_to_2028()
    test_rejects_naive_datetime_on_all_fields()
    test_dora_classification_within_24h_normal_and_capped_paths()
    test_dora_late_classification()
    test_dora_classification_without_awareness_status_note()
    print("All 17 portfolio unit tests passed successfully!")
