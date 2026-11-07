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

from fair_engine import analyze_scenario, run_monte_carlo_fair, summarize
from vendor_evaluator import VendorRiskEvaluator
from materiality_calculator import IncidentMaterialityScreen, IncidentFacts, EntityProfile

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

def test_rejects_naive_datetime_on_all_fields():
    """Verifies that _validate() strictly rejects naive datetimes on all four datetime attributes."""
    for field_name in ("discovery_time", "awareness_time", "determination_time", "dora_classification_time"):
        kwargs = {
            "incident_name": "Naive Test",
            "rev_impact_per_hour": 100.0,
            "downtime_hours": 1.0,
            "records_exposed": 10
        }
        kwargs[field_name] = datetime(2026, 11, 6, 12, 0) # naive datetime!
        facts = IncidentFacts(**kwargs)
        profile = EntityProfile(annual_revenue=100_000_000.0, is_sec_registrant=True, is_dora_entity=True, is_nis2_entity=True)
        try:
            IncidentMaterialityScreen(facts, profile)
            assert False, f"Expected ValueError for naive datetime in {field_name}"
        except ValueError as e:
            assert "must be timezone-aware" in str(e)

def test_dora_late_classification():
    """Under EU DORA RTS, if classification occurs after 24h of awareness, initial notification is due within 4h of classification."""
    now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    awareness = now
    classification = now + timedelta(hours=30) # classified at 30h (> 24h outer limit)
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

if __name__ == '__main__':
    test_fair_engine_reproducibility()
    test_fair_portfolio_event_accumulation()
    test_fair_simulated_mean_matches_analytic_expectation()
    test_vendor_evaluator_tier_scaling()
    test_vendor_evaluator_finding_generation()
    test_sec_due_date_uses_eastern_time_and_holidays()
    test_sec_due_date_default_federal_holidays()
    test_rejects_naive_datetime_on_all_fields()
    test_dora_late_classification()
    print("All 9 portfolio unit tests passed successfully!")
