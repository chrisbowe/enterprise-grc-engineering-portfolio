import os
import sys
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
import numpy as np

try:
    import pytest
except ImportError:
    pytest = None

sys.path.insert(0, os.path.abspath('01-fair-risk-quantification-engine'))
sys.path.insert(0, os.path.abspath('03-third-party-risk-tprm-scoring'))
sys.path.insert(0, os.path.abspath('04-sec-dora-incident-disclosure'))

from fair_engine import analyze_scenario, run_monte_carlo_fair, summarize
from vendor_evaluator import VendorRiskEvaluator
from materiality_calculator import IncidentMaterialityScreen, IncidentFacts, EntityProfile

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

def test_sec_due_date_eastern_time():
    ET = ZoneInfo("America/New_York")
    det_time = datetime(2026, 11, 6, 21, 0, tzinfo=ET) # Friday 9 PM ET
    facts = IncidentFacts(
        incident_name="SEC Disclosure Test",
        rev_impact_per_hour=5000.0,
        downtime_hours=4.0,
        records_exposed=1000,
        determination_time=det_time
    )
    profile = EntityProfile(annual_revenue=100_000_000.0, is_sec_registrant=True)
    assessment = IncidentMaterialityScreen(facts, profile)
    screen = assessment.screen()
    sec_regime = [r for r in screen["regulatory_regimes"] if "SEC" in r["regime"]][0]
    # 4 business days from Friday Nov 6 is Thursday Nov 12
    assert sec_regime["filing_due_date"] == "2026-11-12"

def test_sec_rejects_naive_datetime():
    det_time_naive = datetime(2026, 11, 6, 21, 0) # naive
    facts = IncidentFacts(
        incident_name="Naive Test",
        rev_impact_per_hour=100.0,
        downtime_hours=1.0,
        records_exposed=10,
        determination_time=det_time_naive
    )
    profile = EntityProfile(annual_revenue=100_000_000.0, is_sec_registrant=True)
    assessment = IncidentMaterialityScreen(facts, profile)
    try:
        assessment.screen()
        assert False, "Should have raised ValueError on naive datetime"
    except ValueError as e:
        assert "must be timezone-aware" in str(e)

def test_dora_late_classification():
    now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    awareness = now
    classification = now + timedelta(hours=30) # classified at 30h (> 24h outer)
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
    test_vendor_evaluator_tier_scaling()
    test_vendor_evaluator_finding_generation()
    test_sec_due_date_eastern_time()
    test_sec_rejects_naive_datetime()
    test_dora_late_classification()
    print("All 7 portfolio unit tests passed successfully!")
