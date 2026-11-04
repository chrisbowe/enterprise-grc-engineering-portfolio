#!/usr/bin/env python3
"""
FAIR™ (Factor Analysis of Information Risk) Quantitative Risk Modeling Engine
Simulates annualized financial loss using Monte Carlo methods across defined threat scenarios.
"""

import json
import os
import sys
import numpy as np

def run_monte_carlo_fair(scenario, iterations=10000):
    """
    Simulates Loss Event Frequency (LEF) and Loss Magnitude (LM)
    to calculate Annualized Loss Expectancy (ALE).
    """
    tef_min, tef_mode, tef_max = scenario["threat_event_frequency_range"]
    tef_samples = np.random.triangular(tef_min, tef_mode, tef_max, iterations)
    vuln_rate = scenario["vulnerability_prob"]

    # Calculate successful threat events that become loss events
    lef_events = np.random.binomial(np.round(tef_samples).astype(int), vuln_rate)

    # Primary Loss (direct response, forensic investigation, downtime)
    p_min, p_mode, p_max = scenario["primary_loss_range"]
    primary_loss = np.random.triangular(p_min, p_mode, p_max, iterations)

    # Secondary Loss (litigation, regulatory fines, customer churn)
    sec_prob = scenario["secondary_loss_prob"]
    s_min, s_mode, s_max = scenario["secondary_loss_range"]
    secondary_loss = np.random.triangular(s_min, s_mode, s_max, iterations) * np.random.binomial(1, sec_prob, iterations)

    total_loss_per_event = primary_loss + secondary_loss
    annual_loss = lef_events * total_loss_per_event

    return annual_loss

def analyze_scenario(scenario, iterations=10000):
    losses = run_monte_carlo_fair(scenario, iterations)

    ale_mean = float(np.mean(losses))
    ale_p10 = float(np.percentile(losses, 10))
    ale_p50 = float(np.percentile(losses, 50))
    ale_p90 = float(np.percentile(losses, 90))
    ale_max = float(np.max(losses))

    return {
        "id": scenario["id"],
        "name": scenario["name"],
        "asset": scenario["asset"],
        "threat_community": scenario["threat_community"],
        "simulations": iterations,
        "ale_mean": round(ale_mean, 2),
        "ale_p10_optimistic": round(ale_p10, 2),
        "ale_p50_median": round(ale_p50, 2),
        "ale_p90_worst_case": round(ale_p90, 2),
        "ale_max_observed": round(ale_max, 2)
    }

def print_executive_report(results):
    print("\n" + "=" * 80)
    print("  EXECUTIVE BOARD CYBER RISK QUANTIFICATION REPORT (FAIR™)")
    print("=" * 80)

    total_mean_ale = 0.0
    for res in results:
        total_mean_ale += res["ale_mean"]
        print(f"\nScenario ID: {res['id']}")
        print(f"Description: {res['name']}")
        print(f"Asset Impacted: {res['asset']}")
        print(f"Threat Actor: {res['threat_community']}")
        print("-" * 80)
        print(f"  Expected Annual Loss (Mean ALE):    ${res['ale_mean']:>12,.2f}")
        print(f"  10th Percentile (Low Exposure):     ${res['ale_p10_optimistic']:>12,.2f}")
        print(f"  50th Percentile (Median Exposure):  ${res['ale_p50_median']:>12,.2f}")
        print(f"  90th Percentile (High Exposure):    ${res['ale_p90_worst_case']:>12,.2f}")
        print(f"  Max Simulated Tail Event:           ${res['ale_max_observed']:>12,.2f}")

    print("\n" + "=" * 80)
    print(f"AGGREGATE ENTERPRISE PORTFOLIO LOSS EXPECTANCY (MEAN ALE): ${total_mean_ale:,.2f}")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scenarios_path = os.path.join(script_dir, "scenarios.json")

    if not os.path.exists(scenarios_path):
        print(f"Error: Scenarios file not found at {scenarios_path}", file=sys.stderr)
        sys.exit(1)

    with open(scenarios_path, "r", encoding="utf-8-sig") as f:
        scenarios = json.load(f)

    all_results = [analyze_scenario(sc) for sc in scenarios]
    print_executive_report(all_results)
