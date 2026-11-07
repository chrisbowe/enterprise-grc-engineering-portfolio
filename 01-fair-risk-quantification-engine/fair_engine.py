#!/usr/bin/env python3
"""
FAIR(TM)-style Monte Carlo risk engine.

Model, per simulated year
-------------------------
  TEF   ~ PERT(min, mode, max)        threat events per YEAR (a rate)
  Vuln  = constant p, or PERT range   P(threat event becomes a loss event)
  N     ~ Poisson(TEF * Vuln)         loss events in the year (Poisson thinning)
  For each of the N events, independently:
      primary loss   ~ PERT(...)
      secondary loss occurs with probability `secondary_loss_prob` (SLEF),
                     magnitude ~ PERT(...)
  Annual loss = sum of the N independent per-event losses.

Scenario JSON Schema (list of objects):
  id, name, asset, threat_community
  threat_event_frequency_range : [min, mode, max]   events / year
  vulnerability_prob           : 0..1  OR  [min, mode, max] within 0..1  (optional range)
  primary_loss_range           : [min, mode, max]   USD per event
  secondary_loss_prob          : 0..1
  secondary_loss_range         : [min, mode, max]   USD per event
  distribution                 : "pert" (default) | "triangular"          (optional)

Notes
-----
* Open FAIR calls the output "annualized loss exposure"; the ALE label is kept
  for familiarity.
* Portfolio percentiles assume scenarios are statistically independent.
* Percentiles are the decision-useful numbers; the mean is dominated by the tail.
"""

import argparse
import json
import os
import sys

import numpy as np

REQUIRED_KEYS = (
    "id", "name", "asset", "threat_community",
    "threat_event_frequency_range", "vulnerability_prob",
    "primary_loss_range", "secondary_loss_prob", "secondary_loss_range",
)


# ----------------------------------------------------------------------------
# Validation and sampling helpers
# ----------------------------------------------------------------------------
def _check_range(name, values, upper=None):
    if not isinstance(values, (list, tuple)) or len(values) != 3:
        raise ValueError(f"{name} must be [min, mode, max]")
    lo, mode, hi = (float(v) for v in values)
    if not lo <= mode <= hi:
        raise ValueError(f"{name} must satisfy min <= mode <= max, got {values}")
    if lo < 0:
        raise ValueError(f"{name} must be non-negative, got {values}")
    if upper is not None and hi > upper:
        raise ValueError(f"{name} must be <= {upper}, got {values}")
    return lo, mode, hi


def _check_prob(name, value):
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1, got {value}")
    return value


def _draw(rng, spec, size, distribution="pert"):
    """Draw `size` samples from PERT (default) or triangular(min, mode, max)."""
    lo, mode, hi = spec
    if hi == lo:
        return np.full(size, lo)
    if distribution == "triangular":
        return rng.triangular(lo, mode, hi, size)
    span = hi - lo
    a = 1.0 + 4.0 * (mode - lo) / span
    b = 1.0 + 4.0 * (hi - mode) / span
    return lo + span * rng.beta(a, b, size)


# ----------------------------------------------------------------------------
# Simulation
# ----------------------------------------------------------------------------
def run_monte_carlo_fair(scenario, iterations=100_000, rng=None):
    """
    Returns (annual_loss, loss_event_counts): two arrays of length `iterations`.
    """
    missing = [k for k in REQUIRED_KEYS if k not in scenario]
    if missing:
        raise ValueError(f"Scenario {scenario.get('id', '?')} is missing keys: {missing}")
    if rng is None:
        rng = np.random.default_rng()

    dist = scenario.get("distribution", "pert")
    if dist not in ("pert", "triangular"):
        raise ValueError(f"distribution must be 'pert' or 'triangular', got {dist!r}")

    tef_range = _check_range("threat_event_frequency_range", scenario["threat_event_frequency_range"])
    primary_range = _check_range("primary_loss_range", scenario["primary_loss_range"])
    secondary_range = _check_range("secondary_loss_range", scenario["secondary_loss_range"])
    sec_prob = _check_prob("secondary_loss_prob", scenario["secondary_loss_prob"])

    # Vulnerability: a point estimate or an uncertain range.
    v = scenario["vulnerability_prob"]
    if isinstance(v, (list, tuple)):
        vuln = np.clip(_draw(rng, _check_range("vulnerability_prob", v, upper=1.0), iterations, dist), 0.0, 1.0)
    else:
        vuln = np.full(iterations, _check_prob("vulnerability_prob", v))

    # Loss events per year: Poisson(TEF * Vuln). TEF is a rate, so counts are
    # random even for a fixed TEF; rounding the rate removed that.
    tef = _draw(rng, tef_range, iterations, dist)
    events = rng.poisson(tef * vuln)

    # Every individual event gets its OWN independent loss draw.
    idx = np.repeat(np.arange(iterations), events)
    k = idx.size
    primary = _draw(rng, primary_range, k, dist)
    secondary = np.where(rng.random(k) < sec_prob, _draw(rng, secondary_range, k, dist), 0.0)

    annual_loss = np.bincount(idx, weights=primary + secondary, minlength=iterations)
    return annual_loss, events


def summarize(losses, events):
    return {
        "ale_mean": float(np.mean(losses)),
        "ale_p10": float(np.percentile(losses, 10)),
        "ale_p50": float(np.percentile(losses, 50)),
        "ale_p90": float(np.percentile(losses, 90)),
        "ale_p99": float(np.percentile(losses, 99)),
        "prob_any_loss": float(np.mean(losses > 0)),
        "mean_loss_events": float(np.mean(events)),
    }


def analyze_scenario(scenario, iterations=100_000, rng=None):
    losses, events = run_monte_carlo_fair(scenario, iterations, rng)
    result = {
        "id": scenario["id"],
        "name": scenario["name"],
        "asset": scenario["asset"],
        "threat_community": scenario["threat_community"],
        "simulations": iterations,
    }
    result.update({k: round(v, 4 if k.startswith("prob") or k.startswith("mean_") else 2)
                   for k, v in summarize(losses, events).items()})
    return result, losses, events


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def print_executive_report(results, portfolio, seed):
    print("\n" + "=" * 80)
    print("  EXECUTIVE BOARD CYBER RISK QUANTIFICATION REPORT (FAIR-style Monte Carlo)")
    print("=" * 80)
    print(f"  Random seed: {seed}  (re-run with --seed {seed} to reproduce)")

    for res in results:
        print(f"\nScenario ID: {res['id']}")
        print(f"Description: {res['name']}")
        print(f"Asset Impacted: {res['asset']}")
        print(f"Threat Actor: {res['threat_community']}")
        print("-" * 80)
        print(f"  Mean annual loss:                    ${res['ale_mean']:>14,.2f}")
        print(f"  P10 (90% of years are at/above):     ${res['ale_p10']:>14,.2f}")
        print(f"  P50 (median year):                   ${res['ale_p50']:>14,.2f}")
        print(f"  P90 (1-in-10-year loss):             ${res['ale_p90']:>14,.2f}")
        print(f"  P99 (1-in-100-year loss):            ${res['ale_p99']:>14,.2f}")
        print(f"  Probability of any loss in a year:    {res['prob_any_loss']:>14.1%}")
        print(f"  Mean loss events per year:            {res['mean_loss_events']:>14.2f}")

    print("\n" + "=" * 80)
    print("PORTFOLIO (sum of scenarios, assumes independence)")
    print(f"  Mean annual loss: ${portfolio['ale_mean']:,.2f}")
    print(f"  P10 / P50 / P90 / P99: ${portfolio['ale_p10']:,.0f} / ${portfolio['ale_p50']:,.0f} / "
          f"${portfolio['ale_p90']:,.0f} / ${portfolio['ale_p99']:,.0f}")
    print("=" * 80 + "\n")


def main(argv=None):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--scenarios", default=os.path.join(script_dir, "scenarios.json"))
    parser.add_argument("--iterations", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=None, help="RNG seed (random if omitted, always printed)")
    args = parser.parse_args(argv)

    if not os.path.exists(args.scenarios):
        print(f"Error: Scenarios file not found at {args.scenarios}", file=sys.stderr)
        return 1
    with open(args.scenarios, "r", encoding="utf-8-sig") as f:
        scenarios = json.load(f)

    seed = args.seed if args.seed is not None else int(np.random.SeedSequence().entropy % (2**32))
    child_seeds = np.random.SeedSequence(seed).spawn(len(scenarios))

    results, all_losses, all_events = [], [], []
    for sc, cs in zip(scenarios, child_seeds):
        res, losses, events = analyze_scenario(sc, args.iterations, np.random.default_rng(cs))
        results.append(res)
        all_losses.append(losses)
        all_events.append(events)

    portfolio_losses = np.sum(all_losses, axis=0)
    portfolio_events = np.sum(all_events, axis=0)
    portfolio = summarize(portfolio_losses, portfolio_events)
    print_executive_report(results, portfolio, seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
