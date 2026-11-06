#!/usr/bin/env bash
# Runs the Rego policy against test plan fixtures. Requires the `opa` CLI (0.59+ or 1.x).
set -euo pipefail
cd "$(dirname "$0")"

POLICY="policies/nist_csf_cis_controls.rego"
if [ ! -f "$POLICY" ]; then
  POLICY="nist_csf_cis_controls.rego"
fi

opa check --strict "$POLICY"

check() {
  local fixture="$1"
  local expected_allow="$2"
  local expected_denies="$3"
  local f="test-fixtures/$fixture"
  if [ ! -f "$f" ]; then
    f="$fixture"
  fi

  local allow count
  allow=$(opa eval -f raw -i "$f" -d "$POLICY" 'data.terraform.compliance.allow')
  count=$(opa eval -f raw -i "$f" -d "$POLICY" 'count(data.terraform.compliance.deny)')
  if [[ "$allow" == "$expected_allow" && "$count" == "$expected_denies" ]]; then
    echo "PASS  $fixture  (allow=$allow, denies=$count)"
  else
    echo "FAIL  $fixture  expected allow=$expected_allow denies=$expected_denies, got allow=$allow denies=$count"
    opa eval -f pretty -i "$f" -d "$POLICY" 'data.terraform.compliance.deny'
    exit 1
  fi
}

check plan_compliant.json    true  0
check plan_noncompliant.json false 5
check plan_malformed.json    false 1
echo "All policy fixtures behaved as expected."
