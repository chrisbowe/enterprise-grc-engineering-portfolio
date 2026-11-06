#!/usr/bin/env bash
# Runs the Rego policy against the fixtures. Requires the `opa` CLI (0.59+ or 1.x).
set -euo pipefail
cd "$(dirname "$0")"
POLICY="nist_csf_cis_controls.rego"

opa check --strict "$POLICY"

check() {  # <fixture> <expected allow> <expected deny count>
  local f="test-fixtures/$1" allow count
  allow=$(opa eval -f raw -i "$f" -d "$POLICY" 'data.terraform.compliance.allow')
  count=$(opa eval -f raw -i "$f" -d "$POLICY" 'count(data.terraform.compliance.deny)')
  if [[ "$allow" == "$2" && "$count" == "$3" ]]; then
    echo "PASS  $1  (allow=$allow, denies=$count)"
  else
    echo "FAIL  $1  expected allow=$2 denies=$3, got allow=$allow denies=$count"
    opa eval -f pretty -i "$f" -d "$POLICY" 'data.terraform.compliance.deny'
    exit 1
  fi
}

check plan_compliant.json    true  0
check plan_noncompliant.json false 5
check plan_malformed.json    false 1
echo "All policy fixtures behaved as expected."
