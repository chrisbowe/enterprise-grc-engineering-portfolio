package terraform.compliance

# Terraform plan compliance gate.
#   terraform plan -out=tfplan && terraform show -json tfplan > plan.json
#   opa eval -f pretty -i plan.json -d nist_csf_cis_controls.rego "data.terraform.compliance"
#
# Works on OPA 0.59+ and 1.x (`import rego.v1`).
# Control IDs: CIS Controls v8 and NIST CSF 2.0 (PR.AA / PR.DS / PR.IR).
# Verify mappings against the official CIS and NIST documents before publishing.
#
# Known limitations (by design, documented rather than hidden):
#   * Resources inside child modules are evaluated, but the S3 encryption
#     cross-reference only searches the ROOT module configuration, so a bucket in a
#     child module whose encryption resource lives in that module is flagged
#     (fails closed). Extend `bucket_has_encryption` if you rely on modules.
#   * IAM: only full-admin ("*" action on "*" resource) is checked. Service-level
#     wildcards ("iam:*"), NotAction, and managed-policy attachments are not.

import rego.v1

default allow := false

allow if count(deny) == 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Resources that will exist after apply. Deleted resources have change.after == null
# and must not be evaluated .
live_resources contains r if {
	some r in input.resource_changes
	r.mode == "managed"
	r.change.after != null
}

to_list(x) := x if is_array(x)

to_list(x) := [x] if not is_array(x)

# ---------------------------------------------------------------------------
# Fail closed on malformed input 
# ---------------------------------------------------------------------------
deny contains msg if {
	not input.format_version
	msg := "[PLAN] Input is not Terraform plan JSON (missing format_version); refusing to approve."
}

# ---------------------------------------------------------------------------
# S3 encryption at rest
# CIS v8 3.11 | NIST CSF 2.0 PR.DS-01
# AWS provider >= 4 configures encryption in a SEPARATE resource, so we look for
# an aws_s3_bucket_server_side_encryption_configuration that references the bucket.
# (S3 applies SSE-S3 by default since 2023; this rule enforces an explicit, auditable
#  encryption configuration, which is also where KMS keys are specified.)
# ---------------------------------------------------------------------------
deny contains msg if {
	some r in live_resources
	r.type == "aws_s3_bucket"
	not bucket_has_encryption(r)
	msg := sprintf("[CIS 3.11 | NIST PR.DS-01] S3 bucket '%v' has no server-side encryption configuration.", [r.address])
}

# Legacy provider (< 4): inline block on the bucket itself.
bucket_has_encryption(r) if {
	is_array(r.change.after.server_side_encryption_configuration)
	count(r.change.after.server_side_encryption_configuration) > 0
}

# Provider >= 4: separate resource referencing this bucket by address.
bucket_has_encryption(r) if {
	not r.module_address
	base := concat(".", [r.type, r.name])
	ids := {base, concat(".", [base, "id"]), concat(".", [base, "bucket"])}
	some cfg in input.configuration.root_module.resources
	cfg.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in cfg.expressions.bucket.references
	ref in ids
}

# Provider >= 4: separate resource referencing the bucket by literal name.
bucket_has_encryption(r) if {
	not r.module_address
	some cfg in input.configuration.root_module.resources
	cfg.type == "aws_s3_bucket_server_side_encryption_configuration"
	cfg.expressions.bucket.constant_value == r.change.after.bucket
}

# ---------------------------------------------------------------------------
# Public IP exposure
# CIS v8 12.2 | NIST CSF 2.0 PR.IR-01
# A public IP is not inherently non-compliant (bastions, NAT). Approved exceptions
# are tagged  compliance:public-ip-approved = "true".
# ---------------------------------------------------------------------------
public_ip_exempt(r) if r.change.after.tags["compliance:public-ip-approved"] == "true"

deny contains msg if {
	some r in live_resources
	r.type == "aws_instance"
	r.change.after.associate_public_ip_address == true
	not public_ip_exempt(r)
	msg := sprintf("[CIS 12.2 | NIST PR.IR-01] EC2 instance '%v' is configured with a public IP address.", [r.address])
}

deny contains msg if {
	some r in live_resources
	r.type == "aws_launch_template"
	some ni in r.change.after.network_interfaces
	ni.associate_public_ip_address in {true, "true"}
	not public_ip_exempt(r)
	msg := sprintf("[CIS 12.2 | NIST PR.IR-01] Launch template '%v' assigns public IPs to instances.", [r.address])
}

deny contains msg if {
	some r in live_resources
	r.type == "aws_subnet"
	r.change.after.map_public_ip_on_launch == true
	not public_ip_exempt(r)
	msg := sprintf("[CIS 12.2 | NIST PR.IR-01] Subnet '%v' auto-assigns public IPs to launched instances.", [r.address])
}

# ---------------------------------------------------------------------------
# Full-administrator IAM policies must require MFA
# CIS v8 6.5 (and 5.4/6.8 for least privilege) | NIST CSF 2.0 PR.AA-03, PR.AA-05
# In plan JSON the `policy` attribute is a JSON STRING, so it must be unmarshalled.
# ---------------------------------------------------------------------------
iam_policy_types := {
	"aws_iam_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

iam_policy_resources contains r if {
	some r in live_resources
	r.type in iam_policy_types
}

policy_doc(r) := doc if {
	is_string(r.change.after.policy)
	doc := json.unmarshal(r.change.after.policy)
}

policy_doc(r) := r.change.after.policy if is_object(r.change.after.policy)

policy_statements(doc) := [doc.Statement] if is_object(doc.Statement)

policy_statements(doc) := doc.Statement if is_array(doc.Statement)

# Fail closed if the policy cannot be read at plan time (unknown value / bad JSON).
deny contains msg if {
	some r in iam_policy_resources
	not policy_doc(r)
	msg := sprintf("[IAM] Policy '%v' could not be evaluated at plan time (unknown or invalid JSON); refusing to approve.", [r.address])
}

grants_full_admin(s) if {
	s.Effect == "Allow"
	"*" in to_list(s.Action)
	"*" in to_list(s.Resource)
}

# MFA must be required via Condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}}.
# The string "false" is truthy in Rego, so the value is compared explicitly.
mfa_enforced(s) if {
	some v in to_list(s.Condition.Bool["aws:MultiFactorAuthPresent"])
	v in {"true", true}
}

deny contains msg if {
	some r in iam_policy_resources
	doc := policy_doc(r)
	some s in policy_statements(doc)
	grants_full_admin(s)
	not mfa_enforced(s)
	msg := sprintf("[CIS 6.5 | NIST PR.AA-03/PR.AA-05] IAM policy '%v' grants full administrator access (Action * on Resource *) without an MFA condition.", [r.address])
}
