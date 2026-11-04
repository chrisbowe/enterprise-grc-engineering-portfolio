package terraform.compliance

import future.keywords.in

default allow = false

# CIS Control 3.3 / NIST CSF PR.DS-1: S3 Buckets must enforce default encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.server_side_encryption_configuration
    msg := sprintf("[CIS 3.3 / NIST PR.DS-1] S3 Bucket '%v' lacks default server-side encryption configuration.", [resource.address])
}

# CIS Control 4.1 / NIST CSF PR.AC-3: Prevent compute instances with direct public IPs
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    resource.change.after.associate_public_ip_address == true
    msg := sprintf("[CIS 4.1 / NIST PR.AC-3] EC2 Instance '%v' is configured with an unshielded public IP address.", [resource.address])
}

# CIS Control 5.2 / NIST CSF PR.AC-6: Enforce MFA Condition on Administrator Policies
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    statement := resource.change.after.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action == "*"
    not statement.Condition.Bool["aws:MultiFactorAuthPresent"]
    msg := sprintf("[CIS 5.2 / NIST PR.AC-6] Administrator IAM Policy '%v' grants full access without MFA enforcement.", [resource.address])
}

# Gate rule: pass only when 0 violations detected
allow {
    count(deny) == 0
}
