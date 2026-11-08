# Lab 2: Compliance-as-Code & Continuous Assurance Pipeline

## 📌 Overview
This lab demonstrates how to operationalize **Continuous Assurance** by embedding regulatory compliance and security benchmarks directly into the software development lifecycle (SDLC).

Using **Open Policy Agent (OPA)** and **Rego v1**, compliance guardrails are **unit-tested against Terraform plan fixtures** to validate infrastructure configurations against **NIST CSF 2.0** and **CIS Critical Security Controls v8**.

## 🛡️ Enforced Controls
* **CIS Control 3.11 / NIST CSF 2.0 PR.DS-01:** S3 Bucket Server-Side Encryption (enforces explicit, auditable server-side encryption configuration on all S3 buckets; supports both modern dedicated `aws_s3_bucket_server_side_encryption_configuration` and legacy inline blocks).
* **CIS Control 12.2 / NIST CSF 2.0 PR.IR-01:** Network Infrastructure & Isolation (rejects unapproved public IP assignment on EC2 instances, subnets, and launch templates unless explicitly tagged `compliance:public-ip-approved = "true"`).
* **CIS Control 6.5 / NIST CSF 2.0 PR.AA-03, PR.AA-05:** Identity Least Privilege & MFA (enforces MFA condition blocks on wildcard administrative IAM policies).

## 🚀 How It Works

### 1. Unit Testing in CI (This Repository)
The CI pipeline runs OPA policy tests against hand-crafted, mock Terraform plan JSON fixtures (`plan_compliant.json`, `plan_noncompliant.json`, `plan_malformed.json`). This ensures deterministic testing of both approval and rejection paths without requiring live AWS credentials or cloud provider interaction:
```bash
# Run unit tests across all policy fixtures
cd 02-compliance-as-code-pipeline
bash run_policy_tests.sh
```

### 2. Enforcing in a Real Production Pipeline
In an enterprise deployment workflow, the policy gate is embedded into CI/CD prior to applying infrastructure changes:
```bash
# 1. Generate machine-readable plan JSON (requires AWS credentials & initialized provider)
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# 2. Evaluate plan against Rego compliance guardrails and fail on any violation
opa eval -i plan.json -d policies/ --fail-defined 'data.terraform.compliance.deny[_]'
```

### 3. Reference Infrastructure (`main.tf`)
`main.tf` provides reference Terraform configurations modeling compliant enterprise patterns:
* Dedicated KMS Customer Managed Key (`aws_kms_key`) with automated annual key rotation enabled and a 30-day deletion safety window.
* Dedicated S3 bucket encryption resource (`aws_s3_bucket_server_side_encryption_configuration`) referencing the KMS key dynamically.
* Private internal EC2 analytics worker node (`associate_public_ip_address = false`) with dynamic Amazon Linux 2023 AMI lookup.

## ⚠️ Known Limitations (Documented Guardrail Boundaries)
* **IAM Scope:** Checks full administrative privileges (`*` action on `*` resource). Service-level wildcards (`iam:*`), `NotAction`, and AWS managed policy attachments are not currently evaluated.
* **Child Modules:** The S3 encryption cross-reference evaluates root-module configurations. Buckets defined inside child modules whose encryption resource lives within that child module fail closed.
* **Public IP Coverage:** Applies to `aws_instance`, `aws_launch_template`, and `aws_subnet`. Intentional public egress/ingress resources (e.g. public bastions and public subnets) must include the exception tag `compliance:public-ip-approved = "true"`.
