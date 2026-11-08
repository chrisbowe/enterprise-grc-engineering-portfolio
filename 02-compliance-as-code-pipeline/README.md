# Lab 2: Compliance-as-Code & Continuous Assurance Pipeline

## 📌 Overview
This lab demonstrates how to operationalize **Continuous Assurance** by embedding regulatory compliance and security benchmarks directly into the software development lifecycle (SDLC).

Using **Open Policy Agent (OPA)** and **Rego v1**, infrastructure-as-code (Terraform) changes are programmatically evaluated against **NIST CSF 2.0** and **CIS Critical Security Controls v8** before any cloud resources can be provisioned.

## 🛡️ Enforced Controls
* **CIS Control 3.11 / NIST CSF 2.0 PR.DS-01:** S3 Bucket Server-Side Encryption (enforces explicit, auditable server-side encryption configuration on all S3 buckets; supports both modern dedicated `aws_s3_bucket_server_side_encryption_configuration` and legacy inline blocks).
* **CIS Control 12.2 / NIST CSF 2.0 PR.IR-01:** Network Infrastructure & Isolation (rejects unapproved public IP assignment on EC2 instances, subnets, and launch templates unless explicitly tagged `compliance:public-ip-approved = "true"`).
* **CIS Control 6.5 / NIST CSF 2.0 PR.AA-03, PR.AA-05:** Identity Least Privilege & MFA (enforces MFA condition blocks on wildcard administrative IAM policies).

## 🚀 How It Works
1. Infrastructure-as-Code (`main.tf`) models compliant enterprise resources (such as dedicated KMS encryption configurations and private compute nodes).
2. The CI pipeline runs OPA policy tests against hand-crafted, mock Terraform plan JSON fixtures (`plan_compliant.json`, `plan_noncompliant.json`, `plan_malformed.json`). This ensures deterministic testing of both approval and rejection paths without requiring live AWS credentials.
3. OPA evaluates the planned changes against `policies/nist_csf_cis_controls.rego` (`run_policy_tests.sh`).
4. If policy violations or malformed plan structures are detected, the pipeline fails closed, blocking deployment and outputting specific remediation findings.
