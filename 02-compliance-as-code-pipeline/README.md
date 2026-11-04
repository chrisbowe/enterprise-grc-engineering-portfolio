# Lab 2: Compliance-as-Code & Continuous Assurance Pipeline

## 📌 Overview
This lab demonstrates how to operationalize **Continuous Assurance** by embedding regulatory compliance and security benchmarks directly into the software development lifecycle (SDLC).

Using **Open Policy Agent (OPA)** and **Rego**, infrastructure-as-code (Terraform) changes are programmatically evaluated against **NIST CSF 2.0** and **CIS Critical Security Controls v8** before any cloud resources can be provisioned.

## 🛡️ Enforced Controls
* **CIS Control 3.3 / NIST PR.DS-1:** S3 Bucket Server-Side Encryption (rejects unencrypted storage).
* **CIS Control 4.1 / NIST PR.AC-3:** Compute Network Isolation (rejects public IPs on internal VMs).
* **CIS Control 5.2 / NIST PR.AC-6:** Identity Least Privilege & MFA (rejects unconditioned wildcard administrative policies).

## 🚀 How It Works
1. Developers commit Infrastructure-as-Code (`main.tf`).
2. GitHub Actions generates a machine-readable JSON plan (`terraform show -json`).
3. OPA inspects the planned configuration against `policies/nist_csf_cis_controls.rego`.
4. If violations exist, the pipeline fails, blocking deployment and outputting specific compliance remediation instructions.
