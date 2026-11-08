terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# -----------------------------------------------------------------------------
# Customer Managed Key (CMK) for Evidence Vault Encryption
# Enforces automated key rotation (CIS v8 3.11 / NIST CSF 2.0 PR.DS-01 / PR.DS-02)
# -----------------------------------------------------------------------------
resource "aws_kms_key" "evidence_vault_key" {
  description             = "KMS CMK for Enterprise Audit Evidence Vault"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment        = "Production"
    ComplianceScope    = "NIST-CSF-2.0"
    DataClassification = "Confidential"
  }
}

# -----------------------------------------------------------------------------
# Compliant S3 Bucket & Dedicated Server-Side Encryption Configuration
# Follows AWS Provider >= 4 / 5 best practice (separate encryption resource)
# References the managed KMS key dynamically (valid for plan and apply)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "audit_evidence_store" {
  bucket = "enterprise-audit-evidence-vault-2026"

  tags = {
    Environment        = "Production"
    ComplianceScope    = "NIST-CSF-2.0"
    DataClassification = "Confidential"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_evidence_store_encryption" {
  bucket = aws_s3_bucket.audit_evidence_store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence_vault_key.arn
    }
  }
}

# -----------------------------------------------------------------------------
# EC2 Analytics Worker Node (Compliant by default)
# Associate Public IP is set to false (private internal subnet).
# Set associate_public_ip_address = true to trigger CIS 12.2 / NIST PR.IR-01 violation.
# -----------------------------------------------------------------------------
resource "aws_instance" "internal_analytics_worker" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  associate_public_ip_address = false # Set to true to trigger CIS 12.2 / NIST PR.IR-01 violation

  tags = {
    Name            = "AnalyticsWorker-01"
    ComplianceScope = "CIS-v8"
  }
}
