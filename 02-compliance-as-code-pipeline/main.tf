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
# Compliant S3 Bucket & Dedicated Server-Side Encryption Configuration
# Follows AWS Provider >= 4 / 5 best practice (separate encryption resource)
# Enforces CIS 3.11 / NIST CSF 2.0 PR.DS-01 (explicit KMS encryption vault)
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
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/sample-evidence-vault-key"
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
