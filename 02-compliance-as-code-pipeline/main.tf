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

# Compliant S3 Bucket (With KMS encryption)
resource "aws_s3_bucket" "audit_evidence_store" {
  bucket = "enterprise-audit-evidence-vault-2026"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Environment        = "Production"
    ComplianceScope    = "NIST-CSF-2.0"
    DataClassification = "Confidential"
  }
}

# Non-Compliant EC2 Instance (Violation: public IP on internal node)
resource "aws_instance" "internal_analytics_worker" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  associate_public_ip_address = false # Set to true to trigger CIS 4.1 violation

  tags = {
    Name            = "AnalyticsWorker-01"
    ComplianceScope = "CIS-v8"
  }
}
