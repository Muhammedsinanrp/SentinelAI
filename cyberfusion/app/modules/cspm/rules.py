from typing import Dict, List, Any

CSPM_RULES = [
    {
        "id": "CIS-AWS-S3-01",
        "service": "S3",
        "title": "S3 Bucket Publicly Accessible to Internet",
        "severity": "CRITICAL",
        "evidence": "ACL contains 'AllUsers' with Read/List permissions.",
        "remediation": "Enable S3 Block Public Access at the account and bucket level."
    },
    {
        "id": "CIS-AWS-SG-01",
        "service": "SecurityGroups",
        "title": "Security Group Allows Inbound SSH (Port 22) from 0.0.0.0/0",
        "severity": "HIGH",
        "evidence": "Ingress rule allows tcp/22 from source 0.0.0.0/0.",
        "remediation": "Restrict port 22 ingress to corporate VPN IP ranges or use AWS Systems Manager Session Manager."
    },
    {
        "id": "CIS-AWS-IAM-01",
        "service": "IAM",
        "title": "Root Account Does Not Have Multi-Factor Authentication (MFA) Enabled",
        "severity": "CRITICAL",
        "evidence": "Account root user credentials active without virtual/hardware MFA token.",
        "remediation": "Immediately attach a FIDO2 WebAuthn or TOTP hardware token to AWS Root account."
    },
    {
        "id": "CIS-AWS-EC2-01",
        "service": "EC2",
        "title": "EBS Volume Not Encrypted at Rest with KMS",
        "severity": "MEDIUM",
        "evidence": "Volume attached to production EC2 instance has encryption=False.",
        "remediation": "Enable default EBS encryption for the AWS Region using an AWS KMS Customer Managed Key (CMK)."
    },
    {
        "id": "CIS-AWS-LOG-01",
        "service": "CloudTrail",
        "title": "Multi-Region CloudTrail Logging is Disabled",
        "severity": "HIGH",
        "evidence": "No multi-region trail found logging management and data events.",
        "remediation": "Create an organization-wide multi-region CloudTrail delivered to an isolated S3 bucket."
    }
]
