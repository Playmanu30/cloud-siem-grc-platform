"""
NIST 800-53 Rev5 Compliance Engine
Automates compliance checks against NIST 800-53 controls
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from enum import Enum
from ..utils.logging import get_logger

logger = get_logger(__name__)


class ComplianceStatus(str, Enum):
    """Status of a compliance check"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    NOT_ASSESSED = "not_assessed"


class ComplianceControl:
    """Represents a single compliance control"""

    def __init__(
        self,
        control_id: str,
        family: str,
        title: str,
        description: str,
        priority: str = "P1",
        baseline: str = "moderate",
        check_function: Optional[Callable[[Dict], Any]] = None,
    ):
        self.control_id = control_id
        self.family = family
        self.title = title
        self.description = description
        self.priority = priority
        self.baseline = baseline
        self.check_function = check_function
        self.last_checked: Optional[str] = None
        self.status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
        self.evidence: List[Dict[str, Any]] = []
        self.findings: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "baseline": self.baseline,
            "status": self.status.value,
            "last_checked": self.last_checked,
            "findings_count": len(self.findings),
            "findings": self.findings,
        }


class NIST80053Engine:
    """
    NIST 800-53 Rev5 Compliance Assessment Engine

    Automates checks against NIST 800-53 controls using data
    from AWS, Azure, and on-premises infrastructure.
    """

    def __init__(self):
        self.controls: Dict[str, ComplianceControl] = {}
        self.assessment_results: List[Dict[str, Any]] = []
        self._register_controls()
        logger.info("NIST 800-53 compliance engine initialized", controls=len(self.controls))

    def _register_controls(self) -> None:
        """Register all NIST 800-53 controls with automated check functions"""

        # ── AC: Access Control ──────────────────────────────────
        self._add_control("AC-1", "Access Control", "Policy and Procedures",
            "Develop, document, and disseminate access control policy and procedures.",
            check_function=self._check_ac_policy)

        self._add_control("AC-2", "Access Control", "Account Management",
            "Manage system accounts: create, enable, modify, disable, remove.",
            check_function=self._check_account_management)

        self._add_control("AC-3", "Access Control", "Access Enforcement",
            "Enforce approved authorizations for logical access to information.",
            check_function=self._check_access_enforcement)

        self._add_control("AC-6", "Access Control", "Least Privilege",
            "Employ principle of least privilege, allowing only authorized access.",
            check_function=self._check_least_privilege)

        self._add_control("AC-7", "Access Control", "Unsuccessful Logon Attempts",
            "Enforce limits on consecutive invalid logon attempts.",
            check_function=self._check_logon_attempts)

        self._add_control("AC-17", "Access Control", "Remote Access",
            "Establish usage restrictions for remote access.",
            check_function=self._check_remote_access)

        # ── AU: Audit and Accountability ────────────────────────
        self._add_control("AU-2", "Audit and Accountability", "Event Logging",
            "Identify events that the system is capable of logging.",
            check_function=self._check_event_logging)

        self._add_control("AU-3", "Audit and Accountability", "Content of Audit Records",
            "Ensure audit records contain what type of event, when, where, source, outcome.",
            check_function=self._check_audit_content)

        self._add_control("AU-6", "Audit and Accountability", "Audit Record Review",
            "Review and analyze system audit records for indications of activity.",
            check_function=self._check_audit_review)

        self._add_control("AU-12", "Audit and Accountability", "Audit Record Generation",
            "Provide audit record generation capability at system components.",
            check_function=self._check_audit_generation)

        # ── CA: Assessment, Authorization, and Monitoring ───────
        self._add_control("CA-7", "Assessment", "Continuous Monitoring",
            "Develop and implement continuous monitoring strategy.",
            check_function=self._check_continuous_monitoring)

        # ── CM: Configuration Management ────────────────────────
        self._add_control("CM-2", "Configuration Management", "Baseline Configuration",
            "Develop, document, and maintain baseline configuration of system.",
            check_function=self._check_baseline_config)

        self._add_control("CM-6", "Configuration Management", "Configuration Settings",
            "Establish mandatory configuration settings for IT products.",
            check_function=self._check_config_settings)

        self._add_control("CM-8", "Configuration Management", "System Component Inventory",
            "Develop and document inventory of system components.",
            check_function=self._check_inventory)

        # ── IA: Identification and Authentication ───────────────
        self._add_control("IA-2", "Identification and Authentication", "Identification and Auth (Org Users)",
            "Uniquely identify and authenticate organizational users.",
            check_function=self._check_user_auth)

        self._add_control("IA-5", "Identification and Authentication", "Authenticator Management",
            "Manage system authenticators (password complexity, rotation).",
            check_function=self._check_authenticator_mgmt)

        # ── IR: Incident Response ───────────────────────────────
        self._add_control("IR-4", "Incident Response", "Incident Handling",
            "Implement incident handling capability for incidents.",
            check_function=self._check_incident_handling)

        self._add_control("IR-5", "Incident Response", "Incident Monitoring",
            "Track and document incidents on an ongoing basis.",
            check_function=self._check_incident_monitoring)

        # ── RA: Risk Assessment ─────────────────────────────────
        self._add_control("RA-5", "Risk Assessment", "Vulnerability Monitoring and Scanning",
            "Monitor and scan for vulnerabilities in the system.",
            check_function=self._check_vulnerability_scanning)

        # ── SC: System and Communications Protection ────────────
        self._add_control("SC-7", "System and Communications Protection", "Boundary Protection",
            "Monitor and control communications at external boundary.",
            check_function=self._check_boundary_protection)

        self._add_control("SC-8", "System and Communications Protection", "Transmission Confidentiality",
            "Protect confidentiality of transmitted information.",
            check_function=self._check_encryption_in_transit)

        self._add_control("SC-28", "System and Communications Protection", "Protection of Information at Rest",
            "Protect confidentiality and integrity of information at rest.",
            check_function=self._check_encryption_at_rest)

        # ── SI: System and Information Integrity ────────────────
        self._add_control("SI-2", "System and Information Integrity", "Flaw Remediation",
            "Identify, report, and correct information system flaws.",
            check_function=self._check_flaw_remediation)

        self._add_control("SI-3", "System and Information Integrity", "Malicious Code Protection",
            "Implement malicious code protection mechanisms.",
            check_function=self._check_malware_protection)

        self._add_control("SI-4", "System and Information Integrity", "System Monitoring",
            "Monitor system to detect attacks, unauthorized connections, and anomalies.",
            check_function=self._check_system_monitoring)

    def _add_control(
        self,
        control_id: str,
        family: str,
        title: str,
        description: str,
        priority: str = "P1",
        baseline: str = "moderate",
        check_function: Optional[Callable[[Dict], Any]] = None,
    ) -> None:
        """Add a control to the engine"""
        self.controls[control_id] = ComplianceControl(
            control_id=control_id,
            family=family,
            title=title,
            description=description,
            priority=priority,
            baseline=baseline,
            check_function=check_function,
        )

    # ── Assessment Methods ──────────────────────────────────────

    def run_assessment(
        self,
        aws_data: Optional[Dict[str, Any]] = None,
        azure_data: Optional[Dict[str, Any]] = None,
        control_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run a full or partial compliance assessment

        Args:
            aws_data: Collected AWS security data
            azure_data: Collected Azure security data
            control_ids: Specific controls to assess (None = all)

        Returns:
            Assessment report
        """
        assessment_start = datetime.now(timezone.utc)
        controls_to_check = control_ids or list(self.controls.keys())
        results = []
        cloud_data = {
            "aws": aws_data or {},
            "azure": azure_data or {},
        }
        has_cloud_data = bool(aws_data) or bool(azure_data)

        for control_id in controls_to_check:
            control = self.controls.get(control_id)
            if not control:
                logger.warning("Unknown control", control_id=control_id)
                continue

            try:
                if not has_cloud_data:
                    control.status = ComplianceStatus.NOT_ASSESSED
                    control.findings = ["No cloud data supplied for assessment"]
                elif control.check_function:
                    status, findings = control.check_function(cloud_data)
                    control.status = status
                    control.findings = findings
                else:
                    control.status = ComplianceStatus.NOT_ASSESSED
                    control.findings = ["No automated check available"]

                control.last_checked = datetime.now(timezone.utc).isoformat()
                results.append(control.to_dict())

            except Exception as e:
                control.status = ComplianceStatus.ERROR
                control.findings = [f"Check failed with error: {str(e)}"]
                results.append(control.to_dict())
                logger.error("Control check failed", control_id=control_id, error=str(e))

        # Aggregate results
        status_counts = {}
        for r in results:
            status = r["status"]
            status_counts[status] = status_counts.get(status, 0) + 1

        total = len(results)
        passed = status_counts.get("pass", 0)
        compliance_score = round((passed / total * 100), 1) if total > 0 else 0

        report = {
            "assessment_id": f"NIST-{assessment_start.strftime('%Y%m%d-%H%M%S')}",
            "framework": "NIST 800-53 Rev5",
            "assessment_date": assessment_start.isoformat(),
            "completed_date": datetime.now(timezone.utc).isoformat(),
            "total_controls": total,
            "compliance_score": compliance_score,
            "status_summary": status_counts,
            "controls": results,
        }

        self.assessment_results.append(report)
        logger.info(
            "Compliance assessment complete",
            score=compliance_score,
            total=total,
            passed=passed,
        )
        return report

    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get a high-level compliance summary"""
        if not self.assessment_results:
            return {"message": "No assessments have been run yet"}

        latest = self.assessment_results[-1]
        return {
            "framework": latest["framework"],
            "last_assessment": latest["assessment_date"],
            "compliance_score": latest["compliance_score"],
            "total_controls": latest["total_controls"],
            "status_summary": latest["status_summary"],
            "critical_findings": [
                c for c in latest["controls"]
                if c["status"] == "fail" and c.get("priority") == "P1"
            ],
        }

    # ── Individual Control Checks (AWS/Azure) ───────────────────

    def _check_ac_policy(self, data: Dict) -> tuple:
        """AC-1: Check for access control policies"""
        findings = []
        aws = data.get("aws", {})

        # Check if IAM password policy exists
        password_policy = aws.get("iam_password_policy", {})
        if not password_policy:
            findings.append("No IAM password policy configured")
            return ComplianceStatus.FAIL, findings

        if not password_policy.get("RequireUppercaseCharacters"):
            findings.append("Password policy does not require uppercase characters")
        if not password_policy.get("RequireLowercaseCharacters"):
            findings.append("Password policy does not require lowercase characters")
        if not password_policy.get("RequireSymbols"):
            findings.append("Password policy does not require symbols")
        if password_policy.get("MinimumPasswordLength", 0) < 14:
            findings.append(f"Minimum password length ({password_policy.get('MinimumPasswordLength')}) is below 14 characters")
        if not password_policy.get("MaxPasswordAge") or password_policy.get("MaxPasswordAge", 0) > 90:
            findings.append("Password max age exceeds 90 days")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_account_management(self, data: Dict) -> tuple:
        """AC-2: Check account management practices"""
        findings = []
        aws = data.get("aws", {})

        # Check for inactive IAM users
        iam_users = aws.get("iam_users", [])
        for user in iam_users:
            if user.get("days_since_last_login", 0) > 90:
                findings.append(f"IAM user '{user.get('username')}' inactive for >90 days")
            if user.get("has_console_password") and not user.get("mfa_enabled"):
                findings.append(f"IAM user '{user.get('username')}' has console access without MFA")

        # Check root account
        root_account = aws.get("root_account", {})
        if root_account.get("has_access_keys"):
            findings.append("Root account has active access keys")
        if not root_account.get("mfa_enabled"):
            findings.append("Root account MFA is not enabled")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_access_enforcement(self, data: Dict) -> tuple:
        """AC-3: Check access enforcement mechanisms"""
        findings = []
        aws = data.get("aws", {})

        # Check S3 bucket policies
        s3_buckets = aws.get("s3_buckets", [])
        for bucket in s3_buckets:
            if bucket.get("public_access"):
                findings.append(f"S3 bucket '{bucket.get('name')}' allows public access")
            if not bucket.get("versioning_enabled"):
                findings.append(f"S3 bucket '{bucket.get('name')}' has versioning disabled")

        # Check security groups
        security_groups = aws.get("security_groups", [])
        for sg in security_groups:
            for rule in sg.get("inbound_rules", []):
                if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") != 443:
                    findings.append(
                        f"Security group '{sg.get('name')}' allows unrestricted access on port {rule.get('port')}"
                    )

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_least_privilege(self, data: Dict) -> tuple:
        """AC-6: Check for least privilege"""
        findings = []
        aws = data.get("aws", {})

        # Check for wildcard permissions
        iam_policies = aws.get("iam_policies", [])
        for policy in iam_policies:
            for statement in policy.get("statements", []):
                if statement.get("Action") == "*" and statement.get("Resource") == "*":
                    findings.append(f"Policy '{policy.get('name')}' grants full admin access (*:*)")
                elif statement.get("Action") == "*":
                    findings.append(f"Policy '{policy.get('name')}' grants wildcard actions")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_logon_attempts(self, data: Dict) -> tuple:
        """AC-7: Check login attempt limits"""
        findings = []
        aws = data.get("aws", {})
        password_policy = aws.get("iam_password_policy", {})

        if not password_policy.get("LockoutAfterAttempts"):
            findings.append("No account lockout policy configured for failed login attempts")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.WARNING
        return status, findings

    def _check_remote_access(self, data: Dict) -> tuple:
        """AC-17: Check remote access controls"""
        findings = []
        aws = data.get("aws", {})

        # Check for SSH open to world
        security_groups = aws.get("security_groups", [])
        for sg in security_groups:
            for rule in sg.get("inbound_rules", []):
                if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") in [22, 3389]:
                    findings.append(
                        f"Security group '{sg.get('name')}' allows unrestricted SSH/RDP from 0.0.0.0/0"
                    )

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_event_logging(self, data: Dict) -> tuple:
        """AU-2: Check event logging configuration"""
        findings = []
        aws = data.get("aws", {})

        # Check CloudTrail
        cloudtrail = aws.get("cloudtrail", {})
        if not cloudtrail.get("is_logging"):
            findings.append("CloudTrail logging is not enabled")
        if not cloudtrail.get("is_multi_region"):
            findings.append("CloudTrail is not configured for multi-region")
        if not cloudtrail.get("log_file_validation"):
            findings.append("CloudTrail log file validation is disabled")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_audit_content(self, data: Dict) -> tuple:
        """AU-3: Check audit record content"""
        findings = []
        aws = data.get("aws", {})

        cloudtrail = aws.get("cloudtrail", {})
        if not cloudtrail.get("include_management_events"):
            findings.append("CloudTrail is not recording management events")
        if not cloudtrail.get("include_data_events"):
            findings.append("CloudTrail is not recording data events (S3/Lambda)")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.WARNING
        return status, findings

    def _check_audit_review(self, data: Dict) -> tuple:
        """AU-6: Check audit review processes"""
        findings = []
        aws = data.get("aws", {})

        # Check CloudWatch alarms for monitoring
        cloudwatch_alarms = aws.get("cloudwatch_alarms", [])
        required_alarms = [
            "unauthorized-api-calls",
            "console-sign-in-failures",
            "root-account-usage",
            "iam-policy-changes",
        ]

        existing_alarm_names = [a.get("name", "").lower() for a in cloudwatch_alarms]
        for alarm in required_alarms:
            if not any(alarm in name for name in existing_alarm_names):
                findings.append(f"Missing CloudWatch alarm for: {alarm}")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_audit_generation(self, data: Dict) -> tuple:
        """AU-12: Check audit record generation"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("cloudtrail", {}).get("is_logging"):
            findings.append("CloudTrail is not generating audit records")

        if not aws.get("config_recorder", {}).get("is_recording"):
            findings.append("AWS Config is not recording configuration changes")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_continuous_monitoring(self, data: Dict) -> tuple:
        """CA-7: Check continuous monitoring"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("security_hub", {}).get("enabled"):
            findings.append("AWS Security Hub is not enabled")
        if not aws.get("guardduty", {}).get("enabled"):
            findings.append("AWS GuardDuty is not enabled")
        if not aws.get("inspector", {}).get("enabled"):
            findings.append("AWS Inspector is not enabled")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_baseline_config(self, data: Dict) -> tuple:
        """CM-2: Check baseline configuration"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("config_recorder", {}).get("is_recording"):
            findings.append("AWS Config recorder is not active")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_config_settings(self, data: Dict) -> tuple:
        """CM-6: Check configuration settings"""
        findings = []
        aws = data.get("aws", {})

        config_rules = aws.get("config_rules", [])
        if len(config_rules) < 5:
            findings.append(f"Only {len(config_rules)} AWS Config rules defined (minimum 5 recommended)")

        for rule in config_rules:
            if rule.get("compliance_type") == "NON_COMPLIANT":
                findings.append(f"Config rule '{rule.get('name')}' is non-compliant")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.WARNING
        return status, findings

    def _check_inventory(self, data: Dict) -> tuple:
        """CM-8: Check system component inventory"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("ssm_managed_instances"):
            findings.append("No instances managed by AWS Systems Manager")

        if not aws.get("resource_groups"):
            findings.append("No resource groups/tags defined for inventory management")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.WARNING
        return status, findings

    def _check_user_auth(self, data: Dict) -> tuple:
        """IA-2: Check user identification and authentication"""
        findings = []
        aws = data.get("aws", {})

        iam_users = aws.get("iam_users", [])
        for user in iam_users:
            if user.get("has_console_password") and not user.get("mfa_enabled"):
                findings.append(f"User '{user.get('username')}' does not have MFA enabled")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_authenticator_mgmt(self, data: Dict) -> tuple:
        """IA-5: Check authenticator management"""
        findings = []
        aws = data.get("aws", {})
        password_policy = aws.get("iam_password_policy", {})

        if not password_policy:
            findings.append("No IAM password policy defined")
            return ComplianceStatus.FAIL, findings

        if password_policy.get("MinimumPasswordLength", 0) < 12:
            findings.append("Password minimum length below 12 characters")
        if not password_policy.get("PasswordReusePrevention"):
            findings.append("No password reuse prevention configured")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_incident_handling(self, data: Dict) -> tuple:
        """IR-4: Check incident handling capability"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("guardduty", {}).get("enabled"):
            findings.append("GuardDuty not enabled for threat detection")

        if not aws.get("sns_topics"):
            findings.append("No SNS topics configured for security notifications")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.WARNING
        return status, findings

    def _check_incident_monitoring(self, data: Dict) -> tuple:
        """IR-5: Check incident monitoring"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("security_hub", {}).get("enabled"):
            findings.append("Security Hub not enabled for centralized incident tracking")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_vulnerability_scanning(self, data: Dict) -> tuple:
        """RA-5: Check vulnerability scanning"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("inspector", {}).get("enabled"):
            findings.append("AWS Inspector not enabled for vulnerability scanning")

        if not aws.get("ecr_scan", {}).get("enabled"):
            findings.append("ECR image scanning not enabled")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_boundary_protection(self, data: Dict) -> tuple:
        """SC-7: Check boundary protection"""
        findings = []
        aws = data.get("aws", {})

        # Check VPC flow logs
        vpcs = aws.get("vpcs", [])
        for vpc in vpcs:
            if not vpc.get("flow_logs_enabled"):
                findings.append(f"VPC '{vpc.get('id')}' does not have flow logs enabled")

        # Check WAF
        if not aws.get("waf", {}).get("enabled"):
            findings.append("WAF is not enabled for boundary protection")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_encryption_in_transit(self, data: Dict) -> tuple:
        """SC-8: Check encryption in transit"""
        findings = []
        aws = data.get("aws", {})

        # Check ELB is enforcing HTTPS
        load_balancers = aws.get("load_balancers", [])
        for lb in load_balancers:
            if not lb.get("ssl_policy"):
                findings.append(f"Load balancer '{lb.get('name')}' does not enforce HTTPS")

        # Check RDS SSL
        rds_instances = aws.get("rds_instances", [])
        for rds in rds_instances:
            if not rds.get("ssl_enforced"):
                findings.append(f"RDS '{rds.get('identifier')}' does not enforce SSL/TLS")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_encryption_at_rest(self, data: Dict) -> tuple:
        """SC-28: Check encryption at rest"""
        findings = []
        aws = data.get("aws", {})

        # Check EBS volumes
        ebs_volumes = aws.get("ebs_volumes", [])
        for vol in ebs_volumes:
            if not vol.get("encrypted"):
                findings.append(f"EBS volume '{vol.get('id')}' is not encrypted")

        # Check S3 default encryption
        s3_buckets = aws.get("s3_buckets", [])
        for bucket in s3_buckets:
            if not bucket.get("default_encryption"):
                findings.append(f"S3 bucket '{bucket.get('name')}' does not have default encryption")

        # Check RDS encryption
        rds_instances = aws.get("rds_instances", [])
        for rds in rds_instances:
            if not rds.get("storage_encrypted"):
                findings.append(f"RDS '{rds.get('identifier')}' storage is not encrypted")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_flaw_remediation(self, data: Dict) -> tuple:
        """SI-2: Check flaw remediation"""
        findings = []
        aws = data.get("aws", {})

        # Check SSM patch compliance
        patch_compliance = aws.get("patch_compliance", [])
        for instance in patch_compliance:
            if instance.get("missing_patches", 0) > 0:
                findings.append(
                    f"Instance '{instance.get('id')}' has {instance['missing_patches']} missing patches"
                )

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings

    def _check_malware_protection(self, data: Dict) -> tuple:
        """SI-3: Check malicious code protection"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("guardduty", {}).get("malware_protection_enabled"):
            findings.append("GuardDuty Malware Protection is not enabled")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.WARNING
        return status, findings

    def _check_system_monitoring(self, data: Dict) -> tuple:
        """SI-4: Check system monitoring"""
        findings = []
        aws = data.get("aws", {})

        if not aws.get("cloudtrail", {}).get("is_logging"):
            findings.append("CloudTrail logging is disabled")
        if not aws.get("guardduty", {}).get("enabled"):
            findings.append("GuardDuty is not enabled for threat monitoring")
        if not aws.get("security_hub", {}).get("enabled"):
            findings.append("Security Hub is not enabled for centralized monitoring")

        # Check CloudWatch log groups
        log_groups = aws.get("cloudwatch_log_groups", [])
        if len(log_groups) < 3:
            findings.append("Insufficient CloudWatch log groups for comprehensive monitoring")

        status = ComplianceStatus.PASS if not findings else ComplianceStatus.FAIL
        return status, findings
