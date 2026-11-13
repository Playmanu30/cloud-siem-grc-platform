"""
AWS Cloud Security Log Collector
Fetches CloudTrail, Security Hub, and GuardDuty findings
"""

import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import boto3
from ..utils.logging import get_logger, SecurityEvent

logger = get_logger(__name__)


class AWSCollector:
    """Collects security logs and findings from AWS services"""

    def __init__(
        self,
        region: str = "us-east-1",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
    ):
        self.region = region
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
        )

        # Initialize service clients
        self.cloudtrail = self.session.client("cloudtrail")
        self.security_hub = self.session.client("securityhub")
        self.guardduty = self.session.client("guardduty")
        self.cloudwatch = self.session.client("logs")
        self.sts = self.session.client("sts")

        # Verify credentials
        try:
            account = self.sts.get_caller_identity()
            self.account_id = account["Account"]
            logger.info("AWS collector initialized", account_id=self.account_id, region=region)
        except Exception as e:
            logger.error("Failed to initialize AWS collector", error=str(e))
            raise

    def collect_cloudtrail_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_source: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Collect CloudTrail events

        Args:
            start_time: Start of time range (default: 1 hour ago)
            end_time: End of time range (default: now)
            event_source: Filter by AWS service (e.g., 'iam.amazonaws.com')

        Returns:
            List of CloudTrail events
        """
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        events = []

        try:
            # Look up events
            response = self.cloudtrail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )

            events.extend(response.get("Events", []))

            # Handle pagination (bounded to avoid runaway loops on huge accounts)
            pages = 1
            while "NextToken" in response and pages < 20:
                response = self.cloudtrail.lookup_events(
                    StartTime=start_time,
                    EndTime=end_time,
                    NextToken=response["NextToken"],
                    MaxResults=50,
                )
                events.extend(response.get("Events", []))
                pages += 1

            logger.info(
                "Collected CloudTrail events",
                count=len(events),
                time_range=f"{start_time} to {end_time}",
            )

        except Exception as e:
            logger.error("Failed to collect CloudTrail events", error=str(e))

        return events

    def get_security_hub_findings(
        self,
        severity_labels: Optional[List[str]] = None,
        record_state: str = "ACTIVE",
    ) -> List[Dict[str, Any]]:
        """
        Get Security Hub findings

        Args:
            severity_labels: Filter by severity ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            record_state: Filter by state ('ACTIVE' or 'ARCHIVED')

        Returns:
            List of Security Hub findings
        """
        if not severity_labels:
            severity_labels = ["CRITICAL", "HIGH", "MEDIUM"]

        findings = []

        try:
            # Build filters
            filters = {
                "RecordState": [{"Value": record_state, "Comparison": "EQUALS"}],
                "SeverityLabel": [
                    {"Value": label, "Comparison": "EQUALS"} for label in severity_labels
                ],
            }

            response = self.security_hub.get_findings(Filters=filters, MaxResults=100)

            findings.extend(response.get("Findings", []))

            # Handle pagination
            while "NextToken" in response:
                response = self.security_hub.get_findings(
                    Filters=filters,
                    NextToken=response["NextToken"],
                    MaxResults=100,
                )
                findings.extend(response.get("Findings", []))

            logger.info(
                "Collected Security Hub findings",
                count=len(findings),
                severities=severity_labels,
            )

        except Exception as e:
            logger.error("Failed to collect Security Hub findings", error=str(e))

        return findings

    def get_guardduty_findings(
        self,
        detector_id: Optional[str] = None,
        severity_threshold: int = 4,  # 0.1-3.9 Low, 4-6.9 Medium, 7-8.9 High
    ) -> List[Dict[str, Any]]:
        """
        Get GuardDuty findings

        Args:
            detector_id: GuardDuty detector ID
            severity_threshold: Minimum severity (0.1 to 10.0)

        Returns:
            List of GuardDuty findings
        """
        findings = []

        try:
            # List detectors if not provided
            if not detector_id:
                detectors = self.guardduty.list_detectors()
                detector_ids = detectors.get("DetectorIds", [])
                if not detector_ids:
                    logger.warning("No GuardDuty detectors found")
                    return []
                detector_id = detector_ids[0]

            # List findings
            response = self.guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "severity": {"Gte": severity_threshold},
                        "service.archived": {"Eq": ["false"]},
                    }
                },
            )

            finding_ids = response.get("FindingIds", [])

            if finding_ids:
                # Get finding details (max 50 at a time)
                for i in range(0, len(finding_ids), 50):
                    batch = finding_ids[i:i+50]
                    detail_response = self.guardduty.get_findings(
                        DetectorId=detector_id,
                        FindingIds=batch,
                    )
                    findings.extend(detail_response.get("Findings", []))

            logger.info(
                "Collected GuardDuty findings",
                count=len(findings),
                detector_id=detector_id,
            )

        except Exception as e:
            logger.error("Failed to collect GuardDuty findings", error=str(e))

        return findings

    def parse_event_to_security_event(
        self, event: Dict[str, Any], source: str
    ) -> SecurityEvent:
        """
        Parse AWS event to standardized SecurityEvent

        Args:
            event: Raw AWS event
            source: Source service ('cloudtrail', 'security_hub', 'guardduty')

        Returns:
            SecurityEvent object
        """
        if source == "cloudtrail":
            return self._parse_cloudtrail_event(event)
        elif source == "security_hub":
            return self._parse_security_hub_finding(event)
        elif source == "guardduty":
            return self._parse_guardduty_finding(event)
        else:
            raise ValueError(f"Unknown source: {source}")

    def _parse_cloudtrail_event(self, event: Dict[str, Any]) -> SecurityEvent:
        """Parse CloudTrail event to SecurityEvent"""
        # lookup_events() nests the real payload as a JSON string in CloudTrailEvent
        payload: Dict[str, Any] = {}
        raw_payload = event.get("CloudTrailEvent")
        if isinstance(raw_payload, str):
            try:
                payload = json.loads(raw_payload)
            except ValueError:
                payload = {}

        user_identity = payload.get("userIdentity") or event.get("UserIdentity") or {}
        event_name = event.get("EventName") or payload.get("eventName", "Unknown")
        source_ip = event.get("SourceIPAddress") or payload.get("sourceIPAddress", "Unknown")
        error_code = event.get("ErrorCode") or payload.get("errorCode")

        # Determine severity
        severity = "info"
        if error_code:
            severity = "medium"
        if event_name.startswith("Delete") or event_name.startswith("Remove"):
            severity = "high"

        return SecurityEvent(
            event_type=f"aws.cloudtrail.{event_name.lower()}",
            severity=severity,
            source="AWS CloudTrail",
            message=f"AWS API call: {event_name}",
            details={
                "account_id": self.account_id,
                "region": self.region,
                "event_name": event_name,
                "user_type": user_identity.get("type"),
                "user_name": user_identity.get("userName"),
                "source_ip": source_ip,
                "error_code": error_code,
                "event_time": event.get("EventTime") or payload.get("eventTime"),
                "resources": event.get("Resources", []),
            },
        )

    def _parse_security_hub_finding(self, finding: Dict[str, Any]) -> SecurityEvent:
        """Parse Security Hub finding to SecurityEvent"""
        severity_label = finding.get("Severity", {}).get("Label", "LOW")
        title = finding.get("Title", "Unknown Finding")

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFORMATIONAL": "info",
        }

        return SecurityEvent(
            event_type=(
                f"aws.securityhub."
                f"{(finding.get('Types') or ['unknown'])[0].replace('/', '.').lower()}"
            ),
            severity=severity_map.get(severity_label, "medium"),
            source="AWS Security Hub",
            message=title,
            details={
                "finding_id": finding.get("Id"),
                "severity": severity_label,
                "compliance_status": finding.get("Compliance", {}).get("Status"),
                "workflow_status": finding.get("Workflow", {}).get("Status"),
                "record_state": finding.get("RecordState"),
                "resources": [r.get("Id") for r in finding.get("Resources", [])],
                "remediation": finding.get("Remediation", {}).get("Recommendation", {}).get("Text"),
            },
        )

    def _parse_guardduty_finding(self, finding: Dict[str, Any]) -> SecurityEvent:
        """Parse GuardDuty finding to SecurityEvent"""
        severity = finding.get("Severity", 0)
        title = finding.get("Title", "Unknown Finding")

        # Map severity
        if severity >= 7:
            severity_label = "high"
        elif severity >= 4:
            severity_label = "medium"
        else:
            severity_label = "low"

        return SecurityEvent(
            event_type=f"aws.guardduty.{finding.get('Type', 'unknown').replace(':', '.').lower()}",
            severity=severity_label,
            source="AWS GuardDuty",
            message=title,
            details={
                "finding_id": finding.get("Id"),
                "severity_score": severity,
                "description": finding.get("Description"),
                "resource_type": finding.get("Resource", {}).get("ResourceType"),
                "action_type": finding.get("Service", {}).get("Action", {}).get("ActionType"),
                "city": finding.get("Service", {}).get("Action", {}).get("City", {}).get("CityName"),
                "country": finding.get("Service", {}).get("Action", {}).get("Country", {}).get("CountryName"),
            },
        )
