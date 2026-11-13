"""
Azure Security Log Collector
Fetches Activity Logs, Microsoft Defender findings, and Policy compliance
"""

from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from ..utils.logging import get_logger, SecurityEvent

logger = get_logger(__name__)


class AzureCollector:
    """Collects security logs and findings from Azure services"""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.subscription_id = subscription_id

        # Create credential
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        # Initialize clients
        self.monitor_client = MonitorManagementClient(
            self.credential, subscription_id
        )
        self.resource_client = ResourceManagementClient(
            self.credential, subscription_id
        )
        self.security_client = SecurityCenter(
            self.credential, subscription_id
        )

        logger.info(
            "Azure collector initialized",
            subscription_id=subscription_id,
            tenant_id=tenant_id,
        )

    def collect_activity_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        resource_group: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Collect Azure Activity Logs

        Args:
            start_time: Start of time range (default: 1 hour ago)
            end_time: End of time range (default: now)
            resource_group: Filter by resource group

        Returns:
            List of activity log events
        """
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        events = []

        try:
            # Build filter
            filter_str = (
                f"eventTimestamp ge '{start_time.isoformat()}' "
                f"and eventTimestamp le '{end_time.isoformat()}'"
            )

            if resource_group:
                filter_str += f" and resourceGroupName eq '{resource_group}'"

            # Get activity logs
            activity_logs = self.monitor_client.activity_logs.list(
                filter=filter_str,
                select="eventTimestamp,operationName,status,caller,resourceGroupName,resourceId,category",
            )

            for log in activity_logs:
                events.append({
                    "event_timestamp": log.event_timestamp.isoformat() if log.event_timestamp else None,
                    "operation_name": log.operation_name.value if log.operation_name else None,
                    "status": log.status.value if log.status else None,
                    "caller": log.caller,
                    "resource_group_name": log.resource_group_name,
                    "resource_id": log.resource_id,
                    "category": log.category.value if log.category else None,
                    "event_data_id": log.event_data_id,
                    "correlation_id": log.correlation_id,
                })

            logger.info(
                "Collected Azure activity logs",
                count=len(events),
                time_range=f"{start_time} to {end_time}",
            )

        except Exception as e:
            logger.error("Failed to collect Azure activity logs", error=str(e))

        return events

    def get_security_alerts(
        self,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get Microsoft Defender for Cloud security alerts

        Args:
            severity: Filter by severity ('High', 'Medium', 'Low')

        Returns:
            List of security alerts
        """
        alerts = []

        try:
            # Get alerts from Security Center
            alert_list = self.security_client.alerts.list()

            for alert in alert_list:
                alert_dict = {
                    "alert_name": alert.alert_name,
                    "alert_display_name": alert.alert_display_name,
                    "severity": alert.severity,
                    "status": alert.status,
                    "time_generated": alert.time_generated_utc.isoformat() if alert.time_generated_utc else None,
                    "description": alert.description,
                    "resource_id": alert.resource_id,
                    "compromised_entity": alert.compromised_entity,
                    "attack_detection_source": alert.attack_detection_source,
                    "alert_uri": alert.alert_uri,
                }

                # Filter by severity if specified
                if severity and alert_dict["severity"] != severity:
                    continue

                alerts.append(alert_dict)

            logger.info(
                "Collected Azure security alerts",
                count=len(alerts),
                severity_filter=severity,
            )

        except Exception as e:
            logger.error("Failed to collect Azure security alerts", error=str(e))

        return alerts

    def get_secure_score(self) -> Dict[str, Any]:
        """
        Get Azure Secure Score

        Returns:
            Secure score information
        """
        try:
            scores = self.security_client.secure_scores.list()

            for score in scores:
                return {
                    "score_percentage": score.percentage,
                    "current_score": score.current,
                    "max_score": score.max,
                    "weight": score.weight,
                    "healthy_resources": score.healthy_resources,
                    "unhealthy_resources": score.unhealthy_resources,
                    "not_applicable_resources": score.not_applicable_resources,
                }

        except Exception as e:
            logger.error("Failed to get secure score", error=str(e))
            return {}
        return {}

    def get_compliance_results(self) -> List[Dict[str, Any]]:
        """
        Get regulatory compliance results

        Returns:
            List of compliance results
        """
        compliance_results = []

        try:
            results = self.security_client.regulatory_compliance_results.list()

            for result in results:
                compliance_results.append({
                    "standard_name": result.standard_name,
                    "control_name": result.control_name,
                    "state": result.state,
                    "passed_assessments": result.passed_assessments,
                    "failed_assessments": result.failed_assessments,
                    "skipped_assessments": result.skipped_assessments,
                })

            logger.info(
                "Collected Azure compliance results",
                count=len(compliance_results),
            )

        except Exception as e:
            logger.error("Failed to collect compliance results", error=str(e))

        return compliance_results

    def parse_event_to_security_event(
        self, event: Dict[str, Any], source: str
    ) -> SecurityEvent:
        """
        Parse Azure event to standardized SecurityEvent

        Args:
            event: Raw Azure event
            source: Source service ('activity_log', 'security_alert', 'compliance')

        Returns:
            SecurityEvent object
        """
        if source == "activity_log":
            return self._parse_activity_log(event)
        elif source == "security_alert":
            return self._parse_security_alert(event)
        else:
            raise ValueError(f"Unknown source: {source}")

    def _parse_activity_log(self, event: Dict[str, Any]) -> SecurityEvent:
        """Parse Azure Activity Log to SecurityEvent"""
        operation_name = event.get("operation_name", "Unknown")
        status = event.get("status", "Unknown")
        caller = event.get("caller", "Unknown")

        # Determine severity based on operation and status
        severity = "info"
        if status == "Failed":
            severity = "medium"
        elif operation_name and ("delete" in operation_name.lower() or "remove" in operation_name.lower()):
            severity = "high"

        return SecurityEvent(
            event_type=f"azure.activity.{operation_name.split('/')[-1].lower()}" if operation_name else "azure.activity.unknown",
            severity=severity,
            source="Azure Activity Log",
            message=f"Azure operation: {operation_name}",
            details={
                "subscription_id": self.subscription_id,
                "operation_name": operation_name,
                "status": status,
                "caller": caller,
                "resource_group": event.get("resource_group_name"),
                "resource_id": event.get("resource_id"),
                "category": event.get("category"),
                "timestamp": event.get("event_timestamp"),
                "correlation_id": event.get("correlation_id"),
            },
        )

    def _parse_security_alert(self, alert: Dict[str, Any]) -> SecurityEvent:
        """Parse Azure security alert to SecurityEvent"""
        severity_label = alert.get("severity", "Low")
        alert_name = alert.get("alert_display_name", "Unknown Alert")

        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
        }

        return SecurityEvent(
            event_type=f"azure.defender.{alert.get('alert_name', 'unknown').lower().replace(' ', '_')}",
            severity=severity_map.get(severity_label, "medium"),
            source="Microsoft Defender for Cloud",
            message=alert_name,
            details={
                "alert_name": alert.get("alert_name"),
                "severity": severity_label,
                "status": alert.get("status"),
                "resource_id": alert.get("resource_id"),
                "compromised_entity": alert.get("compromised_entity"),
                "detection_source": alert.get("attack_detection_source"),
                "description": alert.get("description"),
                "timestamp": alert.get("time_generated"),
                "alert_uri": alert.get("alert_uri"),
            },
        )
