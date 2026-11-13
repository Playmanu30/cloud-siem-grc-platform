"""
MITRE ATT&CK Mapper
Maps security events to MITRE ATT&CK tactics, techniques, and procedures (TTPs)
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from ..utils.logging import get_logger

logger = get_logger(__name__)


# ── ATT&CK Knowledge Base ──────────────────────────────────────

TACTICS = {
    "TA0001": {"name": "Initial Access", "description": "Techniques to gain initial foothold"},
    "TA0002": {"name": "Execution", "description": "Techniques to run malicious code"},
    "TA0003": {"name": "Persistence", "description": "Techniques to maintain access"},
    "TA0004": {"name": "Privilege Escalation", "description": "Techniques to gain higher-level permissions"},
    "TA0005": {"name": "Defense Evasion", "description": "Techniques to avoid detection"},
    "TA0006": {"name": "Credential Access", "description": "Techniques to steal credentials"},
    "TA0007": {"name": "Discovery", "description": "Techniques to learn about the environment"},
    "TA0008": {"name": "Lateral Movement", "description": "Techniques to move through the environment"},
    "TA0009": {"name": "Collection", "description": "Techniques to gather data of interest"},
    "TA0010": {"name": "Exfiltration", "description": "Techniques to steal data"},
    "TA0011": {"name": "Command and Control", "description": "Techniques to communicate with compromised systems"},
    "TA0040": {"name": "Impact", "description": "Techniques to manipulate, interrupt, or destroy systems"},
}


# Map AWS CloudTrail event names to MITRE techniques
AWS_EVENT_TECHNIQUE_MAP = {
    # ── Initial Access (TA0001) ──
    "ConsoleLogin": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "subtechnique": "T1078.004",
        "subtechnique_name": "Cloud Accounts",
    },
    "GetFederationToken": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
    },

    # ── Execution (TA0002) ──
    "Invoke": {
        "technique_id": "T1651",
        "technique_name": "Cloud Administration Command",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    "RunInstances": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },
    "SendCommand": {
        "technique_id": "T1651",
        "technique_name": "Cloud Administration Command",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
    },

    # ── Persistence (TA0003) ──
    "CreateUser": {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "subtechnique": "T1136.003",
        "subtechnique_name": "Cloud Account",
    },
    "CreateAccessKey": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "subtechnique": "T1098.001",
        "subtechnique_name": "Additional Cloud Credentials",
    },
    "CreateRole": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    "CreateLoginProfile": {
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    "AttachUserPolicy": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },
    "PutRolePolicy": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
    },

    # ── Privilege Escalation (TA0004) ──
    "AttachRolePolicy": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
    },
    "PutUserPolicy": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
    },
    "AssumeRole": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
    },

    # ── Defense Evasion (TA0005) ──
    "StopLogging": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "subtechnique": "T1562.008",
        "subtechnique_name": "Disable or Modify Cloud Logs",
    },
    "DeleteTrail": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "subtechnique": "T1562.008",
        "subtechnique_name": "Disable or Modify Cloud Logs",
    },
    "DeleteFlowLogs": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
    },
    "ModifyInstanceAttribute": {
        "technique_id": "T1578",
        "technique_name": "Modify Cloud Compute Infrastructure",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
    },
    "DisableSecurityHub": {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
    },

    # ── Credential Access (TA0006) ──
    "GetSecretValue": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "subtechnique": "T1552.005",
        "subtechnique_name": "Cloud Instance Metadata API",
    },
    "GetPasswordData": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
    },

    # ── Discovery (TA0007) ──
    "DescribeInstances": {
        "technique_id": "T1580",
        "technique_name": "Cloud Infrastructure Discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
    },
    "ListBuckets": {
        "technique_id": "T1580",
        "technique_name": "Cloud Infrastructure Discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
    },
    "ListUsers": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "subtechnique": "T1087.004",
        "subtechnique_name": "Cloud Account",
    },
    "GetCallerIdentity": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
    },

    # ── Collection (TA0009) ──
    "GetObject": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
    },
    "CopyDBSnapshot": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
    },

    # ── Exfiltration (TA0010) ──
    "PutBucketPolicy": {
        "technique_id": "T1537",
        "technique_name": "Transfer Data to Cloud Account",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
    },
    "ShareSnapshot": {
        "technique_id": "T1537",
        "technique_name": "Transfer Data to Cloud Account",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
    },
    "CreateSnapshot": {
        "technique_id": "T1537",
        "technique_name": "Transfer Data to Cloud Account",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
    },

    # ── Impact (TA0040) ──
    "DeleteBucket": {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
    },
    "TerminateInstances": {
        "technique_id": "T1489",
        "technique_name": "Service Stop",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
    },
    "DeleteDBInstance": {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
    },
}


# Technique ID → display name, derived from the event map above
TECHNIQUE_NAMES = {
    info["technique_id"]: info["technique_name"]
    for info in AWS_EVENT_TECHNIQUE_MAP.values()
}


class MITREMapper:
    """
    Maps security events to MITRE ATT&CK framework.
    Generates technique heatmaps and attack chain visualizations.
    """

    def __init__(self):
        self.mapped_events: List[Dict[str, Any]] = []
        self.tactic_counts: Dict[str, int] = {tid: 0 for tid in TACTICS}
        self.technique_counts: Dict[str, int] = {}
        logger.info("MITRE ATT&CK mapper initialized")

    @staticmethod
    def _payload(event: Dict[str, Any]) -> Dict[str, Any]:
        """CloudTrail lookup_events() nests the payload as JSON in CloudTrailEvent"""
        raw = event.get("CloudTrailEvent")
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except ValueError:
                return {}
        return raw if isinstance(raw, dict) else {}

    def map_cloudtrail_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Map a CloudTrail event to a MITRE ATT&CK technique

        Args:
            event: CloudTrail event dict with 'EventName' key

        Returns:
            Mapped event with technique info, or None if no mapping found
        """
        payload = self._payload(event)
        event_name = event.get("EventName") or payload.get("eventName", "")

        technique_info = AWS_EVENT_TECHNIQUE_MAP.get(event_name)
        if not technique_info:
            return None

        user_identity = payload.get("userIdentity") or event.get("UserIdentity") or {}
        mapped = {
            "event_name": event_name,
            "event_time": event.get("EventTime") or payload.get("eventTime"),
            "user": event.get("Username") or user_identity.get("userName"),
            "source_ip": event.get("SourceIPAddress") or payload.get("sourceIPAddress"),
            "error_code": event.get("ErrorCode") or payload.get("errorCode"),
            **technique_info,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Track counts
        tactic_id = technique_info["tactic_id"]
        technique_id = technique_info["technique_id"]

        self.tactic_counts[tactic_id] = self.tactic_counts.get(tactic_id, 0) + 1
        self.technique_counts[technique_id] = self.technique_counts.get(technique_id, 0) + 1
        self.mapped_events.append(mapped)

        logger.info(
            "Event mapped to ATT&CK",
            event_name=event_name,
            technique=f"{technique_id} ({technique_info['technique_name']})",
            tactic=f"{tactic_id} ({technique_info['tactic_name']})",
        )

        return mapped

    def map_events_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Map a batch of CloudTrail events to MITRE ATT&CK

        Args:
            events: List of CloudTrail events

        Returns:
            List of mapped events (unmapped events excluded)
        """
        mapped = []
        for event in events:
            result = self.map_cloudtrail_event(event)
            if result:
                mapped.append(result)

        logger.info(
            "Batch mapping complete",
            total_events=len(events),
            mapped=len(mapped),
            unmapped=len(events) - len(mapped),
        )
        return mapped

    def detect_attack_chain(self, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Detect potential attack chains by analyzing tactic progression

        A multi-stage attack typically follows the ATT&CK kill chain:
        Initial Access → Execution → Persistence → Privilege Escalation → ...

        Args:
            time_window_minutes: Time window to correlate events

        Returns:
            List of detected attack chains
        """
        chains = []

        # Group events by source IP / user
        event_groups: Dict[str, List[Dict]] = {}
        for event in self.mapped_events:
            key = event.get("source_ip", event.get("user", "unknown"))
            event_groups.setdefault(key, []).append(event)

        # Analyze each group for kill chain progression
        kill_chain_order = [
            "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
            "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
            "TA0011", "TA0040",
        ]

        for entity, events in event_groups.items():
            # Get unique tactics observed for this entity
            observed_tactics = list(dict.fromkeys(e["tactic_id"] for e in events))

            # Check if tactics follow kill chain order (at least 3 sequential stages)
            chain_stages = []
            for tactic in kill_chain_order:
                if tactic in observed_tactics:
                    chain_stages.append(tactic)

            if len(chain_stages) >= 3:
                chains.append({
                    "entity": entity,
                    "stages": len(chain_stages),
                    "tactics": [
                        {
                            "id": t,
                            "name": TACTICS[t]["name"],
                            "events": [e for e in events if e["tactic_id"] == t],
                        }
                        for t in chain_stages
                    ],
                    "risk_level": "critical" if len(chain_stages) >= 5 else "high",
                    "first_seen": min(e.get("event_time") or "" for e in events),
                    "last_seen": max(e.get("event_time") or "" for e in events),
                    "total_events": len(events),
                })

        if chains:
            logger.warning(
                "Attack chains detected",
                chains=len(chains),
                critical=sum(1 for c in chains if c["risk_level"] == "critical"),
            )

        return chains

    def get_heatmap(self) -> Dict[str, Any]:
        """
        Get ATT&CK technique heatmap data for visualization

        Returns:
            Heatmap data with tactic/technique counts
        """
        return {
            "tactics": {
                tid: {
                    "name": info["name"],
                    "count": self.tactic_counts.get(tid, 0),
                }
                for tid, info in TACTICS.items()
            },
            "techniques": self.technique_counts,
            "total_mapped_events": len(self.mapped_events),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def generate_report(self) -> Dict[str, Any]:
        """Generate a full ATT&CK mapping report"""
        chains = self.detect_attack_chain()
        heatmap = self.get_heatmap()

        # Find most common techniques
        top_techniques = sorted(
            self.technique_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "report_id": f"MITRE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "total_events_analyzed": len(self.mapped_events),
            "attack_chains_detected": len(chains),
            "attack_chains": chains,
            "heatmap": heatmap,
            "top_techniques": [
                {
                    "id": tid,
                    "name": TECHNIQUE_NAMES.get(tid, tid),
                    "count": count,
                }
                for tid, count in top_techniques
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
