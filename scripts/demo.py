#!/usr/bin/env python3
"""
Demo Script - Cloud SIEM & GRC Platform
Run this to see the platform's capabilities with simulated data
"""

import json
from datetime import datetime, timedelta, timezone
import sys
import io
from pathlib import Path

# Set UTF-8 encoding on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# ── Banner ──────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║         Cloud SIEM & GRC Automation Platform                ║
║         ─────────────────────────────────────                ║
║         Unified Security Monitoring & Compliance            ║
║         Version 1.0.0                                       ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def demo_threat_intelligence():
    """Demo threat intelligence enrichment"""
    print_section("🔍 THREAT INTELLIGENCE ENRICHMENT")

    from src.threat_intel.engine import ThreatIntelligenceEngine

    engine = ThreatIntelligenceEngine()

    # Demo with simulated data (no API keys needed)
    print("  Simulating IOC enrichment...")
    print()

    # Simulated results
    simulated_results = [
        {
            "ioc": "185.220.101.34",
            "type": "ip",
            "risk_level": "critical",
            "risk_score": 92,
            "sources": {
                "virustotal": {"malicious_count": 18, "country": "DE"},
                "shodan": {"open_ports": [22, 80, 443, 8080], "vulns": ["CVE-2024-3094"]},
                "abuseipdb": {"abuse_score": 100, "total_reports": 2847},
            },
        },
        {
            "ioc": "44d88612fea8a8f36de82e1278abb02f",
            "type": "hash",
            "risk_level": "high",
            "risk_score": 78,
            "sources": {
                "virustotal": {"malicious_count": 55, "file_type": "Win32 EXE"},
            },
        },
        {
            "ioc": "malware-c2.example.com",
            "type": "domain",
            "risk_level": "critical",
            "risk_score": 95,
            "sources": {
                "virustotal": {"malicious_count": 12, "categories": {"phishing": True}},
            },
        },
    ]

    for result in simulated_results:
        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            result["risk_level"], "⚪"
        )
        print(f"  {risk_emoji} {result['type'].upper()}: {result['ioc']}")
        print(f"     Risk Score: {result['risk_score']}/100 ({result['risk_level'].upper()})")
        for source, data in result["sources"].items():
            print(f"     └─ {source}: {json.dumps(data)}")
        print()


def demo_mitre_mapping():
    """Demo MITRE ATT&CK mapping"""
    print_section("🎯 MITRE ATT&CK MAPPING")

    from src.threat_intel.mitre_mapper import MITREMapper

    mapper = MITREMapper()

    # Simulate a multi-stage attack
    attack_events = [
        {"EventName": "ConsoleLogin", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:15:00Z", "Username": "compromised-user"},
        {"EventName": "ListUsers", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:18:00Z", "Username": "compromised-user"},
        {"EventName": "CreateAccessKey", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:22:00Z", "Username": "compromised-user"},
        {"EventName": "AttachRolePolicy", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:25:00Z", "Username": "compromised-user"},
        {"EventName": "StopLogging", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:28:00Z", "Username": "compromised-user"},
        {"EventName": "GetSecretValue", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:30:00Z", "Username": "compromised-user"},
        {"EventName": "GetObject", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:35:00Z", "Username": "compromised-user"},
        {"EventName": "CreateSnapshot", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:40:00Z", "Username": "compromised-user"},
        {"EventName": "DeleteBucket", "SourceIPAddress": "185.220.101.34",
         "EventTime": "2024-01-15T02:45:00Z", "Username": "compromised-user"},
    ]

    print("  Mapping simulated attack sequence to MITRE ATT&CK...\n")
    mapped = mapper.map_events_batch(attack_events)

    for event in mapped:
        print(f"  ⚔️  {event['event_name']}")
        print(f"     Tactic:    {event['tactic_id']} - {event['tactic_name']}")
        print(f"     Technique: {event['technique_id']} - {event['technique_name']}")
        if event.get("subtechnique"):
            print(f"     Sub-tech:  {event['subtechnique']} - {event.get('subtechnique_name', '')}")
        print()

    # Detect attack chains
    chains = mapper.detect_attack_chain()
    if chains:
        print(f"  🚨 ATTACK CHAIN DETECTED!")
        for chain in chains:
            print(f"     Entity:     {chain['entity']}")
            print(f"     Stages:     {chain['stages']}")
            print(f"     Risk Level: {chain['risk_level'].upper()}")
            print(f"     Kill Chain:")
            for tactic in chain["tactics"]:
                print(f"       → {tactic['id']}: {tactic['name']} ({len(tactic['events'])} events)")
    print()

    # Heatmap
    heatmap = mapper.get_heatmap()
    print("  📊 ATT&CK Heatmap:")
    for tid, info in heatmap["tactics"].items():
        bar = "█" * info["count"] if info["count"] > 0 else "░"
        print(f"     {tid} {info['name']:30s} {bar} ({info['count']})")


def demo_compliance():
    """Demo NIST 800-53 compliance assessment"""
    print_section("📋 NIST 800-53 COMPLIANCE ASSESSMENT")

    from src.compliance.nist_engine import NIST80053Engine

    engine = NIST80053Engine()

    # Simulated AWS environment data
    aws_data = {
        "iam_password_policy": {
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "RequireSymbols": True,
            "MinimumPasswordLength": 14,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        },
        "iam_users": [
            {"username": "admin", "has_console_password": True, "mfa_enabled": True, "days_since_last_login": 1},
            {"username": "developer", "has_console_password": True, "mfa_enabled": True, "days_since_last_login": 5},
            {"username": "old-contractor", "has_console_password": True, "mfa_enabled": False, "days_since_last_login": 120},
        ],
        "root_account": {"has_access_keys": False, "mfa_enabled": True},
        "iam_policies": [
            {"name": "AdminFullAccess", "statements": [{"Action": "*", "Resource": "*"}]},
            {"name": "ReadOnly", "statements": [{"Action": "s3:GetObject", "Resource": "arn:aws:s3:::*"}]},
        ],
        "s3_buckets": [
            {"name": "prod-data", "public_access": False, "versioning_enabled": True, "default_encryption": True},
            {"name": "temp-uploads", "public_access": True, "versioning_enabled": False, "default_encryption": False},
        ],
        "security_groups": [
            {"name": "web-sg", "inbound_rules": [
                {"port": 443, "cidr": "0.0.0.0/0"},
                {"port": 22, "cidr": "0.0.0.0/0"},
            ]},
        ],
        "cloudtrail": {
            "is_logging": True,
            "is_multi_region": True,
            "log_file_validation": True,
            "include_management_events": True,
            "include_data_events": False,
        },
        "security_hub": {"enabled": True},
        "guardduty": {"enabled": True, "malware_protection_enabled": False},
        "inspector": {"enabled": False},
        "config_recorder": {"is_recording": True},
        "config_rules": [
            {"name": "s3-bucket-ssl-requests-only", "compliance_type": "COMPLIANT"},
            {"name": "encrypted-volumes", "compliance_type": "NON_COMPLIANT"},
            {"name": "iam-root-access-key-check", "compliance_type": "COMPLIANT"},
        ],
        "cloudwatch_alarms": [
            {"name": "root-account-usage"},
            {"name": "iam-policy-changes"},
        ],
        "vpcs": [
            {"id": "vpc-123", "flow_logs_enabled": True},
            {"id": "vpc-456", "flow_logs_enabled": False},
        ],
        "waf": {"enabled": True},
        "ebs_volumes": [
            {"id": "vol-123", "encrypted": True},
            {"id": "vol-456", "encrypted": False},
        ],
        "load_balancers": [
            {"name": "prod-alb", "ssl_policy": "ELBSecurityPolicy-TLS-1-2-2017-01"},
        ],
        "rds_instances": [
            {"identifier": "prod-db", "storage_encrypted": True, "ssl_enforced": True},
        ],
        "patch_compliance": [
            {"id": "i-123", "missing_patches": 0},
            {"id": "i-456", "missing_patches": 5},
        ],
    }

    print("  Running assessment against simulated AWS environment...\n")
    report = engine.run_assessment(aws_data=aws_data)

    # Display results
    print(f"  📊 Compliance Score: {report['compliance_score']}%")
    print(f"  📝 Total Controls:   {report['total_controls']}")
    print()

    # Status breakdown
    print("  Status Breakdown:")
    status_emojis = {"pass": "✅", "fail": "❌", "warning": "⚠️", "not_assessed": "⬜", "error": "🔥"}
    for status, count in report["status_summary"].items():
        emoji = status_emojis.get(status, "❓")
        bar = "█" * count
        print(f"     {emoji} {status:15s} {bar} ({count})")

    print()

    # Show failures
    failures = [c for c in report["controls"] if c["status"] == "fail"]
    if failures:
        print(f"  ❌ Failed Controls ({len(failures)}):")
        for control in failures:
            print(f"     {control['control_id']} - {control['title']}")
            for finding in control["findings"][:3]:
                print(f"       └─ {finding}")
            print()

    # Show warnings
    warnings = [c for c in report["controls"] if c["status"] == "warning"]
    if warnings:
        print(f"  ⚠️  Warnings ({len(warnings)}):")
        for control in warnings:
            print(f"     {control['control_id']} - {control['title']}")
            for finding in control["findings"][:2]:
                print(f"       └─ {finding}")
            print()


def demo_dashboard():
    """Demo unified dashboard"""
    print_section("📊 UNIFIED SECURITY DASHBOARD")

    dashboard = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "events_24h": 15847,
        "alerts": {"critical": 3, "high": 12, "medium": 45, "low": 128},
        "compliance_score": 72.0,
        "threat_intel_lookups": 342,
        "active_attack_chains": 1,
        "top_source_ips": [
            ("185.220.101.34", 847, "critical"),
            ("92.118.37.19", 234, "high"),
            ("45.155.205.233", 156, "medium"),
        ],
        "cloud_findings": {
            "aws_security_hub": 23,
            "aws_guardduty": 7,
            "azure_defender": 5,
        },
    }

    print(f"  🕐 {dashboard['timestamp']}")
    print()

    # Alert summary
    alerts = dashboard["alerts"]
    print("  ┌─────────────────────────────────────────┐")
    print(f"  │  Events (24h): {dashboard['events_24h']:>10,}               │")
    print(f"  │  🔴 Critical:  {alerts['critical']:>10}               │")
    print(f"  │  🟠 High:      {alerts['high']:>10}               │")
    print(f"  │  🟡 Medium:    {alerts['medium']:>10}               │")
    print(f"  │  🟢 Low:       {alerts['low']:>10}               │")
    print(f"  │  📋 Compliance: {dashboard['compliance_score']:>9}%              │")
    print(f"  │  🚨 Active Attacks: {dashboard['active_attack_chains']:>5}               │")
    print("  └─────────────────────────────────────────┘")
    print()

    # Top threat IPs
    print("  Top Threat Source IPs:")
    for ip, count, level in dashboard["top_source_ips"]:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(level, "⚪")
        bar = "█" * (count // 50)
        print(f"     {emoji} {ip:20s} {bar} ({count} events)")

    print()

    # Cloud findings
    print("  Cloud Security Findings:")
    for source, count in dashboard["cloud_findings"].items():
        print(f"     ☁️  {source:25s} {count} findings")


def main():
    print(BANNER)
    print(f"  Started at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    demo_dashboard()
    demo_threat_intelligence()
    demo_mitre_mapping()
    demo_compliance()

    print_section("✅ DEMO COMPLETE")
    print("  Platform capabilities demonstrated:")
    print("    ✓ Multi-cloud log collection (AWS + Azure)")
    print("    ✓ Threat intelligence enrichment (VT, Shodan, AbuseIPDB)")
    print("    ✓ MITRE ATT&CK mapping & attack chain detection")
    print("    ✓ NIST 800-53 automated compliance assessment")
    print("    ✓ Unified security dashboard")
    print()
    print("  Next steps:")
    print("    1. Configure API keys in .env file")
    print("    2. Start the API:  python -m uvicorn src.api.main:app --reload")
    print("    3. Visit docs:    http://localhost:8000/docs")
    print("    4. Connect cloud: Configure AWS/Azure credentials")
    print()


if __name__ == "__main__":
    main()
