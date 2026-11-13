"""
Tests for Threat Intelligence Engine
"""

import pytest
from unittest.mock import patch, MagicMock
from src.threat_intel.engine import ThreatIntelligenceEngine


class TestThreatIntelligenceEngine:
    """Test suite for ThreatIntelligenceEngine"""

    def setup_method(self):
        """Set up test fixtures"""
        self.engine = ThreatIntelligenceEngine(
            virustotal_api_key="test_vt_key",
            shodan_api_key="test_shodan_key",
            abuseipdb_api_key="test_abuseipdb_key",
        )

    # ── Risk Score Tests ────────────────────────────────────────

    def test_vt_risk_score_clean(self):
        """Clean file should score 0"""
        attributes = {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 60,
                "undetected": 10,
            },
            "reputation": 50,
        }
        score = self.engine._calculate_vt_risk_score(attributes)
        assert score == 0

    def test_vt_risk_score_malicious(self):
        """Highly malicious file should score high"""
        attributes = {
            "last_analysis_stats": {
                "malicious": 55,
                "suspicious": 5,
                "harmless": 5,
                "undetected": 5,
            },
            "reputation": -100,
        }
        score = self.engine._calculate_vt_risk_score(attributes)
        assert score >= 70

    def test_shodan_risk_score_no_ports(self):
        """Host with no open ports scores 0"""
        data = {"ports": [], "vulns": []}
        score = self.engine._calculate_shodan_risk_score(data)
        assert score == 0

    def test_shodan_risk_score_risky_ports(self):
        """Host with risky open ports scores higher"""
        data = {"ports": [22, 23, 3389, 445], "vulns": []}
        score = self.engine._calculate_shodan_risk_score(data)
        # 22 = risky (+10), 23 = risky (+10), 3389 = risky (+10), 445 = risky (+10)
        assert score >= 30

    def test_shodan_risk_score_with_vulns(self):
        """Host with CVEs scores critical"""
        data = {"ports": [80, 443], "vulns": ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"]}
        score = self.engine._calculate_shodan_risk_score(data)
        assert score >= 45  # 3 vulns * 15 = 45 + port scores

    # ── Risk Level Tests ────────────────────────────────────────

    def test_risk_level_critical(self):
        assert self.engine._risk_level(85) == "critical"

    def test_risk_level_high(self):
        assert self.engine._risk_level(65) == "high"

    def test_risk_level_medium(self):
        assert self.engine._risk_level(45) == "medium"

    def test_risk_level_low(self):
        assert self.engine._risk_level(25) == "low"

    def test_risk_level_info(self):
        assert self.engine._risk_level(10) == "info"

    # ── Caching Tests ───────────────────────────────────────────

    def test_cache_set_and_get(self):
        """Cache stores and retrieves values"""
        self.engine._set_cached("test:key", {"data": "value"})
        result = self.engine._get_cached("test:key")
        assert result == {"data": "value"}

    def test_cache_miss(self):
        """Cache returns None on miss"""
        result = self.engine._get_cached("nonexistent:key")
        assert result is None

    # ── API Call Tests (Mocked) ─────────────────────────────────

    @patch("src.threat_intel.engine.requests.get")
    def test_lookup_ip_virustotal_success(self, mock_get):
        """Test successful VT IP lookup"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 50,
                        "undetected": 10,
                    },
                    "reputation": -10,
                    "country": "US",
                    "as_owner": "Test ISP",
                    "network": "1.2.3.0/24",
                }
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.engine.lookup_ip_virustotal("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["source"] == "VirusTotal"
        assert result["malicious_count"] == 5
        assert result["country"] == "US"
        assert "risk_score" in result

    @patch("src.threat_intel.engine.requests.get")
    def test_lookup_ip_shodan_success(self, mock_get):
        """Test successful Shodan IP lookup"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip_str": "1.2.3.4",
            "os": "Linux",
            "org": "Test Org",
            "isp": "Test ISP",
            "country_name": "United States",
            "city": "New York",
            "ports": [22, 80, 443],
            "vulns": ["CVE-2024-1234"],
            "hostnames": ["test.example.com"],
            "domains": ["example.com"],
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18", "cpe": []},
            ],
            "last_update": "2024-01-01T00:00:00.000000",
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.engine.lookup_ip_shodan("1.2.3.4")
        assert result["ip"] == "1.2.3.4"
        assert result["source"] == "Shodan"
        assert 22 in result["open_ports"]
        assert len(result["vulns"]) == 1

    @patch("src.threat_intel.engine.requests.get")
    def test_lookup_hash_not_found(self, mock_get):
        """Test VT hash lookup returning 404"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = (
            __import__("requests").exceptions.HTTPError(response=mock_response)
        )
        mock_get.return_value = mock_response

        result = self.engine.lookup_hash_virustotal("abc123")
        assert result.get("found") is False

    def test_lookup_without_api_key(self):
        """Engine without API keys returns error"""
        engine = ThreatIntelligenceEngine()
        result = engine.lookup_ip_virustotal("1.2.3.4")
        assert "error" in result

    # ── Batch Enrichment Tests ──────────────────────────────────

    def test_enrich_iocs_empty_list(self):
        """Empty IOC list returns empty results"""
        results = self.engine.enrich_iocs([])
        assert results == []

    def test_enrich_iocs_unsupported_type(self):
        """Unsupported IOC type returns error"""
        results = self.engine.enrich_iocs([{"type": "email", "value": "test@test.com"}])
        assert len(results) == 1
        assert "error" in results[0]

    def test_enrich_iocs_skips_empty_values(self):
        """Empty IOC values are skipped"""
        results = self.engine.enrich_iocs([{"type": "ip", "value": ""}])
        assert results == []


class TestMITREMapper:
    """Test suite for MITRE ATT&CK Mapper"""

    def setup_method(self):
        from src.threat_intel.mitre_mapper import MITREMapper
        self.mapper = MITREMapper()

    def test_map_known_event(self):
        """Known event should map to a technique"""
        event = {
            "EventName": "CreateUser",
            "EventTime": "2024-01-01T00:00:00Z",
            "Username": "attacker",
            "SourceIPAddress": "1.2.3.4",
        }
        result = self.mapper.map_cloudtrail_event(event)
        assert result is not None
        assert result["technique_id"] == "T1136"
        assert result["tactic_id"] == "TA0003"

    def test_map_unknown_event(self):
        """Unknown event should return None"""
        event = {"EventName": "SomeRandomEvent"}
        result = self.mapper.map_cloudtrail_event(event)
        assert result is None

    def test_lookup_events_payload_is_unwrapped(self):
        """lookup_events() nests identity and IP in the CloudTrailEvent JSON string"""
        import json

        event = {
            "EventName": "ConsoleLogin",
            "EventTime": "2024-01-01T00:00:00Z",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {"type": "IAMUser", "userName": "attacker"},
                    "sourceIPAddress": "185.220.101.34",
                    "errorCode": "Failed authentication",
                }
            ),
        }
        result = self.mapper.map_cloudtrail_event(event)
        assert result["source_ip"] == "185.220.101.34"
        assert result["user"] == "attacker"
        assert result["error_code"] == "Failed authentication"

    def test_batch_mapping(self):
        """Batch mapping should process multiple events"""
        events = [
            {"EventName": "CreateUser"},
            {"EventName": "StopLogging"},
            {"EventName": "UnknownEvent"},
            {"EventName": "ConsoleLogin"},
        ]
        results = self.mapper.map_events_batch(events)
        assert len(results) == 3  # UnknownEvent excluded

    def test_attack_chain_detection(self):
        """Should detect multi-stage attack chains"""
        events = [
            {"EventName": "ConsoleLogin", "SourceIPAddress": "1.2.3.4", "EventTime": "2024-01-01T00:00:00Z"},
            {"EventName": "CreateUser", "SourceIPAddress": "1.2.3.4", "EventTime": "2024-01-01T00:05:00Z"},
            {"EventName": "AttachRolePolicy", "SourceIPAddress": "1.2.3.4", "EventTime": "2024-01-01T00:10:00Z"},
            {"EventName": "StopLogging", "SourceIPAddress": "1.2.3.4", "EventTime": "2024-01-01T00:15:00Z"},
            {"EventName": "GetObject", "SourceIPAddress": "1.2.3.4", "EventTime": "2024-01-01T00:20:00Z"},
        ]
        self.mapper.map_events_batch(events)
        chains = self.mapper.detect_attack_chain()
        assert len(chains) >= 1
        assert chains[0]["entity"] == "1.2.3.4"
        assert chains[0]["stages"] >= 3

    def test_heatmap_generation(self):
        """Heatmap should include all tactics"""
        heatmap = self.mapper.get_heatmap()
        assert "tactics" in heatmap
        assert len(heatmap["tactics"]) == 12  # All MITRE tactics

    def test_report_generation(self):
        """Report should include all sections"""
        report = self.mapper.generate_report()
        assert "report_id" in report
        assert "attack_chains" in report
        assert "heatmap" in report


class TestCloudTrailCollectorParsing:
    def test_lookup_event_payload_is_unwrapped(self):
        """CloudTrail lookup_events() returns UserIdentity/SourceIPAddress inside a JSON string"""
        import json

        from src.collectors.aws_collector import AWSCollector

        collector = object.__new__(AWSCollector)
        collector.account_id = "123456789012"
        collector.region = "us-east-1"

        event = {
            "EventName": "CreateUser",
            "EventTime": "2024-01-15T02:22:00Z",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {"type": "IAMUser", "userName": "attacker"},
                    "sourceIPAddress": "185.220.101.34",
                    "errorCode": "AccessDenied",
                }
            ),
        }
        parsed = collector._parse_cloudtrail_event(event)

        assert parsed.details["source_ip"] == "185.220.101.34"
        assert parsed.details["user_name"] == "attacker"
        assert parsed.details["error_code"] == "AccessDenied"
        assert parsed.severity == "medium"


class TestComplianceEngine:
    """Test suite for NIST 800-53 Compliance Engine"""

    def setup_method(self):
        from src.compliance.nist_engine import NIST80053Engine
        self.engine = NIST80053Engine()

    def test_controls_registered(self):
        """Should have registered all controls"""
        assert len(self.engine.controls) >= 20

    def test_run_assessment_no_data(self):
        """Assessment without cloud data must not claim controls pass"""
        report = self.engine.run_assessment()
        assert "compliance_score" in report
        assert "controls" in report
        assert report["compliance_score"] == 0
        assert set(report["status_summary"]) == {"not_assessed"}

    def test_ac1_pass(self):
        """AC-1 should pass with strong password policy"""
        data = {
            "aws": {
                "iam_password_policy": {
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                    "RequireSymbols": True,
                    "MinimumPasswordLength": 16,
                    "MaxPasswordAge": 90,
                }
            }
        }
        status, findings = self.engine._check_ac_policy(data)
        assert status.value == "pass"

    def test_ac1_fail_weak_policy(self):
        """AC-1 should fail with weak password policy"""
        data = {
            "aws": {
                "iam_password_policy": {
                    "RequireUppercaseCharacters": False,
                    "RequireLowercaseCharacters": False,
                    "RequireSymbols": False,
                    "MinimumPasswordLength": 6,
                    "MaxPasswordAge": 365,
                }
            }
        }
        status, findings = self.engine._check_ac_policy(data)
        assert status.value == "fail"
        assert len(findings) >= 3

    def test_ac2_root_account_violations(self):
        """AC-2 should flag root account issues"""
        data = {
            "aws": {
                "iam_users": [],
                "root_account": {
                    "has_access_keys": True,
                    "mfa_enabled": False,
                },
            }
        }
        status, findings = self.engine._check_account_management(data)
        assert status.value == "fail"
        assert any("Root account" in f for f in findings)

    def test_sc28_encryption_at_rest(self):
        """SC-28 should detect unencrypted resources"""
        data = {
            "aws": {
                "ebs_volumes": [
                    {"id": "vol-123", "encrypted": False},
                    {"id": "vol-456", "encrypted": True},
                ],
                "s3_buckets": [
                    {"name": "my-bucket", "default_encryption": False},
                ],
                "rds_instances": [],
            }
        }
        status, findings = self.engine._check_encryption_at_rest(data)
        assert status.value == "fail"
        assert len(findings) == 2  # 1 unencrypted EBS + 1 unencrypted S3

    def test_compliance_summary_no_assessments(self):
        """Summary with no assessments returns message"""
        summary = self.engine.get_compliance_summary()
        assert "message" in summary
