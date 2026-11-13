"""
API and storage tests
"""

from src.utils.store import get_store


def _event(event_type="aws.cloudtrail.createuser", severity="high", source="AWS CloudTrail"):
    return {
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "message": "AWS API call: CreateUser",
        "timestamp": "2024-01-15T02:22:00Z",
        "details": {
            "event_name": "CreateUser",
            "source_ip": "185.220.101.34",
            "user_name": "attacker",
            "event_time": "2024-01-15T02:22:00Z",
            "mitre": {
                "technique_id": "T1136",
                "technique_name": "Create Account",
                "tactic_id": "TA0003",
                "tactic_name": "Persistence",
            },
        },
    }


class TestHealth:
    def test_dashboard_html(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert "Cloud SIEM" in response.text

    def test_static_assets(self, client):
        assert client.get("/ui/styles.css").status_code == 200
        assert client.get("/ui/app.js").status_code == 200
        assert client.get("/ui/fonts/fonts.css").status_code == 200

    def test_health_reports_database(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["services"]["database"] == "up"
        assert body["services"]["aws_collector"] == "not_configured"


class TestEvents:
    def test_query_empty(self, client):
        response = client.get("/api/v1/events")
        assert response.status_code == 200
        assert response.json()["total"] == 0

    def test_query_stored_events(self, client):
        get_store().add_events([_event(), _event(severity="info")])

        response = client.get("/api/v1/events", params={"severity": "high"})
        body = response.json()
        assert body["total"] == 1
        assert body["events"][0]["severity"] == "high"
        assert body["events"][0]["details"]["mitre"]["tactic_id"] == "TA0003"

    def test_collect_skips_without_credentials(self, client):
        response = client.post("/api/v1/events/collect", params={"sources": ["aws", "azure"]})
        assert response.status_code == 200
        results = response.json()["results"]
        assert results["aws"]["status"] == "skipped"
        assert results["azure"]["status"] == "skipped"

    def test_collection_generates_alerts(self, client):
        get_store().add_events([_event(severity="critical")])
        get_store().add_alert("AWS API call: CreateUser", "critical", rule="collected-event")

        response = client.get("/api/v1/alerts", params={"severity": "critical"})
        assert response.json()["total"] == 1

    def test_time_range_filter(self, client):
        get_store().add_events([_event()])

        assert client.get("/api/v1/events", params={"since": "2030-01-01T00:00:00Z"}).json()["total"] == 0
        assert client.get("/api/v1/events", params={"since": "2020-01-01T00:00:00Z"}).json()["total"] == 1

    def test_invalid_severity_rejected(self, client):
        assert client.get("/api/v1/events", params={"severity": "urgent"}).status_code == 422


class TestAlerts:
    def test_acknowledge_alert(self, client):
        alert_id = get_store().add_alert("Investigate", "high")

        response = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "acknowledged"})
        assert response.status_code == 200
        assert response.json()["status"] == "acknowledged"
        assert client.get("/api/v1/alerts", params={"status": "acknowledged"}).json()["total"] == 1

    def test_missing_alert_returns_404(self, client):
        assert client.patch("/api/v1/alerts/9999", json={"status": "resolved"}).status_code == 404

    def test_invalid_alert_status_rejected(self, client):
        alert_id = get_store().add_alert("Investigate", "high")
        response = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "closed"})
        assert response.status_code == 422


class TestHardening:
    def test_security_headers_and_request_id(self, client):
        response = client.get("/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert len(response.headers["X-Request-ID"]) == 32

    def test_request_id_is_echoed(self, client):
        response = client.get("/health", headers={"X-Request-ID": "trace-123"})
        assert response.headers["X-Request-ID"] == "trace-123"

    def test_oversized_body_rejected(self, client):
        response = client.post(
            "/api/v1/threat-intel/enrich",
            content=b"x" * 2_000_001,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413

    def test_openapi_declares_api_key_scheme(self, client):
        spec = client.get("/openapi.json").json()
        assert "ApiKeyAuth" in spec["components"]["securitySchemes"]


class TestDashboard:
    def test_empty_dashboard(self, client):
        body = client.get("/api/v1/dashboard").json()
        assert body["total_events"] == 0
        assert body["compliance_score"] == 0.0

    def test_dashboard_aggregates_events_and_alerts(self, client):
        store = get_store()
        store.add_events([_event(severity="critical"), _event(severity="low")])
        store.add_alert("AWS API call: CreateUser", "critical")

        body = client.get("/api/v1/dashboard").json()
        assert body["total_events"] == 2
        assert body["total_alerts"] == 1
        assert body["open_alerts"] == 1
        assert body["critical_alerts"] == 1
        assert body["active_threats"] == 1
        assert body["cloud_findings"]["aws"] == 2
        assert body["top_source_ips"][0]["ip"] == "185.220.101.34"


class TestCompliance:
    def test_assess_and_summary(self, client):
        response = client.post(
            "/api/v1/compliance/assess",
            json={
                "aws_data": {
                    "iam_password_policy": {
                        "RequireUppercaseCharacters": True,
                        "RequireLowercaseCharacters": True,
                        "RequireSymbols": True,
                        "MinimumPasswordLength": 16,
                        "MaxPasswordAge": 90,
                    }
                }
            },
        )
        assert response.status_code == 200
        report = response.json()
        assert report["total_controls"] >= 20
        assert report["data_sources"] == {"aws": True, "azure": False}

        summary = client.get("/api/v1/compliance/summary").json()
        assert summary["compliance_score"] == report["compliance_score"]

        reports = client.get("/api/v1/compliance/reports").json()
        assert reports["total"] == 1

        latest = client.get("/api/v1/compliance/report/latest")
        assert latest.status_code == 200
        assert latest.json()["assessment_id"] == report["assessment_id"]
        assert len(latest.json()["controls"]) >= 20

    def test_latest_report_missing_returns_404(self, client):
        assert client.get("/api/v1/compliance/report/latest").status_code == 404

    def test_controls_can_be_filtered(self, client):
        all_controls = client.get("/api/v1/compliance/controls").json()
        assert all_controls["total"] >= 20

        access_control = client.get(
            "/api/v1/compliance/controls", params={"family": "Access Control"}
        ).json()
        assert access_control["total"] < all_controls["total"]
        assert all(c["family"] == "Access Control" for c in access_control["controls"])


class TestThreatIntel:
    def test_enrich_requires_api_keys(self, client):
        response = client.post(
            "/api/v1/threat-intel/enrich", json={"type": "ip", "value": "8.8.8.8"}
        )
        assert response.status_code == 503

    def test_unsupported_type_rejected(self, client):
        response = client.post(
            "/api/v1/threat-intel/enrich", json={"type": "email", "value": "a@b.c"}
        )
        assert response.status_code == 422

    def test_batch_limit_enforced(self, client):
        payload = {"iocs": [{"type": "ip", "value": f"10.0.0.{i}"} for i in range(51)]}
        response = client.post("/api/v1/threat-intel/enrich/batch", json=payload)
        assert response.status_code == 422


class TestMitre:
    def test_tactics_have_twelve_entries(self, client):
        body = client.get("/api/v1/mitre/tactics").json()
        assert len(body["tactics"]) == 12

    def test_tactic_counts_from_stored_events(self, client):
        get_store().add_events([_event(), _event()])

        body = client.get("/api/v1/mitre/tactics").json()
        persistence = next(t for t in body["tactics"] if t["id"] == "TA0003")
        assert persistence["events_mapped"] == 2

    def test_techniques_for_tactic(self, client):
        body = client.get("/api/v1/mitre/techniques/TA0003").json()
        assert any(t["id"] == "T1136" for t in body["techniques"])

    def test_unknown_tactic_returns_404(self, client):
        assert client.get("/api/v1/mitre/techniques/TA9999").status_code == 404

    def test_report_resolves_technique_names(self, client):
        get_store().add_events([_event()])

        report = client.get("/api/v1/mitre/report").json()
        assert report["total_events_analyzed"] == 1
        top = report["top_techniques"][0]
        assert top["id"] == "T1136"
        assert top["name"] == "Create Account"


class TestAuth:
    def test_api_key_enforced_when_configured(self, client, monkeypatch):
        from src.api import main

        secured = main.get_settings().model_copy(update={"api_key": "s3cret"})
        monkeypatch.setattr(main, "get_settings", lambda: secured)

        assert client.get("/api/v1/dashboard").status_code == 401
        assert (
            client.get("/api/v1/dashboard", headers={"X-API-Key": "s3cret"}).status_code == 200
        )
        assert client.get("/health").status_code == 200


class TestRateLimit:
    def test_requests_beyond_limit_are_rejected(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.api.main import RateLimitMiddleware

        limited = FastAPI()
        limited.add_middleware(RateLimitMiddleware, limit=2)

        @limited.get("/ping")
        def ping():
            return {"ok": True}

        with TestClient(limited) as test_client:
            assert test_client.get("/ping").status_code == 200
            assert test_client.get("/ping").status_code == 200
            response = test_client.get("/ping")
            assert response.status_code == 429
            assert "Retry-After" in response.headers


class TestProductionGuards:
    def test_startup_fails_without_api_key(self, monkeypatch):
        import pytest
        from fastapi.testclient import TestClient

        from src.api import main

        prod = main.get_settings().model_copy(
            update={"environment": "production", "api_key": None}
        )
        monkeypatch.setattr(main, "get_settings", lambda: prod)

        with pytest.raises(RuntimeError, match="API_KEY"):
            with TestClient(main.app):
                pass


class TestStore:
    def test_alerts_are_deduplicated_within_window(self):
        store = get_store()
        alert = {"message": "AWS API call: CreateUser", "severity": "high", "rule": "collected-event"}

        assert store.add_alerts([alert], dedupe_minutes=60) == 1
        assert store.add_alerts([alert], dedupe_minutes=60) == 0
        assert store.add_alerts([alert]) == 1

    def test_reports_roundtrip(self):
        store = get_store()
        assert store.latest_report() is None

        report = {
            "assessment_id": "NIST-1",
            "framework": "NIST 800-53 Rev5",
            "assessment_date": "2024-01-01T00:00:00",
            "compliance_score": 60.0,
            "total_controls": 25,
            "status_summary": {"pass": 15, "fail": 10},
        }
        store.add_report(report)
        assert store.latest_report()["assessment_id"] == "NIST-1"
        assert store.query_reports()[0] == 1
