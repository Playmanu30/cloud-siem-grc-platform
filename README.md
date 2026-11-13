# Cloud SIEM & GRC Automation Platform

> Cloud security monitoring and compliance automation built with Python, FastAPI and the
> MITRE ATT&CK / NIST 800-53 frameworks.

## Overview

The platform aggregates AWS CloudTrail / Security Hub / GuardDuty and Azure Activity Log /
Defender data over **read-only** credentials, normalizes it into security events, enriches IOCs
through VirusTotal, Shodan and AbuseIPDB, maps events to **MITRE ATT&CK**, and runs automated
**NIST 800-53 Rev5** control assessments. Results are stored in SQLite and exposed through both a
REST API with generated OpenAPI docs and a built-in security workspace at `/`.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    REST API (FastAPI)                         │
│  /dashboard  /events  /threat-intel  /compliance  /mitre      │
│  X-API-Key auth · per-client rate limit · CORS                │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │  Collectors  │  │ Threat Intel   │  │   Compliance     │   │
│  │  ──────────  │  │ ────────────── │  │   ──────────     │   │
│  │  AWS         │  │ VirusTotal     │  │   NIST 800-53    │   │
│  │  Azure       │  │ Shodan         │  │   25 controls    │   │
│  │              │  │ AbuseIPDB      │  │                  │   │
│  └──────────────┘  └────────────────┘  └──────────────────┘   │
│          │                 │                    │             │
│          └─────────────────┴────────────────────┘             │
│                            │                                  │
│                  ┌──────────────────┐                         │
│                  │  SQLite (WAL)    │                         │
│                  │ events · alerts  │                         │
│                  │ compliance       │                         │
│                  └──────────────────┘                         │
└───────────────────────────────────────────────────────────────┘
```

## Features

### Security workspace
- Built-in dashboard at `/` — no build step, no external CDN, self-hosted fonts
- Triage queue with one-click acknowledge/resolve, severity-ordered
- Event explorer with filters, pagination and a detail drawer (normalized record + ATT&CK mapping)
- IOC lookup, NIST control browser, and an ATT&CK kill-chain matrix with coverage gaps
- Responsive down to 390px, keyboard accessible, API-key aware (`Authorize` / API key dialog)

### Multi-cloud log collection
- **AWS**: CloudTrail events, Security Hub findings, GuardDuty findings
- **Azure**: Activity Logs, Defender for Cloud alerts
- Normalized `SecurityEvent` format with severity, source, timestamp and details
- Collection is read-only and reports per-source `collected` / `skipped` / `error` status

### Threat intelligence enrichment
- VirusTotal: IP, hash and domain lookups
- Shodan: exposed services and known CVEs
- AbuseIPDB: abuse reports and confidence score
- Aggregate risk score (0-100), 24-hour IOC cache, VirusTotal rate limiting

### MITRE ATT&CK mapping
- 40+ CloudTrail event names mapped to techniques across all 12 tactics
- Mapping stored with each event, so counts survive restarts
- Attack-chain detection (3+ tactics from one source IP/user) and top-technique report

### Compliance automation (NIST 800-53 Rev5)
- 25 automated control checks: AC, AU, CA, CM, IA, IR, RA, SC, SI families
- Per-control pass / fail / warning / not-assessed with findings
- Controls are `not_assessed` when no cloud data is supplied — the engine does not guess
- Historical reports persisted and queryable

### API and operations
- Full OpenAPI docs at `/docs` (every endpoint has typed response schemas; `Authorize` accepts the API key)
- API-key authentication (required in production), per-client rate limiting and a request-body cap
- Request IDs (`X-Request-ID`) echoed on every response and included in error payloads/logs
- Defensive headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`
- SQLite persistence with WAL, schema created on startup
- Alert triage (`PATCH /alerts/{id}`) and alert deduplication on repeated collection
- Structured JSON logs, container healthcheck, non-root Docker image
- GitHub Actions CI running the suite on Python 3.12

### Not implemented (roadmap)
- Splunk / Elasticsearch collectors (the earlier README advertised these; there is no code yet)
- Slack / email alert delivery (alerts are stored and served by the API)
- Automatic response actions (block IP, isolate instance) — deliberately out of scope
- Postgres storage for multi-replica deployments

## Quick Start

Requires Python 3.12+.

```bash
python -m venv venv
venv\Scripts\activate           # Windows; source venv/bin/activate elsewhere
pip install -r requirements.txt
cp .env.example .env            # add API keys and cloud credentials
pytest
python scripts/demo.py          # offline demo, no keys needed
python -m uvicorn src.api.main:app --reload --port 8000
```

Open http://localhost:8000/ for the security workspace, or http://localhost:8000/docs for the API.

See `QUICK_START.md` for a guided setup, `DEPLOYMENT.md` for Docker and production notes, and `PROJECT_INFO.md` for the full concept/how-it-works/why/setup overview.

## Configuration

All configuration comes from environment variables or `.env` (`src/utils/config.py`).

| Variable | Description | Required |
|----------|-------------|----------|
| `ENV` | `development`, `staging`, `production` | no |
| `DEBUG` | Human-readable logs when `true` | no |
| `LOG_LEVEL` | `INFO` by default | no |
| `API_KEY` | Sent as `X-API-Key`; required when `ENV=production` | production |
| `RATE_LIMIT_RPM` | Per-client requests per minute | no |
| `MAX_BODY_BYTES` | Request body cap, default 2 MB | no |
| `CORS_ORIGINS` | JSON list of allowed origins | no |
| `DATABASE_URL` | `sqlite:///...` path | no |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` | AWS collection | for AWS |
| `AWS_SESSION_TOKEN` / `AWS_GUARDDUTY_DETECTOR_ID` | Optional AWS settings | no |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_SUBSCRIPTION_ID` | Azure collection | for Azure |
| `VT_API_KEY` / `SHODAN_API_KEY` / `ABUSEIPDB_API_KEY` | IOC enrichment | for enrichment |

## API Endpoints

All `/api/v1` endpoints require `X-API-Key` when `API_KEY` is configured.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health, database status, configured integrations |
| `GET` | `/api/v1/dashboard` | Aggregated dashboard (events, alerts, compliance, top source IPs) |
| `POST` | `/api/v1/events/collect` | Collect from `aws` / `azure` for the last N hours |
| `GET` | `/api/v1/events` | Query stored events (severity, source, `since`/`until`, pagination) |
| `POST` | `/api/v1/threat-intel/enrich` | Enrich one IOC (`type`: ip, hash, domain) |
| `POST` | `/api/v1/threat-intel/enrich/batch` | Enrich up to 50 IOCs |
| `GET` | `/api/v1/threat-intel/ioc/{type}/{value}` | Get an IOC report |
| `POST` | `/api/v1/compliance/assess` | Run a NIST 800-53 assessment |
| `GET` | `/api/v1/compliance/summary` | Latest assessment summary |
| `GET` | `/api/v1/compliance/controls` | List controls (filter by family or status) |
| `GET` | `/api/v1/compliance/reports` | Assessment history |
| `GET` | `/api/v1/compliance/report/latest` | Latest full report with every control |
| `GET` | `/api/v1/alerts` | Alerts generated from high/critical events |
| `PATCH` | `/api/v1/alerts/{alert_id}` | Acknowledge or resolve an alert |
| `GET` | `/api/v1/mitre/tactics` | 12 tactics with mapped-event counts |
| `GET` | `/api/v1/mitre/techniques/{tactic_id}` | Techniques mapped to a tactic |
| `GET` | `/api/v1/mitre/report` | Heatmap, top techniques and attack chains from stored events |

## Project Structure

```
cloud-siem-grc-platform/
├── src/
│   ├── api/main.py             # FastAPI app, auth, rate limit, endpoints
│   ├── api/static/             # Dashboard: HTML, CSS, JS, self-hosted fonts
│   ├── collectors/
│   │   ├── aws_collector.py    # CloudTrail / Security Hub / GuardDuty
│   │   └── azure_collector.py  # Activity Log / Defender
│   ├── compliance/nist_engine.py
│   ├── threat_intel/
│   │   ├── engine.py           # VT / Shodan / AbuseIPDB enrichment
│   │   └── mitre_mapper.py     # ATT&CK mapping and attack chains
│   └── utils/
│       ├── config.py           # pydantic-settings configuration
│       ├── logging.py          # structlog setup, SecurityEvent
│       └── store.py            # SQLite persistence
├── tests/                      # unit + API tests (68)
├── scripts/demo.py             # offline demo
├── Dockerfile / docker-compose.yml
├── requirements.txt / setup.py / pytest.ini
└── README.md / PROJECT_INFO.md / QUICK_START.md / DEPLOYMENT.md / BEGINNER_GUIDE.md
```

## Testing

```bash
pytest                    # 68 tests
pytest --cov=src          # with coverage
```

API tests use an isolated SQLite file and blank API keys, so they never call the network.

## Production Notes

- Set `ENV=production`, `DEBUG=false` and a strong `API_KEY`; startup fails without the key.
- Terminate TLS at a reverse proxy. The app serves plain HTTP.
- SQLite is durable for a single instance with a mounted volume; use a managed database before
  scaling horizontally.
- Credentials should be read-only (`SecurityAudit` / `Reader`).

## License

MIT License

Typefaces: **Public Sans** and **IBM Plex Mono**, both under the SIL Open Font License 1.1.
License texts are in `src/api/static/fonts/`.

## Author

**Sansk** — Cybersecurity Analyst & Cloud Security Engineer

---

*Built as part of a cybersecurity portfolio demonstrating cloud security, SIEM engineering,
threat intelligence, and compliance automation.*
