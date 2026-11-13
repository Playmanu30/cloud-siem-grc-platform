# Quick Start Guide - Cloud SIEM & GRC Platform

Requires Python 3.12+.

## PART 1: Get Your Free API Keys (15 minutes)

### 1. VirusTotal API Key
1. Go to https://www.virustotal.com/gui/sign-in and sign up.
2. Open your profile (top-right) → **API Key** → copy it.

### 2. Shodan API Key
1. Register at https://account.shodan.io/register and verify your email.
2. Copy the API key shown on https://account.shodan.io/.

### 3. AbuseIPDB API Key
1. Register at https://www.abuseipdb.com/register.
2. Go to https://www.abuseipdb.com/account/api → **Create Key**.

### 4. (Optional) AWS read-only credentials
1. IAM → Users → Create user.
2. Attach `SecurityAudit` (read-only); do not use your root account.
3. Create an access key and copy the ID and secret.

### 5. (Optional) Azure read-only service principal
```bash
az login
az ad sp create-for-rbac --name cloud-siem-reader --role Reader
```
Copy `tenant`, `appId` (client id), `password` (client secret), plus your subscription id.

---

## PART 2: Configure the Platform (5 minutes)

```bash
cd cloud-siem-grc-platform
cp .env.example .env
notepad .env        # or any editor
```

Minimum useful configuration:

```env
ENV=development
DEBUG=true
VT_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

To use the API from another machine or in production, also set:

```env
ENV=production
API_KEY=<long-random-string>
CORS_ORIGINS=["https://your-frontend.example.com"]
```

`.env` is gitignored. Never commit real keys.

---

## PART 3: Run It (2 minutes)

```bash
# Activate the environment
venv\Scripts\activate           # Windows
# source venv/bin/activate      # macOS / Linux

# Offline demo (no keys or cloud accounts required)
python scripts/demo.py

# API server
python -m uvicorn src.api.main:app --reload --port 8000
```

- Dashboard: http://localhost:8000/ (triage, events, IOC lookup, compliance, ATT&CK)
- Swagger UI: http://localhost:8000/docs
- Health: http://localhost:8000/health

Run the tests at any time:

```bash
pytest
```

---

## PART 4: Use the API

### Interactive docs (easiest)

Open http://localhost:8000/ for the dashboard, or http://localhost:8000/docs, click an endpoint, **Try it out**, **Execute**. 
If `API_KEY` is set, click **Authorize** and enter the key (header `X-API-Key`).

### curl / PowerShell

```powershell
# Health and dashboard
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/dashboard

# Enrich an IP (requires at least one threat-intel key)
curl -X POST http://localhost:8000/api/v1/threat-intel/enrich `
  -H "Content-Type: application/json" `
  -d '{"type":"ip","value":"185.220.101.34"}'

# Batch enrichment (max 50)
curl -X POST http://localhost:8000/api/v1/threat-intel/enrich/batch `
  -H "Content-Type: application/json" `
  -d '{"iocs":[{"type":"ip","value":"8.8.8.8"},{"type":"domain","value":"example.com"}]}'

# Collect from configured cloud sources (last 1 hour by default)
curl -X POST "http://localhost:8000/api/v1/events/collect?sources=aws&sources=azure"

# Stored events / generated alerts
curl "http://localhost:8000/api/v1/events?severity=high"
curl "http://localhost:8000/api/v1/alerts"

# Acknowledge an alert
curl -X PATCH http://localhost:8000/api/v1/alerts/1 `
  -H "Content-Type: application/json" -d '{"status":"acknowledged"}'

# Compliance: pass a collected AWS snapshot, or omit it for a not-assessed report
curl -X POST http://localhost:8000/api/v1/compliance/assess `
  -H "Content-Type: application/json" -d "{}"
curl http://localhost:8000/api/v1/compliance/summary

# ATT&CK overview from stored CloudTrail events
curl http://localhost:8000/api/v1/mitre/tactics
curl http://localhost:8000/api/v1/mitre/report
```

With `API_KEY` configured, add the header to every `/api/v1` call:

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/dashboard
```

### Notes

- `POST /events/collect` returns `"status": "skipped"` with a reason when cloud credentials are
  missing; that is expected on a fresh install.
- Compliance controls are marked `not_assessed` unless you supply `aws_data`/`azure_data`
  (see `scripts/demo.py` for a realistic snapshot shape).
- IOC results are cached for 24 hours; VirusTotal is throttled to 4 requests/minute.

---

## PART 5: Capture Results for Your Portfolio

```powershell
python scripts/demo.py > demo_results.txt 2>&1
curl http://localhost:8000/api/v1/dashboard > dashboard.json
curl -X POST http://localhost:8000/api/v1/compliance/assess -H "Content-Type: application/json" -d "{}" > compliance.json
```

Suggested screenshots:

1. Security workspace (`/`)
2. Dashboard response or Swagger UI (`/docs`)
3. IOC enrichment result
4. Compliance assessment output
5. `demo.py` console output

---

## Troubleshooting

**`ModuleNotFoundError: pydantic_settings`**
```bash
pip install -r requirements.txt
```

**`RuntimeError: API_KEY must be set when ENV=production`** — set `API_KEY`, or use
`ENV=development` locally.

**`503 No threat-intelligence API keys configured`** — fill in at least one of `VT_API_KEY`,
`SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`.

**`429 Rate limit exceeded`** — lower your request rate or raise `RATE_LIMIT_RPM`.

**Port 8000 in use** — `python -m uvicorn src.api.main:app --port 8001`.

**`ModuleNotFoundError: src`** — run commands from the project root, or `pip install -e .`.

---

## Next Steps

1. Add the project to your resume/LinkedIn with the screenshots above.
2. Keep `.env` out of git and rotate any key that was ever committed.
3. Read `DEPLOYMENT.md` before exposing the API publicly.
