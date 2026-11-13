# Cloud SIEM & GRC Automation Platform — Project Info & Setup

> What this project is, how it works, why it exists, and how to set it up from scratch.
> Companion docs: `QUICK_START.md` (short path), `DEPLOYMENT.md` (production), `BEGINNER_GUIDE.md` (walkthrough).

---

## 1. What is this project?

A self-hosted **security monitoring dashboard + REST API** — a portfolio-grade SIEM
(Security Information & Event Management) and GRC (Governance, Risk, Compliance) tool that:

- **Pulls security events from your cloud accounts** — AWS (CloudTrail, Security Hub,
  GuardDuty) and Azure (Activity Log, Defender) — using read-only credentials.
- **Normalizes** all of that into one stream of security events in SQLite.
- **Maps events to MITRE ATT&CK** — the industry framework of attacker tactics ("what was
  the attacker trying to do") and techniques ("how did they do it"). An event like
  `CreateAccessKey` becomes *T1098 Account Manipulation → Persistence*.
- **Generates alerts** — high/critical events become a triage queue you can acknowledge/resolve.
- **Runs 25 automated NIST 800-53 Rev5 controls** — checks your AWS/Azure config
  (MFA on users? public S3 buckets? CloudTrail enabled? SSH open to the world?) and
  produces a compliance score.
- **Enriches indicators of compromise** — look up an IP, file hash, or domain against
  VirusTotal, Shodan and AbuseIPDB and get one combined risk score.
- **Detects attack chains** — if one source IP/user walks through 3+ ATT&CK tactics in
  the stored window, it is flagged as a multi-stage attack.

Two interfaces:

| Interface | URL | What it does |
|---|---|---|
| Dashboard | `/` | Triage queue, event explorer, compliance browser, ATT&CK matrix, IOC lookup |
| API | `/docs` | Swagger UI for 17 typed endpoints |

---

## 2. How it works

```
AWS / Azure (read-only creds)
        │  collectors (CloudTrail, GuardDuty, Security Hub, Activity Log)
        ▼
Normalized events → SQLite (WAL) → correlation + dedupe (60-min window)
        │
        ├─ MITRE mapper   → tactic/technique counts, attack chains
        ├─ Alert engine   → high/critical events → triage queue
        └─ Compliance     → 25 NIST 800-53 controls vs live cloud config
        ▼
FastAPI (17 typed endpoints, X-API-Key auth, rate limit, CORS)
        ├─ /         → dashboard UI (vanilla JS, self-hosted fonts, no CDN)
        └─ /docs     → OpenAPI/Swagger
```

**Key behaviors:**

- **Data flows one way: cloud → DB → views.** Nothing is auto-modified in AWS/Azure —
  the platform is read-only by design.
- **Collect is on-demand** (`POST /api/v1/events/collect` or the Collect button) —
  fetches the last hour and stores it.
- **Compliance is honest**: without a cloud snapshot it reports `not_assessed` instead
  of inventing passing scores.
- **Auth**: every `/api/v1/*` call needs the `X-API-Key` header (the dashboard asks for
  the key once and stores it in your browser). `ENV=production` refuses to start
  without `API_KEY` set.
- **Everything is config-driven from `.env`** — no YAML, no database server to install.
- Data persists in `data/platform.db` and survives restarts.

**Project layout (short):**

```
cloud-siem-grc-platform/
├── run.bat                     # one-command start (Windows)
├── src/
│   ├── api/main.py             # FastAPI app: auth, rate limit, 17 endpoints
│   ├── api/static/             # dashboard: HTML/CSS/JS + self-hosted fonts
│   ├── collectors/             # AWS + Azure collectors
│   ├── engines/                # MITRE mapper, alert rules, compliance
│   └── utils/                  # config (pydantic-settings), SQLite store
├── scripts/demo.py             # offline demo, no cloud needed
├── tests/                      # 68 unit + API tests
├── Dockerfile / docker-compose.yml
├── .env.example                # every setting, commented
└── requirements.txt            # pinned dependencies
```

---

## 3. Why you need this

- **Visibility** — cloud consoles show you *what happened*; this shows you *what it
  means* (ATT&CK mapping) and *what to do now* (triage queue).
- **Compliance without the spreadsheet** — NIST 800-53 checks run continuously instead
  of during an audit panic.
- **One place for AWS + Azure** — one normalized event stream instead of two consoles.
- **Practical skills** — it exercises exactly the tooling cloud-security roles use:
  collectors, normalization, correlation, ATT&CK, control frameworks, API hardening —
  which is why it works as a portfolio piece.
- **Cost** — SQLite + Python, no infrastructure. Runs on a laptop.

---

## 4. Setup from scratch

### Requirements

- **Python 3.12 or newer** (check: `python --version`)
- Windows / macOS / Linux. Nothing else — no Docker, no database server.

### Option A — one command (Windows)

```bat
cd E:\Chatbots-Ai\cybersecurity-portfolio\cloud-siem-grc-platform
run.bat
```

`run.bat` does everything on first run:

1. Creates `venv` and installs pinned dependencies from `requirements.txt`
2. Copies `.env.example` → `.env` if you don't have one
3. Starts the server on **http://localhost:8000** (use a different port with `set PORT=8001` first)
4. Fails with a clear message if the port is already taken (tells you the PID to kill)

Stop the server with **Ctrl+C**.

### Option B — manual (any OS)

```bash
cd cloud-siem-grc-platform
python -m venv venv
venv\Scripts\python -m pip install -r requirements.txt      # Windows
# source venv/bin/activate && pip install -r requirements.txt   # macOS/Linux
copy .env.example .env                                      # Windows (cp on *nix)
venv\Scripts\python -m uvicorn src.api.main:app --port 8000
```

### 4.1 Configure `.env` (optional — it runs fine without)

Edit `.env` and fill in what you want:

| Setting | Purpose | Needed? |
|---|---|---|
| `ENV=development` | dev = open start; `production` refuses without `API_KEY` | always |
| `API_KEY` | the key for API/dashboard auth (sent as `X-API-Key`) | yes in production |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` | CloudTrail/GuardDuty/Security Hub collection | for AWS events |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_SUBSCRIPTION_ID` | Activity Log/Defender collection | for Azure events |
| `VT_API_KEY` / `SHODAN_API_KEY` / `ABUSEIPDB_API_KEY` | IOC enrichment (free tiers work) | for threat intel |

- AWS: access key of a **read-only** IAM user.
- Azure: app registration with a secret and a *Security Reader*-equivalent role.
- Details and exact role names: `QUICK_START.md`, `DEPLOYMENT.md`.

### 4.2 Use it

1. Open **http://localhost:8000/** → paste your `API_KEY` when asked
   (dialog in the sidebar; skip if you didn't set one).
2. Click **Collect events** → alerts, events and the ATT&CK matrix populate.
3. For the compliance score with real data: click **Run assessment**, or
   `POST /api/v1/compliance/assess` with `aws_data`/`azure_data` snapshots
   (`scripts/demo.py` shows the snapshot shape).
4. Try **Threat intel**: look up `185.220.101.34` (IP), `44d88612fea8a8f36de82e1278abb02f`
   (hash) or any domain — needs at least one intel key in `.env`.

### 4.3 Sanity checks

```bat
venv\Scripts\python.exe -m pytest     # 68 tests should pass
python scripts\demo.py                # offline demo, no cloud needed
```

### 4.4 Deploying (later)

- `Dockerfile` (non-root, healthcheck) and `docker-compose.yml` are provided, but
  **never built on this machine** (no Docker installed). Verify on a Docker-capable
  machine: `docker build -t cloud-siem-grc-platform .` then `docker compose up`.
- Production notes (reverse proxy, TLS, backups, key rotation): `DEPLOYMENT.md`.

---

## 5. Known limits & cautions

| Limit | Detail |
|---|---|
| Single node | SQLite only; Postgres support is documented but not implemented |
| No notification delivery | Alerts live in the queue; no email/Slack/PagerDuty yet |
| On-demand collection | No streaming; run Collect or schedule it yourself |
| Docker | Built + smoke-tested by CI on every push to `main`; not built on this workstation (no Docker installed) |
| `data/` is not committed | The SQLite file is local; back it up yourself (`DEPLOYMENT.md` has the steps) |
| Browser-stored API key | The dashboard keeps your key in `localStorage` for convenience — rotate `API_KEY` periodically |
| Rotate local intel keys | The `.env` on this machine holds real VirusTotal/Shodan/AbuseIPDB keys — rotate them before sharing |

---

## 6. Status

- **68 tests passing** (Python 3.12 and 3.14)
- Live smoke-tested: all 17 endpoints, auth (401/200), rate limit, security headers
- Dashboard checked at 1440 / 768 / 390 px, zero console errors
- License: MIT. Fonts: Public Sans + IBM Plex Mono (OFL 1.1, licenses included in
  `src/api/static/fonts/`).
