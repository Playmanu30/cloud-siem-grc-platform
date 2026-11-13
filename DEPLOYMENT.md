# Deployment Guide - Cloud SIEM & GRC Platform

## Current Status

Verified locally:

- `pytest` — 68 tests passing on Python 3.12 and 3.14
- `python scripts/demo.py` — runs offline with simulated data
- `uvicorn src.api.main:app` — dashboard, docs, health, compliance, enrichment, alerts and ATT&CK exercised in a browser
- Swagger UI and ReDoc render; typed schemas for every endpoint
- Dashboard checked at 1440, 768 and 390px with no console errors
- Docker build + compose configuration included (image build not run on this workstation)

Cloud log collection requires AWS/Azure credentials; threat-intelligence lookups require API keys.
Neither is required to start the API or run the tests.

## Local Development

Requires Python 3.12+ (`python_requires` in `setup.py`).

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

pip install -r requirements.txt
cp .env.example .env           # then edit .env
pytest
python scripts/demo.py
python -m uvicorn src.api.main:app --reload --port 8000
```

- Swagger UI: http://localhost:8000/docs
- Dashboard: http://localhost:8000/
- Health: http://localhost:8000/health

## Docker

The image runs as a non-root user and stores data in `/app/data`.

CI/CD (GitHub Actions) builds, smoke-tests and pushes the image to GHCR on every push
to `main` and on version tags (`v*`), so you can skip the local build:

```bash
docker pull ghcr.io/playmanu30/cloud-siem-grc-platform:latest
docker run -d -p 8000:8000 --env-file .env \
  -v platform-data:/app/data \
  ghcr.io/playmanu30/cloud-siem-grc-platform:latest
```

To build locally instead:

```bash
docker build -t cloud-siem-grc-platform .
docker run -d -p 8000:8000 --env-file .env \
  -v platform-data:/app/data \
  cloud-siem-grc-platform
```

### Docker Compose

`docker-compose.yml` runs the API in `ENV=production`, so it **requires `API_KEY`** in `.env`
and reuses the named `platform-data` volume for SQLite:

```bash
# .env
API_KEY=<long-random-string>
# clients must send: X-API-Key: <long-random-string>

docker compose up -d
docker compose logs -f
```

## Production Configuration

| Variable | Required | Notes |
|----------|----------|-------|
| `ENV=production` | yes | Enables fail-fast startup checks |
| `API_KEY` | yes in production | Sent by clients as `X-API-Key`; startup aborts if missing |
| `DEBUG=false` | yes | JSON logs |
| `DATABASE_URL` | no | Defaults to `sqlite:///…/data/platform.db` |
| `CORS_ORIGINS` | no | JSON list; set to your frontend origins only |
| `RATE_LIMIT_RPM` | no | Per-client requests/minute (default 100) |
| `MAX_BODY_BYTES` | no | Largest accepted request body (default 2 MB) |
| `AWS_*`, `AZURE_*` | for collection | Read-only security audit credentials recommended |
| `VT_API_KEY`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY` | for enrichment | Free tiers are rate limited |

### Security checklist

- [x] API-key authentication for every `/api/v1` route (`ENV=production` refuses to start without it)
- [x] Rate limiting per client IP
- [x] CORS limited to configured origins
- [x] Request-body cap and defensive response headers
- [x] Non-root container user
- [x] Secrets read from environment only; `.env` is gitignored
- [ ] Terminate TLS at a reverse proxy (nginx/Caddy/ALB); the app serves plain HTTP
  (or pass `--ssl-keyfile`/`--ssl-certfile` to Uvicorn if it terminates TLS itself)
- [ ] Use least-privilege, read-only AWS/Azure credentials (e.g. `SecurityAudit`)
- [ ] Back up the SQLite volume, or move to a managed database before multi-replica deployment
- [ ] Set `CORS_ORIGINS` and `API_KEY` before exposing `/docs` to an untrusted network

### Behind a reverse proxy

Rate limiting keys off the TCP peer address. When running behind a proxy, start Uvicorn with
trusted proxy headers so the real client IP is used:

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 \
  --proxy-headers --forwarded-allow-ips="10.0.0.10"
```

Do not set `--forwarded-allow-ips="*"` on a public host: clients could spoof `X-Forwarded-For` and
evade the limit.

### Data storage caveat

Storage is SQLite (WAL mode) with the schema created on startup. It is durable across restarts
on a single host or a mounted volume, but it is **not** suitable for multiple replicas or
serverless (Lambda). A Postgres backend would require a new `Store` implementation.

Back up the volume while the API is running with SQLite's online backup command:

```bash
# host install
sqlite3 /path/to/platform.db ".backup '/backups/platform-$(date +%F).db'"

# docker compose
docker compose exec api python -c "import sqlite3; sqlite3.connect('/app/data/platform.db').backup(sqlite3.connect('/app/data/backup.db'))"
```

## Platform notes

**AWS ECS / EC2 / Elastic Beanstalk** — build the Docker image, mount a persistent volume for
`/app/data`, and provide secrets through the task definition or parameter store.

**Azure App Service** — deploy the container; set `WEBSITES_PORT=8000` and the variables above;
mount persistent storage for `/app/data`.

**Google Cloud Run** — works for stateless requests, but `/app/data` is ephemeral. Mount a
persistent volume (or replace SQLite) before relying on stored events.

**AWS Lambda** — not supported as-is: SQLite persistence and in-process rate limiting assume a
long-running process.

## Monitoring

- `GET /health` — 200 when the database is reachable, 503 when degraded; use it for the
  container healthcheck or load-balancer probe.
- Logs are structured JSON on stdout (or readable console output when `DEBUG=true`); collect them
  with your platform's log driver.
- Watch upstream quotas for VirusTotal/Shodan/AbuseIPDB; the client caches IOC lookups for 24h and
  throttles VirusTotal to 4 requests/minute.

## CI

`.github/workflows/ci.yml` runs on every push and pull request: installs the pinned requirements on
Python 3.12 and runs `pytest --cov=src`.

## Troubleshooting

**`ModuleNotFoundError: pydantic_settings`** — `pip install -r requirements.txt` (the dependency is
declared there; older environments installed before this fix need a reinstall).

**`RuntimeError: API_KEY must be set when ENV=production`** — expected fail-fast; set `API_KEY` or
run with `ENV=development`.

**`API error: 401/403` on enrichment** — an API key is present but invalid or out of quota.

**Collection returns `skipped`** — cloud credentials are missing or incomplete; `/health` shows
which integrations are configured.

**`413 Request body too large`** — raise `MAX_BODY_BYTES` if you legitimately post a larger
compliance snapshot.

**Repeated collection creates duplicate alerts** — alerts are deduplicated per rule/message/severity
within an hour.

**Port already in use** — `uvicorn src.api.main:app --port 8001`.

## Next Steps

1. Configure read-only cloud credentials to enable collection.
2. Set `API_KEY` and `ENV=production` before exposing the API.
3. Put it behind TLS and restrict `CORS_ORIGINS`.
4. Add Slack/email alert delivery if you need push notifications (not implemented yet).
