# 🎓 Beginner's Guide to Cloud SIEM & GRC Platform

Welcome! This guide explains the project in simple terms, from basics to deployment.

---

## 📚 Table of Contents
1. [What is this project?](#what-is-this-project)
2. [Key concepts explained](#key-concepts)
3. [What each part does](#project-parts)
4. [How to get started](#getting-started)
5. [Running the project](#running-the-project)
6. [Testing the API](#testing-the-api)
7. [Troubleshooting](#troubleshooting)

---

## What is this project?

This is a **Security Monitoring Platform** - think of it as a security guard for your cloud systems.

### Simple Analogy
Imagine you have a house with multiple doors (AWS, Azure, cloud services):
- **SIEM** = Security cameras watching all doors for suspicious activity
- **GRC** = Checklist ensuring your house follows security rules
- **This Platform** = A dashboard that combines camera feeds + checklist status + alerts

### What problems does it solve?
1. **Too many security logs** - Hard to track events across multiple cloud providers
2. **Security threats** - Need to quickly identify malicious IPs and threats
3. **Compliance** - Must prove your systems follow security standards (NIST 800-53)
4. **Attack detection** - Identify attack patterns and tactics

---

## Key Concepts

### 1. SIEM (Security Information and Event Management)
**What it means:** A system that collects, analyzes, and alerts on security events

**Simple example:**
```
AWS CloudTrail logs   ┐
Azure Activity logs   ┼→  SIEM  →  Alerts & API
Threat intel feeds    ┘
```

### 2. GRC (Governance, Risk, Compliance)
**What it means:** Ensuring systems follow rules and regulations

**Simple example:**
- **Governance**: "Who can access what?"
- **Risk**: "What bad things could happen?"
- **Compliance**: "Are we following NIST 800-53 rules?"

### 3. IOC (Indicators of Compromise)
**What it means:** Suspicious stuff that might indicate a cyber attack
- Malicious IP addresses
- Domain names used by hackers
- File hashes of malware

### 4. MITRE ATT&CK
**What it means:** A framework that lists all known attack techniques

**Example:**
```
Attacker Action          → MITRE Tactic      → Technique
"Steal user password"    → Credential Access → Brute Force
"Delete logs"            → Defense Evasion   → Clear Logs
```

### 5. NIST 800-53
**What it means:** Official US government security standards

**Example controls:**
- "Encrypt data at rest"
- "Log all user actions"
- "Require password changes every 90 days"

### 6. REST API (Application Programming Interface)
**What it means:** A way for programs to talk to each other over the internet

**Simple example:**
```
Your Browser/Script  →  HTTP Request  →  Our Server
                        "GET /health"
                    ←  JSON Response  ←
                    {"status":"healthy"}
```

---

## Project Parts

### Part 1: Data Collection (Collectors)
**What it does:** Gathers security logs from cloud providers

```
AWS Collector    →  Reads CloudTrail logs
                 →  Reads GuardDuty alerts
                 →  Reads SecurityHub findings

Azure Collector  →  Reads Activity logs
                 →  Reads Defender alerts
                 →  Reads Compliance status
```

### Part 2: Threat Intelligence (Enrichment)
**What it does:** Checks suspicious IPs/domains against threat databases

```
You ask: "Is 8.8.8.8 dangerous?"
         ↓
System checks: VirusTotal, Shodan, AbuseIPDB
         ↓
Response: "Risk Score: 45/100, Flagged in X reports"
```

### Part 3: Compliance Engine
**What it does:** Checks if your systems follow NIST 800-53 rules

```
Questions checked:
✓ "Is encryption enabled?"
✓ "Are logs being collected?"
✓ "Are admins restricted?"
✓ "Is MFA enabled?"
         ↓
Result: "Compliance Score: 78%"
```

### Part 4: MITRE ATT&CK Mapper
**What it does:** Identifies attack techniques used in your logs

```
Log: "User logged in from 5 different countries in 1 hour"
     ↓
Identifies: "This is Lateral Movement - MITRE T1570"
     ↓
Alert: "Suspicious lateral movement detected"
```

### Part 5: REST API
**What it does:** Exposes all features through HTTP endpoints

```
Endpoints available:
GET    /health                    → Check if system is running
GET    /api/v1/dashboard          → Get security overview
POST   /api/v1/threat-intel/enrich → Check if IP is dangerous
POST   /api/v1/compliance/assess  → Run compliance check
GET    /api/v1/mitre/tactics      → View attack tactics
```

---

## Getting Started

### Prerequisites (What you need)
- **Python 3.12+** - Programming language
- **pip** - Package installer for Python
- **Git** - Version control
- **API Keys** - Free threat intelligence keys

### Step 1: Check Python Installation

Open Command Prompt and type:
```bash
python --version
```

**Expected output:**
```
Python 3.12.x or higher
```

If not installed, download from: https://www.python.org/

### Step 2: Navigate to Project

```bash
cd E:\Chatbots-Ai\cybersecurity-portfolio\cloud-siem-grc-platform
```

### Step 3: Create Virtual Environment

Virtual environment = Isolated Python setup for this project

```bash
python -m venv venv
```

Activate it:
```bash
# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

### Step 4: Install Dependencies

Dependencies = Libraries/packages the project needs

```bash
pip install -r requirements.txt
```

**What gets installed:**
- **FastAPI** - Framework for building APIs
- **Uvicorn** - Server to run the API
- **boto3** - AWS SDK
- **azure-identity** - Azure SDK
- **requests** - HTTP requests library

### Step 5: Get Free API Keys (Optional but Recommended)

#### VirusTotal (Check if files/IPs are malicious)
1. Go to https://www.virustotal.com/gui/sign-in
2. Click "Sign Up" → Use Google or create account
3. Login → Click profile (top-right) → API Key
4. Copy the key

#### Shodan (Find exposed services)
1. Go to https://account.shodan.io/register
2. Sign up with email
3. Verify email
4. Login → Account page shows your API key

#### AbuseIPDB (Check reported malicious IPs)
1. Go to https://www.abuseipdb.com/register
2. Sign up and verify email
3. Login → Go to API → Create Key

### Step 6: Configure .env File

The `.env` file stores your API keys (like a password file)

```bash
# Open the .env file
notepad .env
```

Add your keys:
```env
# Threat Intelligence (Required for full features)
VT_API_KEY=your_virustotal_key_here
SHODAN_API_KEY=your_shodan_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# AWS (Optional - if you have AWS account)
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret

# Azure (Optional - if you have Azure account)
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_secret

# Application Settings (Keep as-is for now)
ENV=development
DEBUG=true
# Required only when ENV=production
API_KEY=change-me-to-a-long-random-string
```

Save the file (Ctrl+S).

---

## Running the Project

### Method 1: Start the API Server (Recommended)

```bash
python -m uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

**What this does:**
- `uvicorn` = Starts the web server
- `src.api.main:app` = Tells it which app to run
- `--reload` = Auto-restarts when you change code
- `--host 0.0.0.0` = Makes it accessible from anywhere
- `--port 8000` = Uses port 8000

**Expected output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

### Method 2: Run Demo Script (Quick Test)

```bash
python scripts/demo.py
```

This runs predefined tests to show all features working.

### Method 3: Run Tests

```bash
pytest tests/ -v
```

This verifies everything works correctly.

---

## Testing the API

### Option A: Security workspace or Swagger (Easiest)

1. Open web browser
2. Go to **http://localhost:8000/** for the dashboard (triage, events, IOC lookup, compliance, ATT&CK)
3. Go to **http://localhost:8000/docs** for Swagger UI with all endpoints

### Option B: Command Line

Open Command Prompt and test endpoints:

#### Test 1: Health Check
```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "services": {
    "database": "up",
    "aws_collector": "not_configured",
    "threat_intel": "configured",
    "compliance_engine": "ready"
  }
}
```

**What it means:** Your API is running fine ✅

#### Test 2: Get Dashboard
```bash
curl http://localhost:8000/api/v1/dashboard
```

**Response:**
```json
{
  "total_events": 0,
  "total_alerts": 0,
  "critical_alerts": 0,
  "compliance_score": 0.0,
  "active_threats": 0,
  "top_source_ips": [],
  "recent_events": []
}
```

**What it means:** Overview of your security status

#### Test 3: Check if IP is Dangerous
```bash
curl -X POST http://localhost:8000/api/v1/threat-intel/enrich ^
  -H "Content-Type: application/json" ^
  -d "{\"type\":\"ip\",\"value\":\"8.8.8.8\"}"
```

**Response (abridged):**
```json
{
  "ip": "8.8.8.8",
  "sources": {
    "virustotal": {"malicious_count": 0, "risk_score": 0},
    "shodan": {"open_ports": [53], "vulns": []},
    "abuseipdb": {"abuse_confidence_score": 0, "total_reports": 0}
  },
  "aggregate_risk_score": 0.0,
  "risk_level": "info"
}
```

**What it means:** IP 8.8.8.8 shows no malicious signals (Google DNS)

#### Test 4: Run Compliance Check
```bash
curl -X POST http://localhost:8000/api/v1/compliance/assess ^
  -H "Content-Type: application/json" ^
  -d "{}"
```

**Response (abridged):**
```json
{
  "compliance_score": 0.0,
  "total_controls": 25,
  "status_summary": {"not_assessed": 25},
  "data_sources": {"aws": false, "azure": false}
}
```

**What it means:** Without a cloud data snapshot the engine reports `not_assessed` rather than
inventing a score. Pass `aws_data` (see `scripts/demo.py`) for a real assessment.

**What it means:** Your system passes 78.5% of security standards

---

## Understanding the Responses

### JSON Format

All responses are in **JSON** format:
```json
{
  "key1": "value1",
  "key2": 123,
  "key3": true,
  "nested": {
    "key4": "value4"
  }
}
```

### Common Fields Explained

| Field | Meaning | Example |
|-------|---------|---------|
| `status` | Is it working? | `"healthy"`, `"error"` |
| `risk_score` | How dangerous (0-100)? | `45` = Medium risk |
| `compliance_score` | % of rules followed | `78.5` = 78.5% compliant |
| `timestamp` | When was this checked? | `"2026-10-17T14:08:04"` |
| `error` | What went wrong? | `"API key invalid"` |

---

## Project Structure

```
cloud-siem-grc-platform/
├── src/                              # Main code
│   ├── api/
│   │   └── main.py                  # API endpoints (REST API)
│   ├── collectors/
│   │   ├── aws_collector.py         # Reads AWS logs
│   │   └── azure_collector.py       # Reads Azure logs
│   ├── compliance/
│   │   └── nist_engine.py           # Checks NIST rules
│   ├── threat_intel/
│   │   ├── engine.py                # VirusTotal/Shodan/AbuseIPDB
│   │   └── mitre_mapper.py          # Maps attacks to MITRE
│   └── utils/
│       └── config.py                # Configuration settings
│
├── tests/                            # Test files
├── scripts/
│   └── demo.py                      # Demo script
│
├── .env                              # Your API keys (SECRET!)
├── .env.example                      # Template for .env
├── requirements.txt                  # Python dependencies
├── README.md                         # Project overview
└── BEGINNER_GUIDE.md                # This file!
```

**Key files explained:**
- `main.py` = Where API endpoints are defined
- `requirements.txt` = List of packages to install
- `.env` = Your secrets (don't share!)

---

## Troubleshooting

### Issue 1: "Python not found"
**Problem:** Command prompt doesn't recognize `python`

**Solution:**
1. Go to https://www.python.org/
2. Download and install (check "Add Python to PATH")
3. Restart command prompt

---

### Issue 2: "Port 8000 already in use"
**Problem:** Another program is using port 8000

**Solution - Option A:** Use different port
```bash
python -m uvicorn src.api.main:app --port 8001
# Now access http://localhost:8001
```

**Solution - Option B:** Kill the process using port 8000
```bash
# On Windows
tasklist | findstr uvicorn
taskkill /PID <PID_NUMBER> /F
```

---

### Issue 3: "ModuleNotFoundError: No module named 'src'"
**Problem:** Python can't find your code

**Solution:**
```bash
# Make sure you're in the right directory
cd E:\Chatbots-Ai\cybersecurity-portfolio\cloud-siem-grc-platform

# Check if venv is activated (should see (venv) in prompt)
# If not:
venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt
```

---

### Issue 4: "API keys not working"
**Problem:** Threat intel enrichment returns errors

**Solution:**
1. Check your `.env` file has the keys
2. Verify keys are correct (copy-paste carefully)
3. Test key validity:
```bash
python -c "from src.utils.config import settings; print(settings.vt_api_key)"
```

---

### Issue 5: "ImportError: No module named 'fastapi'"
**Problem:** Dependencies not installed

**Solution:**
```bash
# Activate virtual environment first
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
pip list
```

---

## Common HTTP Status Codes

When you call an endpoint, you get a status code:

| Code | Meaning | Example |
|------|---------|---------|
| `200` | Success ✅ | Request worked |
| `400` | Bad request ❌ | Wrong format |
| `401` | Unauthorized ❌ | Invalid API key |
| `404` | Not found ❌ | Endpoint doesn't exist |
| `500` | Server error ❌ | Something broke on server |

---

## What Each Endpoint Does

### Health Check
```
GET /health
Purpose: Check if server is running
Returns: Status of all services
```

### Dashboard
```
GET /api/v1/dashboard
Purpose: Get security overview
Returns: Total alerts, compliance score, active threats
```

### Enrich Single IOC
```
POST /api/v1/threat-intel/enrich
Purpose: Check if one IP/domain/hash is dangerous
Input: IOC (IP address, domain, file hash)
Returns: Risk score, source alerts, reputation
```

### Batch Enrich
```
POST /api/v1/threat-intel/enrich/batch
Purpose: Check multiple IOCs at once
Input: List of IOCs
Returns: Results for each IOC
```

### Compliance Assessment
```
POST /api/v1/compliance/assess
Purpose: Run NIST 800-53 compliance checks
Input: None (uses your system settings)
Returns: Compliance score, passed/failed controls, findings
```

### MITRE ATT&CK Tactics
```
GET /api/v1/mitre/tactics
Purpose: View all MITRE attack tactics
Returns: List of tactics and techniques
```

---

## Next Steps

### 1. Explore the Web Interface
Open http://localhost:8000/docs and try clicking different endpoints

### 2. Run the Demo
```bash
python scripts/demo.py
```

### 3. Read the API Docs
Open http://localhost:8000/redoc for detailed documentation

### 4. Test with Real Data
- Replace test IPs with real malicious IPs
- Connect your actual AWS/Azure account
- Run actual compliance checks

### 5. Integrate into Portfolio
- Document what you learned
- Screenshot the results
- Add to GitHub
- Update resume

---

## Key Takeaways

✅ **SIEM** = Aggregates security logs from multiple sources
✅ **GRC** = Ensures compliance with security standards
✅ **Threat Intel** = Checks if IPs/files are dangerous
✅ **MITRE ATT&CK** = Identifies attack techniques
✅ **REST API** = Provides programmatic access to all features
✅ **This project** = Combines all of the above into one platform

---

## Need Help?

### Common Issues Resources
1. Check the [DEPLOYMENT.md](DEPLOYMENT.md) for advanced setup
2. Check the [README.md](README.md) for technical details
3. Check logs for error messages:
```bash
# View recent API logs
tail -f logs/api.log
```

### Learning Resources
- FastAPI Docs: https://fastapi.tiangolo.com/
- NIST 800-53: https://csrc.nist.gov/publications/fips/
- MITRE ATT&CK: https://attack.mitre.org/
- REST APIs: https://restfulapi.net/

---

## Glossary

| Term | Simple Definition |
|------|-------------------|
| **API** | Way for programs to talk to each other |
| **JSON** | Format for data (like a template) |
| **IOC** | Suspicious thing that might be hacked |
| **Endpoint** | URL path for a specific action |
| **Request** | Question you ask the server |
| **Response** | Answer the server gives back |
| **Status Code** | Number telling if request worked (200=yes, 404=no) |
| **Header** | Extra info about the request |
| **Body** | Main data in request/response |
| **HTTP** | Protocol for web communication |
| **HTTPS** | HTTP + encrypted (secure) |
| **Port** | Door on server (8000, 443, etc.) |
| **Localhost** | Your own computer (127.0.0.1) |
| **Virtual Environment** | Isolated Python setup for this project |
| **Dependency** | Library/package code needs to work |
| **Framework** | Pre-built code structure to build on |
| **Server** | Computer that handles requests |
| **Client** | Your browser or script making requests |

---

## Success Checklist

- [ ] Python installed (version 3.12+)
- [ ] Project downloaded
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] .env file configured with API keys
- [ ] API server running (`python -m uvicorn src.api.main:app --reload`)
- [ ] Health check works (`http://localhost:8000/health`)
- [ ] Swagger UI accessible (`http://localhost:8000/docs`)
- [ ] Tested at least one endpoint
- [ ] Can explain what each part does

---

**Congratulations! You now understand the Cloud SIEM & GRC Platform! 🎉**

Start exploring the API at: **http://localhost:8000/docs**

---

*Last Updated: 2026-10-17*
*Created for beginners transitioning into cybersecurity*
