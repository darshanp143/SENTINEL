# SENTINEL — Phase 1
A local-first cybersecurity event monitor built with FastAPI and SQLite.

## Phase 1 scope
- FastAPI service with health and summary endpoints
- SQLite persistence via SQLAlchemy
- Event ingestion and event listing
- Rule-based detection for repeated failed logins and suspicious HTTP paths
- Alert listing and acknowledgement
- Unit/API tests with pytest

> Use only on systems and logs you own or are authorized to monitor. This starter ingests synthetic/local events; it does not perform offensive scanning.

## Requirements
- Windows 10/11
- Python 3.11 or 3.12 recommended
- PowerShell

## Install (PowerShell)
```powershell
cd sentinel-phase1
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks activation, run this in the current terminal:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If Python 3.12 is not installed, use `py -0p` to list installed versions and replace `-3.12` with a supported version.

## Run the API
```powershell
uvicorn app.main:app --reload
```
Open:
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health
- Summary: http://127.0.0.1:8000/api/v1/summary

## Quick smoke test
In another PowerShell window:
```powershell
$body = @{
  source = "demo-auth"
  event_type = "login_failed"
  severity = "medium"
  source_ip = "192.0.2.10"
  message = "Failed login for test-user"
  metadata = @{ username = "test-user" }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/events" `
  -ContentType "application/json" `
  -Body $body
```
Repeat the request at least five times with the same `source_ip` within 10 minutes. The detector should create a high-severity alert.

You can also ingest a suspicious path event:
```powershell
$body = @{
  source = "demo-web"
  event_type = "http_request"
  severity = "low"
  source_ip = "192.0.2.11"
  message = "Request to /../../etc/passwd"
  metadata = @{ path = "/../../etc/passwd"; status_code = 404 }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/events" -ContentType "application/json" -Body $body
```

## Test
```powershell
pytest -q
```
Tests use a temporary SQLite database and do not depend on a running server.

## API routes
- `GET /health`
- `GET /api/v1/summary`
- `POST /api/v1/events`
- `GET /api/v1/events?limit=50`
- `GET /api/v1/alerts?limit=50`
- `PATCH /api/v1/alerts/{alert_id}/acknowledge`

## Folder map
```text
sentinel-phase1/
├── app/
│   ├── __init__.py
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   ├── schemas.py
│   └── detection.py
├── tests/
│   └── test_api.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Current limitations
This is a development starter, not a production SIEM. It has no authentication, rate limiting, tenant isolation, or external log collectors yet. Do not expose it to the public internet. These controls and PostgreSQL migration are planned for later phases.
