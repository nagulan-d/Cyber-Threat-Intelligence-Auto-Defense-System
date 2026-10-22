# ThreatGuard

## Cyber Threat Intelligence & Auto-Defense Platform

[![CI](https://github.com/nagulan-d/Cyber-Threat-Intelligence-Auto-Defense-System/actions/workflows/ci.yml/badge.svg)](https://github.com/nagulan-d/Cyber-Threat-Intelligence-Auto-Defense-System/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=20232A)](https://react.dev/)

ThreatGuard is a full-stack cyber threat intelligence and automated defense platform. It collects threat indicators, enriches and scores them, presents actionable intelligence in a React dashboard, and can synchronize high-risk IP blocks across a Windows host and a Linux/Kali enforcement agent.

> **Security notice:** Never commit `.env` files, databases, API keys, SMTP passwords, JWT secrets, VM tokens, or private keys. Use the example environment files as templates and inject real values locally or through deployment secrets.

## Contents

- [What the project does](#what-the-project-does)
- [Key features](#key-features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Running the platform](#running-the-platform)
- [Automated IP defense](#automated-ip-defense)
- [Docker](#docker)
- [Validation](#validation)
- [Project structure](#project-structure)
- [Documentation](#documentation)
- [Security](#security)

## What the project does

ThreatGuard connects threat intelligence, risk analysis, user notifications, and defensive enforcement in one workflow:

1. Fetch indicators from AlienVault OTX.
2. Validate and normalize indicators.
3. Score threats and classify them by risk and category.
4. Display current intelligence in the React dashboard.
5. Notify subscribed users about high-risk activity.
6. Block malicious IPs on the Windows host.
7. Optionally synchronize blocks with a Linux/Kali VM.
8. Record actions, status, and audit information for administrators.

## Key features

### Threat intelligence

- AlienVault OTX indicator ingestion.
- IP extraction and indicator validation.
- Threat deduplication, categorization, and risk scoring.
- Current, recent, and high-risk threat views.
- Optional Gemini-powered summaries and prevention guidance.

### Defense automation

- Automatic blocking for threats above a configurable risk threshold.
- Windows Firewall inbound and outbound enforcement.
- Linux/Kali VM synchronization through REST and WebSocket services.
- Block and unblock workflows from the administrator dashboard.
- Configurable retry, timeout, and partial-failure behavior.

### Notifications and administration

- Email notifications for high-risk indicators.
- Email action links for subscribed users.
- Admin dashboard for users, alerts, blocks, and action logs.
- Subscription-aware threat detail views.
- JWT-based API authentication and optional security hardening.

### Engineering and operations

- Flask REST API with SQLAlchemy and migrations.
- React single-page application.
- CI checks for Ruff, Black, and the frontend production build.
- Docker Compose support for local containerized development.
- Environment-based configuration with safe example files.

## Screenshots

### Login experience

The repository includes the current login animation:

![ThreatGuard login experience](frontend/src/assets/loginpage.gif)

### Dashboard screenshots

Add dashboard captures to `readme/assets/` and reference them here when available:

```text
readme/assets/admin-dashboard.png
readme/assets/threat-details.png
readme/assets/block-management.png
readme/assets/user-dashboard.png
```

Recommended screenshots for a project presentation:

| Screenshot | What to show |
|---|---|
| Admin dashboard | Threat counts, risk distribution, and recent alerts |
| Threat details | Indicator metadata, score, category, and mitigation guidance |
| Block management | Active blocks, action history, and unblock controls |
| User dashboard | Notifications, subscription status, and user blocks |
| VM enforcement | Synchronized block status from the Linux/Kali agent |

## Architecture

```text
                         +----------------------+
                         |  AlienVault OTX      |
                         +----------+-----------+
                                    |
                                    v
+----------------+       +----------+-----------+       +------------------+
| React frontend | <----> | Flask threat API     | <---> | SQLite/Postgres  |
| localhost:3000 |  REST | localhost:5000       |       | SQLAlchemy       |
+--------+-------+       +----+----------+-------+       +------------------+
         |                    |          |
         |                    |          +--> Email notifications
         |                    |
         |                    +--> Windows Firewall
         |
         +--------------------------> Admin/user workflows
                                    |
                                    v
                         +----------+-----------+
                         | Linux/Kali VM agent  |
                         | REST + WebSocket     |
                         +----------------------+
```

## Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React 18, React Router, Framer Motion |
| Backend | Python, Flask, Flask-CORS, Flask-Mail |
| Data | SQLAlchemy, Flask-Migrate, SQLite by default |
| Intelligence | AlienVault OTX, optional Gemini integration |
| Enforcement | Windows Firewall, Linux/Kali iptables agent |
| Quality | Ruff, Black, React production build |
| Deployment | Docker, Docker Compose, GitHub Actions |

## Quick start

### Prerequisites

- Python 3.11 or newer
- Node.js 20 or newer and npm
- Windows Administrator access for local firewall enforcement
- Optional: AlienVault OTX API key
- Optional: Gemini API key
- Optional: SMTP app password for email notifications
- Optional: Linux/Kali VM for synchronized enforcement

### 1. Clone the repository

```powershell
git clone https://github.com/nagulan-d/Cyber-Threat-Intelligence-Auto-Defense-System.git
cd Cyber-Threat-Intelligence-Auto-Defense-System
```

### 2. Configure the backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `backend/.env` and provide the values required for your environment. At minimum, set a strong `SECRET_KEY` and `DEFAULT_ADMIN_PASSWORD`. Add OTX, Gemini, and mail settings only when you use those integrations.

Initialize the database:

```powershell
flask db upgrade
```

### 3. Configure the frontend

Open a second terminal:

```powershell
cd frontend
Copy-Item .env.example .env
npm ci
```

The frontend example configuration uses:

```text
REACT_APP_API_ORIGIN=http://127.0.0.1:5000
```

## Running the platform

### Start the backend

Run PowerShell as Administrator when Windows Firewall enforcement is enabled:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python app.py
```

The API is available at `http://127.0.0.1:5000`.

### Start the frontend

In a second terminal:

```powershell
cd frontend
npm start
```

The dashboard is available at `http://localhost:3000`.

### Optional background services

Run these in separate backend terminals when their functionality is enabled:

```powershell
cd backend
python websocket_server.py
python auto_block_monitor.py
```

The repository also includes `backend/start_all_services.ps1` and `backend/START_BACKEND_ADMIN.ps1` for Windows workflows.

### First login

Use the administrator username and password configured through environment variables. Do not use a shared or documented production password.

## Configuration

Copy the templates before adding local values:

| File | Purpose |
|---|---|
| [backend/.env.example](backend/.env.example) | Main Flask, mail, OTX, Gemini, and auto-blocking settings |
| [backend/.env.blocking-sync.example](backend/.env.blocking-sync.example) | Windows-to-Linux/Kali synchronization settings |
| [frontend/.env.example](frontend/.env.example) | React API origin |

Common settings include:

```text
SECRET_KEY=generate-a-long-random-value
DEFAULT_ADMIN_PASSWORD=generate-a-unique-password
API_KEY=your_otx_api_key
GEMINI_API_KEY=your_gemini_api_key
BLOCKING_API_TOKEN=generate-a-unique-token
```

Keep all real values in local `.env` files or a secret manager. The `.gitignore` rules exclude local environments, databases, tokens, logs, and generated output.

## Automated IP defense

When auto-blocking is enabled, ThreatGuard:

1. Selects indicators above `AUTO_BLOCK_THRESHOLD`.
2. Validates that the indicator contains a usable IP address.
3. Creates inbound and outbound Windows Firewall rules.
4. Sends the block to the Linux/Kali agent when configured.
5. Records the result and reports partial failures.

For a Kali agent setup, see:

- [Blocking agent guide](readme/BLOCKING_AGENT_GUIDE.md)
- [Deployment guide](readme/DEPLOYMENT_GUIDE.md)
- [IP blocking synchronization guide](readme/IP_BLOCKING_SYNC_IMPLEMENTATION.md)

Useful Kali checks:

```bash
sudo journalctl -u threatguard-agent -f
sudo iptables -S THREATGUARD
sudo iptables -L THREATGUARD -n -v --line-numbers
```

## Docker

From the repository root:

```powershell
docker compose up --build
```

To start only the frontend:

```powershell
docker compose up --build frontend
```

Review [docker-compose.yml](docker-compose.yml) and the deployment documentation before using containers for enforcement workloads.

## Validation

Backend checks:

```powershell
cd backend
ruff check .
black --check .
python -m compileall -q .
```

Frontend checks:

```powershell
cd frontend
$env:CI="true"
npm run build
```

GitHub Actions runs these checks automatically for pushes and pull requests. See [ci.yml](.github/workflows/ci.yml).

## Project structure

```text
.
├── backend/
│   ├── app.py                         Flask API and application routes
│   ├── models.py                      SQLAlchemy models
│   ├── threat_processor.py            Indicator parsing and validation
│   ├── scorer.py                      Threat risk scoring
│   ├── summarizer.py                  AI summaries and prevention guidance
│   ├── ip_blocker.py                  Windows Firewall enforcement
│   ├── blocking_sync_manager.py      Host/VM synchronization
│   ├── vm_agent/                      Linux/Kali enforcement agent
│   └── migrations/                    Database migrations
├── frontend/
│   ├── src/components/                React views and dashboard components
│   ├── src/config.js                  API configuration
│   └── public/                        Static frontend assets
├── readme/                            Detailed guides and technical notes
├── .github/workflows/ci.yml           Backend and frontend CI
├── docker-compose.yml                 Container orchestration
└── pyproject.toml                     Ruff and Black configuration
```

## Documentation

The [readme/](readme/) directory contains focused guides for:

- [Quick start](readme/QUICK_START.md)
- [Deployment](readme/DEPLOYMENT_GUIDE.md)
- [Admin dashboard](readme/ADMIN_DASHBOARD_AUTO_BLOCKING.md)
- [Auto-blocking](readme/AUTO_BLOCKING_GUIDE.md)
- [Real-time threat ingestion](readme/REALTIME_THREAT_FETCHER.md)
- [Testing](readme/QUICK_START_TESTING.md)
- [System workflow](readme/SYSTEM_WORKFLOW.md)
- [Technical architecture](readme/TECHNICAL_ARCHITECTURE.md)

## Security

Before publishing or deploying:

- Rotate any credential that may have appeared in an earlier local copy or Git history.
- Use unique, strong values for all secrets and administrator passwords.
- Never commit `.env`, database, token, certificate, or private-key files.
- Run the application with only the permissions it needs.
- Restrict VM synchronization endpoints to trusted networks.
- Keep Windows Firewall and Linux/Kali enforcement hosts patched.
- Review logs for failed authentication and synchronization attempts.

## Contributing

1. Create a feature branch.
2. Make focused changes.
3. Run the backend and frontend validation commands.
4. Confirm no secrets or generated databases are staged.
5. Open a pull request with a concise description and screenshots for UI changes.

## License

Add the project license that applies to your intended distribution before publishing a release.
