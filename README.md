<div align="center">

<a href="https://github.com/your-repo/NovaShield_Final_Product">
  <img src="https://api.iconify.design/lucide:shield-check.svg?color=%23069f59&width=96" width="96" alt="NovaShield logo" />
</a>

# NovaShield AI-Powered Next-Generation Firewall

### Enterprise-style gateway security with WAF, AI threat classification, rate limiting, and live monitoring.

[![Rust](https://img.shields.io/badge/Rust-1.76-black?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=000)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-24-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5.0-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[**Quick start**](#-quick-start) · [**Features**](#-features) · [**Architecture**](#-architecture) · [**Components**](#-components) · [**Run locally**](#-run-locally) · [**Report**](#-report)

</div>

---

## ✨ What is NovaShield?

NovaShield is a full-stack security gateway demo built to protect a backend banking API using layered defenses:

- WAF regex detection for SQL injection, XSS, path traversal, and command injection
- AI threat classification service for suspicious requests
- Route-aware rate limiting and IP blacklist enforcement
- JWT authentication with admin RBAC
- Live monitoring dashboard powered by WebSocket streams

This project is designed as a deployable proof-of-concept for next-generation firewall functionality, not just a toy demo.

---

## 🎯 Highlights

- **Multi-layered defense**: blacklist → WAF → rate limit → auth → AI
- **AI enforcement**: FastAPI service exposes `/predict` for runtime threat classification
- **Live observability**: React dashboard receives event streams from the gateway
- **Docker Compose deployment**: Redis, AI engine, backend, gateway, dashboard
- **Realistic API flow**: login, balance, transfer, admin endpoints, metrics, snapshots
- **Interview-ready docs**: full architecture and design notes in `PROJECT_COMPLETE_DETAILS.txt`

---

## 🧱 Architecture

```mermaid
flowchart TB
  Client[Client / Browser]
  Gateway[Gateway (Rust / Axum)]
  Backend[Backend (Rust / Axum)]
  AI[AI Engine (Python / FastAPI)]
  Redis[Redis]
  Dashboard[Dashboard (React / Vite)]

  Client -->|HTTP traffic| Gateway
  Gateway -->|WAF / blacklist / rate limit / auth| Gateway
  Gateway -->|AI / predict| AI
  Gateway -->|Forward safe traffic| Backend
  Gateway -->|WebSocket events| Dashboard
  Redis -->|state + counters| Gateway
  Dashboard -->|snapshot + live events| Gateway
```

### Runtime components

- `gateway/` — Rust Axum gateway, security enforcement, proxying, admin API, metrics, WebSocket
- `backend/` — Rust Axum mock banking API with login, balance, transfer, and admin endpoints
- `ai_engine/` — Python FastAPI threat classifier using scikit-learn
- `dashboard/` — React + Vite monitoring UI with live event charting and logs
- `redis` — runtime storage for rate limits, blacklist, and telemetry

---

## 🚀 Quick start

> Requires Docker and Docker Compose.

```powershell
docker compose up --build
```

Or use Windows helper scripts:

```powershell
START_NOVASHIELD.bat
```

### Service ports

- `gateway`: `http://localhost:8080`
- `backend`: `http://localhost:8081`
- `ai_engine`: `http://localhost:8000`
- `dashboard`: `http://localhost`

---

## 🔧 Run locally

### Rust workspace

```powershell
cargo build --workspace
cargo test --workspace
```

### Dashboard

```powershell
cd dashboard
npm install
npm run build
```

### AI Engine

```powershell
cd ai_engine
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## 🛠️ Features

### Security enforcement
- Regex-based WAF for SQLi, XSS, path traversal, and command injection
- IP blacklist with runtime admin add/remove
- Route-specific rate limiting for login, transfer, balance, and default paths
- JWT authentication and admin RBAC
- Prometheus-style metrics and health endpoints

### AI threat classification
- FastAPI `/predict` endpoint for real-time request scoring
- Decision flow: `BENIGN` allow, else block with `AI_BLOCKED`
- Fail-open behavior when AI service is unavailable
- Feature order preserved with saved `features.pkl`

### Observability
- Live WebSocket event stream from gateway to dashboard
- Admin snapshot APIs for logs, metrics, and blacklist state
- Real-time counters and security events in UI

### Full-stack deployment
- Docker Compose orchestrates Redis, AI service, backend, gateway, dashboard
- `config/` contains environment-ready JSON configs for each service
- `PROJECT_COMPLETE_DETAILS.txt` documents architecture, flows, and implementation details

---

## 📦 Components

| Component | Purpose | Port |
|---|---|---|
| `gateway/` | Security gateway and proxy | `8080` |
| `backend/` | Mock backend banking API | `8081` |
| `ai_engine/` | ML threat classification service | `8000` |
| `dashboard/` | React monitoring UI | `80` |
| `redis` | Runtime state store | `6379` |

---

## 📚 Project structure

```
NovaShield_Final_Product/
├─ ai_engine/
│  ├─ Dockerfile
│  ├─ main.py
│  ├─ feature_extractor.py
│  ├─ model.py
│  ├─ requirements.txt
│  └─ model/
├─ backend/
│  └─ src/
├─ gateway/
│  └─ src/
├─ dashboard/
│  └─ src/
├─ shared/
│  └─ src/
├─ config/
├─ docker-compose.yml
├─ PROJECT_COMPLETE_DETAILS.txt
├─ README.md
├─ .gitignore
└─ tests/
```

---

## ✅ Notes

- The root `Cargo.toml` defines a Rust workspace for `backend`, `gateway`, and `shared`.
- `Cargo.lock` should be committed for workspace reproducibility.
- Keep generated artifacts out of Git using `.gitignore`.
- `PROJECT_COMPLETE_DETAILS.txt` contains the full technical report and interview-ready architecture notes.

---

<div align="center">

Built as a full-stack AI-powered firewall proof-of-concept with Rust, Python, React, and Docker.

</div>
