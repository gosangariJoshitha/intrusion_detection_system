# ML-Based Real-Time Adaptive Intrusion Detection System (AIDS)

A fully-functional, real-time defensive cybersecurity platform that continuously observes live network traffic, extracts network-flow features, applies machine learning and anomaly detection models, and generates real-time security alerts on an interactive dashboard.

## Overview
This system was built to satisfy all MVP and Advanced Scope requirements outlined in the PRD. It transitions from traditional signature-based detection to a dynamic, self-learning AI-based approach capable of detecting zero-day threats via Hybrid ML (Random Forest for known threats, Isolation Forest for zero-day anomalies).

## Features

- **Live Packet Capture & Feature Extraction**: A standalone Python agent (`live_agent.py`) using `scapy` to sniff actual network traffic, extracting true IP addresses, extracting Domain/URLs from HTTP/DNS, and calculating live flow statistics (bytes, packet counts, etc.).
- **Hybrid Machine Learning Engine**: 
  - *Random Forest Classifier*: Pre-trained on NSL-KDD to detect and classify known attack families (DoS, Probe, U2R, R2L).
  - *Isolation Forest*: Runs in parallel to flag statistically anomalous behavior (Zero-Day detection).
- **Explainable AI (XAI)**: SHAP integration breaks down exactly which network features contributed to the model's decision, presenting human-readable evidence for the analyst.
- **Threat Intelligence Enrichment**: Deterministic IP profiling, tagging, and geolocation simulation.
- **Incident Correlation**: Automatically groups related alerts (by IP and attack type) into overarching Incidents that analysts can track through a lifecycle (New, Investigating, Contained, Resolved).
- **Model Drift & Incremental Retraining**: The backend tracks statistical drift in traffic distributions. When data drift reaches critical levels, the system prompts the analyst to trigger a seamless hot-reload retraining pipeline using analyst-corrected labels!
- **Automated Responses & Audit Trail**: Analysts can simulate blocking malicious IPs with a single click. A persistent, immutable `AuditLog` tracks every action, status change, and system operation.
- **Real-Time Interactive Dashboard**: A premium, dark-mode dashboard providing live WebSocket streams of network events, dynamic charts, health monitoring, and in-depth IP investigation modals.

## Quick Start

### 1. Backend Server
The backend is powered by FastAPI and SQLAlchemy (SQLite).
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Live Capture Agent
To capture real traffic on your host machine, run the agent in a separate terminal. (Requires Npcap on Windows).
```bash
cd backend
python live_agent.py
```
*(Note: If Npcap is missing, the agent will gracefully fall back to a mock traffic generator to keep the dashboard alive).*

### 3. Frontend Dashboard
The frontend is a lightweight Vanilla JS/HTML/CSS application.
```bash
cd frontend
python -m http.server 3000
```
Navigate to `http://localhost:3000` in your browser. Ensure the connection bar is pointing to `http://localhost:8000` and switch the toggle to **Live capture**!

## Architecture
- **Frontend**: HTML5, CSS3, Vanilla JS, WebSockets.
- **Backend API**: Python, FastAPI, WebSockets, Uvicorn.
- **Database**: SQLite (SQLAlchemy ORM).
- **Machine Learning**: Scikit-Learn (RandomForest, IsolationForest), SHAP, Joblib.
- **Network Capture**: Scapy.
