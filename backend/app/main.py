import asyncio
import hashlib
import json
import os
import time
import uuid
import datetime
from collections import deque
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.model_utils import predict_record
from app.simulator import generate_event
from app.database import engine, Base, get_db, SessionLocal
from app.models import Event, Incident, AuditLog
from app.retrain import run_retraining_pipeline
from app.model_utils import reload_models

Base.metadata.create_all(bind=engine)

BLOCKED_IPS = set()

def log_audit(db: Session, actor: str, action: str, target: str, reason: str, status: str = "Success"):
    log = AuditLog(actor=actor, action=action, target=target, reason=reason, status=status)
    db.add(log)
    db.commit()

MODEL_METRICS_PATH = os.path.join(os.path.dirname(__file__), "..", "artifacts", "metrics.json")
try:
    with open(MODEL_METRICS_PATH) as f:
        MODEL_METRICS = json.load(f)
except FileNotFoundError:
    MODEL_METRICS = {"binary_accuracy": None, "multiclass_accuracy": None}

app = FastAPI(title="AIDS — Adaptive Intrusion Detection System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATE = {
    "mode": "simulated",
    "clients": [],
    "event_count": 0,
    "intrusion_count": 0,
    "start_time": time.time(),
    "confidence_sum": 0.0,
    "confidence_count": 0,
    "recent_event_times": deque(maxlen=500),
    "recent_intrusion_times": deque(maxlen=500),
    "category_tally": {},
}

BASELINE_DISTRIBUTION = {
    "Normal": 0.46,
    "DoS": 0.23,
    "Probe": 0.15,
    "R2L": 0.08,
    "U2R": 0.04,
    "Zero-Day/Unknown": 0.04
}

def calculate_drift_score():
    total_events = STATE["event_count"]
    if total_events < 20:
        return 0.0, "OK"
        
    live_dist = {}
    normal_count = total_events - STATE["intrusion_count"]
    live_dist["Normal"] = normal_count / total_events
    for cat in BASELINE_DISTRIBUTION:
        if cat != "Normal":
            live_dist[cat] = STATE["category_tally"].get(cat, 0) / total_events
            
    drift_sum = sum(abs(live_dist.get(c, 0) - expected) for c, expected in BASELINE_DISTRIBUTION.items())
    drift_score = min(100.0, (drift_sum / 2.0) * 100 * 2.0) 
    
    if drift_score > 30:
        return drift_score, "CRITICAL"
    elif drift_score > 15:
        return drift_score, "WARNING"
    return drift_score, "OK"

def _rate_per_minute(dq: deque):
    now = time.time()
    cutoff = now - 60
    while dq and dq[0] < cutoff:
        dq.popleft()
    return len(dq)

async def broadcast(payload: dict):
    dead = []
    for ws in STATE["clients"]:
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in STATE["clients"]:
            STATE["clients"].remove(ws)

def sev_for_event(status: str, attack_type: Optional[str]):
    if status == 'Normal':
        return 'NONE'
    if attack_type in ['DoS', 'R2L', 'U2R']:
        return 'CRITICAL'
    return 'LOW'

def score_and_package(raw_record: dict, source_ip: str, dest_ip: str, protocol: str, origin: str, db: Session, url: str = None):
    result = predict_record(raw_record)
    anomaly_score = result.get("anomaly_score", 0.0)
    is_anomaly = result.get("is_anomaly", False)
    
    # Hybrid scoring logic
    if result["binary_label"] == "Attack":
        status = "Intrusion"
        severity = "HIGH" if result["category_confidence"] > 80 else "MEDIUM"
        attack_type = result["attack_category"]
        confidence = result["category_confidence"]
    elif is_anomaly:
        status = "Anomaly"
        severity = "MEDIUM"
        attack_type = "Zero-Day/Unknown"
        confidence = anomaly_score
    else:
        status = "Normal"
        severity = "LOW"
        attack_type = None
        confidence = result["binary_confidence"]

    now = time.time()
    STATE["event_count"] += 1
    STATE["confidence_sum"] += result["binary_confidence"]
    STATE["confidence_count"] += 1
    STATE["recent_event_times"].append(now)
    
    incident_id = None

    if status != "Normal":
        STATE["intrusion_count"] += 1
        STATE["recent_intrusion_times"].append(now)
        cat = attack_type
        STATE["category_tally"][cat] = STATE["category_tally"].get(cat, 0) + 1
        
        recent_cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        incident = db.query(Incident).filter(
            Incident.source_ip == source_ip,
            Incident.attack_type == attack_type,
            Incident.status.in_(["New", "Investigating", "Contained"]),
            Incident.updated_at >= recent_cutoff
        ).first()
        
        if not incident:
            incident = Incident(
                source_ip=source_ip,
                attack_type=attack_type,
                severity=severity
            )
            db.add(incident)
            db.commit()
            db.refresh(incident)
        else:
            incident.updated_at = datetime.datetime.utcnow()
            if severity == 'CRITICAL' and incident.severity != 'CRITICAL':
                incident.severity = 'CRITICAL'
            db.commit()
            
        incident_id = incident.id

    event_id = str(uuid.uuid4())[:8]

    db_event = Event(
        id=event_id,
        source_ip=source_ip,
        dest_ip=dest_ip,
        protocol=protocol,
        status=status,
        attack_type=attack_type,
        confidence=confidence,
        severity=severity,
        origin=origin,
        incident_id=incident_id,
        raw_features=json.dumps(raw_record),
        url=url,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly
    )
    db.add(db_event)
    db.commit()

    return {
        "id": event_id,
        "time": time.strftime("%H:%M:%S"),
        "src": source_ip,
        "dst": dest_ip,
        "url": url,
        "proto": protocol,
        "status": status,
        "attack_type": attack_type,
        "confidence": confidence,
        "category_confidence": result["category_confidence"],
        "origin": origin,
        "incident_id": incident_id,
        "severity": severity
    }

@app.get("/metrics")
async def metrics():
    try:
        with open(MODEL_METRICS_PATH) as f:
            metrics_data = json.load(f)
    except FileNotFoundError:
        metrics_data = {"binary_accuracy": None, "multiclass_accuracy": None}
        
    return {
        "binary_accuracy": metrics_data.get("binary_accuracy"),
        "multiclass_accuracy": metrics_data.get("multiclass_accuracy"),
        "session_category_tally": STATE["category_tally"],
    }

@app.get("/health")
async def health():
    avg_conf = (STATE["confidence_sum"] / STATE["confidence_count"]) if STATE["confidence_count"] else None
    d_score, d_status = calculate_drift_score()
    return {
        "status": "ok",
        "mode": STATE["mode"],
        "connected_clients": len(STATE["clients"]),
        "events_processed": STATE["event_count"],
        "intrusions_detected": STATE["intrusion_count"],
        "uptime_seconds": round(time.time() - STATE["start_time"], 1),
        "avg_confidence": round(avg_conf, 1) if avg_conf is not None else None,
        "events_per_minute": _rate_per_minute(STATE["recent_event_times"]),
        "intrusions_per_minute": _rate_per_minute(STATE["recent_intrusion_times"]),
        "drift_score": round(d_score, 1),
        "drift_status": d_status
    }

@app.post("/mode")
async def set_mode(payload: dict = Body(...)):
    mode = payload.get("mode")
    if mode not in ("simulated", "live"):
        return {"error": "mode must be 'simulated' or 'live'"}
    STATE["mode"] = mode
    return {"mode": STATE["mode"]}

@app.post("/predict")
async def predict(payload: dict = Body(...)):
    return predict_record(payload)

class IngestPayload(BaseModel):
    source_ip: str
    dest_ip: str
    protocol: str
    url: str = None
    features: dict

@app.post("/api/ingest")
async def ingest_event(payload: IngestPayload, db: Session = Depends(get_db)):
    if STATE["mode"] != "live":
        return {"status": "ignored", "reason": "Not in live mode"}
    if payload.source_ip in BLOCKED_IPS:
        return {"status": "dropped", "reason": "IP blocked by firewall"}
        
    event = score_and_package(
        payload.features, 
        payload.source_ip, 
        payload.dest_ip, 
        payload.protocol, 
        origin="live", 
        db=db,
        url=payload.url
    )
    
    await broadcast(event)
    return {"status": "success", "event_id": event["id"]}

@app.get("/api/events")
def get_events(limit: int = 100, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(desc(Event.timestamp)).limit(limit).all()
    return events

@app.get("/api/incidents")
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(desc(Incident.updated_at)).all()
    return incidents

@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, payload: dict = Body(...), db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    status = payload.get("status")
    if status in ["New", "Investigating", "Contained", "Resolved"]:
        incident.status = status
        log_audit(db, "Analyst", "UPDATE_STATUS", f"Incident #{incident_id}", f"Status changed to {status}")
        db.commit()
    return {"ok": True}

@app.post("/api/response")
def trigger_response(payload: dict = Body(...), db: Session = Depends(get_db)):
    action = payload.get("action", "BLOCK_IP")
    target = payload.get("target")
    reason = payload.get("reason", "Manual analyst action")
    
    if action == "BLOCK_IP":
        BLOCKED_IPS.add(target)
        
    log_audit(db, "Analyst", action, target, reason)
    return {"ok": True, "message": f"{action} executed on {target}"}

@app.post("/api/events/{event_id}/label")
def label_event(event_id: str, payload: dict = Body(...), db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    label = payload.get("label")
    event.analyst_label = label
    log_audit(db, "Analyst", "LABEL_EVENT", str(event_id), f"Relabeled as {label}")
    return {"ok": True, "message": f"Event {event_id} labeled as {label}"}

@app.post("/api/retrain")
def trigger_retrain(db: Session = Depends(get_db)):
    result = run_retraining_pipeline(db)
    log_audit(db, "System", "RETRAIN", "Models", result.get("message", "Triggered"))
    return result

@app.get("/api/audit")
def get_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).all()
    return logs

@app.get("/api/ip/{ip}")
def get_ip_profile(ip: str, db: Session = Depends(get_db)):
    events = db.query(Event).filter(Event.source_ip == ip).all()
    incidents = db.query(Incident).filter(Incident.source_ip == ip).all()
    
    total_events = len(events)
    intrusions = [e for e in events if e.status == "Attack"]
    attack_types = list(set([e.attack_type for e in intrusions if e.attack_type]))
    
    return {
        "total_events": len(events),
        "intrusion_count": len(intrusions),
        "incidents": len(incidents),
        "attack_types": list(attack_types)
    }

@app.get("/api/ip/{ip}/enrich")
def enrich_ip(ip: str):
    # Deterministic mock based on IP hash
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    
    countries = ["US", "CN", "RU", "DE", "BR", "IN", "KR", "NL", "JP", "GB"]
    asns = ["AS15169 Google LLC", "AS4134 Chinanet", "AS8359 MTS PJSC", "AS3320 Deutsche Telekom", "AS16509 Amazon.com", "AS13335 Cloudflare"]
    tags_pool = ["Botnet", "Spam", "Scanner", "Proxy", "Tor Node", "Malware C2"]
    
    country = countries[h % len(countries)]
    asn = asns[(h // 10) % len(asns)]
    
    # 30% chance of having a high risk score, else low risk
    is_risky = (h % 100) > 70
    
    if is_risky:
        risk_score = 60 + (h % 40)
        num_tags = (h % 3) + 1
        tags = [tags_pool[(h + i) % len(tags_pool)] for i in range(num_tags)]
    else:
        risk_score = (h % 30)
        tags = []
        
    return {
        "ip": ip,
        "country": country,
        "asn": asn,
        "risk_score": risk_score,
        "tags": tags
    }

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    STATE["clients"].append(websocket)
    try:
        await websocket.send_text(json.dumps({"type": "hello", "mode": STATE["mode"]}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in STATE["clients"]:
            STATE["clients"].remove(websocket)

async def simulation_loop():
    while True:
        await asyncio.sleep(2.0)
        if STATE["mode"] != "simulated" or not STATE["clients"]:
            continue
        raw = generate_event()
        source_ip = raw.pop("_source_ip")
        dest_ip = raw.pop("_dest_ip")
        raw.pop("_true_category", None)
        protocol = str(raw.get("protocol_type", "tcp")).upper()
        if source_ip in BLOCKED_IPS:
            continue
            
        db = SessionLocal()
        try:
            event = score_and_package(raw, source_ip, dest_ip, protocol, origin="simulated", db=db)
            await broadcast(event)
        finally:
            db.close()

@app.on_event("startup")
async def startup():
    asyncio.create_task(simulation_loop())
