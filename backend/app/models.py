import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from app.database import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    attack_type = Column(String, index=True)
    status = Column(String, default="New") # New, Investigating, Contained, Resolved
    severity = Column(String, default="LOW")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    events = relationship("Event", back_populates="incident")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    actor = Column(String) # Admin, System, Analyst
    action = Column(String) # BLOCK_IP, UPDATE_STATUS, RETRAIN
    target = Column(String) # Target IP or ID
    reason = Column(String)
    status = Column(String, default="Success")


class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, index=True) # Using UUID from main.py
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    dest_ip = Column(String, index=True)
    protocol = Column(String)
    status = Column(String, index=True) # Normal | Attack
    attack_type = Column(String, index=True, nullable=True)
    confidence = Column(Float)
    severity = Column(String)
    origin = Column(String) # simulated | live
    raw_features = Column(Text, nullable=True)
    url = Column(String, nullable=True)
    analyst_label = Column(String, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, default=False)
    
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    incident = relationship("Incident", back_populates="events")
