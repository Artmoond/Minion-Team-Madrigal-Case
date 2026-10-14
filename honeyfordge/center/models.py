from sqlalchemy import Column, Integer, String, Float, JSON, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class Honeypot(Base):
    __tablename__ = 'honeypots'

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String, unique=True, index=True, default="dmz-node-alpha")
    name = Column(String, default="DMZ Primary Decoy")
    ip_address = Column(String, default="172.20.0.10")
    status = Column(String, default="online")
    services = Column(JSON, default=lambda: ["SSH (2222)", "FTP (2121)", "Telnet (2323)"])
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    events = relationship("Event", back_populates="honeypot", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True, index=True)
    honeypot_id = Column(Integer, ForeignKey('honeypots.id', ondelete='CASCADE'), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, default="info", index=True)
    mitre_technique = Column(String, nullable=True)
    country = Column(String, default="Local / Unknown")
    country_code = Column(String, default="UN")
    flag_emoji = Column(String, default="🌐")
    city = Column(String, default="Unknown")
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    details = Column(JSON, default=dict)

    honeypot = relationship("Honeypot", back_populates="events")