from sqlalchemy import Column, Integer, String, JSON, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class Honeypot(Base):
    __tablename__ = 'honeypots'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    ip_address = Column(String)
    status = Column(String, default="online")
    
class Event(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True, index=True)
    honeypot_id = Column(Integer, ForeignKey('honeypots.id'))
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    event_type = Column(String) 
    details = Column(JSON)