# center/main.py
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Dict, Any, List
import os
import models
import json

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://honey_user:honey_password@db:5432/honeyforge")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="HoneyForge Control Center")

# --- Менеджер WebSocket соединений (для реалтайм дашборда) ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class TelemetryEvent(BaseModel):
    honeypot_id: int
    event_type: str
    source_ip: str
    details: Dict[str, Any]

@app.post("/cdn/assets/v2/metrics.json")
async def receive_telemetry(event: TelemetryEvent, db: Session = Depends(get_db)):
    """Прием событий от агентов и моментальная рассылка во фронтенд"""
    # 1. Сохраняем в БД
    db_event = models.Event(
        honeypot_id=event.honeypot_id,
        source_ip=event.source_ip,
        event_type=event.event_type,
        details=event.details
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # 2. Отправляем по WebSocket всем подключенным клиентам (фронтенду)
    event_data = {
        "id": db_event.id,
        "type": event.event_type,
        "ip": event.source_ip,
        "details": event.details
    }
    await manager.broadcast(json.dumps(event_data))
    
    return {"status": "ok"}

@app.get("/api/honeypots")
def get_honeypots(db: Session = Depends(get_db)):
    """Отдаем фронтенду реальный список ловушек из базы"""
    return db.query(models.Honeypot).all()

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """Эндпоинт для подключения фронтенда к ленте событий"""
    await manager.connect(websocket)
    try:
        while True:
            # Держим соединение открытым
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)