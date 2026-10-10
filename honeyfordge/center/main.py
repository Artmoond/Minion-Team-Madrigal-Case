from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any

app = FastAPI(title="HoneyForge Control Center")

class TelemetryEvent(BaseModel):
    honeypot_id: int
    event_type: str
    source_ip: str
    details: Dict[str, Any]

@app.post("/cdn/assets/v2/metrics.json")
def receive_telemetry(event: TelemetryEvent):
    # TODO: Реализовать сохранение события в PostgreSQL через SQLAlchemy
    print(f"[CENTER] Получено событие: {event}")
    return {"status": "ok"}

@app.get("/api/honeypots")
def get_honeypots():
    # TODO: Сделать выборку ловушек из БД
    return [{"id": 1, "name": "dmz-node-1", "status": "online"}]