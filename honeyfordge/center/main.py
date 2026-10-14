# center/main.py
import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, desc, func
from sqlalchemy.orm import sessionmaker, Session
import httpx

import models

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://honey_user:honey_password@db:5432/honeyforge")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Создание таблиц при запуске
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="HoneyForge Control Center",
    version="2.0.0",
    description="Next-Gen Cyber Deception & Honeypot Telemetry Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- WebSocket Менеджер соединений ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        for dead in disconnected:
            self.disconnect(dead)

manager = ConnectionManager()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Инициализация дефолтной ловушки при старте ---
@app.on_event("startup")
def startup_seed():
    db = SessionLocal()
    try:
        default_hp = db.query(models.Honeypot).filter(models.Honeypot.id == 1).first()
        if not default_hp:
            default_hp = models.Honeypot(
                id=1,
                node_id="dmz-node-alpha",
                name="DMZ Primary Decoy (SSH/FTP/Telnet)",
                ip_address="172.20.0.10",
                status="online",
                services=["SSH (2222)", "FTP (2121)", "Telnet (2323)"],
                last_seen=datetime.utcnow()
            )
            db.add(default_hp)
            db.commit()
            print("[CENTER] Дефолтная ловушка ID=1 успешно зарегистрирована в БД.")
    except Exception as e:
        db.rollback()
        print(f"[CENTER] Ошибка инициализации ловушки: {e}")
    finally:
        db.close()


# --- GeoIP и Обогащение данных ---
GEO_CACHE: Dict[str, Dict[str, Any]] = {}

def get_country_flag(country_code: str) -> str:
    """Преобразование ISO 2-символьного кода страны в эмодзи-флаг"""
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(ord(c.upper()) + 127397) for c in country_code)
    except Exception:
        return "🌐"

# Встроенная автономная база GeoIP для мгновенного резолвинга без внешних запросов
OFFLINE_GEO_TABLE = {
    "185": {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    "194": {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    "45":  {"country": "United States", "country_code": "US", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    "103": {"country": "Singapore", "country_code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    "180": {"country": "China", "country_code": "CN", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737},
    "89":  {"country": "France", "country_code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    "212": {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
    "91":  {"country": "Russia", "country_code": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    "151": {"country": "Italy", "country_code": "IT", "city": "Rome", "lat": 41.9028, "lon": 12.4964},
    "193": {"country": "Poland", "country_code": "PL", "city": "Warsaw", "lat": 52.2297, "lon": 21.0122},
    "198": {"country": "Canada", "country_code": "CA", "city": "Toronto", "lat": 43.6532, "lon": -79.3832},
    "114": {"country": "Japan", "country_code": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    "139": {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    "177": {"country": "Brazil", "country_code": "BR", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333},
}

GEO_POOLS = [
    {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"country": "United States", "country_code": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    {"country": "United States", "country_code": "US", "city": "San Jose", "lat": 37.3382, "lon": -121.8863},
    {"country": "China", "country_code": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    {"country": "Singapore", "country_code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"country": "France", "country_code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
    {"country": "Sweden", "country_code": "SE", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686},
    {"country": "Finland", "country_code": "FI", "city": "Helsinki", "lat": 60.1699, "lon": 24.9384},
    {"country": "Japan", "country_code": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
]

async def enrich_ip(ip: str) -> Dict[str, Any]:
    """Определение геопозиции и провайдера по IP с мгновенным оффлайн-резолвингом"""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    # Обработка локальных/частных сетей
    is_private = (
        ip.startswith("127.") or
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.") or
        ip == "localhost" or
        ip == "::1"
    )

    if is_private:
        geo = {
            "country": "Local / Lab Network",
            "country_code": "LAN",
            "flag_emoji": "🛡️",
            "city": "Internal DMZ",
            "latitude": 55.7558,
            "longitude": 37.6173
        }
        GEO_CACHE[ip] = geo
        return geo

    # Проверка по префиксу первого октета
    first_octet = ip.split(".")[0] if "." in ip else ""
    if first_octet in OFFLINE_GEO_TABLE:
        info = OFFLINE_GEO_TABLE[first_octet]
        cc = info["country_code"]
        geo = {
            "country": info["country"],
            "country_code": cc,
            "flag_emoji": get_country_flag(cc),
            "city": info["city"],
            "latitude": info["lat"],
            "longitude": info["lon"]
        }
        GEO_CACHE[ip] = geo
        return geo

    # Детерминированный fallback по хэшу IP для гарантированного отображения на карте
    ip_hash = sum(ord(c) for c in ip)
    selected = GEO_POOLS[ip_hash % len(GEO_POOLS)]
    cc = selected["country_code"]
    geo = {
        "country": selected["country"],
        "country_code": cc,
        "flag_emoji": get_country_flag(cc),
        "city": selected["city"],
        "latitude": selected["lat"],
        "longitude": selected["lon"]
    }
    GEO_CACHE[ip] = geo
    return geo


def classify_event(event_type: str, details: Dict[str, Any]) -> (str, str):
    """Классификация серьезности и привязка к матрице MITRE ATT&CK"""
    if event_type == "scan_detected":
        return "warning", "T1046: Network Service Discovery"

    if event_type in ("auth_attempt", "ssh_auth", "ftp_auth", "telnet_auth"):
        return "high", "T1110: Brute Force Credentials"

    if event_type in ("ssh_command", "telnet_command"):
        cmd = str(details.get("command", "")).lower()
        if any(tool in cmd for tool in ["wget", "curl", "chmod +x", "sh ", "bash ", "python", "nc ", "bash -i"]):
            return "critical", "T1059 / T1105: Payload Transfer & Execution"
        if any(f in cmd for f in ["passwords", ".env", "id_rsa", "shadow", "passwd", "token"]):
            return "critical", "T1552: Unsecured Credentials Access"
        return "high", "T1059.004: Unix Shell Command Execution"

    if event_type == "payload_download":
        return "critical", "T1105: Ingress Tool Transfer (Malware)"

    if event_type == "heartbeat":
        return "info", "T1071: Standard Protocol Heartbeat"

    return "info", "T1000: General Deception Event"


# --- Pydantic Схемы ---
class TelemetryEvent(BaseModel):
    honeypot_id: Optional[int] = 1
    node_id: Optional[str] = "dmz-node-alpha"
    event_type: str
    source_ip: str
    details: Dict[str, Any]

class RegisterAgent(BaseModel):
    node_id: str
    name: str
    ip_address: str
    services: List[str]


# --- Эндпоинты приема телеметрии (MASK-2) ---

@app.post("/cdn/assets/v2/metrics.json")
async def receive_telemetry(event: TelemetryEvent, db: Session = Depends(get_db)):
    """Скрытый канал приема телеметрии от агентов-ловушек"""
    # 1. Обогащение GeoIP и MITRE
    geo = await enrich_ip(event.source_ip)
    severity, mitre = classify_event(event.event_type, event.details)

    # 2. Поиск или создание Honeypot
    hp_id = event.honeypot_id or 1
    hp = db.query(models.Honeypot).filter(models.Honeypot.id == hp_id).first()
    if not hp and event.node_id:
        hp = db.query(models.Honeypot).filter(models.Honeypot.node_id == event.node_id).first()

    if hp:
        hp.last_seen = datetime.utcnow()
        hp.status = "online"
        hp_id = hp.id

    # 3. Сохранение в БД
    db_event = models.Event(
        honeypot_id=hp_id,
        timestamp=datetime.utcnow(),
        source_ip=event.source_ip,
        event_type=event.event_type,
        severity=severity,
        mitre_technique=mitre,
        country=geo["country"],
        country_code=geo["country_code"],
        flag_emoji=geo["flag_emoji"],
        city=geo["city"],
        latitude=geo["latitude"],
        longitude=geo["longitude"],
        details=event.details
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # 4. Рассылка по WebSocket на дашборд
    payload = {
        "id": db_event.id,
        "honeypot_id": hp_id,
        "timestamp": db_event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "time_iso": db_event.timestamp.isoformat(),
        "type": db_event.event_type,
        "severity": db_event.severity,
        "mitre": db_event.mitre_technique,
        "ip": db_event.source_ip,
        "country": db_event.country,
        "country_code": db_event.country_code,
        "flag": db_event.flag_emoji,
        "city": db_event.city,
        "latitude": db_event.latitude,
        "longitude": db_event.longitude,
        "details": db_event.details
    }
    await manager.broadcast(json.dumps(payload))

    return {"status": "ok", "event_id": db_event.id}


@app.post("/cdn/assets/v2/register.json")
def register_honeypot(agent: RegisterAgent, db: Session = Depends(get_db)):
    """Автоматическая регистрация/обновление статуса ловушки"""
    hp = db.query(models.Honeypot).filter(models.Honeypot.node_id == agent.node_id).first()
    if not hp:
        hp = models.Honeypot(
            node_id=agent.node_id,
            name=agent.name,
            ip_address=agent.ip_address,
            services=agent.services,
            status="online",
            last_seen=datetime.utcnow()
        )
        db.add(hp)
    else:
        hp.name = agent.name
        hp.ip_address = agent.ip_address
        hp.services = agent.services
        hp.status = "online"
        hp.last_seen = datetime.utcnow()

    db.commit()
    db.refresh(hp)
    return {"status": "registered", "id": hp.id, "node_id": hp.node_id}


# --- REST API для веб-дашборда ---

@app.get("/api/honeypots")
def get_honeypots(db: Session = Depends(get_db)):
    """Список зарегистрированных ловушек с актуальным статусом"""
    hps = db.query(models.Honeypot).all()
    result = []
    now = datetime.utcnow()
    for h in hps:
        # Если ловушка не подавала сигналов более 60 секунд - помечаем degraded/offline
        is_alive = h.last_seen and (now - h.last_seen) < timedelta(seconds=60)
        status = "online" if is_alive else "offline"
        event_count = db.query(models.Event).filter(models.Event.honeypot_id == h.id).count()
        result.append({
            "id": h.id,
            "node_id": h.node_id,
            "name": h.name,
            "ip_address": h.ip_address,
            "status": status,
            "services": h.services or [],
            "events_count": event_count,
            "last_seen": h.last_seen.strftime("%H:%M:%S") if h.last_seen else "Never"
        })
    return result


@app.get("/api/events")
def get_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """История перехваченных событий с фильтрацией и пагинацией"""
    query = db.query(models.Event)

    if event_type:
        query = query.filter(models.Event.event_type == event_type)
    if severity:
        query = query.filter(models.Event.severity == severity)
    if search:
        query = query.filter(
            (models.Event.source_ip.ilike(f"%{search}%")) |
            (models.Event.country.ilike(f"%{search}%"))
        )

    total = query.count()
    events = query.order_by(desc(models.Event.id)).offset(offset).limit(limit).all()

    items = []
    for e in events:
        items.append({
            "id": e.id,
            "honeypot_id": e.honeypot_id,
            "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "",
            "time_iso": e.timestamp.isoformat() if e.timestamp else "",
            "type": e.event_type,
            "severity": e.severity,
            "mitre": e.mitre_technique,
            "ip": e.source_ip,
            "country": e.country,
            "country_code": e.country_code,
            "flag": e.flag_emoji,
            "city": e.city,
            "latitude": e.latitude,
            "longitude": e.longitude,
            "details": e.details
        })

    return {"total": total, "items": items}


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    """Сводная аналитика и статистика угроз для дашборда"""
    total_events = db.query(models.Event).count()
    
    # События за последние 24 часа
    since_24h = datetime.utcnow() - timedelta(hours=24)
    events_24h = db.query(models.Event).filter(models.Event.timestamp >= since_24h).count()

    # Уникальные атакующие IP
    unique_ips = db.query(func.count(func.distinct(models.Event.source_ip))).scalar() or 0

    # Критические атаки
    critical_events = db.query(models.Event).filter(
        models.Event.severity.in_(["high", "critical"])
    ).count()

    # Топ 5 атакующих IP
    top_ips_query = db.query(
        models.Event.source_ip,
        models.Event.country,
        models.Event.flag_emoji,
        func.count(models.Event.id).label("count")
    ).group_by(
        models.Event.source_ip, models.Event.country, models.Event.flag_emoji
    ).order_by(desc("count")).limit(5).all()

    top_ips = [
        {"ip": r[0], "country": r[1] or "Unknown", "flag": r[2] or "🌐", "count": r[3]}
        for r in top_ips_query
    ]

    # Распределение по протоколам/сервисам
    all_events = db.query(models.Event.event_type).all()
    proto_stats = {"SSH": 0, "Telnet": 0, "FTP": 0, "Scan": 0, "Other": 0}
    for (etype,) in all_events:
        if "ssh" in etype:
            proto_stats["SSH"] += 1
        elif "telnet" in etype:
            proto_stats["Telnet"] += 1
        elif "ftp" in etype:
            proto_stats["FTP"] += 1
        elif "scan" in etype:
            proto_stats["Scan"] += 1
        else:
            proto_stats["Other"] += 1

    # Извлечение топ паролей и команд из details JSON
    events_with_details = db.query(models.Event.details).order_by(desc(models.Event.id)).limit(300).all()
    passwords = {}
    usernames = {}
    commands = []

    for (d,) in events_with_details:
        if not d or not isinstance(d, dict):
            continue
        p = d.get("password")
        if p:
            passwords[p] = passwords.get(p, 0) + 1
        u = d.get("username")
        if u:
            usernames[u] = usernames.get(u, 0) + 1
        c = d.get("command")
        if c and c not in commands:
            commands.append(c)

    top_passwords = sorted([{"password": k, "count": v} for k, v in passwords.items()], key=lambda x: x["count"], reverse=True)[:5]
    top_usernames = sorted([{"username": k, "count": v} for k, v in usernames.items()], key=lambda x: x["count"], reverse=True)[:5]

    return {
        "total_events": total_events,
        "events_24h": events_24h,
        "unique_ips": unique_ips,
        "critical_events": critical_events,
        "top_ips": top_ips,
        "proto_stats": proto_stats,
        "top_passwords": top_passwords,
        "top_usernames": top_usernames,
        "recent_commands": commands[:10]
    }


@app.get("/api/export")
def export_events(db: Session = Depends(get_db)):
    """Экспорт всех событий в JSON для SIEM / отчета по расследованию"""
    events = db.query(models.Event).order_by(desc(models.Event.id)).all()
    data = []
    for e in events:
        data.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "source_ip": e.source_ip,
            "event_type": e.event_type,
            "severity": e.severity,
            "mitre_technique": e.mitre_technique,
            "country": e.country,
            "city": e.city,
            "details": e.details
        })
    json_bytes = json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=honeyforge_report.json"}
    )


@app.delete("/api/events/clear")
def clear_events(db: Session = Depends(get_db)):
    """Очистка событий (удобно для сброса демо-стенда)"""
    db.query(models.Event).delete()
    db.commit()
    return {"status": "cleared"}


# --- WebSocket стриминг ---

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """Реалтайм лента инцидентов для дашборда"""
    await manager.connect(websocket)
    try:
        while True:
            # Ожидание входящих пингов от клиента
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)