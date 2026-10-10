import time
import requests

# Обращаемся к Nginx, а не напрямую к API (маскировка MASK-2)
CENTER_URL = "http://nginx:80/cdn/assets/v2/metrics.json" 

def send_event(event_type: str, source_ip: str, details: dict):
    payload = {
        "honeypot_id": 1,
        "event_type": event_type,
        "source_ip": source_ip,
        "details": details
    }
    try:
        response = requests.post(CENTER_URL, json=payload)
        print(f"[AGENT] Телеметрия отправлена, ответ: {response.status_code}")
    except Exception as e:
        # TODO: Реализовать буферизацию при недоступности центра (FR-A4)
        print(f"[AGENT] Ошибка отправки: {e}")

def main():
    print("[AGENT] Запуск ловушки...")
    # TODO: Поднять TCP-слушатели (socket/asyncio) на портах 2121 и 2323
    
    # Временная заглушка для проверки связи с центром
    while True:
        send_event("heartbeat", "127.0.0.1", {"status": "listening"})
        time.sleep(10)

if __name__ == "__main__":
    main()