# agent/agent.py
import time
import requests
import socket
import threading

CENTER_URL = "http://nginx:80/cdn/assets/v2/metrics.json"

def send_event(event_type: str, source_ip: str, details: dict):
    """Отправка телеметрии в центр (маскированный канал)"""
    payload = {
        "honeypot_id": 1,
        "event_type": event_type,
        "source_ip": source_ip,
        "details": details
    }
    try:
        requests.post(CENTER_URL, json=payload, timeout=3)
        print(f"[AGENT] Событие {event_type} от {source_ip} отправлено.")
    except Exception as e:
        print(f"[AGENT] Ошибка отправки (нужен локальный буфер!): {e}")

def handle_ftp_connection(client_socket, addr):
    """Эмуляция ответа FTP сервера (Low interaction)"""
    ip, port = addr
    print(f"[FTP] Подключение от {ip}:{port}")
    
    # Фиксируем попытку сканирования/подключения
    send_event("scan_detected", ip, {"target_port": 21, "protocol": "TCP"})
    
    try:
        # Отправляем фейковый баннер
        client_socket.send(b"220 (vsFTPd 3.0.3)\r\n")
        # Ждем ввода от атакующего (логируем первые 1024 байта)
        data = client_socket.recv(1024).decode('utf-8').strip()
        if data:
            send_event("auth_attempt", ip, {"input": data, "target_port": 21})
    except Exception:
        pass
    finally:
        client_socket.close()

def start_ftp_honeypot(port=21):
    """Запуск TCP-слушателя на заданном порту"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[AGENT] Low-interaction FTP ловушка запущена на порту {port}")
    
    while True:
        client, addr = server.accept()
        # Обрабатываем каждое подключение в отдельном потоке
        client_handler = threading.Thread(target=handle_ftp_connection, args=(client, addr))
        client_handler.start()

if __name__ == "__main__":
    # Запускаем ловушку (в докере она замаплена на порт 2121 снаружи)
    start_ftp_honeypot(port=21)