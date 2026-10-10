# agent/agent.py
import time
import requests
import socket
import threading
import sqlite3
import json
import paramiko

CENTER_URL = "http://nginx:80/cdn/assets/v2/metrics.json"
DB_FILE = "buffer.db"
HOST_KEY = paramiko.RSAKey.generate(2048) # Ключ для SSH сервера

# --- 1. СИСТЕМА БУФЕРИЗАЦИИ (Локальная SQLite) ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, payload TEXT)''')
    conn.commit()
    conn.close()

def save_to_buffer(payload):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO events (payload) VALUES (?)", (json.dumps(payload),))
    conn.commit()
    conn.close()

def send_event(event_type: str, source_ip: str, details: dict):
    """Пытаемся отправить событие. Если не выходит - прячем в буфер."""
    payload = {
        "honeypot_id": 1,
        "event_type": event_type,
        "source_ip": source_ip,
        "details": details
    }
    try:
        requests.post(CENTER_URL, json=payload, timeout=2)
        print(f"[AGENT] Успех: {event_type} от {source_ip}")
    except requests.exceptions.RequestException:
        print(f"[AGENT] Связь потеряна! Сохраняем в локальный буфер: {event_type}")
        save_to_buffer(payload)

def flush_buffer():
    """Фоновый процесс: пытается отправить накопленные события из буфера"""
    while True:
        time.sleep(5) # Джиттер можно добавить сюда
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, payload FROM events")
        rows = c.fetchall()
        
        for row_id, payload_str in rows:
            try:
                requests.post(CENTER_URL, json=json.loads(payload_str), timeout=2)
                c.execute("DELETE FROM events WHERE id=?", (row_id,))
                conn.commit()
                print(f"[AGENT] Событие из буфера успешно доставлено!")
            except requests.exceptions.RequestException:
                break # Центр всё еще недоступен, ждем
        conn.close()


# --- 2. LOW INTERACTION: FTP Ловушка ---
def handle_ftp_connection(client_socket, addr):
    ip, port = addr
    send_event("scan_detected", ip, {"target_port": 21, "protocol": "TCP"})
    try:
        client_socket.send(b"220 (vsFTPd 3.0.3)\r\n")
        data = client_socket.recv(1024).decode('utf-8').strip()
        if data:
            send_event("auth_attempt", ip, {"input": data, "target_port": 21})
    except Exception:
        pass
    finally:
        client_socket.close()

def start_ftp_honeypot(port=21):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[FTP] Запущен на порту {port}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_ftp_connection, args=(client, addr), daemon=True).start()


# --- 3. MEDIUM INTERACTION: SSH Ловушка ---
class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Логируем введенный логин и пароль
        send_event("ssh_auth", self.client_ip, {"username": username, "password": password, "target_port": 2222})
        return paramiko.AUTH_SUCCESSFUL # Всегда пускаем внутрь!

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_ssh_connection(client_socket, addr):
    ip, port = addr
    send_event("scan_detected", ip, {"target_port": 2222, "protocol": "TCP"})
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return
        
        channel = transport.accept(20)
        if channel is None: return
        server.event.wait(10)
        if not server.event.is_set(): return
            
        # Эмулируем приветствие Ubuntu
        channel.send("Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-43-generic x86_64)\r\n\r\n")
        channel.send("root@server:~# ")
        
        command = ""
        while True:
            char = channel.recv(1024).decode('utf-8')
            if not char: break
            if char == '\r' or char == '\n':
                channel.send("\r\n")
                cmd = command.strip()
                if cmd:
                    # Логируем каждую введенную команду
                    send_event("ssh_command", ip, {"command": cmd, "target_port": 2222})
                    
                    # Имитируем ответы файловой системы
                    if cmd == "ls":
                        channel.send("passwords.txt  config.yml  script.sh\r\n")
                    elif cmd == "whoami":
                        channel.send("root\r\n")
                    elif cmd == "pwd":
                        channel.send("/root\r\n")
                    elif cmd == "exit":
                        break
                    else:
                        channel.send(f"bash: {cmd}: command not found\r\n")
                command = ""
                channel.send("root@server:~# ")
            else:
                command += char
                channel.send(char) # Эхо-ввод
    except Exception:
        pass
    finally:
        try: transport.close()
        except: pass

def start_ssh_honeypot(port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[SSH] Запущен на порту {port}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_ssh_connection, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    init_db()
    
    # Запускаем фоновый процесс отправки буфера
    threading.Thread(target=flush_buffer, daemon=True).start()
    
    # Запускаем две ловушки параллельно
    threading.Thread(target=start_ftp_honeypot, args=(21,), daemon=True).start()
    start_ssh_honeypot(port=2222)