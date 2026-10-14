# agent/agent.py
import os
import sys
import time
import socket
import threading
import sqlite3
import json
import random
import re
from datetime import datetime
import requests
import paramiko

NODE_ID = os.getenv("NODE_ID", "dmz-node-alpha")
NODE_NAME = os.getenv("NODE_NAME", "DMZ Edge Decoy (SSH/Telnet/FTP)")
CENTER_METRICS_URL = "http://nginx:80/cdn/assets/v2/metrics.json"
CENTER_REGISTER_URL = "http://nginx:80/cdn/assets/v2/register.json"

DATA_DIR = "/app/data"
os.makedirs(DATA_DIR, exist_ok=True)
DB_FILE = os.path.join(DATA_DIR, "buffer.db")
KEY_FILE = os.path.join(DATA_DIR, "ssh_host_rsa")

# Потокобезопасный доступ к SQLite
db_lock = threading.Lock()

# --- 1. ПЕРСИСТЕНТНЫЙ SSH КЛЮЧ ХОСТА (Anti-Fingerprinting) ---
def get_or_create_host_key():
    if os.path.exists(KEY_FILE):
        try:
            return paramiko.RSAKey.from_private_key_file(KEY_FILE)
        except Exception as e:
            print(f"[AGENT] Ошибка чтения ключа: {e}, генерируем новый")
    key = paramiko.RSAKey.generate(2048)
    try:
        key.write_private_key_file(KEY_FILE)
        print("[AGENT] Новый SSH RSA ключ успешно сохранен на диск")
    except Exception as e:
        print(f"[AGENT] Не удалось сохранить ключ на диск: {e}")
    return key

HOST_KEY = get_or_create_host_key()


# --- 2. БУФЕРИЗАЦИЯ И ОТПРАВКА ТЕЛЕМЕТРИИ ---
def init_db():
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            payload TEXT, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()

def save_to_buffer(payload: dict):
    with db_lock:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("INSERT INTO events (payload) VALUES (?)", (json.dumps(payload),))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[AGENT] Ошибка записи в локальный буфер: {e}")

def send_event(event_type: str, source_ip: str, details: dict):
    """Отправка события в центр (через скрытый URL Nginx). При обрыве связи - буферизация."""
    payload = {
        "honeypot_id": 1,
        "node_id": NODE_ID,
        "event_type": event_type,
        "source_ip": source_ip,
        "details": details
    }
    try:
        resp = requests.post(CENTER_METRICS_URL, json=payload, timeout=2.5)
        if resp.status_code == 200:
            print(f"[AGENT] Событие отправлено: {event_type} от {source_ip}")
        else:
            save_to_buffer(payload)
    except requests.exceptions.RequestException:
        print(f"[AGENT] Центр недоступен. Событие сохранено в SQLite: {event_type}")
        save_to_buffer(payload)

def register_with_center():
    """Регистрация узла ловушки в центре управления"""
    reg_payload = {
        "node_id": NODE_ID,
        "name": NODE_NAME,
        "ip_address": "172.20.0.10",
        "services": ["SSH (2222)", "FTP (2121)", "Telnet (2323)"]
    }
    try:
        requests.post(CENTER_REGISTER_URL, json=reg_payload, timeout=3)
        print("[AGENT] Успешная регистрация в Control Center")
    except Exception:
        pass

def flush_buffer_worker():
    """Фоновый воркер: выгрузка накопленных событий при восстановлении связи с джиттером"""
    while True:
        # Случайный джиттер 4-7 сек (маскировка паттернов трафика)
        time.sleep(4.0 + random.uniform(0.5, 3.0))

        rows = []
        with db_lock:
            try:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute("SELECT id, payload FROM events ORDER BY id ASC LIMIT 20")
                rows = c.fetchall()
                conn.close()
            except Exception:
                continue

        if not rows:
            continue

        for row_id, payload_str in rows:
            try:
                data = json.loads(payload_str)
                resp = requests.post(CENTER_METRICS_URL, json=data, timeout=2.5)
                if resp.status_code == 200:
                    with db_lock:
                        conn = sqlite3.connect(DB_FILE)
                        c = conn.cursor()
                        c.execute("DELETE FROM events WHERE id=?", (row_id,))
                        conn.commit()
                        conn.close()
                    print(f"[AGENT] Буферизованное событие #{row_id} успешно доставлено!")
                else:
                    break
            except Exception:
                break


def heartbeat_worker():
    """Периодический heartbeat раз в 30 секунд"""
    while True:
        time.sleep(30)
        register_with_center()


# --- 3. MEDIUM-INTERACTION SSH HONEYPOT ---

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Фиксируем все логины/пароли атакующего
        send_event("ssh_auth", self.client_ip, {
            "username": username,
            "password": password,
            "target_port": 2222
        })
        return paramiko.AUTH_SUCCESSFUL  # Всегда пускаем внутрь ловушки!

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode('utf-8', errors='ignore') if isinstance(command, bytes) else str(command)
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_ssh_command(cmd: str, client_ip: str) -> (str, bool):
    """Эмуляция ответов реалистичной Linux-системы на команды атакующего"""
    cmd_clean = cmd.strip()
    cmd_lower = cmd_clean.lower()

    # Фиксируем введенную команду
    send_event("ssh_command", client_ip, {
        "command": cmd_clean,
        "target_port": 2222
    })

    if cmd_clean == "exit" or cmd_clean == "logout":
        return "logout\r\n", True

    if cmd_clean in ("ls", "ls -l", "ls -la", "ll"):
        return (
            "total 48\r\n"
            "drwx------ 4 root root 4096 Oct 15 01:00 .\r\n"
            "drwxr-xr-x 20 root root 4096 Oct 10 12:00 ..\r\n"
            "-rw------- 1 root root  248 Oct 14 22:15 .bash_history\r\n"
            "-rw-r--r-- 1 root root  420 Oct 15 00:45 .env\r\n"
            "drwxr-xr-x 2 root root 4096 Oct 15 00:30 config\r\n"
            "-rwxr-xr-x 1 root root 1024 Oct 14 18:20 deploy.sh\r\n"
            "-rw-r--r-- 1 root root  180 Oct 15 00:40 passwords.txt\r\n"
            "-rw-r--r-- 1 root root 8192 Oct 15 00:10 backup.sql\r\n"
        ), False

    if cmd_clean in ("cat passwords.txt", "cat passwords", "more passwords.txt"):
        return (
            "# Production Services Credentials (CONFIDENTIAL)\r\n"
            "postgres_master: P@ssw0rdProd2026!\r\n"
            "redis_cache: R3d1s#Auth_Key_Prod\r\n"
            "grafana_admin: admin:HoneyAdm1n2026\r\n"
            "backup_token: glpat-s8xY91ZbA34kLp9921\r\n"
        ), False

    if cmd_clean in ("cat .env", "more .env"):
        return (
            "NODE_ENV=production\r\n"
            "PORT=3000\r\n"
            "DATABASE_URL=postgres://app_user:DbSecr3t2026@10.0.1.5:5432/appdb\r\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\r\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"
            "JWT_SECRET=super_secret_jwt_token_prod_99182\r\n"
        ), False

    if cmd_clean in ("whoami",):
        return "root\r\n", False

    if cmd_clean in ("id",):
        return "uid=0(root) gid=0(root) groups=0(root)\r\n", False

    if cmd_clean in ("pwd",):
        return "/root\r\n", False

    if cmd_clean in ("uname -a", "uname"):
        return "Linux prod-srv-01 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 18:37:34 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n", False

    if cmd_clean in ("cat /etc/os-release",):
        return (
            "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\r\n"
            "NAME=\"Ubuntu\"\r\n"
            "VERSION_ID=\"22.04\"\r\n"
            "VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\r\n"
            "ID=ubuntu\r\n"
        ), False

    if cmd_clean in ("cat /etc/passwd",):
        return (
            "root:x:0:0:root:/root:/bin/bash\r\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\r\n"
            "deploy:x:1000:1000:Deploy Service,,,:/home/deploy:/bin/bash\r\n"
            "backup:x:1001:1001:Backup Manager:/home/backup:/bin/bash\r\n"
            "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\r\n"
        ), False

    if cmd_clean in ("uptime",):
        return " 01:24:10 up 45 days, 3:12, 1 user, load average: 0.08, 0.03, 0.01\r\n", False

    if cmd_clean in ("ifconfig", "ip a", "ip addr"):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 10.0.1.15  netmask 255.255.255.0  broadcast 10.0.1.255\r\n"
            "        inet6 fe80::42:acff:fe11:a  prefixlen 64  scopeid 0x20<link>\r\n"
            "        ether 02:42:ac:11:00:0a  txqueuelen 0  (Ethernet)\r\n"
        ), False

    if cmd_clean in ("ps aux", "ps -ef", "ps"):
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
            "root         1  0.0  0.1 168344 11200 ?        Ss   Sep01   0:04 /sbin/init\r\n"
            "root       450  0.0  0.1  72300  8400 ?        Ss   Sep01   0:01 /lib/systemd/systemd-journald\r\n"
            "root       612  0.0  0.1  15420  4120 ?        Ss   Sep01   0:00 /usr/sbin/cron -f\r\n"
            "root       890  0.0  0.2  98400 14200 ?        Ss   Sep01   0:03 sshd: /usr/sbin/sshd -D\r\n"
            "root      1204  0.0  0.1  24100  6500 pts/0    Ss   01:15   0:00 -bash\r\n"
            "root      1210  0.0  0.0  18900  3200 pts/0    R+   01:20   0:00 ps aux\r\n"
        ), False

    if cmd_clean in ("netstat -tuln", "ss -tuln"):
        return (
            "Active Internet connections (only servers)\r\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\r\n"
        ), False

    # Перехват попыток скачивания малвари атакующим через wget / curl
    if cmd_lower.startswith("wget ") or cmd_lower.startswith("curl "):
        urls = re.findall(r'https?://[^\s<>"]+|ftp://[^\s<>"]+', cmd_clean)
        target_url = urls[0] if urls else "http://remote-payload/malware.sh"
        send_event("payload_download", client_ip, {
            "tool": "wget/curl",
            "command": cmd_clean,
            "url": target_url,
            "target_port": 2222
        })
        filename = target_url.split("/")[-1] or "script.sh"
        return (
            f"--{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}--  {target_url}\r\n"
            f"Resolving c2-server... connected.\r\n"
            f"HTTP request sent, awaiting response... 200 OK\r\n"
            f"Length: 28410 (28K) [application/x-sh]\r\n"
            f"Saving to: '{filename}'\r\n\r\n"
            f"{filename}          100%[===================>]  27.74K  --.-KB/s    in 0.02s\r\n\r\n"
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} (1.38 MB/s) - '{filename}' saved [28410/28410]\r\n"
        ), False

    if cmd_lower.startswith("chmod ") or cmd_lower.startswith("touch ") or cmd_lower.startswith("rm "):
        return "", False

    if cmd_lower in ("history",):
        return (
            "    1  cd /root\r\n"
            "    2  docker-compose up -d\r\n"
            "    3  systemctl status nginx\r\n"
            "    4  cat passwords.txt\r\n"
            "    5  history\r\n"
        ), False

    return f"bash: {cmd_clean}: command not found\r\n", False


def handle_ssh_connection(client_socket, addr):
    ip, port = addr
    send_event("scan_detected", ip, {"target_port": 2222, "protocol": "SSH (TCP)"})
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            return

        # Если поступил non-interactive exec запрос (например, ssh user@host "cat passwords.txt")
        if hasattr(server, 'exec_command') and server.exec_command:
            output, _ = handle_ssh_command(server.exec_command, ip)
            if output:
                channel.send(output.replace("\r\n", "\n"))
            channel.send_exit_status(0)
            channel.close()
            return

        # Приветствие Ubuntu для интерактивного терминала
        channel.send("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
                     " * Documentation:  https://help.ubuntu.com\r\n"
                     " * Management:     https://landscape.canonical.com\r\n\r\n"
                     "Last login: Sun Oct 11 00:15:21 2026 from 192.168.1.105\r\n"
                     "root@prod-srv-01:~# ")

        cmd_buffer = ""
        while True:
            char = channel.recv(1024).decode('utf-8', errors='ignore')
            if not char:
                break

            # Backspace handling (\x7f или \x08)
            if char in ('\x7f', '\x08'):
                if len(cmd_buffer) > 0:
                    cmd_buffer = cmd_buffer[:-1]
                    channel.send("\b \b")
                continue

            # Ctrl+C handling
            if char == '\x03':
                cmd_buffer = ""
                channel.send("^C\r\nroot@prod-srv-01:~# ")
                continue

            # Enter handling
            if char in ('\r', '\n'):
                channel.send("\r\n")
                if cmd_buffer.strip():
                    output, should_exit = handle_ssh_command(cmd_buffer, ip)
                    if output:
                        channel.send(output)
                    if should_exit:
                        break
                cmd_buffer = ""
                channel.send("root@prod-srv-01:~# ")
            else:
                cmd_buffer += char
                channel.send(char)  # Echo char
    except Exception:
        pass
    finally:
        try:
            transport.close()
        except Exception:
            pass


def start_ssh_honeypot(port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(10)
    print(f"[SSH] Ловушка запущена на порту {port}")
    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_ssh_connection, args=(client, addr), daemon=True).start()
        except Exception:
            pass


# --- 4. MEDIUM-INTERACTION TELNET HONEYPOT (IoT / Mirai / Mozi) ---

def handle_telnet_connection(client_socket, addr):
    ip, port = addr
    send_event("scan_detected", ip, {"target_port": 23, "protocol": "Telnet (TCP)"})
    try:
        # Отправляем стандартные Telnet опции (DO ECHO, WILL SGA)
        client_socket.send(b"\xff\xfb\x01\xff\xfb\x03")
        client_socket.send(b"\r\n\r\nBusyBox v1.33.1 (2022-09-15 11:20:00 UTC) built-in shell (ash)\r\n"
                           b"Enter 'help' for a list of built-in commands.\r\n\r\n"
                           b"edge-router login: ")

        username = ""
        while True:
            ch = client_socket.recv(1).decode('utf-8', errors='ignore')
            if not ch or ch in ('\r', '\n'):
                break
            if ch in ('\x7f', '\x08'):
                username = username[:-1]
            else:
                username += ch

        client_socket.send(b"\r\nPassword: ")
        password = ""
        while True:
            ch = client_socket.recv(1).decode('utf-8', errors='ignore')
            if not ch or ch in ('\r', '\n'):
                break
            password += ch

        send_event("telnet_auth", ip, {
            "username": username.strip(),
            "password": password.strip(),
            "target_port": 23
        })

        client_socket.send(b"\r\n\r\n# ")
        cmd = ""
        while True:
            ch = client_socket.recv(1).decode('utf-8', errors='ignore')
            if not ch:
                break
            if ch in ('\r', '\n'):
                client_socket.send(b"\r\n")
                cmd_clean = cmd.strip()
                if cmd_clean:
                    send_event("telnet_command", ip, {
                        "command": cmd_clean,
                        "target_port": 23
                    })
                    if cmd_clean in ("exit", "quit"):
                        break
                    elif cmd_clean in ("help", "?"):
                        client_socket.send(b"Built-in commands: cat, cd, cp, echo, kill, ls, ps, reboot, sh\r\n")
                    elif cmd_clean == "cat /proc/mounts":
                        client_socket.send(b"rootfs / rootfs rw 0 0\r\n/dev/root / squashfs ro 0 0\r\n")
                    elif cmd_clean in ("sh", "enable", "system", "/bin/busybox"):
                        pass
                    else:
                        client_socket.send(f"/bin/ash: {cmd_clean}: not found\r\n".encode('utf-8'))
                cmd = ""
                client_socket.send(b"# ")
            elif ch in ('\x7f', '\x08'):
                if cmd:
                    cmd = cmd[:-1]
                    client_socket.send(b"\b \b")
            else:
                cmd += ch
                client_socket.send(ch.encode('utf-8'))
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def start_telnet_honeypot(port=23):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(10)
    print(f"[TELNET] Ловушка запущена на порту {port}")
    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_telnet_connection, args=(client, addr), daemon=True).start()
        except Exception:
            pass


# --- 5. INTERACTIVE FTP HONEYPOT (RFC-959 State Machine) ---

def handle_ftp_connection(client_socket, addr):
    ip, port = addr
    send_event("scan_detected", ip, {"target_port": 21, "protocol": "FTP (TCP)"})
    username = None
    try:
        client_socket.send(b"220 (vsFTPd 3.0.5 - Secure FTP Service)\r\n")
        while True:
            data = client_socket.recv(1024).decode('utf-8', errors='ignore')
            if not data:
                break
            line = data.strip()
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                username = arg
                client_socket.send(b"331 Please specify the password.\r\n")
            elif cmd == "PASS":
                send_event("ftp_auth", ip, {
                    "username": username or "unknown",
                    "password": arg,
                    "target_port": 21
                })
                client_socket.send(b"230 Login successful.\r\n")
            elif cmd == "SYST":
                client_socket.send(b"215 UNIX Type: L8\r\n")
            elif cmd == "PWD":
                client_socket.send(b"257 \"/\" is current directory.\r\n")
            elif cmd == "TYPE":
                client_socket.send(b"200 Switching to Binary mode.\r\n")
            elif cmd in ("PASV", "EPSV"):
                client_socket.send(b"227 Entering Passive Mode (172,20,0,10,120,40).\r\n")
            elif cmd == "LIST":
                client_socket.send(b"150 Here comes the directory listing.\r\n226 Directory send OK.\r\n")
            elif cmd == "QUIT":
                client_socket.send(b"221 Goodbye.\r\n")
                break
            else:
                client_socket.send(b"500 Unknown command.\r\n")
    except Exception:
        pass
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def start_ftp_honeypot(port=21):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(10)
    print(f"[FTP] Ловушка запущена на порту {port}")
    while True:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_ftp_connection, args=(client, addr), daemon=True).start()
        except Exception:
            pass


# --- ТОЧКА ВХОДА ---
if __name__ == "__main__":
    init_db()

    # Стартовая регистрация в центре
    register_with_center()

    # Фоновые службы
    threading.Thread(target=flush_buffer_worker, daemon=True).start()
    threading.Thread(target=heartbeat_worker, daemon=True).start()

    # Запуск всех трех протоколов ловушек параллельно
    threading.Thread(target=start_ftp_honeypot, args=(21,), daemon=True).start()
    threading.Thread(target=start_telnet_honeypot, args=(23,), daemon=True).start()
    
    # Главный поток держит SSH
    start_ssh_honeypot(port=2222)