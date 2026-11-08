"""
Атакующий агент (консольный).
Сканирует целевой сервер: порты, сервисы, баннеры.
Формирует список возможных векторов атак и отправляет на сервер для анализа
по HTTPS с токеном доступа.

Возможности:
  - Захват баннеров с версиями
  - CVE-маппинг по баннерам (известные уязвимые версии)
  - Определение ОС по набору открытых портов
  - Генерация векторов атак с учётом версий
"""

import socket
import json
import sys
import os
import struct
import time
import re
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.config import (
    TARGET_SERVER_HOST, TARGET_SERVER_PORT,
    SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT, KNOWN_PORTS
)
from common.models import (
    ScanResult, OpenPort, AttackVector, Severity, to_json
)
from common.netsec import build_client_ssl_context, get_server_fingerprint


# ─── Маппинг известных уязвимых версий ───

BANNER_CVE_MAP = {
    # Apache
    r"Apache[/ ]2\.4\.49": [("CVE-2021-41773", "CRITICAL", "Apache 2.4.49 — Path Traversal/RCE")],
    r"Apache[/ ]2\.4\.50": [("CVE-2021-42013", "CRITICAL", "Apache 2.4.50 — Path Traversal/RCE")],
    r"Apache[/ ]2\.4\.(1[0-9]|2[0-9]|3[0-9]|4[0-8])": [
        ("CVE-2021-44790", "HIGH", "Apache < 2.4.51 — mod_lua buffer overflow")
    ],
    # Nginx
    r"nginx/1\.([0-9]|1[0-7])\.": [("CVE-2021-23017", "HIGH", "Nginx < 1.18 — DNS resolver vulnerability")],
    # OpenSSH
    r"SSH-.*OpenSSH[_ ]([1-7]\.)": [("CVE-2020-15778", "MEDIUM", "OpenSSH < 8.0 — command injection via scp")],
    r"SSH-.*OpenSSH[_ ]8\.[0-7]": [("CVE-2023-38408", "HIGH", "OpenSSH < 8.8 — PKCS#11 vulnerability")],
    # IIS
    r"Microsoft-IIS/([7-9]|10)\.0": [("CVE-2021-31166", "CRITICAL", "IIS — HTTP Protocol Stack RCE")],
    # ProFTPD
    r"ProFTPD\s+1\.3\.[0-5]": [("CVE-2019-12815", "CRITICAL", "ProFTPD 1.3.x — file copy/RCE")],
    # vsftpd
    r"vsftpd\s+2\.3\.4": [("CVE-2011-2523", "CRITICAL", "vsftpd 2.3.4 — backdoor")],
    # MySQL
    r"MySQL.*5\.[0-5]\.": [("CVE-2012-2122", "HIGH", "MySQL 5.x — authentication bypass")],
    # PostgreSQL
    r"PostgreSQL.*([8-9]\.|10\.|11\.[0-7])": [("CVE-2019-10164", "HIGH", "PostgreSQL < 11.8 — stack buffer overrun")],
    # SMB
    r"Windows.*SMB": [("CVE-2017-0144", "CRITICAL", "EternalBlue — SMB RCE")],
    # Exim
    r"Exim\s+4\.(8[0-9]|9[01])": [("CVE-2019-10149", "CRITICAL", "Exim 4.87-4.91 — RCE")],
    # Dovecot
    r"Dovecot": [("CVE-2019-11500", "HIGH", "Dovecot — IMAP literal handling vulnerability")],
    # Redis
    r"redis_version:([1-5]\.)": [("CVE-2022-0543", "CRITICAL", "Redis < 6.0 — Lua sandbox escape")],
}


class PortScanner:
    """Сканер портов с расширенным фингерпринтингом."""

    def __init__(self, target: str, port_start: int = 1, port_end: int = 1024,
                 timeout: float = 0.5, max_threads: int = 100):
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.max_threads = max_threads

    def scan(self) -> list[OpenPort]:
        """Сканирование портов с многопоточностью."""
        print(f"[*] Сканирование портов {self.target} [{self.port_start}-{self.port_end}]...")
        open_ports = []
        total = self.port_end - self.port_start + 1
        scanned = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._check_port, port): port
                for port in range(self.port_start, self.port_end + 1)
            }
            for future in as_completed(futures):
                scanned += 1
                if scanned % 200 == 0:
                    print(f"  [*] Просканировано {scanned}/{total} портов...")
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"  [+] Порт {result.port} ОТКРЫТ ({result.service})"
                          f"{' — ' + result.banner if result.banner else ''}")

        open_ports.sort(key=lambda x: x.port)
        print(f"[+] Сканирование завершено. Найдено {len(open_ports)} открытых портов.")
        return open_ports

    def _check_port(self, port: int) -> OpenPort | None:
        """Проверка одного порта."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = KNOWN_PORTS.get(port, "Unknown")
                banner = self._grab_banner(sock, port)
                sock.close()
                return OpenPort(port=port, service=service, banner=banner)
            sock.close()
        except Exception:
            pass
        return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Получение баннера сервиса."""
        try:
            # Для HTTP-портов отправляем запрос
            if port in (80, 8080, 8000, 8888):
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
            elif port in (443, 8443):
                # Для HTTPS не пытаемся через сырой сокет
                return ""
            else:
                # Для остальных ждём приветственный баннер
                sock.settimeout(2)

            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()

            # Извлекаем полезную информацию из HTTP-ответа
            if banner.startswith("HTTP/"):
                server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
                powered_match = re.search(r"X-Powered-By:\s*(.+)", banner, re.IGNORECASE)
                parts = []
                if server_match:
                    parts.append(f"Server: {server_match.group(1).strip()}")
                if powered_match:
                    parts.append(f"X-Powered-By: {powered_match.group(1).strip()}")
                if parts:
                    return " | ".join(parts)
                # Если нет заголовков, берём первую строку
                return banner.split("\r\n")[0][:100]

            return banner[:200]
        except Exception:
            return ""


class BannerAnalyzer:
    """Анализатор баннеров — маппинг на CVE по известным уязвимым версиям."""

    @staticmethod
    def analyze(open_ports: list[OpenPort]) -> list[dict]:
        """
        Анализирует баннеры на наличие известных уязвимых версий.
        Возвращает список словарей: {port, cve_id, severity, description}
        """
        findings = []
        for port_info in open_ports:
            banner = port_info.banner
            if not banner:
                continue
            for pattern, cves in BANNER_CVE_MAP.items():
                if re.search(pattern, banner, re.IGNORECASE):
                    for cve_id, severity, desc in cves:
                        findings.append({
                            "port": port_info.port,
                            "cve_id": cve_id,
                            "severity": severity,
                            "description": f"{desc} (обнаружено в баннере порта {port_info.port})",
                            "banner_match": banner[:100],
                        })
        return findings


class OSDetector:
    """Определение ОС по сетевым характеристикам."""

    @staticmethod
    def detect(target: str, open_ports: list[OpenPort]) -> str:
        """Попытка определить ОС по TTL и набору портов."""
        os_hints = []

        # TTL-анализ
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            # Пробуем подключиться к первому открытому порту
            if open_ports:
                sock.connect((target, open_ports[0].port))
                # TTL из IP-заголовка не доступен через обычный сокет,
                # но мы можем анализировать по набору портов
                sock.close()
        except Exception:
            pass

        # Анализ по открытым портам
        port_set = {p.port for p in open_ports}

        # Windows signatures
        win_ports = {135, 139, 445, 3389, 5985}
        if len(port_set & win_ports) >= 2:
            os_hints.append("Windows")

        # Linux signatures
        if 22 in port_set and 135 not in port_set and 445 not in port_set:
            os_hints.append("Linux/Unix")

        # Web server analysis
        for p in open_ports:
            if "IIS" in p.banner:
                os_hints.append("Windows (IIS)")
            elif "Apache" in p.banner and "Win" in p.banner:
                os_hints.append("Windows (Apache)")
            elif "nginx" in p.banner.lower():
                os_hints.append("Linux (nginx)")

        if os_hints:
            return "; ".join(set(os_hints))
        return "Не удалось определить"


class AttackVectorGenerator:
    """Генерация векторов атак для обнаруженных портов и сервисов."""

    ATTACK_TEMPLATES = {
        21: [
            AttackVector("AV-FTP-ANON", "FTP Anonymous Login", "Попытка анонимного входа на FTP", 21, "FTP", "information_disclosure", Severity.MEDIUM.value, "Nmap, Metasploit"),
            AttackVector("AV-FTP-BRUTE", "FTP Brute Force", "Подбор учётных данных FTP", 21, "FTP", "brute_force", Severity.MEDIUM.value, "Hydra, Medusa"),
            AttackVector("AV-FTP-BOUNCE", "FTP Bounce Attack", "Использование FTP для сканирования внутренней сети", 21, "FTP", "network_reconnaissance", Severity.LOW.value, "Nmap"),
        ],
        22: [
            AttackVector("AV-SSH-BRUTE", "SSH Brute Force", "Подбор учётных данных SSH", 22, "SSH", "brute_force", Severity.MEDIUM.value, "Hydra, Medusa"),
            AttackVector("AV-SSH-ENUM", "SSH User Enumeration", "Перечисление пользователей через SSH", 22, "SSH", "information_disclosure", Severity.LOW.value, "Metasploit"),
            AttackVector("AV-SSH-WEAK-KEY", "SSH Weak Key Exchange", "Использование слабых алгоритмов обмена ключами", 22, "SSH", "protocol_attack", Severity.MEDIUM.value, "ssh-audit"),
        ],
        23: [
            AttackVector("AV-TELNET-BRUTE", "Telnet Brute Force", "Подбор учётных данных Telnet (открытый текст)", 23, "Telnet", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-TELNET-SNIFF", "Telnet Credential Sniffing", "Перехват учётных данных (нет шифрования)", 23, "Telnet", "credential_theft", Severity.HIGH.value, "Wireshark, tcpdump"),
        ],
        25: [
            AttackVector("AV-SMTP-ENUM", "SMTP User Enumeration", "Перечисление пользователей через VRFY/EXPN", 25, "SMTP", "information_disclosure", Severity.LOW.value, "smtp-user-enum"),
            AttackVector("AV-SMTP-RELAY", "SMTP Open Relay", "Использование сервера как открытого релея", 25, "SMTP", "abuse", Severity.MEDIUM.value, "Nmap, swaks"),
        ],
        53: [
            AttackVector("AV-DNS-TRANSFER", "DNS Zone Transfer", "Запрос полной зоны DNS (AXFR)", 53, "DNS", "information_disclosure", Severity.MEDIUM.value, "dig, nslookup"),
            AttackVector("AV-DNS-CACHE", "DNS Cache Poisoning", "Отравление кэша DNS", 53, "DNS", "dns_attack", Severity.HIGH.value, "dnsspoof"),
        ],
        80: [
            AttackVector("AV-HTTP-SQLI", "SQL Injection (HTTP)", "SQL-инъекция через веб-приложение", 80, "HTTP", "sql_injection", Severity.HIGH.value, "SQLMap, Burp Suite"),
            AttackVector("AV-HTTP-XSS", "Cross-Site Scripting (HTTP)", "XSS через веб-приложение", 80, "HTTP", "cross_site_scripting", Severity.MEDIUM.value, "Burp Suite, OWASP ZAP"),
            AttackVector("AV-HTTP-DIR", "Directory Traversal", "Обход директорий веб-сервера", 80, "HTTP", "path_traversal", Severity.MEDIUM.value, "DirBuster, Gobuster"),
            AttackVector("AV-HTTP-VERB", "HTTP Verb Tampering", "Использование нестандартных HTTP-методов", 80, "HTTP", "misconfiguration", Severity.LOW.value, "curl, Burp Suite"),
        ],
        110: [
            AttackVector("AV-POP3-BRUTE", "POP3 Brute Force", "Подбор учётных данных POP3", 110, "POP3", "brute_force", Severity.MEDIUM.value, "Hydra"),
        ],
        135: [
            AttackVector("AV-RPC-ENUM", "RPC Enumeration", "Перечисление RPC-интерфейсов", 135, "RPC", "information_disclosure", Severity.LOW.value, "rpcclient"),
            AttackVector("AV-RPC-DCOM", "DCOM Exploitation", "Эксплуатация уязвимостей DCOM", 135, "RPC", "remote_code_execution", Severity.HIGH.value, "Metasploit"),
        ],
        139: [
            AttackVector("AV-NETBIOS-ENUM", "NetBIOS Enumeration", "Перечисление NetBIOS-имён и ресурсов", 139, "NetBIOS", "information_disclosure", Severity.LOW.value, "nbtscan"),
        ],
        143: [
            AttackVector("AV-IMAP-BRUTE", "IMAP Brute Force", "Подбор учётных данных IMAP", 143, "IMAP", "brute_force", Severity.MEDIUM.value, "Hydra"),
        ],
        443: [
            AttackVector("AV-HTTPS-SQLI", "SQL Injection (HTTPS)", "SQL-инъекция через защищённое соединение", 443, "HTTPS", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-HTTPS-XSS", "Cross-Site Scripting (HTTPS)", "XSS через защищённое соединение", 443, "HTTPS", "cross_site_scripting", Severity.MEDIUM.value, "Burp Suite"),
            AttackVector("AV-HTTPS-SSRF", "Server-Side Request Forgery", "SSRF через веб-приложение", 443, "HTTPS", "ssrf", Severity.HIGH.value, "Burp Suite"),
            AttackVector("AV-HTTPS-SSL", "SSL/TLS Vulnerability", "Атака на уязвимости SSL/TLS протокола", 443, "HTTPS", "protocol_attack", Severity.MEDIUM.value, "SSLScan, testssl.sh"),
            AttackVector("AV-HTTPS-HEART", "Heartbleed Check", "Проверка уязвимости Heartbleed (CVE-2014-0160)", 443, "HTTPS", "information_disclosure", Severity.CRITICAL.value, "Nmap, sslscan"),
        ],
        445: [
            AttackVector("AV-SMB-ETERNAL", "EternalBlue (MS17-010)", "Эксплуатация CVE-2017-0144 через SMB", 445, "SMB", "remote_code_execution", Severity.CRITICAL.value, "Metasploit, EternalBlue"),
            AttackVector("AV-SMB-RELAY", "SMB Relay Attack", "Перенаправление аутентификации SMB", 445, "SMB", "credential_theft", Severity.HIGH.value, "Impacket, Responder"),
            AttackVector("AV-SMB-ENUM", "SMB Enumeration", "Перечисление ресурсов через SMB", 445, "SMB", "information_disclosure", Severity.LOW.value, "Enum4linux, SMBClient"),
            AttackVector("AV-SMB-SIGN", "SMB Signing Disabled", "Подпись SMB не обязательна — MITM возможен", 445, "SMB", "man_in_the_middle", Severity.MEDIUM.value, "CrackMapExec"),
        ],
        1433: [
            AttackVector("AV-MSSQL-BRUTE", "MSSQL Brute Force", "Подбор учётных данных MSSQL", 1433, "MSSQL", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-MSSQL-XP", "MSSQL xp_cmdshell", "Выполнение команд через xp_cmdshell", 1433, "MSSQL", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        3306: [
            AttackVector("AV-MYSQL-BRUTE", "MySQL Brute Force", "Подбор учётных данных MySQL", 3306, "MySQL", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-MYSQL-NOAUTH", "MySQL No Auth Check", "Проверка доступа без аутентификации", 3306, "MySQL", "authentication_bypass", Severity.CRITICAL.value, "mysql client"),
        ],
        3389: [
            AttackVector("AV-RDP-BRUTE", "RDP Brute Force", "Подбор учётных данных RDP", 3389, "RDP", "brute_force", Severity.HIGH.value, "Hydra, Crowbar"),
            AttackVector("AV-RDP-BLUEKEEP", "BlueKeep (CVE-2019-0708)", "Эксплуатация CVE-2019-0708 через RDP", 3389, "RDP", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
            AttackVector("AV-RDP-NLA", "RDP NLA Bypass Check", "Проверка наличия Network Level Authentication", 3389, "RDP", "authentication_bypass", Severity.MEDIUM.value, "rdp-sec-check"),
        ],
        5432: [
            AttackVector("AV-PGSQL-BRUTE", "PostgreSQL Brute Force", "Подбор учётных данных PostgreSQL", 5432, "PostgreSQL", "brute_force", Severity.HIGH.value, "Hydra"),
        ],
        5900: [
            AttackVector("AV-VNC-BRUTE", "VNC Brute Force", "Подбор пароля VNC", 5900, "VNC", "brute_force", Severity.HIGH.value, "Hydra, Crowbar"),
            AttackVector("AV-VNC-NOAUTH", "VNC No Authentication", "VNC без аутентификации", 5900, "VNC", "authentication_bypass", Severity.CRITICAL.value, "vncviewer"),
        ],
        6379: [
            AttackVector("AV-REDIS-NOAUTH", "Redis No Authentication", "Redis без пароля — полный доступ", 6379, "Redis", "authentication_bypass", Severity.CRITICAL.value, "redis-cli"),
            AttackVector("AV-REDIS-RCE", "Redis RCE via Lua", "Выполнение кода через Lua sandbox escape", 6379, "Redis", "remote_code_execution", Severity.CRITICAL.value, "redis-cli"),
        ],
        8080: [
            AttackVector("AV-PROXY-SQLI", "SQL Injection (Proxy)", "SQL-инъекция через прокси/приложение", 8080, "HTTP-Proxy", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-PROXY-RCE", "Remote Code Execution (Proxy)", "RCE через веб-приложение на порту 8080", 8080, "HTTP-Proxy", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        27017: [
            AttackVector("AV-MONGO-NOAUTH", "MongoDB No Authentication", "MongoDB без аутентификации", 27017, "MongoDB", "authentication_bypass", Severity.CRITICAL.value, "mongosh"),
        ],
    }

    def generate(self, open_ports: list[OpenPort]) -> list[AttackVector]:
        """Генерация векторов атак для обнаруженных портов."""
        print("\n[*] Генерация векторов атак...")
        vectors = []

        for port_info in open_ports:
            port = port_info.port
            if port in self.ATTACK_TEMPLATES:
                vectors.extend(self.ATTACK_TEMPLATES[port])

        # Добавляем атаки на основе анализа баннеров
        banner_findings = BannerAnalyzer.analyze(open_ports)
        for finding in banner_findings:
            av = AttackVector(
                id=f"AV-BANNER-{finding['cve_id']}",
                name=f"{finding['cve_id']} (по баннеру)",
                description=finding['description'],
                target_port=finding['port'],
                target_service="banner_detected",
                attack_type="known_vulnerability",
                severity=finding['severity'],
                tools_used="Version-specific exploit",
            )
            vectors.append(av)

        # Общие атаки для любого открытого сервиса
        if open_ports:
            vectors.append(AttackVector(
                "AV-DOS-GENERIC", "Denial of Service",
                "Атака отказа в обслуживании на обнаруженные сервисы",
                None, "generic", "denial_of_service",
                Severity.MEDIUM.value, "hping3, LOIC"
            ))

            # Если больше 5 открытых портов — добавляем рекомендацию по hardening
            if len(open_ports) > 5:
                vectors.append(AttackVector(
                    "AV-SURFACE-LARGE", "Large Attack Surface",
                    f"Обнаружено {len(open_ports)} открытых портов — большая поверхность атаки",
                    None, "generic", "misconfiguration",
                    Severity.MEDIUM.value, "Firewall configuration"
                ))

        print(f"[+] Сгенерировано {len(vectors)} возможных векторов атак "
              f"(в т.ч. {len(banner_findings)} по баннерам)")
        return vectors


class AttackSender:
    """Отправка результатов на серверный агент (HTTPS + токен)."""

    def __init__(self, server_url: str, token: str = ""):
        self.server_url = server_url.replace("http://", "https://", 1)
        self.token = token
        self._ssl_ctx = build_client_ssl_context()

    def send(self, scan_result: ScanResult) -> dict:
        """Отправка результатов сканирования на сервер."""
        print(f"\n[*] Отправка результатов на {self.server_url}/analyze ...")

        from dataclasses import asdict
        data = asdict(scan_result)
        json_data = json.dumps(data, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            f"{self.server_url}/analyze",
            data=json_data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-Auth-Token": self.token,
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=120, context=self._ssl_ctx) as response:
                result = json.loads(response.read().decode("utf-8"))
                print("[+] Ответ от сервера получен!")
                return result
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print("[!] Ошибка 401: неверный или отсутствующий токен доступа (--token)")
                return {"error": "401 Unauthorized: проверьте токен"}
            print(f"[!] Ошибка HTTP {e.code}: {e.reason}")
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except urllib.error.URLError as e:
            print(f"[!] Ошибка подключения к серверу: {e}")
            return {"error": str(e)}
        except Exception as e:
            print(f"[!] Ошибка: {e}")
            return {"error": str(e)}


def run_attacker(target_ip: str = None, server_port: int = None,
                 port_start: int = None, port_end: int = None, token: str = ""):
    """Основная функция атакующего агента."""
    target = target_ip or TARGET_SERVER_HOST
    srv_port = server_port or TARGET_SERVER_PORT
    p_start = port_start or SCAN_PORT_START
    p_end = port_end or SCAN_PORT_END

    print("=" * 60)
    print("  АТАКУЮЩИЙ АГЕНТ — СКАНИРОВАНИЕ И АНАЛИЗ")
    print("=" * 60)
    print(f"  Цель:      {target}")
    print(f"  Порты:     {p_start}-{p_end}")
    print(f"  Сервер:    https://{target}:{srv_port}")
    print("=" * 60)

    # 1. Сканирование портов
    scanner = PortScanner(target, p_start, p_end)
    open_ports = scanner.scan()

    if not open_ports:
        print("[!] Открытых портов не обнаружено. Завершение.")
        return

    # 2. Определение ОС
    os_info = OSDetector.detect(target, open_ports)
    print(f"\n[*] Определение ОС: {os_info}")

    # 3. Анализ баннеров
    banner_findings = BannerAnalyzer.analyze(open_ports)
    if banner_findings:
        print(f"\n[!] Обнаружено {len(banner_findings)} CVE по баннерам:")
        for f in banner_findings:
            print(f"  [{f['severity']:>8}] {f['cve_id']}: {f['description'][:60]}")

    # 4. Генерация векторов атак
    generator = AttackVectorGenerator()
    attack_vectors = generator.generate(open_ports)

    # 5. Формирование результата
    scan_result = ScanResult(
        scanner_ip=socket.gethostbyname(socket.gethostname()),
        target_ip=target,
        open_ports=open_ports,
        discovered_services=[f"{p.service} (:{p.port})" for p in open_ports],
        attack_vectors=attack_vectors,
        os_detection=os_info,
        scan_timestamp=datetime.now().isoformat(),
    )

    # 6. Вывод сводки
    print("\n" + "=" * 60)
    print("СВОДКА СКАНИРОВАНИЯ")
    print("=" * 60)
    print(f"Определённая ОС: {os_info}")
    print(f"Открытые порты ({len(open_ports)}):")
    for p in open_ports:
        print(f"  {p.port:>5}/TCP  {p.service:<15} {p.banner[:50] if p.banner else ''}")
    print(f"\nВекторы атак ({len(attack_vectors)}):")
    for av in attack_vectors:
        print(f"  [{av.severity:>8}] {av.name}: {av.description[:60]}")

    # 7. Отправка на сервер
    fingerprint = get_server_fingerprint(target, srv_port)
    if fingerprint:
        print(f"\n[*] Отпечаток сертификата сервера (SHA-256):\n    {fingerprint}")
        print("    Сверьте его с отпечатком, показанным на серверном агенте!")
    else:
        print("\n[!] Не удалось получить отпечаток сертификата сервера.")

    server_url = f"https://{target}:{srv_port}"
    sender = AttackSender(server_url, token=token)
    result = sender.send(scan_result)

    if "error" in result:
        print(f"\n[!] Ошибка от сервера: {result['error']}")
    else:
        print(f"\n[+] Анализ завершён. Результатов: {result.get('results_count', '?')}")
        summary = result.get("summary", {})
        print(f"  Реализуемых атак: {summary.get('feasible_attacks', '?')}")
        print(f"  Частично реализуемых: {summary.get('partially_feasible', '?')}")
        print(f"  Нереализуемых: {summary.get('not_feasible_attacks', '?')}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Атакующий агент")
    parser.add_argument("-t", "--target", default=None, help="IP-адрес цели")
    parser.add_argument("-p", "--port", type=int, default=None, help="Порт API сервера")
    parser.add_argument("--scan-start", type=int, default=None, help="Начало диапазона")
    parser.add_argument("--scan-end", type=int, default=None, help="Конец диапазона")
    parser.add_argument("--token", default="", help="Токен доступа к API сервера")
    args = parser.parse_args()

    run_attacker(args.target, args.port, args.scan_start, args.scan_end, token=args.token)