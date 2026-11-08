"""
Конфигурация системы анализа безопасности.
"""

# Настройки серверного агента (API)
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8443

# Безопасность API
# Статичный токен доступа. Пустая строка = генерировать случайный при каждом запуске
# (отображается в GUI сервера и в логе консольного режима).
API_TOKEN = ""
# Максимальный размер тела запроса к API (байт)
MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 МБ
# Папка для TLS-сертификата сервера (генерируется автоматически)
CERTS_DIR = "certs"

# Адрес сервера для атакующего агента
TARGET_SERVER_HOST = "127.0.0.1"
TARGET_SERVER_PORT = 8443

# Диапазон портов для сканирования
SCAN_PORT_START = 1
SCAN_PORT_END = 1024
SCAN_TIMEOUT = 0.5  # секунды

# Пути к базам данных
DB_DIR = "databases"
CVE_DB_PATH = f"{DB_DIR}/cve_database.json"
CWE_DB_PATH = f"{DB_DIR}/cwe_database.json"
CAPEC_DB_PATH = f"{DB_DIR}/capec_database.json"
MITRE_DB_PATH = f"{DB_DIR}/mitre_attack.json"

# Путь для отчётов
REPORTS_DIR = "reports"

# Известные порты и связанные сервисы
KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}
