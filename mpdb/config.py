import sys
from pathlib import Path

if getattr(sys, 'frozen', False):
    # Собранный .exe: данные храним рядом с исполняемым файлом
    _BASE_DIR = Path(sys.executable).parent
else:
    _BASE_DIR = Path(__file__).parent

class Config:
    BASE_DIR = _BASE_DIR
    OUTPUT_DIR = BASE_DIR / "data" / "snapshots"
    
    # 🔹 НАСТРОЙКА ПЕРЕВОДА 🔹
    ENABLE_TRANSLATION = False
    TRANSLATE_TO = "ru" # <- Код языка для Русского
    TRANSLATION_DELAY = 0.2     # Базовая задержка перед запросом в потоке (сек, применяется джиттер ±50%)
    TRANSLATION_WORKERS = 8     # Запросы упаковываются пачками, поэтому много потоков не нужно
    TRANSLATION_MAX_RETRIES = 5     # Число повторных попыток при ошибке
    TRANSLATION_SERVICE = "google" # перевод выполняется через Google Translate

    # Настройки загрузки
    REQUEST_TIMEOUT = 30
    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 5

    # 🔹 Ограничение записей (0 или None = все) 🔹
    MAX_CAPEC_RECORDS = 1000
    MAX_CWE_RECORDS = 1000
    MAX_CVE_RECORDS = 4000
    MAX_ATTACK_RECORDS = 1000

    # 🔹 АВТОЗАПОЛНЕНИЕ ПУСТЫХ ПОЛЕЙ (step4_autofill.py) 🔹
    # Шаблонные фразы для полей, которые не удалось восстановить из первоисточников.
    # Поля-связи (related_*) шаблонами НЕ заполняются — там должны быть только реальные ID.
    AUTOFILL_TEMPLATES = {
        "capec_database.json": {
            "prerequisites": "Предварительные условия не указаны в первоисточнике",
            "mitigations": "Меры противодействия не указаны; рекомендуются общие практики защиты (обновление ПО, минимизация привилегий, мониторинг)",
        },
        "cwe_database.json": {
            "mitigation": "Меры противодействия не указаны в первоисточнике",
            "detection_methods": "Метод обнаружения не указан в первоисточнике",
            "requires_technology": "Не зависит от конкретной технологии",
        },
        "cve_database.json": {
            "prerequisites": "Предварительные условия не указаны; как правило, требуется доступ к уязвимому компоненту",
            "mitigations": "Меры противодействия не указаны; рекомендуется обновить уязвимое ПО до исправленной версии",
            "affected_software": "Не указано в первоисточнике",
            "requires_service": "не определено",
            "requires_port": "не определено",
        },
        "mitre_attack.json": {
            "detection": "Метод обнаружения не указан в первоисточнике",
            "mitigations": "Меры противодействия не указаны; рекомендуются общие практики защиты (сегментация сети, минимизация привилегий, мониторинг)",
            "requires_service": "не определено",
        },
    }

    # Источники данных
    SOURCES = {
        "capec": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "cve_latest": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
        "attack_stix": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    }
    
    # Маппинг полей (без пробелов в концах ключей!)
    FIELD_MAPPING = {
        "capec": {"id": "id", "name": "name", "description": "description", "severity": "severity", "related_cwe": "related_cwe", "related_mitre": "related_mitre", "prerequisites": "prerequisites", "mitigations": "mitigations"},
        "cve": {"id": "id", "description": "description", "severity": "severity", "cvss_score": "cvss_score", "affected_software": "affected_software", "attack_type": "attack_type", "related_cwe": "related_cwe", "related_capec": "related_capec", "related_mitre": "related_mitre", "requires_service": "requires_service", "requires_port": "requires_port", "prerequisites": "prerequisites"},
        "mitre_attack": {"id": "id", "name": "name", "tactic": "tactic", "description": "description", "platforms": "platforms", "related_cwe": "related_cwe", "related_capec": "related_capec", "requires_service": "requires_service", "detection": "detection", "mitigations": "mitigations"},
        "cwe": {"id": "id", "name": "name", "description": "description", "category": "category", "related_capec": "related_capec", "mitigation": "mitigation", "requires_technology": "requires_technology", "detection_methods": "detection_methods"}
        }