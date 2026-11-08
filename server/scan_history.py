"""
Модуль истории сканирований системы.
Сохраняет и загружает результаты предыдущих сканирований,
чтобы не сканировать систему каждый раз заново.
"""
import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from typing import List, Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.logger import get_server_logger
from common.models import SystemInfo, OpenPort, InstalledSoftware, SecurityMeasure

logger = get_server_logger()

SCAN_HISTORY_DIR = "data/scan_history"
SCAN_HISTORY_PATTERN = "scan_*.json"


@dataclass
class ScanRecord:
    """Запись в истории сканирований системы."""
    scan_id: str = ""
    timestamp: str = ""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    installed_software: List[Dict[str, str]] = field(default_factory=list)
    running_services: List[str] = field(default_factory=list)
    security_measures: List[Dict[str, str]] = field(default_factory=list)
    has_database: bool = False
    database_types: List[str] = field(default_factory=list)
    has_web_server: bool = False
    web_server_types: List[str] = field(default_factory=list)
    has_rdp_enabled: bool = False
    has_smb_enabled: bool = False
    has_ftp_enabled: bool = False
    trivy_scan_result: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "ScanRecord":
        return ScanRecord(
            scan_id=d.get("scan_id", ""),
            timestamp=d.get("timestamp", ""),
            hostname=d.get("hostname", ""),
            os_name=d.get("os_name", ""),
            os_version=d.get("os_version", ""),
            ip_addresses=d.get("ip_addresses", []),
            open_ports=d.get("open_ports", []),
            installed_software=d.get("installed_software", []),
            running_services=d.get("running_services", []),
            security_measures=d.get("security_measures", []),
            has_database=d.get("has_database", False),
            database_types=d.get("database_types", []),
            has_web_server=d.get("has_web_server", False),
            web_server_types=d.get("web_server_types", []),
            has_rdp_enabled=d.get("has_rdp_enabled", False),
            has_smb_enabled=d.get("has_smb_enabled", False),
            has_ftp_enabled=d.get("has_ftp_enabled", False),
            trivy_scan_result=d.get("trivy_scan_result", {}),
            summary=d.get("summary", {}),
            scan_duration_seconds=d.get("scan_duration_seconds", 0.0),
            notes=d.get("notes", ""),
        )

    @property
    def formatted_timestamp(self) -> str:
        """Форматированная дата/время."""
        try:
            dt = datetime.fromisoformat(self.timestamp)
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            return self.timestamp

    def to_system_info(self) -> SystemInfo:
        """Преобразование записи сканирования в объект SystemInfo."""
        system_info = SystemInfo()
        system_info.hostname = self.hostname
        system_info.os_name = self.os_name
        system_info.os_version = self.os_version
        system_info.ip_addresses = self.ip_addresses
        system_info.open_ports = [
            OpenPort(
                port=p.get("port", 0),
                service=p.get("service", ""),
                protocol=p.get("protocol", "TCP")
            )
            for p in self.open_ports
        ]
        system_info.installed_software = [
            InstalledSoftware(
                name=sw.get("name", ""),
                version=sw.get("version", "")
            )
            for sw in self.installed_software
        ]
        system_info.running_services = self.running_services
        system_info.security_measures = [
            SecurityMeasure(
                name=m.get("name", ""),
                category=m.get("category", ""),
                status=m.get("status", ""),
                details=m.get("details", "")
            )
            for m in self.security_measures
        ]
        system_info.has_database = self.has_database
        system_info.database_types = self.database_types
        system_info.has_web_server = self.has_web_server
        system_info.web_server_types = self.web_server_types
        system_info.has_rdp_enabled = self.has_rdp_enabled
        system_info.has_smb_enabled = self.has_smb_enabled
        system_info.has_ftp_enabled = self.has_ftp_enabled
        system_info.trivy_scan_result = self.trivy_scan_result
        return system_info


class ScanHistory:
    """
    Менеджер истории сканирований системы.
    Сохраняет и загружает историю из JSON-файла.
    """

    def __init__(self, base_dir: str = ""):
        self.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._history_dir = os.path.join(self.base_dir, SCAN_HISTORY_DIR)
        self._records: List[ScanRecord] = []
        self._record_files: Dict[str, str] = {}  # scan_id -> filepath
        self._load()

    def _load(self):
        """Загрузка истории из файлов в директории."""
        os.makedirs(self._history_dir, exist_ok=True)

        import glob
        pattern = os.path.join(self._history_dir, SCAN_HISTORY_PATTERN)
        files = glob.glob(pattern)

        self._records = []
        self._record_files = {}

        for filepath in files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                record = ScanRecord.from_dict(data)
                self._records.append(record)
                self._record_files[record.scan_id] = filepath
            except Exception as e:
                logger.warning(f"[SCAN HISTORY] Ошибка загрузки файла {filepath}: {e}")

        # Сортировка по времени (новые первыми)
        self._records.sort(key=lambda r: r.timestamp, reverse=True)
        logger.info(f"[SCAN HISTORY] Загружено {len(self._records)} записей из {len(files)} файлов")

    def _save(self):
        """Этот метод больше не используется - каждая запись сохраняется в отдельный файл."""
        pass

    def add_record(self, record: ScanRecord):
        """Добавление новой записи в историю."""
        # Создаем файл для новой записи
        filename = f"{record.scan_id}.json"
        filepath = os.path.join(self._history_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(record.to_dict(), f, ensure_ascii=False, indent=2)

            # Добавляем в память
            self._records.insert(0, record)
            self._record_files[record.scan_id] = filepath
            logger.info(f"[SCAN HISTORY] Создана новая запись: {record.scan_id} в файле {filename}")
        except Exception as e:
            logger.error(f"[SCAN HISTORY] Ошибка сохранения записи {record.scan_id}: {e}")

    def get_all(self) -> List[ScanRecord]:
        """Получение всех записей."""
        return list(self._records)

    def get_latest(self) -> Optional[ScanRecord]:
        """Получение последней записи сканирования."""
        return self._records[0] if self._records else None

    def get_by_id(self, scan_id: str) -> Optional[ScanRecord]:
        """Поиск записи по ID."""
        for r in self._records:
            if r.scan_id == scan_id:
                return r
        return None

    def get_by_hostname(self, hostname: str) -> List[ScanRecord]:
        """Поиск записей по имени хоста."""
        return [r for r in self._records if r.hostname == hostname]

    def delete_record(self, scan_id: str) -> bool:
        """Удалить запись по ID."""
        if scan_id in self._record_files:
            filepath = self._record_files[scan_id]
            try:
                # Удаляем файл
                if os.path.exists(filepath):
                    os.remove(filepath)

                # Удаляем из памяти
                self._records = [r for r in self._records if r.scan_id != scan_id]
                del self._record_files[scan_id]

                logger.info(f"[SCAN_HISTORY] Удалена запись {scan_id} и файл {filepath}")
                return True
            except Exception as e:
                logger.error(f"[SCAN_HISTORY] Ошибка удаления файла {filepath}: {e}")
                return False
        return False

    def update_record(self, scan_id: str, updated_record: ScanRecord) -> bool:
        """Обновить запись по ID."""
        if scan_id in self._record_files:
            filepath = self._record_files[scan_id]
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(updated_record.to_dict(), f, ensure_ascii=False, indent=2)

                # Обновляем в памяти
                for i, r in enumerate(self._records):
                    if r.scan_id == scan_id:
                        self._records[i] = updated_record
                        break

                logger.info(f"[SCAN_HISTORY] Обновлена запись {scan_id} с Trivy данными: {len(updated_record.trivy_scan_result.get('vulnerabilities', []))} уязвимостей")
                return True
            except Exception as e:
                logger.error(f"[SCAN_HISTORY] Ошибка обновления файла {filepath}: {e}")
                return False
        else:
            logger.warning(f"[SCAN_HISTORY] Файл для записи {scan_id} не найден")
            return False

    def is_scan_available(self, hostname: str = "") -> bool:
        """Проверка, есть ли сканирование для данного хоста."""
        if hostname:
            return any(r.hostname == hostname for r in self._records)
        return len(self._records) > 0

    @staticmethod
    def from_system_info(system_info: SystemInfo, summary: dict, scan_duration: float = 0.0, notes: str = "") -> ScanRecord:
        """Создание записи истории из объекта SystemInfo."""
        timestamp = datetime.now().isoformat()
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        record = ScanRecord(
            scan_id=scan_id,
            timestamp=timestamp,
            hostname=system_info.hostname,
            os_name=system_info.os_name,
            os_version=system_info.os_version,
            ip_addresses=system_info.ip_addresses,
            open_ports=[
                {"port": p.port, "service": p.service, "protocol": p.protocol}
                for p in system_info.open_ports
            ],
            installed_software=[
                {"name": sw.name, "version": sw.version}
                for sw in system_info.installed_software
            ],
            running_services=system_info.running_services,
            security_measures=[
                {"name": m.name, "category": m.category, "status": m.status, "details": m.details}
                for m in system_info.security_measures
            ],
            has_database=system_info.has_database,
            database_types=system_info.database_types,
            has_web_server=system_info.has_web_server,
            web_server_types=system_info.web_server_types,
            has_rdp_enabled=system_info.has_rdp_enabled,
            has_smb_enabled=system_info.has_smb_enabled,
            has_ftp_enabled=system_info.has_ftp_enabled,
            trivy_scan_result=getattr(system_info, 'trivy_scan_result', {}),
            summary=summary,
            scan_duration_seconds=scan_duration,
            notes=notes,
        )
        return record

    @property
    def total_count(self) -> int:
        return len(self._records)

    @property
    def stats(self) -> dict:
        """Общая статистика по истории."""
        records = self._records
        return {
            "total": len(records),
            "unique_hosts": len(set(r.hostname for r in records)),
            "avg_scan_duration": round(
                sum(r.scan_duration_seconds for r in records) / max(len(records), 1), 1
            ),
            "latest_scan": records[0].formatted_timestamp if records else "Нет сканирований",
        }
