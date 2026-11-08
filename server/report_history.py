"""
Модуль истории отчётов.
Хранит метаданные всех сгенерированных отчётов с возможностью
сортировки, фильтрации и быстрого доступа.
"""
import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.logger import get_server_logger
logger = get_server_logger()
HISTORY_FILE = "reports/report_history.json"
@dataclass
class ReportRecord:
    """Запись в истории отчётов."""
    report_id: str = ""
    timestamp: str = ""
    html_path: str = ""
    json_path: str = ""
    target_ip: str = ""
    scanner_ip: str = ""
    total_vulnerabilities: int = 0
    feasible_count: int = 0
    not_feasible_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    os_name: str = ""
    hostname: str = ""
    attack_vectors_used: list = field(default_factory=list)
    notes: str = ""
    def to_dict(self) -> dict:
        return asdict(self)
    @staticmethod
    def from_dict(d: dict) -> "ReportRecord":
        return ReportRecord(
            report_id=d.get("report_id", ""),
            timestamp=d.get("timestamp", ""),
            html_path=d.get("html_path", ""),
            json_path=d.get("json_path", ""),
            target_ip=d.get("target_ip", ""),
            scanner_ip=d.get("scanner_ip", ""),
            total_vulnerabilities=d.get("total_vulnerabilities", 0),
            feasible_count=d.get("feasible_count", 0),
            not_feasible_count=d.get("not_feasible_count", 0),
            critical_count=d.get("critical_count", 0),
            high_count=d.get("high_count", 0),
            medium_count=d.get("medium_count", 0),
            low_count=d.get("low_count", 0),
            os_name=d.get("os_name", ""),
            hostname=d.get("hostname", ""),
            attack_vectors_used=d.get("attack_vectors_used", []),
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
    @property
    def exists_on_disk(self) -> bool:
        """Проверка, что файл отчёта существует."""
        return bool(self.html_path) and os.path.exists(self.html_path)
    @property
    def risk_level(self) -> str:
        """Уровень риска на основе результатов."""
        if self.critical_count > 0:
            return "КРИТИЧЕСКИЙ"
        elif self.high_count > 0:
            return "ВЫСОКИЙ"
        elif self.medium_count > 0:
            return "СРЕДНИЙ"
        elif self.low_count > 0:
            return "НИЗКИЙ"
        return "ИНФОРМАЦИОННЫЙ"
    @property
    def risk_color(self) -> str:
        """Цвет для уровня риска."""
        colors = {
            "КРИТИЧЕСКИЙ": "#c44",
            "ВЫСОКИЙ": "#a85",
            "СРЕДНИЙ": "#997",
            "НИЗКИЙ": "#696",
            "ИНФОРМАЦИОННЫЙ": "#668",
        }
        return colors.get(self.risk_level, "#888")
class ReportHistory:
    """
    Менеджер истории отчётов.
    Сохраняет и загружает историю из JSON-файла.
    """
    def __init__(self, base_dir: str = ""):
        self.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._history_path = os.path.join(self.base_dir, HISTORY_FILE)
        self._records: list[ReportRecord] = []
        self._load()
    def _load(self):
        """Загрузка истории из файла."""
        os.makedirs(os.path.dirname(self._history_path), exist_ok=True)
        if not os.path.exists(self._history_path):
            self._records = []
            return
        try:
            with open(self._history_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._records = [ReportRecord.from_dict(d) for d in data]
            logger.info(f"[HISTORY] Загружено {len(self._records)} записей из истории")
        except Exception as e:
            logger.error(f"[HISTORY] Ошибка загрузки истории: {e}")
            self._records = []
    def _save(self):
        """Сохранение истории в файл."""
        try:
            os.makedirs(os.path.dirname(self._history_path), exist_ok=True)
            with open(self._history_path, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in self._records], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"[HISTORY] Ошибка сохранения истории: {e}")
    def add_record(self, record: ReportRecord):
        """Добавление новой записи в историю."""
        # Вставляем в начало (новые записи первые)
        self._records.insert(0, record)
        self._save()
        logger.info(f"[HISTORY] Добавлена запись: {record.report_id} ({record.timestamp})")
    def get_all(self) -> list[ReportRecord]:
        """Получение всех записей (с проверкой существования файлов)."""
        return list(self._records)
    def get_existing(self) -> list[ReportRecord]:
        """Только записи с существующими файлами на диске."""
        return [r for r in self._records if r.exists_on_disk]
    def get_by_id(self, report_id: str) -> Optional[ReportRecord]:
        """Поиск записи по ID."""
        for r in self._records:
            if r.report_id == report_id:
                return r
        return None
    def delete_record(self, report_id: str) -> bool:
        """Удаление записи из истории (без удаления файла)."""
        before = len(self._records)
        self._records = [r for r in self._records if r.report_id != report_id]
        if len(self._records) < before:
            self._save()
            return True
        return False
    def delete_with_files(self, report_id: str) -> bool:
        """Удаление записи вместе с файлами отчёта."""
        record = self.get_by_id(report_id)
        if not record:
            return False
        # Удаляем HTML-файл
        if record.html_path and os.path.exists(record.html_path):
            try:
                os.remove(record.html_path)
            except Exception as e:
                logger.warning(f"[HISTORY] Не удалось удалить HTML: {e}")
        # Удаляем JSON-файл
        if record.json_path and os.path.exists(record.json_path):
            try:
                os.remove(record.json_path)
            except Exception as e:
                logger.warning(f"[HISTORY] Не удалось удалить JSON: {e}")
        return self.delete_record(report_id)
    def sync_from_disk(self, reports_dir: str):
        """
        Синхронизация истории с файлами на диске.
        Добавляет отчёты, которые есть на диске но отсутствуют в истории.
        """
        if not os.path.exists(reports_dir):
            return
        existing_paths = {r.html_path for r in self._records}
        new_count = 0
        for fname in sorted(os.listdir(reports_dir), reverse=True):
            if not fname.endswith(".html") or not fname.startswith("report_"):
                continue
            fpath = os.path.join(reports_dir, fname)
            if fpath in existing_paths:
                continue
            # Пытаемся прочитать метаданные из JSON
            json_path = fpath.replace(".html", ".json")
            record = self._build_record_from_files(fpath, json_path)
            if record:
                self._records.append(record)
                new_count += 1
        if new_count > 0:
            # Сортируем по времени (новые первые)
            self._records.sort(key=lambda r: r.timestamp, reverse=True)
            self._save()
            logger.info(f"[HISTORY] Синхронизировано {new_count} новых отчётов с диска")
    def _build_record_from_files(self, html_path: str, json_path: str) -> Optional[ReportRecord]:
        """Построение записи истории из файлов отчёта."""
        try:
            fname = os.path.basename(html_path)
            # Извлекаем timestamp из имени файла (report_YYYYMMDD_HHMMSS.html)
            ts_str = fname.replace("report_", "").replace(".html", "")
            try:
                dt = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                timestamp = dt.isoformat()
                report_id = ts_str
            except ValueError:
                # Fallback to file modification time if name format is wrong
                try:
                    mtime = os.path.getmtime(html_path)
                    timestamp = datetime.fromtimestamp(mtime).isoformat()
                except OSError:
                    timestamp = datetime.now().isoformat()
                report_id = fname.replace(".html", "")

            record = ReportRecord(
                report_id=report_id,
                timestamp=timestamp,
                html_path=html_path,
                json_path=json_path if os.path.exists(json_path) else "",
            )
            # Читаем метаданные из JSON если он есть
            if os.path.exists(json_path):
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    server_info = data.get("server_info", {})
                    record.hostname = server_info.get("hostname", "")
                    record.os_name = server_info.get("os", "")
                    results = data.get("results", [])
                    record.total_vulnerabilities = len(results)
                    record.feasible_count = sum(1 for r in results if r.get("feasibility") == "РЕАЛИЗУЕМА")
                    record.not_feasible_count = sum(1 for r in results if r.get("feasibility") == "НЕ РЕАЛИЗУЕМА")
                    record.critical_count = sum(1 for r in results if r.get("severity") == "CRITICAL")
                    record.high_count = sum(1 for r in results if r.get("severity") == "HIGH")
                    record.medium_count = sum(1 for r in results if r.get("severity") == "MEDIUM")
                    record.low_count = sum(1 for r in results if r.get("severity") == "LOW")
                    summary = data.get("summary", {})
                    record.target_ip = summary.get("target_ip", "")
                    record.scanner_ip = summary.get("scanner_ip", "")
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"[HISTORY] Ошибка чтения JSON для отчёта {html_path}: {e}")
            return record
        except Exception as e:
            logger.error(f"[HISTORY] Критическая ошибка при построении записи для {html_path}: {e}", exc_info=True)
            return None
    @property
    def total_count(self) -> int:
        return len(self._records)
    @property
    def stats(self) -> dict:
        """Общая статистика по истории."""
        records = self._records
        return {
            "total": len(records),
            "with_files": sum(1 for r in records if r.exists_on_disk),
            "critical_reports": sum(1 for r in records if r.critical_count > 0),
            "avg_vulns": round(
                sum(r.total_vulnerabilities for r in records) / max(len(records), 1), 1
            ),
        }
