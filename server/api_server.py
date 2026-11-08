"""
API сервера для приёма результатов сканирования от атакующего агента.

- HTTPS (self-signed сертификат, генерируется автоматически)
- Аутентификация по заголовку X-Auth-Token на всех эндпоинтах
- Многопоточный ThreadingHTTPServer
- Ограничение размера тела запроса
"""

import json
import os
import sys
import threading
import logging
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.config import SERVER_HOST, SERVER_PORT, MAX_BODY_SIZE, CERTS_DIR
from common.models import from_json_scan_result
from common.logger import get_server_logger
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator
from server.trivy_scanner import TrivyScanResult
from server.api_security import (
    build_server_ssl_context, get_cert_fingerprint,
    generate_token, check_token,
)

logger = get_server_logger()


class ServerState:
    """Глобальное состояние сервера."""

    def __init__(self):
        self.system_analyzer = None
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.toolkit = None           # AttackToolkit — для схем 3,4,5 отчёта
        self.local_scan_report = None # ScanReport — для схемы 3 отчёта
        self.trivy_result = None      # TrivyScanResult — для корреляции уязвимостей
        self.base_dir = ""
        self.ready = False
        self.connected_clients = []
        self.api_token = ""           # Токен доступа к API
        self.lock = threading.Lock()
        self.last_scan_data = {}      # Последние данные от атакующего (для GUI)
        self.last_results = []        # Последние результаты корреляции (для GUI)
        self.on_client_connected = None
        self.on_analysis_complete = None
        # Прогресс корреляции
        self.correlation_progress = 0
        self.correlation_message = ""
        self.on_correlation_progress = None


state = ServerState()


def _safe_hostname() -> str:
    """Безопасное получение hostname из system_summary."""
    if state.system_summary and isinstance(state.system_summary, dict):
        return state.system_summary.get("hostname", "")
    return ""


def _save_to_history(results: list, summary: dict, ts: str,
                     html_path: str, json_path: str, scan_data: dict):
    """Сохранение результатов в историю отчётов (если ReportHistory доступен)."""
    try:
        from server.report_history import ReportHistory, ReportRecord
        history = ReportHistory(state.base_dir)
        rec = ReportRecord(
            report_id=ts,
            timestamp=datetime.now().isoformat(),
            html_path=html_path,
            json_path=json_path,
            hostname=state.system_summary.get("hostname", "") if isinstance(state.system_summary, dict) else "",
            os_name=state.system_summary.get("os", "") if isinstance(state.system_summary, dict) else "",
            target_ip=scan_data.get("target_ip", ""),
            scanner_ip=scan_data.get("scanner_ip", ""),
            total_vulnerabilities=len(results),
            feasible_count=summary.get("feasible_attacks", 0),
            not_feasible_count=summary.get("not_feasible_attacks", 0),
            critical_count=summary.get("critical_count", 0),
            high_count=summary.get("high_count", 0),
            medium_count=summary.get("medium_count", 0),
            low_count=summary.get("low_count", 0),
        )
        history.add_record(rec)
        logger.info(f"[HISTORY] Запись добавлена: {ts}")
    except ImportError:
        logger.debug("[HISTORY] ReportHistory недоступен — пропускаем")
    except Exception as e:
        logger.warning(f"[HISTORY] Ошибка сохранения в историю: {e}")


class RequestHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP(S)-запросов."""

    def _check_auth(self) -> bool:
        """Проверка токена доступа. Возвращает True, если запрос авторизован."""
        token = self.headers.get("X-Auth-Token", "")
        if check_token(token, state.api_token):
            return True
        logger.warning(f"[HTTP-IN] 401 от {self.client_address[0]}: неверный/отсутствующий токен ({self.path})")
        self._respond(401, {"error": "Неавторизован: неверный или отсутствующий заголовок X-Auth-Token"})
        return False

    def _register_client(self, client_ip: str):
        with state.lock:
            if client_ip in state.connected_clients:
                return
            state.connected_clients.append(client_ip)
        logger.info(f"[HTTP-IN] НОВЫЙ КЛИЕНТ: {client_ip}")
        if state.on_client_connected:
            state.on_client_connected(client_ip)

    def do_GET(self):
        client_ip = self.client_address[0]
        logger.info(f"[HTTP-IN] GET {self.path} от {client_ip}")
        if not self._check_auth():
            return
        try:
            if self.path == "/status":
                self._respond(200, {
                    "status": "running",
                    "ready": state.ready,
                    "hostname": _safe_hostname(),
                    "timestamp": datetime.now().isoformat(),
                    "clients": state.connected_clients,
                })

            elif self.path == "/system-info":
                if state.system_summary and isinstance(state.system_summary, dict):
                    self._respond(200, state.system_summary)
                else:
                    self._respond(200, {"error": "Система ещё не проанализирована", "ready": False})

            elif self.path == "/ping":
                self._register_client(client_ip)
                self._respond(200, {
                    "status": "pong",
                    "ready": state.ready,
                    "hostname": _safe_hostname(),
                })

            elif self.path == "/":
                self._respond(200, {
                    "message": "Security Assessment Server API v3.0",
                    "ready": state.ready,
                    "endpoints": ["/ping", "/status", "/system-info", "/analyze (POST)"],
                })

            else:
                self._respond(404, {"error": "Не найдено"})

        except Exception as e:
            logger.error(f"[HTTP-IN] Ошибка GET {self.path}: {e}", exc_info=True)
            self._respond(500, {"error": f"Внутренняя ошибка: {e}"})

    def do_POST(self):
        client_ip = self.client_address[0]
        logger.info(f"[HTTP-IN] POST {self.path} от {client_ip}")
        if not self._check_auth():
            return

        if self.path == "/analyze":
            if not state.ready or not state.system_info or not state.vuln_db:
                parts = []
                if not state.system_info:
                    parts.append("анализ системы не выполнен")
                if not state.vuln_db:
                    parts.append("базы данных не загружены")
                reason = "; ".join(parts) if parts else "сервер не готов"
                logger.warning(f"[HTTP-IN] POST /analyze от {client_ip}: НЕ ГОТОВ ({reason})")
                self._respond(503, {
                    "error": f"Сервер не готов: {reason}",
                    "ready": False,
                    "hint": "Выполните: 1) Анализ системы, 2) Загрузка баз, 3) Запуск сервера"
                })
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length == 0:
                    self._respond(400, {"error": "Пустое тело запроса"})
                    return
                if content_length > MAX_BODY_SIZE:
                    self._respond(413, {"error": f"Слишком большой запрос (лимит {MAX_BODY_SIZE} байт)"})
                    return

                body = self.rfile.read(content_length).decode("utf-8")
                scan_data = json.loads(body)

                logger.info(
                    f"[HTTP-IN] Данные от {client_ip}: "
                    f"{len(scan_data.get('open_ports', []))} портов, "
                    f"{len(scan_data.get('attack_vectors', []))} атак"
                )

                self._register_client(client_ip)

                scan_result = from_json_scan_result(scan_data)

                # Корреляция с прогрессом
                logger.info(f"[HTTP-IN] Начинаем корреляцию...")
                state.correlation_progress = 0
                state.correlation_message = "Начало корреляции..."
                if state.on_correlation_progress:
                    state.on_correlation_progress(0, "Начало корреляции...")

                correlator = AttackCorrelator(
                    state.system_info,
                    state.vuln_db,
                    trivy_result=state.trivy_result
                )

                def progress_callback(percent, message):
                    state.correlation_progress = percent
                    state.correlation_message = message
                    logger.info(f"[CORRELATION] {percent}% - {message}")
                    if state.on_correlation_progress:
                        state.on_correlation_progress(percent, message)

                correlator.set_progress_callback(progress_callback)

                results = correlator.correlate(scan_result)
                summary = correlator.get_summary()

                # Сохраняем для GUI (ручная генерация отчёта, таблица результатов)
                state.last_scan_data = scan_data
                state.last_results = results

                state.correlation_progress = 100
                state.correlation_message = "Корреляция завершена"
                if state.on_correlation_progress:
                    state.on_correlation_progress(100, "Корреляция завершена")

                # Генерация отчётов
                reports_dir = os.path.join(state.base_dir, "reports")
                os.makedirs(reports_dir, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")

                reporter = ReportGenerator(
                    system_summary=state.system_summary if isinstance(state.system_summary, dict) else {},
                    results=results,
                    summary=summary,
                    toolkit=state.toolkit,
                    local_scan_report=state.local_scan_report,
                    attacker_scan_data=scan_data,
                )

                html_path = reporter.generate_html(os.path.join(reports_dir, f"report_{ts}.html"))
                json_path = reporter.generate_json(os.path.join(reports_dir, f"report_{ts}.json"))

                logger.info(f"[HTTP-IN] Отчёты сгенерированы: {html_path}")

                # Сохранение в историю отчётов
                _save_to_history(results, summary, ts, html_path, json_path, scan_data)

                response = {
                    "status": "success",
                    "summary": summary,
                    "html_report": html_path,
                    "json_report": json_path,
                    "results_count": len(results),
                    "details": [
                        {
                            "cve_id": str(r.cve_id) if r.cve_id else "",
                            "attack_name": str(r.attack_name) if r.attack_name else "",
                            "severity": getattr(r.severity, "name", str(r.severity)),
                            "feasibility": getattr(r.feasibility, "name", str(r.feasibility)),
                            "reason": str(r.reason) if r.reason else "",
                            "recommendation": str(r.recommendation) if r.recommendation else "",
                            "description": str(r.description) if r.description else "",
                        }
                        for r in results
                    ]
                }

                self._respond(200, response)
                logger.info(f"[HTTP-IN] Корреляция завершена: {len(results)} уникальных результатов")

                if state.on_analysis_complete:
                    state.on_analysis_complete(summary, html_path)

            except json.JSONDecodeError as e:
                logger.error(f"[HTTP-IN] Некорректный JSON: {e}")
                self._respond(400, {"error": f"Некорректный JSON: {e}"})
            except Exception as e:
                logger.error(f"[HTTP-IN] Ошибка анализа: {e}", exc_info=True)
                self._respond(500, {"error": str(e)})
        else:
            self._respond(404, {"error": "Не найдено"})

    def _respond(self, code: int, data: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        # Подавляем стандартные логи — используем свой логгер
        pass


def init_api_security() -> tuple:
    """
    Инициализация безопасности API: токен + TLS-сертификат.
    Возвращает (token, fingerprint).
    """
    state.api_token = generate_token()
    certs_dir = os.path.join(state.base_dir, CERTS_DIR)
    fingerprint = get_cert_fingerprint(certs_dir)
    return state.api_token, fingerprint


def create_api_server(port: int, handler_class=RequestHandler) -> ThreadingHTTPServer:
    """Создаёт HTTPS-сервер с TLS. Требует предварительной инициализации state.base_dir."""
    certs_dir = os.path.join(state.base_dir, CERTS_DIR)
    ssl_ctx = build_server_ssl_context(certs_dir)
    server = ThreadingHTTPServer(("0.0.0.0", port), handler_class)
    server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    return server


def start_server(base_dir: str = "", port: int = None):
    """Инициализация и запуск серверного агента (консольный режим)."""
    state.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srv_port = port or SERVER_PORT

    logger.info("=" * 60)
    logger.info(" СЕРВЕРНЫЙ АГЕНТ АНАЛИЗА БЕЗОПАСНОСТИ v3.0")
    logger.info("=" * 60)

    # 1. Анализ системы
    state.system_analyzer = SystemAnalyzer()
    state.system_info = state.system_analyzer.analyze()
    state.system_summary = state.system_analyzer.get_summary()

    # 2. Загрузка баз уязвимостей
    state.vuln_db = VulnerabilityDatabase(state.base_dir)
    state.vuln_db.load_all()

    # 3. Загрузка базы инструментов (опционально)
    try:
        from server.attack_toolkit import AttackToolkit
        state.toolkit = AttackToolkit(state.base_dir)
        state.toolkit.load()
        logger.info("[SRV] База инструментов загружена")
    except Exception as e:
        logger.warning(f"[SRV] База инструментов недоступна: {e}")

    state.ready = True
    logger.info("Сервер ГОТОВ к приёму данных")

    # 4. Безопасность API: токен + TLS
    token, _ = init_api_security()
    try:
        server = create_api_server(srv_port)
    except RuntimeError as e:
        logger.error(str(e))
        raise SystemExit(1)

    fingerprint = get_cert_fingerprint(os.path.join(state.base_dir, CERTS_DIR))

    logger.info("=" * 60)
    logger.info(f"Сервер запущен: https://0.0.0.0:{srv_port}")
    logger.info(f"Токен доступа: {token}")
    logger.info(f"Отпечаток сертификата (SHA-256): {fingerprint}")
    logger.info("Передайте токен атакующему агенту. Сверьте отпечаток на обеих сторонах.")
    logger.info("=" * 60)
    logger.info(f"Ожидание данных: POST https://<IP>:{srv_port}/analyze")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Сервер остановлен.")
        server.shutdown()


if __name__ == "__main__":
    start_server()
