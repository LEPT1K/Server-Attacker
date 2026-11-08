"""
Атакующий агент — графический интерфейс PyQt6.

Возможности:
  - Сканирование портов с фингерпринтингом, Nuclei и Nmap (при наличии)
  - История сканирований по серверам и датам (древовидная структура)
  - Отправка результатов на серверный агент по HTTPS с токеном доступа
"""

import sys
import os
import json
import socket
import urllib.request
import urllib.error
import time
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

proxy_handler = urllib.request.ProxyHandler({})
opener = urllib.request.build_opener(proxy_handler)
urllib.request.install_opener(opener)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar,
    QFrame, QMessageBox, QStatusBar, QCheckBox, QFileDialog,
    QTreeWidget, QTreeWidgetItem, QAbstractItemView, QSplitter,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor, QTextCursor, QIcon

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

def get_app_dir() -> str:
    """Возвращает папку с .exe (frozen) или папку скрипта (Python)."""
    if getattr(sys, 'frozen', False):  # запущено из PyInstaller EXE
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

APP_DIR = get_app_dir()
sys.path.insert(0, APP_DIR)
HISTORY_DIR = os.path.join(APP_DIR, "history")
os.makedirs(HISTORY_DIR, exist_ok=True)

from common.config import (TARGET_SERVER_HOST, TARGET_SERVER_PORT,
                           SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT)
from common.models import ScanResult, OpenPort, AttackVector
from common.logger import get_attacker_logger, GUILogHandler
from common.netsec import build_client_ssl_context, get_server_fingerprint
from attacker.attacker_agent import AttackVectorGenerator, PortScanner



logger = get_attacker_logger()

# ─────────────────────────── СТИЛЬ ───────────────────────────
STYLE = """
QMainWindow { background: #121212; }
QWidget { color: #d0d0d0; font-family: 'Segoe UI', 'Consolas'; }
QGroupBox {
    background: #1a1a1a; border: 1px solid #333; border-radius: 4px;
    margin-top: 14px; padding-top: 22px; font-weight: 600; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #909090; }
QPushButton {
    padding: 6px 12px; border-radius: 3px; font-weight: 600; font-size: 10px;
    border: 1px solid #444; color: #d0d0d0; background: #252525;
    min-height: 28px;
}
QPushButton:hover { background: #333; border-color: #555; }
QPushButton:disabled { background: #1a1a1a; color: #555; border-color: #2a2a2a; }
QTextEdit {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; font-family: 'Consolas'; font-size: 11px; padding: 6px;
}
QLineEdit {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 6px; font-size: 12px;
}
QSpinBox {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px;
}
QTableWidget {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; gridline-color: #222; font-size: 11px;
}
QTableWidget::item { padding: 4px 6px; }
QTableWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
QTreeWidget {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; font-size: 11px;
}
QTreeWidget::item { padding: 3px 4px; }
QTreeWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
QTreeWidget::branch { background: #0e0e0e; }
QHeaderView::section {
    background: #181818; color: #888; border: none; padding: 6px; font-weight: 600;
}
QTabWidget::pane { border: 1px solid #333; border-radius: 3px; background: #1a1a1a; }
QTabBar::tab {
    background: #181818; color: #777; padding: 8px 18px;
    border: 1px solid #2a2a2a; border-bottom: none;
    border-top-left-radius: 3px; border-top-right-radius: 3px; margin-right: 2px;
}
QTabBar::tab:selected { background: #1a1a1a; color: #d0d0d0; border-color: #333; }
QProgressBar {
    background: #0e0e0e; border: 1px solid #333; border-radius: 3px;
    text-align: center; color: #999; font-weight: 600; font-size: 10px;
}
QProgressBar::chunk { background: #555; border-radius: 2px; }
QCheckBox { color: #b0b0b0; }
QCheckBox::indicator {
    width: 14px; height: 14px; border: 1px solid #444; border-radius: 2px; background: #1a1a1a;
}
QCheckBox::indicator:checked { background: #666; border-color: #888; }
QStatusBar { background: #0e0e0e; color: #666; border-top: 1px solid #222; }
QLabel { color: #b0b0b0; }
QSplitter::handle { background: #222; }
QScrollBar:vertical {
    background: #0e0e0e; width: 8px; border: none;
}
QScrollBar::handle:vertical { background: #333; border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

# ─────────────────────────── ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ЛОГИРОВАНИЯ ───────────────────────────

def _log_phase(phase_name: str, icon: str = "━") -> str:
    """Формирует заголовок этапа для лога."""
    line = icon * 50
    return f"\n{line}\n  {phase_name}\n{line}"


def _log_result_line(key: str, value, icon: str = "▸") -> str:
    return f"  {icon} {key:<28} {value}"


# ─────────────────────────── WORKERS ───────────────────────────

class CheckConnectionWorker(QThread):
    connected_signal = pyqtSignal(str, bool, int)
    failed_signal = pyqtSignal(str)

    def __init__(self, target, port, token=""):
        super().__init__()
        self.target = target
        self.port = port
        self.token = token

    def run(self):
        try:
            url = f"https://{self.target}:{self.port}/ping"
            req = urllib.request.Request(url, method="GET")
            req.add_header("X-Auth-Token", self.token)
            ctx = build_client_ssl_context()
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            fingerprint = get_server_fingerprint(self.target, self.port)
            if fingerprint:
                logger.info(f"  ▸ Отпечаток сертификата сервера (SHA-256):\n    {fingerprint}")
                logger.info("    Сверьте его с отпечатком на серверном агенте!")

            self.connected_signal.emit(
                data.get("hostname", "?"),
                data.get("ready", False),
                data.get("server_port", self.port)
            )
        except urllib.error.HTTPError as e:
            msg = f"HTTP {e.code}: Сервер отклонил запрос."
            if e.code == 401:
                msg = "Ошибка 401: неверный или отсутствующий токен доступа."
            elif e.code == 503:
                msg = (f"Порт {self.port} отвечает 503 (Не готов).\n\n"
                       "Сервер найден, но вы не выполнили шаги 1 и 2 в серверной программе.")
            self.failed_signal.emit(msg)
        except Exception as e:
            msg = str(e)
            if "10061" in msg or "refused" in msg.lower():
                msg = (f"Подключение не удалось. Сервер выключен "
                       f"или указан неверный порт ({self.port}).")
            self.failed_signal.emit(msg)


class ScanWorker(QThread):
    port_found = pyqtSignal(object)
    progress = pyqtSignal(int, int)
    log_phase = pyqtSignal(str)          # ← новый сигнал для фазовых сообщений
    finished = pyqtSignal(list, float)   # ← добавлено время выполнения
    error = pyqtSignal(str)

    def __init__(self, target, ps, pe, timeout=0.3, deep=False):
        super().__init__()
        self.target = target
        self.ps = ps
        self.pe = pe
        self.timeout = timeout
        self.deep = deep
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        t_start = time.time()
        try:
            ports = []
            total = self.pe - self.ps + 1
            scanned = 0
            sc = PortScanner(self.target, self.ps, self.pe, timeout=self.timeout)

            # ── Фаза 1: старт ──
            logger.info(_log_phase(f"СКАНИРОВАНИЕ ПОРТОВ  [{self.target}]", "═"))
            logger.info(_log_result_line("Диапазон:", f"{self.ps} – {self.pe}  ({total} портов)"))
            logger.info(_log_result_line("Таймаут:", f"{self.timeout}s"))
            logger.info(_log_result_line("Фингерпринтинг:", "Да (глубокий)" if self.deep else "Нет"))
            logger.info(_log_result_line("Потоков:", "100"))

            with ThreadPoolExecutor(max_workers=100) as ex:
                futs = {ex.submit(sc._check_port, p): p for p in range(self.ps, self.pe + 1)}
                for f in as_completed(futs):
                    if self._cancel:
                        logger.warning("⚠  Сканирование прервано пользователем.")
                        return
                    scanned += 1
                    if scanned % 100 == 0 or scanned == total:
                        self.progress.emit(scanned, total)
                    r = f.result()
                    if r:
                        if self.deep:
                            r = self._df(r)
                        ports.append(r)
                        self.port_found.emit(r)
                        banner_info = f"  [{r.banner[:40]}]" if r.banner else ""
                        logger.info(f"  ✔  Порт {r.port:<6}  {r.service:<18}{banner_info}")

            ports.sort(key=lambda x: x.port)
            elapsed = time.time() - t_start

            # ── Фаза 2: итоги ──
            logger.info(_log_phase("ИТОГИ СКАНИРОВАНИЯ ПОРТОВ", "─"))
            logger.info(_log_result_line("Просканировано портов:", total))
            logger.info(_log_result_line("Открытых портов:", len(ports)))
            logger.info(_log_result_line("Время выполнения:", f"{elapsed:.1f} сек"))
            if ports:
                logger.info(_log_result_line("Открытые порты:", ", ".join(str(p.port) for p in ports)))
            logger.info("")

            self.finished.emit(ports, elapsed)

        except Exception as e:
            logger.error(f"❌ Ошибка сканирования: {e}", exc_info=True)
            self.error.emit(str(e))

    def _df(self, pi):
        port = pi.port
        try:
            if port in (80, 443, 8080, 8443, 8000, 8888):
                scheme = "https" if port in (443, 8443) else "http"
                try:
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(
                        f"{scheme}://{self.target}:{port}/",
                        headers={"User-Agent": "SecurityScanner/1.0"},
                        method="HEAD"
                    )
                    with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                        sv = resp.headers.get("Server", "")
                        pw = resp.headers.get("X-Powered-By", "")
                        parts = []
                        if sv:  parts.append(f"Server: {sv}")
                        if pw:  parts.append(f"X-Powered-By: {pw}")
                        if parts:
                            pi.banner = " | ".join(parts)
                except Exception:
                    pass
            elif port in (21, 22, 25, 110, 143):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((self.target, port))
                    b = s.recv(1024).decode("utf-8", errors="replace").strip()
                    s.close()
                    if b:
                        pi.banner = b[:200]
                except Exception:
                    pass
        except Exception:
            pass
        return pi


class SendWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url, data, token=""):
        super().__init__()
        self.url = url
        self.data = data
        self.token = token

    def run(self):
        try:
            jd = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
            logger.info(_log_phase("ОТПРАВКА НА СЕРВЕР", "─"))
            logger.info(_log_result_line("URL:", self.url))
            logger.info(_log_result_line("Размер пакета:", f"{len(jd):,} байт"))
            logger.info(_log_result_line("Векторов атак:", len(self.data.get("attack_vectors", []))))
            logger.info(_log_result_line("Открытых портов:", len(self.data.get("open_ports", []))))

            t0 = time.time()
            req = urllib.request.Request(
                self.url, data=jd,
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "X-Auth-Token": self.token,
                },
                method="POST"
            )
            ctx = build_client_ssl_context()
            with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))

            elapsed = time.time() - t0
            logger.info(_log_result_line("Ответ получен за:", f"{elapsed:.2f} сек"))
            logger.info("  ✔  Отчёт успешно принят сервером.")
            self.finished.emit(response_data)
        except urllib.error.HTTPError as e:
            msg = f"HTTP {e.code}: {e.reason}"
            if e.code == 401:
                msg = "Ошибка 401: неверный или отсутствующий токен доступа."
            logger.error(f"❌ Ошибка при отправке: {msg}")
            self.error.emit(msg)
        except Exception as e:
            logger.error(f"❌ Ошибка при отправке: {e}")
            self.error.emit(str(e))


class NucleiWorker(QThread):
    progress = pyqtSignal(str, int)
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(list, float)   # vectors, elapsed
    error = pyqtSignal(str)

    def __init__(self, target, open_ports):
        super().__init__()
        self.target = target
        self.open_ports = open_ports
        self.nuclei_path = r"C:\BOS\tools\nuclei.exe"

    def run(self):
        t_start = time.time()
        vectors = []

        if not os.path.exists(self.nuclei_path):
            msg = f"Nuclei не найден: {self.nuclei_path}"
            self.error.emit(msg)
            self.finished.emit([], 0.0)
            return

        urls = ([f"{self.target}:{p.port}" for p in self.open_ports]
                if self.open_ports else [self.target])

        self.log_msg.emit("═" * 60)
        self.log_msg.emit(f"  🚀 ЗАПУСК NUCLEI  [{datetime.now().strftime('%H:%M:%S')}]")
        self.log_msg.emit("═" * 60)
        self.log_msg.emit(f"  ▸ Цель:        {self.target}")
        self.log_msg.emit(f"  ▸ URL-ы:       {', '.join(urls)}")
        self.log_msg.emit(f"  ▸ Параллельно: 50 шаблонов")
        self.log_msg.emit("")

        logger.info(_log_phase(f"NUCLEI СКАНИРОВАНИЕ  [{self.target}]", "═"))
        logger.info(_log_result_line("Цели:", ", ".join(urls)))

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        fd_url, url_list_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd_url)

        with open(url_list_path, "w", encoding="utf-8") as f:
            f.write("\n".join(urls))

        try:
            cmd = [
                self.nuclei_path,
                "-l", url_list_path,
                "-json-export", temp_path,
                "-ni", "-disable-update-check",
                "-mhe", "100000",
                "-c", "50",
                "-timeout", "2",
                "-retries", "0",
                "-stats", "-si", "2"
            ]

            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo:
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True,
                startupinfo=startupinfo
            )

            vuln_count_live = 0
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                stat_match = re.search(r'(?:reqs?|Requests):\s*(\d+)/(\d+)', clean_line, re.IGNORECASE)
                if stat_match:
                    tot = int(stat_match.group(2))
                    pct = int((int(stat_match.group(1)) / tot) * 100) if tot > 0 else 0
                    self.progress.emit(f"Nuclei: {stat_match.group(1)} из {tot} запросов...", pct)
                    continue
                # Определяем, нашлась ли уязвимость в строке
                if "[" in clean_line and ("] [" in clean_line or "critical" in clean_line.lower()
                                          or "high" in clean_line.lower()):
                    vuln_count_live += 1
                    self.log_msg.emit(f"  🔴 [{vuln_count_live}] {clean_line}")
                    logger.info(f"  🔴 Nuclei находка #{vuln_count_live}: {clean_line[:120]}")
                else:
                    self.log_msg.emit(f"  {clean_line}")

            process.wait()
            elapsed = time.time() - t_start

            self.log_msg.emit("")
            self.log_msg.emit("─" * 60)
            self.log_msg.emit(f"  ✅ Nuclei завершён  (время: {elapsed:.1f} сек)")

            logger.info(_log_phase("ИТОГИ NUCLEI", "─"))
            logger.info(_log_result_line("Время выполнения:", f"{elapsed:.1f} сек"))

            # ── Парсинг результатов ──
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            parsed = json.loads(line)
                            for item in (parsed if isinstance(parsed, list) else [parsed]):
                                if not isinstance(item, dict):
                                    continue
                                info = item.get("info", {})
                                if isinstance(info, list) and len(info) > 0:
                                    info = info[0]
                                elif not isinstance(info, dict):
                                    info = {}
                                name = f"[NUCLEI] {info.get('name', item.get('template-id', 'Unknown'))}"
                                sev = str(info.get("severity", "MEDIUM")).upper()
                                pt = item.get("port", "")
                                vectors.append(AttackVector(
                                    id=str(item.get("template-id", "nuclei-vuln"))[:50],
                                    name=name[:100],
                                    description=str(info.get("description", "Обнаружено Nuclei."))[:500],
                                    severity=sev if sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else "MEDIUM",
                                    target_port=int(pt) if str(pt).isdigit() else None
                                ))
                        except Exception:
                            pass

            logger.info(_log_result_line("Найдено векторов:", len(vectors)))
            self.log_msg.emit(f"  ▸ Найдено векторов атак: {len(vectors)}")
            self.log_msg.emit("═" * 60)

        except Exception as e:
            logger.error(f"❌ Ошибка Nuclei: {e}", exc_info=True)
            self.error.emit(str(e))
        finally:
            for p in [temp_path, url_list_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            self.finished.emit(vectors, elapsed if 'elapsed' in dir() else 0.0)


class NmapWorker(QThread):
    progress = pyqtSignal(str, int)
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(list, float)   # vectors, elapsed
    error = pyqtSignal(str)

    def __init__(self, target, open_ports):
        super().__init__()
        self.target = target
        self.open_ports = open_ports
        portable_nmap = os.path.join(APP_DIR, "tools", "nmap.exe")
        system_nmap_1  = r"C:\Program Files (x86)\Nmap\nmap.exe"
        system_nmap_2  = r"C:\Program Files\Nmap\nmap.exe"
        if os.path.exists(portable_nmap):
            self.nmap_path = portable_nmap
        elif os.path.exists(system_nmap_1):
            self.nmap_path = system_nmap_1
        else:
            self.nmap_path = system_nmap_2

    def run(self):
        t_start = time.time()
        vectors = []
        elapsed = 0.0

        if not os.path.exists(self.nmap_path):
            msg = f"Nmap не найден: {self.nmap_path}"
            self.log_msg.emit(f"❌ {msg}")
            self.error.emit(msg)
            self.finished.emit([], 0.0)
            return

        if not self.open_ports:
            self.log_msg.emit("⚠️ Нет открытых портов для Nmap.")
            self.finished.emit([], 0.0)
            return

        ports_str = ",".join(str(p.port) for p in self.open_ports)

        self.log_msg.emit("═" * 60)
        self.log_msg.emit(f"  🚀 ЗАПУСК NMAP  [{datetime.now().strftime('%H:%M:%S')}]")
        self.log_msg.emit("═" * 60)
        self.log_msg.emit(f"  ▸ Цель:   {self.target}")
        self.log_msg.emit(f"  ▸ Порты:  {ports_str}")
        self.log_msg.emit(f"  ▸ Режим:  -sV --script vuln -T4")
        self.log_msg.emit("")

        logger.info(_log_phase(f"NMAP (NSE) СКАНИРОВАНИЕ  [{self.target}]", "═"))
        logger.info(_log_result_line("Порты:", ports_str))

        fd, temp_xml = tempfile.mkstemp(suffix=".xml")
        os.close(fd)

        try:
            cmd = [
                self.nmap_path,
                "-sV", "--script", "vuln",
                "-T4",
                "--min-rate", "300",
                "--max-retries", "2",
                "--script-timeout", "2m",
                "-p", ports_str,
                "-oX", temp_xml,
                "--stats-every", "5s",
                self.target
            ]
            self.log_msg.emit(f"  💻 Команда: {' '.join(cmd)}\n")
            logger.info(_log_result_line("Команда:", " ".join(cmd)))

            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo:
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True,
                startupinfo=startupinfo
            )

            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line:
                    continue
                stat_match = re.search(r'About (\d+\.\d+)% done', clean_line)
                if stat_match:
                    pct = int(float(stat_match.group(1)))
                    self.progress.emit(f"Nmap: {pct}% выполнено...", pct)
                elif "undergoing" in clean_line:
                    action = clean_line.split(",")[-1].strip()
                    self.progress.emit(f"Nmap: {action}...", -1)
                else:
                    self.log_msg.emit(f"  {clean_line}")

            process.wait()
            elapsed = time.time() - t_start

            self.log_msg.emit("")
            self.log_msg.emit("─" * 60)
            self.log_msg.emit(f"  ✅ Nmap завершён  (время: {elapsed:.1f} сек)")
            self.log_msg.emit("  📄 Парсинг XML отчёта...")

            logger.info(_log_phase("ИТОГИ NMAP", "─"))
            logger.info(_log_result_line("Время выполнения:", f"{elapsed:.1f} сек"))

            # ── Парсинг XML ──
            if os.path.exists(temp_xml) and os.path.getsize(temp_xml) > 0:
                tree = ET.parse(temp_xml)
                root = tree.getroot()
                for host in root.findall("host"):
                    for port_elem in host.findall(".//port"):
                        port_id = port_elem.get("portid")
                        service_elem = port_elem.find("service")
                        service_name = (service_elem.get("name")
                                        if service_elem is not None else "unknown")
                        for script in port_elem.findall(".//script"):
                            script_id = script.get("id", "nmap-script")
                            output = script.get("output", "")
                            if ("VULNERABLE" in output or "State: VULNERABLE" in output
                                    or "Likely vulnerable" in output):
                                name = f"[NMAP] Уязвимость {service_name.upper()}"
                                cve_match = re.search(r"(CVE-\d{4}-\d+)", output)
                                cve = cve_match.group(1) if cve_match else script_id
                                sev = "HIGH"
                                if "cvss" in output.lower() and "10.0" in output:
                                    sev = "CRITICAL"
                                desc = (f"Nmap скрипт '{script_id}' выявил уязвимость:\n"
                                        f"{output[:400]}...")
                                vectors.append(AttackVector(
                                    id=cve,
                                    name=name,
                                    description=desc,
                                    severity=sev,
                                    target_port=int(port_id) if port_id.isdigit() else None
                                ))
                                self.log_msg.emit(f"  🔴 Уязвимость: {cve}  порт {port_id}  [{sev}]")
                                logger.info(f"  🔴 Nmap: {cve}  порт {port_id}  [{sev}]")
            else:
                self.log_msg.emit("  ⚠️ XML отчёт Nmap пуст.")

            logger.info(_log_result_line("Найдено векторов:", len(vectors)))
            self.log_msg.emit(f"  ▸ Найдено векторов атак: {len(vectors)}")
            self.log_msg.emit("═" * 60)

        except Exception as e:
            self.error.emit(f"Сбой Nmap: {str(e)}")
            self.log_msg.emit(f"❌ Ошибка Nmap: {str(e)}")
            logger.error(f"❌ Сбой Nmap: {e}", exc_info=True)
        finally:
            if os.path.exists(temp_xml):
                try:
                    os.remove(temp_xml)
                except Exception:
                    pass
            self.finished.emit(vectors, elapsed)


# ─────────────────────────── ГЛАВНОЕ ОКНО ───────────────────────────

class AttackerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Атакующий агент v2")
        self.setMinimumSize(1350, 850)  # Увеличиваем размер окна

        self.open_ports = []
        self.attack_vectors = []   # Накопительный список векторов (мёрж всех сканирований)
        self.scan_worker = None
        self.connected_to_server = False
        self._scan_elapsed = 0.0

        # Счётчики по источникам
        self._vectors_from_portscan = 0
        self._vectors_from_nuclei   = 0
        self._vectors_from_nmap     = 0

        self._build_ui()
        self.setStyleSheet(STYLE)

        gh = GUILogHandler(self._on_log_message)
        gh.setLevel(10)
        logger.addHandler(gh)
        self.log_signal.connect(self._append_log)

        self._load_history_tree()

        logger.info(_log_phase("АТАКУЮЩИЙ АГЕНТ ЗАПУЩЕН", "═"))
        logger.info(_log_result_line("Версия:", "2.0"))
        logger.info(_log_result_line("Время запуска:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        logger.info(_log_result_line("Директория:", APP_DIR))
        logger.info(_log_result_line("История:", HISTORY_DIR))
        logger.info("")

    # ──────────── UI ────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        ml = QHBoxLayout(central)
        ml.setSpacing(8)
        ml.setContentsMargins(8, 8, 8, 8)

        # ── Левая панель ──
        # Создаём контейнер с скроллом для левой панели
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setStyleSheet("""
            QScrollArea {
                background: #121212;
                border: none;
            }
            QScrollBar:vertical {
                background: #121212;
                width: 6px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: #444;
                border-radius: 3px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #555;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
                border: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #121212;
            }
        """)
        
        left = QWidget()
        left.setFixedWidth(265)  # Увеличенная ширина левой панели
        left.setStyleSheet("background: #121212;")
        ll = QVBoxLayout(left)
        ll.setSpacing(6)
        ll.setContentsMargins(4, 4, 4, 4)

        t = QLabel("АТАКУЮЩИЙ АГЕНТ")
        t.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        t.setStyleSheet("color:#888;padding:6px 0;letter-spacing:2px;")
        ll.addWidget(t)

        # Статус соединения
        self.conn_frame = QFrame()
        self.conn_frame.setStyleSheet(
            "background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        cf = QVBoxLayout(self.conn_frame)
        cf.setSpacing(4)
        self.conn_icon = QLabel("● Нет связи с сервером")
        self.conn_icon.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.conn_icon.setStyleSheet("color:#666;")
        cf.addWidget(self.conn_icon)
        self.conn_detail = QLabel("")
        self.conn_detail.setStyleSheet("color:#555;font-size:10px;")
        self.conn_detail.setWordWrap(True)
        cf.addWidget(self.conn_detail)
        ll.addWidget(self.conn_frame)

        # Параметры цели - расширены
        tg = QGroupBox("Параметры цели")
        tg.setStyleSheet("QGroupBox { font-size: 12px; font-weight: bold; padding-top: 20px; }")
        tl = QVBoxLayout(tg)
        tl.setSpacing(6)
        tl.setContentsMargins(8, 12, 8, 10)

        tl.addWidget(QLabel("IP-адрес сервера:"))
        self.target_input = QLineEdit(TARGET_SERVER_HOST)
        self.target_input.setFont(QFont("Consolas", 12))
        self.target_input.setFixedHeight(32)
        tl.addWidget(self.target_input)

        tl.addWidget(QLabel("Порт API сервера:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(TARGET_SERVER_PORT)
        self.port_spin.setFixedHeight(28)
        tl.addWidget(self.port_spin)

        tl.addWidget(QLabel("Токен доступа (с серверного агента):"))
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Вставьте токен, показанный на сервере")
        self.token_input.setFont(QFont("Consolas", 10))
        self.token_input.setFixedHeight(28)
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        tl.addWidget(self.token_input)

        r = QHBoxLayout()
        r.setSpacing(6)
        r.addWidget(QLabel("Порты от:"))
        self.ps_spin = QSpinBox()
        self.ps_spin.setRange(1, 65535)
        self.ps_spin.setValue(1)
        self.ps_spin.setFixedHeight(28)
        r.addWidget(self.ps_spin)
        r.addWidget(QLabel("до:"))
        self.pe_spin = QSpinBox()
        self.pe_spin.setRange(1, 65535)
        self.pe_spin.setValue(10000)
        self.pe_spin.setFixedHeight(28)
        r.addWidget(self.pe_spin)
        tl.addLayout(r)

        self.chk_deep = QCheckBox("Глубокий фингерпринтинг")
        self.chk_deep.setChecked(True)
        tl.addWidget(self.chk_deep)
        ll.addWidget(tg)

        # Действия - расширены
        ag = QGroupBox("Действия")
        ag.setStyleSheet("QGroupBox { font-size: 12px; font-weight: bold; padding-top: 20px; }")
        al = QVBoxLayout(ag)
        al.setSpacing(8)
        al.setContentsMargins(8, 12, 8, 10)

        # Кнопки действий - динамический размер
        action_btn_style = """
            QPushButton { 
                padding: 10px 14px; 
                font-size: 11px; 
                min-height: 36px; 
                text-align: center;
            }
        """

        self.btn_check = QPushButton("1. Проверить связь с сервером")
        self.btn_check.setStyleSheet(action_btn_style)
        self.btn_check.clicked.connect(self._check_connection)
        al.addWidget(self.btn_check)

        self.btn_scan = QPushButton("2. Сканировать порты")
        self.btn_scan.setStyleSheet(action_btn_style)
        self.btn_scan.clicked.connect(self._start_scan)
        al.addWidget(self.btn_scan)

        self.btn_nuclei = QPushButton("3. Веб-уязвимости (Nuclei)  ➕")
        self.btn_nuclei.setStyleSheet(action_btn_style)
        self.btn_nuclei.setEnabled(False)
        self.btn_nuclei.clicked.connect(self._start_nuclei)
        al.addWidget(self.btn_nuclei)

        self.btn_nmap = QPushButton("4. Сетевые протоколы (Nmap)  ➕")
        self.btn_nmap.setStyleSheet(action_btn_style)
        self.btn_nmap.setEnabled(False)
        self.btn_nmap.clicked.connect(self._start_nmap)
        al.addWidget(self.btn_nmap)

        # Кнопка параллельного сканирования
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("color:#333;")
        al.addWidget(sep2)

        self.btn_parallel_scan = QPushButton("⚡ Запустить все сканеры параллельно")
        self.btn_parallel_scan.setStyleSheet(action_btn_style + "QPushButton { background: #2a3a4a; }")
        self.btn_parallel_scan.setToolTip("Запускает Nuclei + Nmap одновременно для экономии времени")
        self.btn_parallel_scan.setEnabled(False)
        self.btn_parallel_scan.clicked.connect(self._start_parallel_scan)
        al.addWidget(self.btn_parallel_scan)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setVisible(False)
        al.addWidget(self.progress_bar)

        self.btn_send = QPushButton("5. Отправить на сервер для анализа")
        self.btn_send.setStyleSheet(action_btn_style + "QPushButton { background: #2a4a2a; }")
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self._send_results)
        al.addWidget(self.btn_send)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#333;")
        al.addWidget(sep)

        small_btn_style = "QPushButton { padding: 6px 12px; font-size: 10px; min-height: 28px; }"
        self.btn_clear_vectors = QPushButton("🗑  Очистить таблицу векторов")
        self.btn_clear_vectors.setStyleSheet(small_btn_style)
        self.btn_clear_vectors.clicked.connect(self._clear_vectors)
        al.addWidget(self.btn_clear_vectors)

        self.btn_export = QPushButton("📥 Экспорт лога")
        self.btn_export.setStyleSheet(small_btn_style)
        self.btn_export.clicked.connect(self._export_log)
        al.addWidget(self.btn_export)

        ll.addWidget(ag)
        ll.addStretch()

        # Статистика
        sf = QFrame()
        sf.setStyleSheet(
            "background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        sl = QVBoxLayout(sf)
        sl.setSpacing(2)
        self.lbl_stats = QLabel("Ожидание сканирования")
        self.lbl_stats.setStyleSheet("color:#666;font-size:10px;")
        self.lbl_stats.setWordWrap(True)
        sl.addWidget(self.lbl_stats)
        ll.addWidget(sf)

        scroll.setWidget(left)
        ml.addWidget(scroll)

        # ── Правая часть — вкладки ──
        self.tabs = QTabWidget()

        # Вкладка 0: Порты
        pt = QWidget()
        ptl = QVBoxLayout(pt)
        self.ports_table = QTableWidget(0, 4)
        self.ports_table.setHorizontalHeaderLabels(["Порт", "Протокол", "Сервис", "Баннер"])
        self.ports_table.horizontalHeader().setStretchLastSection(True)
        self.ports_table.setColumnWidth(0, 70)
        self.ports_table.setColumnWidth(1, 70)
        self.ports_table.setColumnWidth(2, 120)
        self.ports_table.verticalHeader().setVisible(False)
        self.ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ptl.addWidget(self.ports_table)
        self.tabs.addTab(pt, "🔌 Порты")

        # Вкладка 1: Векторы атак (накопительная)
        at = QWidget()
        atl = QVBoxLayout(at)

        # Подсказка
        hint = QLabel(
            "💡 Таблица накапливает уникальные векторы из всех сканирований. "
            "Кнопка «➕ Nuclei» и «➕ Nmap» добавляют результаты без дубликатов."
        )
        hint.setStyleSheet(
            "background:#1e2a1e;border:1px solid #2a4a2a;border-radius:3px;"
            "padding:6px;color:#7a9a7a;font-size:10px;"
        )
        hint.setWordWrap(True)
        atl.addWidget(hint)

        # Полоса источников
        self.source_bar = QLabel("Источники: —")
        self.source_bar.setStyleSheet("color:#666;font-size:10px;padding:2px 4px;")
        atl.addWidget(self.source_bar)

        self.attacks_table = QTableWidget(0, 6)
        self.attacks_table.setHorizontalHeaderLabels(
            ["ID/CVE", "Серьёзность", "Порт", "Источник", "Название", "Описание"])
        self.attacks_table.horizontalHeader().setStretchLastSection(True)
        self.attacks_table.setColumnWidth(0, 130)
        self.attacks_table.setColumnWidth(1, 85)
        self.attacks_table.setColumnWidth(2, 55)
        self.attacks_table.setColumnWidth(3, 80)
        self.attacks_table.setColumnWidth(4, 210)
        self.attacks_table.verticalHeader().setVisible(False)
        self.attacks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        atl.addWidget(self.attacks_table)
        self.tabs.addTab(at, "⚔ Векторы атак")

        # Вкладка 2: Ответ сервера
        rpt = QWidget()
        rtl = QVBoxLayout(rpt)
        self.response_table = QTableWidget(0, 5)
        self.response_table.setHorizontalHeaderLabels(
            ["CVE", "Серьёзность", "Реализуемость", "Атака", "Рекомендация"])
        self.response_table.horizontalHeader().setStretchLastSection(True)
        self.response_table.setColumnWidth(0, 130)
        self.response_table.setColumnWidth(1, 85)
        self.response_table.setColumnWidth(2, 130)
        self.response_table.setColumnWidth(3, 180)
        self.response_table.verticalHeader().setVisible(False)
        self.response_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rtl.addWidget(self.response_table)
        self.response_summary = QLabel("")
        self.response_summary.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        rtl.addWidget(self.response_summary)
        self.tabs.addTab(rpt, "📋 Ответ сервера")

        # Вкладка 3: История (дерево)
        ht = QWidget()
        htl = QVBoxLayout(ht)

        hist_hint = QLabel(
            "📂 История разделена по: Серверу → Дате → Времени → Типу сканирования.\n"
            "Выберите любой узел и нажмите кнопку загрузки."
        )
        hist_hint.setStyleSheet(
            "background:#1a1e2a;border:1px solid #2a3a4a;border-radius:3px;"
            "padding:6px;color:#6a8aaa;font-size:10px;"
        )
        hist_hint.setWordWrap(True)
        htl.addWidget(hist_hint)

        # Кнопки истории
        hist_btns = QHBoxLayout()
        self.btn_load_history = QPushButton("📂 Загрузить (заменить таблицу)")
        self.btn_load_history.clicked.connect(lambda: self._load_selected_history(merge=False))
        hist_btns.addWidget(self.btn_load_history)

        self.btn_merge_history = QPushButton("➕ Добавить к текущей таблице")
        self.btn_merge_history.clicked.connect(lambda: self._load_selected_history(merge=True))
        hist_btns.addWidget(self.btn_merge_history)

        htl.addLayout(hist_btns)

        self.btn_expand_all = QPushButton("▼ Развернуть всё")
        self.btn_expand_all.clicked.connect(self._expand_history)
        self.btn_collapse_all = QPushButton("▲ Свернуть всё")
        self.btn_collapse_all.clicked.connect(self._collapse_history)
        exp_row = QHBoxLayout()
        exp_row.addWidget(self.btn_expand_all)
        exp_row.addWidget(self.btn_collapse_all)
        htl.addLayout(exp_row)

        # Дерево истории
        self.history_tree = QTreeWidget()
        self.history_tree.setHeaderLabels(["Серверы / Даты / Сканирования", "Векторов", "Тип"])
        self.history_tree.setColumnWidth(0, 300)
        self.history_tree.setColumnWidth(1, 70)
        self.history_tree.setColumnWidth(2, 120)
        self.history_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_tree.itemDoubleClicked.connect(
            lambda item, col: self._load_selected_history(merge=False))
        htl.addWidget(self.history_tree)

        # Превью выбранного файла
        self.history_preview = QLabel("Выберите запись для просмотра деталей")
        self.history_preview.setStyleSheet(
            "background:#0e0e0e;border:1px solid #2a2a2a;border-radius:3px;"
            "padding:8px;color:#666;font-size:10px;font-family:'Consolas';"
        )
        self.history_preview.setWordWrap(True)
        self.history_tree.itemSelectionChanged.connect(self._on_history_selection)
        htl.addWidget(self.history_preview)

        self.tabs.addTab(ht, "📁 История")

        # Вкладка Trivy УБРАНА - она не нужна атакующему агенту
        # Trivy сканирует только серверную часть

        # Вкладка 5: Сканеры Лог (разделён на 2 части)
        nt = QWidget()
        ntl = QVBoxLayout(nt)
        
        # Заголовок
        log_title = QLabel("🖥 Вывод сканеров (слева Nmap, справа Nuclei)")
        log_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        log_title.setStyleSheet("color:#888;padding:4px 0;")
        ntl.addWidget(log_title)
        
        # Разделённый layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая часть - Nmap
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_label = QLabel("🔷 Nmap")
        left_label.setStyleSheet("color:#4488cc;font-weight:bold;padding:2px;")
        left_layout.addWidget(left_label)
        self.scanner_output_left = QTextEdit()
        self.scanner_output_left.setReadOnly(True)
        self.scanner_output_left.setStyleSheet(
            "background: #050f05; color: #00dd00; "
            "font-family: 'Consolas'; font-size: 11px;"
        )
        left_layout.addWidget(self.scanner_output_left)
        splitter.addWidget(left_widget)
        
        # Правая часть - Nuclei
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_label = QLabel("🔶 Nuclei")
        right_label.setStyleSheet("color:#cc8844;font-weight:bold;padding:2px;")
        right_layout.addWidget(right_label)
        self.scanner_output_right = QTextEdit()
        self.scanner_output_right.setReadOnly(True)
        self.scanner_output_right.setStyleSheet(
            "background: #050f05; color: #00dd00; "
            "font-family: 'Consolas'; font-size: 11px;"
        )
        right_layout.addWidget(self.scanner_output_right)
        splitter.addWidget(right_widget)
        
        splitter.setSizes([500, 500])
        ntl.addWidget(splitter)
        self.tabs.addTab(nt, "🖥 Сканеры Лог")
        
        # Для обратной совместимости
        self.scanner_output = self.scanner_output_left

        # Вкладка 5: Системный Лог
        lt = QWidget()
        ltl = QVBoxLayout(lt)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        ltl.addWidget(self.log_output)
        self.tabs.addTab(lt, "📜 Системный Лог")

        ml.addWidget(self.tabs, 1)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Готов к работе")

    # ──────────── ЛОГИРОВАНИЕ ────────────

    def _on_log_message(self, msg, level):
        self.log_signal.emit(msg, level)

    def _append_log(self, msg, level):
        colors = {
            "ERROR":    "#c55",
            "WARNING":  "#b87",
            "CRITICAL": "#e33",
            "INFO":     "#888",
            "DEBUG":    "#555",
        }
        color = colors.get(level, "#888")
        # Выделяем заголовки фаз
        if msg.strip().startswith("═") or msg.strip().startswith("─"):
            color = "#4a6a8a"
        elif "✔" in msg or "✅" in msg:
            color = "#5a8a5a"
        elif "❌" in msg:
            color = "#c55"
        elif "⚠" in msg:
            color = "#b87"
        elif "🔴" in msg:
            color = "#c44"
        self.log_output.append(f'<span style="color:{color};">{msg}</span>')
        self.log_output.moveCursor(QTextCursor.MoveOperation.End)

    def _append_scanner_log(self, msg):
        # Цветовая раскраска в зеленом логе сканеров
        if "🔴" in msg or "❌" in msg:
            color = "#ff4444"
        elif "✅" in msg or "✔" in msg:
            color = "#44ff44"
        elif "⚠" in msg:
            color = "#ffaa44"
        elif "═" in msg or "─" in msg:
            color = "#448844"
        elif "▸" in msg or "💻" in msg or "🚀" in msg:
            color = "#88cc88"
        else:
            color = "#00dd00"
        self.scanner_output.append(f'<span style="color:{color};">{msg}</span>')
        self.scanner_output.moveCursor(QTextCursor.MoveOperation.End)
    
    def _append_scanner_log_left(self, msg):
        """Логирование в левую панель (Nmap)"""
        if "🔴" in msg or "❌" in msg:
            color = "#ff4444"
        elif "✅" in msg or "✔" in msg:
            color = "#44ff44"
        elif "⚠" in msg:
            color = "#ffaa44"
        elif "═" in msg or "─" in msg:
            color = "#4488cc"
        elif "▸" in msg or "💻" in msg or "🚀" in msg:
            color = "#88bbdd"
        else:
            color = "#00dd00"
        self.scanner_output_left.append(f'<span style="color:{color};">{msg}</span>')
        self.scanner_output_left.moveCursor(QTextCursor.MoveOperation.End)
    
    def _append_scanner_log_right(self, msg):
        """Логирование в правую панель (Nuclei)"""
        if "🔴" in msg or "❌" in msg:
            color = "#ff4444"
        elif "✅" in msg or "✔" in msg:
            color = "#44ff44"
        elif "⚠" in msg:
            color = "#ffaa44"
        elif "═" in msg or "─" in msg:
            color = "#cc8844"
        elif "▸" in msg or "💻" in msg or "🚀" in msg:
            color = "#ddbb88"
        else:
            color = "#00dd00"
        self.scanner_output_right.append(f'<span style="color:{color};">{msg}</span>')
        self.scanner_output_right.moveCursor(QTextCursor.MoveOperation.End)

    # ──────────── ПРОВЕРКА СВЯЗИ ────────────

    def _check_connection(self):
        logger.info(_log_phase("ПРОВЕРКА СВЯЗИ С СЕРВЕРОМ", "─"))
        logger.info(_log_result_line("Адрес:", self.target_input.text()))
        logger.info(_log_result_line("Порт:", self.port_spin.value()))

        self.btn_check.setEnabled(False)
        self.btn_check.setText("Проверка...")
        self.conn_icon.setText("● Проверка связи...")
        self.conn_icon.setStyleSheet("color:#888;")

        self.check_worker = CheckConnectionWorker(
            self.target_input.text(), self.port_spin.value(),
            token=self.token_input.text().strip())
        self.check_worker.connected_signal.connect(self._on_connected)
        self.check_worker.failed_signal.connect(self._on_connection_failed)
        self.check_worker.start()

    def _on_connected(self, hostname, ready, server_port):
        self.connected_to_server = True
        self.conn_icon.setText("● Связь установлена")
        self.conn_icon.setStyleSheet("color:#8a8;")
        self.conn_detail.setText(
            f"Сервер: {hostname}\n"
            f"{'✔ Готов к приёму' if ready else '✖ НЕ ГОТОВ'}\n"
            f"Порт: {server_port}"
        )
        self.conn_frame.setStyleSheet(
            "background:#1a1a1a;border:1px solid #3a5a3a;border-radius:4px;padding:8px;")
        self.btn_check.setText("1. Связь установлена ✔")
        self.btn_check.setEnabled(True)
        logger.info(f"  ✔  Связь установлена: {hostname}  (порт {server_port})")
        self.statusBar().showMessage(f"Подключено: {hostname}:{server_port}")

    def _on_connection_failed(self, error):
        self.connected_to_server = False
        self.conn_icon.setText("● Нет связи")
        self.conn_icon.setStyleSheet("color:#866;")
        self.conn_detail.setText(error[:300])
        self.conn_frame.setStyleSheet(
            "background:#1a1a1a;border:1px solid #5a3a3a;border-radius:4px;padding:8px;")
        self.btn_check.setText("1. Повторить проверку")
        self.btn_check.setEnabled(True)
        logger.error(f"  ❌  Сбой подключения: {error}")

    # ──────────── СКАНИРОВАНИЕ ПОРТОВ ────────────

    def _start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.btn_scan.setText("2. Сканировать порты")
            return

        self.open_ports = []
        self.ports_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.btn_nuclei.setEnabled(False)
        self.btn_nmap.setEnabled(False)
        self.btn_send.setEnabled(False)
        self.btn_scan.setText("⏹ Остановить")

        self.scan_worker = ScanWorker(
            self.target_input.text(),
            self.ps_spin.value(),
            self.pe_spin.value(),
            0.3,
            self.chk_deep.isChecked()
        )
        self.scan_worker.port_found.connect(self._on_port_found)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_done)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()

    def _on_port_found(self, p):
        r = self.ports_table.rowCount()
        self.ports_table.insertRow(r)
        self.ports_table.setItem(r, 0, QTableWidgetItem(str(p.port)))
        self.ports_table.setItem(r, 1, QTableWidgetItem(p.protocol))
        self.ports_table.setItem(r, 2, QTableWidgetItem(p.service))
        self.ports_table.setItem(r, 3, QTableWidgetItem(p.banner or ""))
        self.statusBar().showMessage(f"Найден порт: {p.port} ({p.service})")

    def _on_scan_progress(self, s, t):
        self.progress_bar.setValue(int(s / t * 100) if t else 0)
        self.progress_bar.setFormat(f"Сканирование: {s}/{t}")

    def _on_scan_done(self, ports, elapsed):
        self.open_ports = ports
        self.progress_bar.setVisible(False)
        self.btn_scan.setText("2. Сканировать порты")

        # Генерируем базовые векторы из портов и МЁРЖИМ
        new_vectors = AttackVectorGenerator().generate(ports)
        self._vectors_from_portscan = len(new_vectors)
        added = self._merge_vectors(new_vectors, source="PortScan")

        self._update_attacks_table()
        self._update_stats()

        if ports:
            self.btn_nuclei.setEnabled(True)
            self.btn_nmap.setEnabled(True)
            self.btn_parallel_scan.setEnabled(True)  # Включаем кнопку параллельного сканирования
            self.btn_send.setEnabled(True)

        self._save_history_file("PortScan")
        self.tabs.setCurrentIndex(1)
        self.statusBar().showMessage(
            f"Сканирование завершено: {len(ports)} портов, {elapsed:.1f} сек, "
            f"добавлено {added} новых векторов"
        )

    def _on_scan_error(self, e):
        self.progress_bar.setVisible(False)
        self.btn_scan.setText("2. Сканировать порты")
        QMessageBox.critical(self, "Ошибка сканирования", e)

    # ──────────── NUCLEI ────────────

    def _start_nuclei(self):
        logger.info("  ▸ Пользователь запустил Nuclei")
        self._lock_scanners()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.scanner_output_right.clear()  # Очищаем правую панель
        self.tabs.setCurrentIndex(4)

        self.nuclei_worker = NucleiWorker(self.target_input.text(), self.open_ports)
        self.nuclei_worker.progress.connect(self._on_scanner_progress)
        self.nuclei_worker.log_msg.connect(self._append_scanner_log_right)  # Правая панель
        self.nuclei_worker.finished.connect(
            lambda v, t: self._on_scanner_done(v, t, "NucleiScan"))
        self.nuclei_worker.error.connect(self._on_scanner_error)
        self.nuclei_worker.start()

    # ──────────── NMAP ────────────

    def _start_nmap(self):
        logger.info("  ▸ Пользователь запустил Nmap")
        self._lock_scanners()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.scanner_output_left.clear()  # Очищаем левую панель
        self.tabs.setCurrentIndex(4)

        self.nmap_worker = NmapWorker(self.target_input.text(), self.open_ports)
        self.nmap_worker.progress.connect(self._on_scanner_progress)
        self.nmap_worker.log_msg.connect(self._append_scanner_log_left)  # Левая панель
        self.nmap_worker.finished.connect(
            lambda v, t: self._on_scanner_done(v, t, "NmapScan"))
        self.nmap_worker.error.connect(self._on_scanner_error)
        self.nmap_worker.start()
    
    def _start_parallel_scan(self):
        """Запускает Nuclei и Nmap параллельно (PortScan уже выполнен)"""
        logger.info("=" * 60)
        logger.info(" ⚡ ПАРАЛЛЕЛЬНОЕ СКАНИРОВАНИЕ (Nuclei + Nmap)")
        logger.info("=" * 60)
        
        if not self.open_ports:
            QMessageBox.warning(self, "Предупреждение", 
                "Сначала выполните сканирование портов!")
            return
        
        # Блокируем кнопки
        self.btn_parallel_scan.setEnabled(False)
        self.btn_nuclei.setEnabled(False)
        self.btn_nmap.setEnabled(False)
        self.btn_scan.setEnabled(False)
        self.btn_send.setEnabled(False)
        
        # Показываем оба прогресс-бара
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Nuclei: ожидание...")
        
        # Создаём второй прогресс-бар для Nmap если его нет
        if not hasattr(self, 'progress_bar_nmap'):
            self.progress_bar_nmap = QProgressBar()
            self.progress_bar_nmap.setFixedHeight(18)
            # Вставляем после первого прогресс-бара
            al = self.btn_parallel_scan.parent().layout()
            idx = al.indexOf(self.progress_bar)
            al.insertWidget(idx + 1, self.progress_bar_nmap)
        
        self.progress_bar_nmap.setVisible(True)
        self.progress_bar_nmap.setValue(0)
        self.progress_bar_nmap.setFormat("Nmap: ожидание...")
        
        self.scanner_output.clear()
        self.tabs.setCurrentIndex(4)
        
        # Счётчики для завершения
        self._parallel_completed = {"nuclei": False, "nmap": False}
        self._parallel_vectors = {"nuclei": [], "nmap": []}
        self._parallel_start_time = time.time()
        
        # Генерируем векторы из PortScan (уже выполнено)
        from attacker.attacker_agent import AttackVectorGenerator
        vec_gen = AttackVectorGenerator()
        portscan_vectors = vec_gen.generate(self.open_ports)
        added_portscan = self._merge_vectors(portscan_vectors, source="PortScan")
        logger.info(f"  ✔ PortScan: {len(portscan_vectors)} векторов добавлено ({added_portscan} новых)")
        
        # Запускаем Nuclei
        logger.info("  ▸ Запуск Nuclei...")
        self.nuclei_worker = NucleiWorker(self.target_input.text(), self.open_ports)
        self.nuclei_worker.progress.connect(self._on_nuclei_parallel_progress)
        self.nuclei_worker.log_msg.connect(lambda msg: self._append_scanner_log_left(msg))
        self.nuclei_worker.finished.connect(self._on_parallel_nuclei_done)
        self.nuclei_worker.error.connect(self._on_parallel_error)
        self.nuclei_worker.start()
        
        # Запускаем Nmap
        logger.info("  ▸ Запуск Nmap...")
        self.nmap_worker = NmapWorker(self.target_input.text(), self.open_ports)
        self.nmap_worker.progress.connect(self._on_nmap_parallel_progress)
        self.nmap_worker.log_msg.connect(lambda msg: self._append_scanner_log_right(msg))
        self.nmap_worker.finished.connect(self._on_parallel_nmap_done)
        self.nmap_worker.error.connect(self._on_parallel_error)
        self.nmap_worker.start()
        
        self._append_scanner_log_left("═" * 40)
        self._append_scanner_log_left("  ⚡ NUCLEI ЗАПУЩЕН")
        self._append_scanner_log_left("═" * 40)
        
        self._append_scanner_log_right("═" * 40)
        self._append_scanner_log_right("  ⚡ NMAP ЗАПУЩЕН")
        self._append_scanner_log_right("═" * 40)
    
    def _on_nuclei_parallel_progress(self, msg, val):
        """Обновление прогресса Nuclei при параллельном сканировании"""
        self.progress_bar.setFormat(f"Nuclei: {msg}")
        if val >= 0:
            self.progress_bar.setValue(val)
    
    def _on_nmap_parallel_progress(self, msg, val):
        """Обновление прогресса Nmap при параллельном сканировании"""
        self.progress_bar_nmap.setFormat(f"Nmap: {msg}")
        if val >= 0:
            self.progress_bar_nmap.setValue(val)
    
    def _on_parallel_nuclei_done(self, vectors, elapsed):
        """Nuclei завершил работу в параллельном режиме"""
        self._parallel_vectors["nuclei"] = vectors
        self._parallel_completed["nuclei"] = True
        self._append_scanner_log_left(f"  ✅ Nuclei завершён за {elapsed:.1f} сек, найдено {len(vectors)} векторов")
        self.progress_bar.setFormat(f"Nuclei: завершён за {elapsed:.1f} сек")
        self._check_parallel_completion()
    
    def _on_parallel_nmap_done(self, vectors, elapsed):
        """Nmap завершил работу в параллельном режиме"""
        self._parallel_vectors["nmap"] = vectors
        self._parallel_completed["nmap"] = True
        self._append_scanner_log_right(f"  ✅ Nmap завершён за {elapsed:.1f} сек, найдено {len(vectors)} векторов")
        self.progress_bar_nmap.setFormat(f"Nmap: завершён за {elapsed:.1f} сек")
        self._check_parallel_completion()
    
    def _on_parallel_error(self, error_msg):
        """Ошибка в одном из параллельных сканеров"""
        logger.error(f"  ❌ Ошибка сканера: {error_msg}")
        # Не блокируем остальные сканеры, просто логируем
    
    def _check_parallel_completion(self):
        """Проверяет, все ли сканеры завершили работу"""
        if all(self._parallel_completed.values()):
            elapsed = time.time() - self._parallel_start_time
            
            self._append_scanner_log_left("═" * 40)
            self._append_scanner_log_left(f"  ⚡ ВСЕ СКАНЕРЫ ЗАВЕРШЕНЫ за {elapsed:.1f} сек")
            
            self._append_scanner_log_right("═" * 40)
            self._append_scanner_log_right(f"  ⚡ ВСЕ СКАНЕРЫ ЗАВЕРШЕНЫ за {elapsed:.1f} сек")
            
            # Мёржим все векторы
            all_vectors = []
            for scan_type, vectors in self._parallel_vectors.items():
                all_vectors.extend(vectors)
                logger.info(f"  [{scan_type}] {len(vectors)} векторов")
            
            # Добавляем без дубликатов
            added = self._merge_vectors(all_vectors, source="Parallel")
            
            logger.info(f"  Итого добавлено: {added} уникальных векторов")
            
            # Обновляем UI
            self._update_attacks_table()
            self._update_stats()
            
            # Разблокируем кнопки
            self.progress_bar.setVisible(False)
            if hasattr(self, 'progress_bar_nmap'):
                self.progress_bar_nmap.setVisible(False)
            self.btn_parallel_scan.setEnabled(True)
            self.btn_nuclei.setEnabled(True)
            self.btn_nmap.setEnabled(True)
            self.btn_scan.setEnabled(True)
            self.btn_send.setEnabled(True)
            
            self.tabs.setCurrentIndex(1)  # Вкладка векторов атак
            
            self._save_history_file("Parallel")
            self.statusBar().showMessage(
                f"Параллельное сканирование: завершено за {elapsed:.1f} сек, "
                f"добавлено {added} новых векторов (итого {len(self.attack_vectors)})"
            )
            
            QMessageBox.information(
                self,
                "Параллельное сканирование завершено",
                f"Все сканеры завершили работу за {elapsed:.1f} секунд!\n\n"
                f"Добавлено {added} уникальных векторов атак.\n"
                f"Итого в таблице: {len(self.attack_vectors)} векторов."
            )

    def _lock_scanners(self):
        self.btn_nuclei.setEnabled(False)
        self.btn_nmap.setEnabled(False)
        self.btn_scan.setEnabled(False)
        self.btn_send.setEnabled(False)

    def _on_scanner_progress(self, msg, val):
        self.progress_bar.setFormat(msg)
        if val >= 0:
            self.progress_bar.setValue(val)

    def _on_scanner_error(self, e):
        QMessageBox.warning(self, "Ошибка сканера", e)

    def _on_scanner_done(self, new_vectors, elapsed, scan_type):
        self.progress_bar.setVisible(False)
        self.btn_nuclei.setEnabled(True)
        self.btn_nmap.setEnabled(True)
        self.btn_scan.setEnabled(True)
        self.btn_send.setEnabled(True)

        if scan_type == "NucleiScan":
            self._vectors_from_nuclei += len(new_vectors)
        elif scan_type == "NmapScan":
            self._vectors_from_nmap += len(new_vectors)

        added = self._merge_vectors(new_vectors, source=scan_type)

        logger.info(_log_phase(f"МЁРЖ РЕЗУЛЬТАТОВ  [{scan_type}]", "─"))
        logger.info(_log_result_line("Новых от сканера:", len(new_vectors)))
        logger.info(_log_result_line("Добавлено (без дубл.):", added))
        logger.info(_log_result_line("Итого в таблице:", len(self.attack_vectors)))

        self._update_attacks_table()
        self._update_stats()
        self.tabs.setCurrentIndex(1)

        self._save_history_file(scan_type)
        self.statusBar().showMessage(
            f"{scan_type}: завершён за {elapsed:.1f} сек, "
            f"добавлено {added} новых векторов (итого {len(self.attack_vectors)})"
        )

    # ──────────── МЁРЖ ВЕКТОРОВ (без дубликатов) ────────────

    def _merge_vectors(self, new_vectors: list, source: str = "") -> int:
        """
        Добавляет векторы в self.attack_vectors без дубликатов.
        Дубликат определяется по нормализованному ID.
        Возвращает количество фактически добавленных векторов.
        """
        existing_ids = {self._normalize_id(v.id) for v in self.attack_vectors}
        added = 0
        for v in new_vectors:
            nid = self._normalize_id(v.id)
            if nid not in existing_ids:
                # Добавляем метку источника в имя, если её ещё нет
                if source and f"[{source.upper()[:6]}]" not in v.name.upper():
                    pass  # источник уже встроен в имя ([NUCLEI], [NMAP])
                self.attack_vectors.append(v)
                existing_ids.add(nid)
                added += 1
            else:
                logger.debug(f"  ⊘  Дубликат пропущен: {v.id}")
        return added

    @staticmethod
    def _normalize_id(vid: str) -> str:
        """Нормализует ID для сравнения (нижний регистр, без пробелов)."""
        return str(vid).lower().strip().replace(" ", "-")

    def _clear_vectors(self):
        reply = QMessageBox.question(
            self, "Очистить векторы",
            "Очистить таблицу векторов атак?\n(Порты останутся)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.attack_vectors = []
            self._vectors_from_portscan = 0
            self._vectors_from_nuclei   = 0
            self._vectors_from_nmap     = 0
            self._update_attacks_table()
            self._update_stats()
            logger.info("  ▸ Таблица векторов очищена пользователем.")

    # ──────────── ТАБЛИЦА ВЕКТОРОВ ────────────

    def _update_attacks_table(self):
        self.attacks_table.setRowCount(0)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        for av in sorted(self.attack_vectors, key=lambda v: sev_order.get(v.severity, 5)):
            r = self.attacks_table.rowCount()
            self.attacks_table.insertRow(r)

            self.attacks_table.setItem(r, 0, QTableWidgetItem(str(av.id)))

            sev_item = QTableWidgetItem(str(av.severity))
            sev_colors = {
                "CRITICAL": "#ff4444", "HIGH": "#ff8844",
                "MEDIUM":   "#ccaa44", "LOW":  "#44aa44", "INFO": "#4488aa"
            }
            sev_item.setForeground(QColor(sev_colors.get(av.severity, "#888")))
            self.attacks_table.setItem(r, 1, sev_item)

            self.attacks_table.setItem(r, 2, QTableWidgetItem(str(av.target_port or "—")))

            # Источник
            source = "PortScan"
            src_color = "#888"
            if "[NUCLEI]" in str(av.name):
                source = "NUCLEI"
                src_color = "#5a9a5a"
            elif "[NMAP]" in str(av.name):
                source = "NMAP"
                src_color = "#4a7aaa"
            src_item = QTableWidgetItem(source)
            src_item.setForeground(QColor(src_color))
            self.attacks_table.setItem(r, 3, src_item)

            name_item = QTableWidgetItem(str(av.name))
            if "[NUCLEI]" in str(av.name):
                name_item.setForeground(QColor("#7acc7a"))
            elif "[NMAP]" in str(av.name):
                name_item.setForeground(QColor("#6aaae0"))
            self.attacks_table.setItem(r, 4, name_item)

            self.attacks_table.setItem(r, 5, QTableWidgetItem(str(av.description)))

        # Источники в строке-подсказке
        parts = []
        if self._vectors_from_portscan > 0:
            parts.append(f"PortScan: {self._vectors_from_portscan}")
        if self._vectors_from_nuclei > 0:
            parts.append(f"Nuclei: {self._vectors_from_nuclei}")
        if self._vectors_from_nmap > 0:
            parts.append(f"Nmap: {self._vectors_from_nmap}")
        self.source_bar.setText(
            f"Источники: {' | '.join(parts) if parts else '—'}  "
            f"(итого в таблице: {len(self.attack_vectors)})"
        )

    def _update_stats(self):
        cr = sum(1 for v in self.attack_vectors if v.severity == "CRITICAL")
        hi = sum(1 for v in self.attack_vectors if v.severity == "HIGH")
        me = sum(1 for v in self.attack_vectors if v.severity == "MEDIUM")
        lo = sum(1 for v in self.attack_vectors if v.severity == "LOW")
        self.lbl_stats.setText(
            f"Открытых портов:    {len(self.open_ports)}\n"
            f"Всего векторов:     {len(self.attack_vectors)}\n"
            f"  CRITICAL:  {cr}\n"
            f"  HIGH:      {hi}\n"
            f"  MEDIUM:    {me}\n"
            f"  LOW:       {lo}"
        )

    # ──────────── ИСТОРИЯ (ДЕРЕВО) ────────────

    def _save_history_file(self, scan_type: str):
        """Сохраняет текущее состояние в history/<IP>/<YYYY-MM-DD>/<HH-MM-SS>_<type>.json"""
        if not self.open_ports and not self.attack_vectors:
            return

        t = self.target_input.text().replace(":", "_").replace("/", "_")
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H-%M-%S")

        # Создаём вложенные директории: history/IP/Date/
        server_dir = os.path.join(HISTORY_DIR, t)
        date_dir   = os.path.join(server_dir, date_str)
        os.makedirs(date_dir, exist_ok=True)

        filename = f"{time_str}_{scan_type}.json"
        filepath = os.path.join(date_dir, filename)

        sr = ScanResult(
            scanner_ip="127.0.0.1",
            target_ip=self.target_input.text(),
            open_ports=self.open_ports,
            discovered_services=[f"{x.service} (:{x.port})" for x in self.open_ports],
            attack_vectors=self.attack_vectors,
            os_detection="Windows",
            scan_timestamp=now.isoformat()
        )
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(asdict(sr), f, ensure_ascii=False, indent=2)
            logger.info(_log_result_line("История сохранена:", filepath))
            self._load_history_tree()
        except Exception as e:
            logger.error(f"❌ Ошибка сохранения истории: {e}")

    def _load_history_tree(self):
        """Строит дерево: Сервер → Дата → Файл(ы)"""
        self.history_tree.clear()
        if not os.path.exists(HISTORY_DIR):
            return

        # Проверяем есть ли вложенная структура (новый формат)
        # ИЛИ плоские json файлы (старый формат)
        has_new_format = False
        has_old_format = False
        for entry in os.listdir(HISTORY_DIR):
            full = os.path.join(HISTORY_DIR, entry)
            if os.path.isdir(full):
                has_new_format = True
            elif entry.endswith(".json"):
                has_old_format = True

        # ── Новый формат: IP/Date/time_type.json ──
        if has_new_format:
            for server_name in sorted(os.listdir(HISTORY_DIR)):
                server_dir = os.path.join(HISTORY_DIR, server_name)
                if not os.path.isdir(server_dir):
                    continue

                # Подсчёт всех файлов сервера
                all_files = []
                for date_name in os.listdir(server_dir):
                    date_dir = os.path.join(server_dir, date_name)
                    if os.path.isdir(date_dir):
                        for f in os.listdir(date_dir):
                            if f.endswith(".json"):
                                all_files.append(f)

                server_item = QTreeWidgetItem(self.history_tree)
                server_item.setText(0, f"🖥  {server_name}")
                server_item.setText(1, str(len(all_files)))
                server_item.setText(2, "Сервер")
                server_item.setData(0, Qt.ItemDataRole.UserRole, None)
                server_item.setFont(0, QFont("Segoe UI", 11, QFont.Weight.Bold))
                server_item.setForeground(0, QColor("#8ab4e8"))

                for date_name in sorted(os.listdir(server_dir), reverse=True):
                    date_dir = os.path.join(server_dir, date_name)
                    if not os.path.isdir(date_dir):
                        continue

                    date_files = [f for f in os.listdir(date_dir) if f.endswith(".json")]
                    if not date_files:
                        continue

                    date_item = QTreeWidgetItem(server_item)
                    date_item.setText(0, f"📅  {date_name}")
                    date_item.setText(1, str(len(date_files)))
                    date_item.setText(2, "Дата")
                    date_item.setData(0, Qt.ItemDataRole.UserRole, None)
                    date_item.setForeground(0, QColor("#88aa88"))

                    for fname in sorted(date_files, reverse=True):
                        fpath = os.path.join(date_dir, fname)
                        # Парсим имя: HH-MM-SS_ScanType.json
                        parts = fname.replace(".json", "").split("_", 1)
                        time_str  = parts[0].replace("-", ":") if len(parts) > 0 else "?"
                        scan_type = parts[1] if len(parts) > 1 else "?"

                        # Читаем количество векторов из файла
                        vec_count = "?"
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                d = json.load(f)
                            vec_count = str(len(d.get("attack_vectors", [])))
                        except Exception:
                            pass

                        # Иконка по типу
                        icon = {"PortScan": "🔌", "NucleiScan": "🌐", "NmapScan": "🗺"}.get(
                            scan_type, "📄")

                        file_item = QTreeWidgetItem(date_item)
                        file_item.setText(0, f"  {icon}  {time_str}  — {scan_type}")
                        file_item.setText(1, vec_count)
                        file_item.setText(2, scan_type)
                        file_item.setData(0, Qt.ItemDataRole.UserRole, fpath)
                        file_item.setForeground(0, QColor("#aaa"))

        # ── Старый формат: плоские .json файлы ──
        if has_old_format:
            old_item = QTreeWidgetItem(self.history_tree)
            old_item.setText(0, "📦  Старые записи (legacy)")
            old_item.setText(2, "Legacy")
            old_item.setForeground(0, QColor("#666"))

            for fname in sorted(
                [f for f in os.listdir(HISTORY_DIR) if f.endswith(".json")],
                reverse=True
            ):
                fpath = os.path.join(HISTORY_DIR, fname)
                vec_count = "?"
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        d = json.load(f)
                    vec_count = str(len(d.get("attack_vectors", [])))
                except Exception:
                    pass

                fi = QTreeWidgetItem(old_item)
                fi.setText(0, f"  📄  {fname}")
                fi.setText(1, vec_count)
                fi.setData(0, Qt.ItemDataRole.UserRole, fpath)
                fi.setForeground(0, QColor("#666"))

    def _on_history_selection(self):
        """Показывает превью выбранного файла истории."""
        items = self.history_tree.selectedItems()
        if not items:
            return
        fpath = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath):
            self.history_preview.setText("Выберите конкретный файл сканирования для просмотра.")
            return
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                d = json.load(f)

            ports     = d.get("open_ports", [])
            vectors   = d.get("attack_vectors", [])
            ts        = d.get("scan_timestamp", "?")
            target    = d.get("target_ip", "?")

            cr = sum(1 for v in vectors if v.get("severity") == "CRITICAL")
            hi = sum(1 for v in vectors if v.get("severity") == "HIGH")
            me = sum(1 for v in vectors if v.get("severity") == "MEDIUM")
            lo = sum(1 for v in vectors if v.get("severity") == "LOW")

            port_list = ", ".join(str(p.get("port")) for p in ports[:20])
            if len(ports) > 20:
                port_list += f" ... (+{len(ports)-20})"

            text = (
                f"Сервер:        {target}\n"
                f"Время:         {ts[:19]}\n"
                f"Открытых портов: {len(ports)}\n"
                f"  {port_list}\n\n"
                f"Векторов атак: {len(vectors)}\n"
                f"  CRITICAL: {cr}  HIGH: {hi}  MEDIUM: {me}  LOW: {lo}\n\n"
                f"Файл: {os.path.basename(fpath)}"
            )
            self.history_preview.setText(text)
            self.history_preview.setStyleSheet(
                "background:#0e0e0e;border:1px solid #2a3a2a;border-radius:3px;"
                "padding:8px;color:#8aaa8a;font-size:10px;font-family:'Consolas';"
            )
        except Exception as e:
            self.history_preview.setText(f"Ошибка чтения: {e}")

    def _load_selected_history(self, merge: bool = False):
        """
        merge=False → заменяет таблицы
        merge=True  → добавляет к текущей таблице (без дубликатов)
        """
        items = self.history_tree.selectedItems()
        if not items:
            QMessageBox.information(self, "История", "Выберите запись в дереве.")
            return

        fpath = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not fpath:
            QMessageBox.information(self, "История",
                                    "Выберите конкретный файл сканирования (нижний уровень дерева).")
            return

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)

            loaded_ports   = [OpenPort(**p)    for p in data.get("open_ports", [])]
            loaded_vectors = [AttackVector(**v) for v in data.get("attack_vectors", [])]

            if merge:
                # ── Режим добавления ──
                existing_ports = {p.port for p in self.open_ports}
                for p in loaded_ports:
                    if p.port not in existing_ports:
                        self.open_ports.append(p)
                        r = self.ports_table.rowCount()
                        self.ports_table.insertRow(r)
                        self.ports_table.setItem(r, 0, QTableWidgetItem(str(p.port)))
                        self.ports_table.setItem(r, 1, QTableWidgetItem(p.protocol))
                        self.ports_table.setItem(r, 2, QTableWidgetItem(p.service))
                        self.ports_table.setItem(r, 3, QTableWidgetItem(p.banner or ""))

                added = self._merge_vectors(loaded_vectors, source="History")
                logger.info(
                    f"  ✔  История добавлена: {os.path.basename(fpath)}  "
                    f"(+{added} новых векторов)"
                )
                self.statusBar().showMessage(
                    f"Добавлено из истории: +{added} векторов  |  "
                    f"Итого: {len(self.attack_vectors)}"
                )
            else:
                # ── Режим замены ──
                self.target_input.setText(data.get("target_ip", TARGET_SERVER_HOST))
                self.open_ports = loaded_ports
                self.attack_vectors = loaded_vectors
                self._vectors_from_portscan = 0
                self._vectors_from_nuclei   = 0
                self._vectors_from_nmap     = 0

                self.ports_table.setRowCount(0)
                for p in self.open_ports:
                    r = self.ports_table.rowCount()
                    self.ports_table.insertRow(r)
                    self.ports_table.setItem(r, 0, QTableWidgetItem(str(p.port)))
                    self.ports_table.setItem(r, 1, QTableWidgetItem(p.protocol))
                    self.ports_table.setItem(r, 2, QTableWidgetItem(p.service))
                    self.ports_table.setItem(r, 3, QTableWidgetItem(p.banner or ""))

                logger.info(f"  ✔  История загружена: {os.path.basename(fpath)}")
                self.statusBar().showMessage(
                    f"Загружено из истории: {len(self.open_ports)} портов, "
                    f"{len(self.attack_vectors)} векторов"
                )

            self._update_attacks_table()
            self._update_stats()
            self.btn_nuclei.setEnabled(True)
            self.btn_nmap.setEnabled(True)
            self.btn_send.setEnabled(True)
            self.tabs.setCurrentIndex(1)

        except Exception as e:
            QMessageBox.critical(self, "Ошибка загрузки", str(e))
            logger.error(f"❌ Ошибка загрузки истории: {e}")

    def _expand_history(self):
        self.history_tree.expandAll()

    def _collapse_history(self):
        self.history_tree.collapseAll()

    # ──────────── ОТПРАВКА НА СЕРВЕР ────────────

    def _send_results(self):
        if not self.open_ports and not self.attack_vectors:
            return
        t = self.target_input.text()
        p = self.port_spin.value()
        sr = ScanResult(
            scanner_ip="127.0.0.1",
            target_ip=t,
            open_ports=self.open_ports,
            discovered_services=[],
            attack_vectors=self.attack_vectors,
            os_detection="Windows",
            scan_timestamp=datetime.now().isoformat()
        )
        self.btn_send.setEnabled(False)
        self.btn_send.setText("Отправка...")
        self.send_worker = SendWorker(
            f"https://{t}:{p}/analyze", asdict(sr),
            token=self.token_input.text().strip())
        self.send_worker.finished.connect(self._on_send_done)
        self.send_worker.error.connect(self._on_send_error)
        self.send_worker.start()

    def _on_send_done(self, result):
        self.btn_send.setText("5. Отправить на сервер для анализа")
        self.btn_send.setEnabled(True)
        if result.get("status") == "success":
            sm      = result.get("summary", {})
            details = result.get("details", [])
            self.response_table.setRowCount(0)
            for it in details:
                r = self.response_table.rowCount()
                self.response_table.insertRow(r)
                self.response_table.setItem(r, 0, QTableWidgetItem(str(it.get("cve_id", ""))))
                sev = str(it.get("severity", ""))
                si = QTableWidgetItem(sev)
                si.setForeground(QColor(
                    {"CRITICAL": "#ff4444", "HIGH": "#ff8844",
                     "MEDIUM": "#ccaa44", "LOW": "#44aa44"}.get(sev, "#888")))
                self.response_table.setItem(r, 1, si)
                fi = QTableWidgetItem(str(it.get("feasibility", "")))
                fi.setForeground(QColor(
                    "#c55" if fi.text() == "РЕАЛИЗУЕМА"
                    else "#5a9" if fi.text() == "НЕ РЕАЛИЗУЕМА"
                    else "#d29922"))
                self.response_table.setItem(r, 2, fi)
                self.response_table.setItem(r, 3, QTableWidgetItem(str(it.get("attack_name", ""))))
                self.response_table.setItem(r, 4, QTableWidgetItem(str(it.get("recommendation", ""))[:150]))

            feasible = sum(1 for d in details if d.get("feasibility") == "РЕАЛИЗУЕМА")
            self.response_summary.setText(
                f"Всего: {len(details)}  |  🔴 Реализуемых: {feasible}  |  "
                f"🟢 Нереализуемых: {len(details) - feasible}"
            )
            logger.info(_log_phase("ОТВЕТ СЕРВЕРА ПОЛУЧЕН", "─"))
            logger.info(_log_result_line("Всего уязвимостей:", len(details)))
            logger.info(_log_result_line("Реализуемых:", feasible))
            logger.info(_log_result_line("Нереализуемых:", len(details) - feasible))
            self.tabs.setCurrentIndex(2)
        else:
            QMessageBox.warning(self, "Ответ сервера", f"Ошибка: {result.get('error', '?')}")

    def _on_send_error(self, error):
        self.btn_send.setText("5. Отправить на сервер для анализа")
        self.btn_send.setEnabled(True)
        if "503" in error:
            QMessageBox.warning(self, "Сервер не готов", error)
        else:
            QMessageBox.critical(self, "Ошибка отправки", error)
        logger.error(f"❌ Ошибка отправки: {error}")

    # ──────────── ЭКСПОРТ ────────────

    def _export_log(self):
        text = self.log_output.toPlainText()
        if not text:
            return
        p, _ = QFileDialog.getSaveFileName(
            self, "Сохранить лог",
            f"attacker_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text (*.txt)"
        )
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            logger.info(f"  ✔  Лог экспортирован: {p}")


# ─────────────────────────── ТОЧКА ВХОДА ───────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = AttackerGUI()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
