"""
Серверный агент — графический интерфейс PyQt6.

Возможности:
  - Анализ системы, локальное сканирование уязвимостей, интеграция Trivy
  - HTTPS API (общий обработчик из server.api_server) с токеном доступа
  - Вкладки: система, обнаруженное ПО, Trivy, история Trivy, локальный скан,
    корреляция, выбор вектора атаки, история отчётов, лог
  - Генерация HTML/JSON отчётов со схемами защиты и инструкциями
"""
import sys, os, json, socket, threading, webbrowser
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QFrame, QMessageBox, QStatusBar, QProgressBar, QFileDialog,
    QComboBox, QListWidget, QListWidgetItem, QSplitter,
    QScrollArea, QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)
from common.config import SERVER_HOST, SERVER_PORT, CERTS_DIR
from common.models import from_json_scan_result, AttackVector, Severity
from common.logger import get_server_logger, GUILogHandler
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator
from server.attack_toolkit import AttackToolkit
from server.report_history import ReportHistory, ReportRecord
from server.scan_history import ScanHistory, ScanRecord
from server.local_vuln_scanner import LocalVulnScanner, ScanReport
from server.api_server import (
    state as api_state, create_api_server, init_api_security,
)
from server.api_security import get_cert_fingerprint
logger = get_server_logger()
# ─────────────────────────────────────────
#  Стили
# ─────────────────────────────────────────
STYLE = """
QMainWindow { background: #121212; }
QWidget { color: #d0d0d0; font-family: 'Segoe UI', 'Consolas'; }
QGroupBox {
    background: #1a1a1a; border: 1px solid #333; border-radius: 4px;
    margin-top: 14px; padding-top: 22px; font-weight: 600; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #909090; }
QPushButton {
    padding: 10px 16px; border-radius: 4px; font-weight: 600; font-size: 11px;
    border: 1px solid #444; color: #d0d0d0; background: #252525;
    min-height: 36px;
}
QPushButton:hover { background: #333; border-color: #555; }
QPushButton:pressed { background: #1a1a1a; }
QPushButton:disabled { background: #1a1a1a; color: #555; border-color: #2a2a2a; }
QTextEdit {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; font-family: 'Consolas'; font-size: 11px; padding: 6px;
}
QTableWidget {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; gridline-color: #222; font-size: 11px;
}
QTableWidget::item { padding: 4px 6px; }
QTableWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
QHeaderView::section {
    background: #181818; color: #888; border: none; padding: 6px; font-weight: 600;
}
QTabWidget::pane { border: 1px solid #333; border-radius: 3px; background: #1a1a1a; }
QTabBar::tab {
    background: #181818; color: #777; padding: 8px 18px; border: 1px solid #2a2a2a;
    border-bottom: none; border-top-left-radius: 3px; border-top-right-radius: 3px;
    margin-right: 2px;
}
QTabBar::tab:selected { background: #1a1a1a; color: #d0d0d0; border-color: #333; }
QSpinBox {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px;
}
QProgressBar {
    background: #0e0e0e; border: 1px solid #333; border-radius: 3px;
    text-align: center; color: #999; font-weight: 600; font-size: 10px;
}
QProgressBar::chunk { background: #555; border-radius: 2px; }
QStatusBar { background: #0e0e0e; color: #666; border-top: 1px solid #222; }
QLabel { color: #b0b0b0; }
QComboBox {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px 8px; font-size: 11px;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background: #1a1a1a; color: #d0d0d0; border: 1px solid #333; }
QListWidget {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; font-size: 11px;
}
QListWidget::item:selected { background: #2a4070; color: #e0e0e0; }
QListWidget::item:hover { background: #222; }
QLineEdit {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px 8px;
}
QSplitter::handle { background: #333; width: 1px; }
"""
def is_port_available(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex(("127.0.0.1", port))
        s.close()
        if r == 0:
            return False, f"Порт {port} уже занят"
        return True, f"Порт {port} свободен"
    except Exception as e:
        return True, str(e)
# ─────────────────────────────────────────
#  Рабочие потоки
# ─────────────────────────────────────────
class AnalysisWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def run(self):
        try:
            a = SystemAnalyzer()
            info = a.analyze()
            s = a.get_summary()
            self.finished.emit({"info": info, "summary": s, "analyzer": a})
        except Exception as e:
            logger.error(f"Ошибка анализа: {e}", exc_info=True)
            self.error.emit(str(e))
class DBLoadWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    def run(self):
        try:
            db = VulnerabilityDatabase(PROJECT_DIR)
            db.load_all()
            self.finished.emit(db)
        except Exception as e:
            logger.error(f"Ошибка загрузки БД: {e}", exc_info=True)
            self.error.emit(str(e))
class VulnScanWorker(QThread):
    finished = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)
    error = pyqtSignal(str)
    def run(self):
        try:
            sc = LocalVulnScanner()
            sc.progress_callback = lambda c, t, m: self.progress.emit(c, t, m)
            res = sc.scan_all()
            self.finished.emit(res)
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}", exc_info=True)
            self.error.emit(str(e))
class ToolkitLoadWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    def run(self):
        try:
            tk = AttackToolkit(PROJECT_DIR)
            tk.load()
            self.finished.emit(tk)
        except Exception as e:
            logger.error(f"Ошибка загрузки toolkit: {e}", exc_info=True)
            self.error.emit(str(e))

class TrivyScanWorker(QThread):
    finished = pyqtSignal(object)  # dict summary
    progress = pyqtSignal(int, str)  # percent, message
    error = pyqtSignal(str)
    
    def __init__(self, system_analyzer, trivy_path=""):
        super().__init__()
        self.system_analyzer = system_analyzer
        self.trivy_path = trivy_path
    
    def run(self):
        try:
            self.progress.emit(0, "Запуск сканирования Trivy...")
            result = self.system_analyzer.run_trivy_scan(self.trivy_path)
            self.progress.emit(100, "Сканирование Trivy завершено")
            self.finished.emit(result)
        except Exception as e:
            logger.error(f"Ошибка сканирования Trivy: {e}", exc_info=True)
            self.error.emit(str(e))
# ─────────────────────────────────────────
#  Главное окно
# ─────────────────────────────────────────
class ServerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    analysis_done_signal = pyqtSignal(dict, str)
    update_results_signal = pyqtSignal(object)
    correlation_progress_signal = pyqtSignal(int, str)  # Прогресс корреляции
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Серверный агент v2.0")
        self.setMinimumSize(1600, 900)  # Увеличиваем размер окна для широкой панели
        # Состояние
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.vuln_scan_report = None
        self.toolkit = None
        self.trivy_summary = None  # Результаты Trivy
        self.trivy_available = False  # Доступен ли Trivy
        self.report_history = ReportHistory(PROJECT_DIR)
        self.scan_history = ScanHistory(PROJECT_DIR)
        self.http_server = None
        self.server_thread = None
        self.server_running = False
        self.last_report_path = None
        self.actual_server_port = None
        self._last_scan_data = {}        # Данные от атакующего (для схем)
        self._last_results = []          # Результаты корреляции
        self._build_ui()
        self.setStyleSheet(STYLE)
        self.update_results_signal.connect(self._update_results_table_slot)
        self.correlation_progress_signal.connect(self._on_correlation_progress_update)
        gh = GUILogHandler(self._on_log_message)
        gh.setLevel(10)
        logger.addHandler(gh)
        self.log_signal.connect(self._append_log)
        self.client_connected_signal.connect(self._on_client_connected)
        self.analysis_done_signal.connect(self._on_server_analysis_done)
        # Синхронизируем историю с диском при старте
        QTimer.singleShot(500, self._sync_history)
    # ─────────────────────────────────────────
    #  Построение интерфейса
    # ─────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        ml = QHBoxLayout(central)
        ml.setSpacing(8)
        ml.setContentsMargins(8, 8, 8, 8)
        # Левая панель управления - значительно расширена
        left = self._build_left_panel()
        ml.addWidget(left)
        # Правая панель с вкладками - уменьшена
        self.tabs = QTabWidget()
        self._build_system_tab()
        self._build_software_tab() # НОВАЯ ВКЛАДКА
        self._build_trivy_tab()  # НОВАЯ ВКЛАДКА TRIVY
        self._build_trivy_history_tab()  # НОВАЯ ВКЛАДКА ИСТОРИИ TRIVY
        self._build_vuln_tab()
        self._build_correlation_tab()
        self._build_attack_selector_tab()
        self._build_history_tab()
        self._build_log_tab()
        ml.addWidget(self.tabs, 1)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Готов к работе")
    def _build_left_panel(self) -> QWidget:
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
        t = QLabel("СЕРВЕРНЫЙ АГЕНТ")
        t.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        t.setStyleSheet("color:#999;padding:8px 0;letter-spacing:2px;")
        ll.addWidget(t)
        # Статус
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet(
            "background:#1e1e1e;border:1px solid #3a3a3a;border-radius:6px;padding:12px;"
        )
        sf = QVBoxLayout(self.status_frame)
        sf.setSpacing(4)
        self.status_icon = QLabel("● Сервер не запущен")
        self.status_icon.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.status_icon.setStyleSheet("color:#666;")
        sf.addWidget(self.status_icon)
        self.connection_label = QLabel("Клиенты: нет подключений")
        self.connection_label.setStyleSheet("color:#555;font-size:10px;")
        self.connection_label.setWordWrap(True)
        sf.addWidget(self.connection_label)
        self.port_display = QLabel("")
        self.port_display.setFont(QFont("Consolas", 10))
        self.port_display.setStyleSheet("color:#666;")
        self.port_display.setWordWrap(True)
        sf.addWidget(self.port_display)
        ll.addWidget(self.status_frame)
        # Управление - значительно увеличен
        cg = QGroupBox("Управление")
        cg.setStyleSheet("QGroupBox { font-size: 13px; font-weight: bold; padding-top: 24px; }")
        cl = QVBoxLayout(cg)
        cl.setSpacing(8)
        cl.setContentsMargins(8, 12, 8, 12)

        # Кнопки управления - динамический размер
        btn_style = """
            QPushButton { 
                padding: 10px 14px; 
                font-size: 11px; 
                min-height: 36px; 
                text-align: center;
            }
        """

        self.btn_analyze = QPushButton("1. Анализ системы")
        self.btn_analyze.setStyleSheet(btn_style)
        self.btn_analyze.clicked.connect(self._start_analysis)
        cl.addWidget(self.btn_analyze)

        self.btn_load_db = QPushButton("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setStyleSheet(btn_style)
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.clicked.connect(self._load_databases)
        cl.addWidget(self.btn_load_db)

        self.btn_load_toolkit = QPushButton("2б. Загрузить базу инструментов")
        self.btn_load_toolkit.setStyleSheet(btn_style)
        self.btn_load_toolkit.setEnabled(False)
        self.btn_load_toolkit.clicked.connect(self._load_toolkit)
        cl.addWidget(self.btn_load_toolkit)

        self.btn_vuln_scan = QPushButton("3. Локальное сканирование уязвимостей")
        self.btn_vuln_scan.setStyleSheet(btn_style)
        self.btn_vuln_scan.setEnabled(False)
        self.btn_vuln_scan.clicked.connect(self._start_vuln_scan)
        cl.addWidget(self.btn_vuln_scan)

        self.vuln_progress = QProgressBar()
        self.vuln_progress.setFixedHeight(20)
        self.vuln_progress.setVisible(False)
        cl.addWidget(self.vuln_progress)

        # Кнопка Trivy
        self.btn_trivy_scan = QPushButton("3б. Сканирование Trivy (CVE/CWE/CAPEC)")
        self.btn_trivy_scan.setStyleSheet(btn_style)
        self.btn_trivy_scan.setEnabled(False)
        self.btn_trivy_scan.clicked.connect(self._start_trivy_scan)
        cl.addWidget(self.btn_trivy_scan)

        self.trivy_progress = QProgressBar()
        self.trivy_progress.setFixedHeight(20)
        self.trivy_progress.setVisible(False)
        cl.addWidget(self.trivy_progress)

        self.btn_server = QPushButton("4. Запустить сервер")
        self.btn_server.setStyleSheet(btn_style + "QPushButton { background: #2a4a2a; }")
        self.btn_server.setEnabled(False)
        self.btn_server.clicked.connect(self._toggle_server)
        cl.addWidget(self.btn_server)

        ll.addWidget(cg)

        # Параметры - уменьшены
        pg = QGroupBox("Параметры")
        pg.setStyleSheet("QGroupBox { font-size: 11px; padding-top: 18px; }")
        pl = QVBoxLayout(pg)
        pl.setSpacing(4)
        pl.setContentsMargins(6, 10, 6, 8)

        r = QHBoxLayout()
        r.addWidget(QLabel("Порт API:"))
        r.setSpacing(4)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(SERVER_PORT)
        self.port_spin.setFixedHeight(24)
        r.addWidget(self.port_spin)
        pl.addLayout(r)

        small_btn_style = "QPushButton { padding: 4px 10px; font-size: 10px; min-height: 24px; }"
        self.btn_check_port = QPushButton("Проверить порт")
        self.btn_check_port.setStyleSheet(small_btn_style)
        self.btn_check_port.clicked.connect(self._check_port_availability)
        pl.addWidget(self.btn_check_port)

        self.btn_regen_token = QPushButton("Перегенерировать токен")
        self.btn_regen_token.setStyleSheet(small_btn_style)
        self.btn_regen_token.setToolTip("Сгенерировать новый токен доступа к API")
        self.btn_regen_token.clicked.connect(self._regenerate_token)
        pl.addWidget(self.btn_regen_token)

        self.port_status_label = QLabel("")
        self.port_status_label.setStyleSheet("font-size:9px;")
        self.port_status_label.setWordWrap(True)
        pl.addWidget(self.port_status_label)
        ll.addWidget(pg)

        # Отчёт - уменьшены
        rg = QGroupBox("Отчёт")
        rg.setStyleSheet("QGroupBox { font-size: 11px; padding-top: 18px; }")
        rl = QVBoxLayout(rg)
        rl.setSpacing(4)
        rl.setContentsMargins(6, 10, 6, 8)

        self.btn_open_report = QPushButton("Открыть последний отчёт")
        self.btn_open_report.setStyleSheet(small_btn_style)
        self.btn_open_report.setEnabled(False)
        self.btn_open_report.clicked.connect(self._open_report)
        rl.addWidget(self.btn_open_report)

        self.btn_generate_manual = QPushButton("Сгенерировать отчёт вручную")
        self.btn_generate_manual.setStyleSheet(small_btn_style)
        self.btn_generate_manual.setEnabled(False)
        self.btn_generate_manual.setToolTip("Сгенерировать отчёт на основе выбранного вектора атаки")
        self.btn_generate_manual.clicked.connect(self._generate_manual_report)
        rl.addWidget(self.btn_generate_manual)

        self.btn_export_log = QPushButton("Экспорт лога")
        self.btn_export_log.setStyleSheet(small_btn_style)
        self.btn_export_log.clicked.connect(self._export_log)
        rl.addWidget(self.btn_export_log)
        ll.addWidget(rg)
        ll.addStretch()
        # Статистика
        sf2 = QFrame()
        sf2.setStyleSheet("background:#1e1e1e;border:1px solid #3a3a3a;border-radius:6px;padding:12px;")
        sl = QVBoxLayout(sf2)
        sl.setSpacing(4)
        self.lbl_stats = QLabel("Статистика недоступна")
        self.lbl_stats.setStyleSheet("color:#777;font-size:11px;")
        self.lbl_stats.setWordWrap(True)
        sl.addWidget(self.lbl_stats)
        self.lbl_history_stats = QLabel("")
        self.lbl_history_stats.setStyleSheet("color:#666;font-size:11px;")
        sl.addWidget(self.lbl_history_stats)
        ll.addWidget(sf2)
        
        scroll.setWidget(left)
        return scroll
    def _build_system_tab(self):
        st = QWidget()
        stl = QVBoxLayout(st)
        self.sys_table = QTableWidget(0, 2)
        self.sys_table.setHorizontalHeaderLabels(["Параметр", "Значение"])
        self.sys_table.horizontalHeader().setStretchLastSection(True)
        self.sys_table.setColumnWidth(0, 220)
        self.sys_table.verticalHeader().setVisible(False)
        self.sys_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        stl.addWidget(self.sys_table)
        self.tabs.addTab(st, "🖥️ Система")

    def _build_software_tab(self):
        """Новая вкладка для реального ПО от сканера"""
        st = QWidget()
        stl = QVBoxLayout(st)
        label = QLabel("Реестр программного обеспечения и открытых портов, найденных сканером на сервере:")
        stl.addWidget(label)

        self.software_table = QTableWidget(0, 3)
        self.software_table.setHorizontalHeaderLabels(["Тип", "Название / Компонент", "Порт / Версия"])
        self.software_table.horizontalHeader().setStretchLastSection(True)
        self.software_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        stl.addWidget(self.software_table)
        self.tabs.addTab(st, "📦 Обнаруженное ПО")

    def _build_trivy_tab(self):
        """Вкладка для отображения результатов сканирования Trivy"""
        st = QWidget()
        stl = QVBoxLayout(st)
        
        # Заголовок
        title = QLabel("🔍 Результаты сканирования Trivy (CVE/CWE/CAPEC)")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        stl.addWidget(title)
        
        # Панель управления Trivy
        ctrl_layout = QHBoxLayout()
        self.btn_load_trivy = QPushButton("📂 Загрузить отчёт из файла (История)")
        self.btn_load_trivy.clicked.connect(self._load_trivy_report)
        ctrl_layout.addWidget(self.btn_load_trivy)
        ctrl_layout.addStretch()
        stl.addLayout(ctrl_layout)
        
        # Статус
        self.trivy_status_label = QLabel("⚪ Trivy не запущен")
        self.trivy_status_label.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        stl.addWidget(self.trivy_status_label)
        
        # Таблица уязвимостей
        self.trivy_table = QTableWidget(0, 7)
        self.trivy_table.setHorizontalHeaderLabels([
            "CVE-ID", "ПО", "Версия", "Исправлено", "Серьёзность", "Заголовок", "CWE/CAPEC"
        ])
        self.trivy_table.horizontalHeader().setStretchLastSection(True)
        self.trivy_table.setColumnWidth(0, 140)
        self.trivy_table.setColumnWidth(1, 150)
        self.trivy_table.setColumnWidth(2, 90)
        self.trivy_table.setColumnWidth(3, 90)
        self.trivy_table.setColumnWidth(4, 90)
        self.trivy_table.setColumnWidth(5, 250)
        self.trivy_table.verticalHeader().setVisible(False)
        self.trivy_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        stl.addWidget(self.trivy_table)
        
        # Сводка
        self.trivy_summary_label = QLabel("")
        self.trivy_summary_label.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        self.trivy_summary_label.setWordWrap(True)
        stl.addWidget(self.trivy_summary_label)
        
        self.tabs.addTab(st, "🛡️ Trivy")

    def _build_trivy_history_tab(self):
        """Вкладка истории сканирований Trivy"""
        tht = QWidget()
        thtl = QVBoxLayout(tht)
        
        title = QLabel("📂 История сканирований Trivy")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        thtl.addWidget(title)
        
        ctrl = QHBoxLayout()
        self.btn_refresh_trivy_hist = QPushButton("🔄 Обновить")
        self.btn_refresh_trivy_hist.clicked.connect(self._refresh_trivy_history)
        ctrl.addWidget(self.btn_refresh_trivy_hist)
        
        self.btn_load_trivy_hist = QPushButton("📥 Подгрузить выбранное сканирование")
        self.btn_load_trivy_hist.clicked.connect(self._load_selected_trivy_history)
        self.btn_load_trivy_hist.setEnabled(False)
        ctrl.addWidget(self.btn_load_trivy_hist)
        ctrl.addStretch()
        thtl.addLayout(ctrl)
        
        self.trivy_hist_table = QTableWidget(0, 4)
        self.trivy_hist_table.setHorizontalHeaderLabels(["Дата и Время", "Уязвимостей", "Критических", "Файл"])
        self.trivy_hist_table.horizontalHeader().setStretchLastSection(True)
        self.trivy_hist_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.trivy_hist_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.trivy_hist_table.itemSelectionChanged.connect(lambda: self.btn_load_trivy_hist.setEnabled(bool(self.trivy_hist_table.selectedItems())))
        thtl.addWidget(self.trivy_hist_table)
        
        self.tabs.addTab(tht, "📜 История Trivy")

    def _update_software_tab(self, system_info):
        """Заполнение вкладки реальным ПО"""
        self.software_table.setRowCount(0)
        row = 0
        for port_info in getattr(system_info, 'open_ports', []):
            self.software_table.insertRow(row)
            self.software_table.setItem(row, 0, QTableWidgetItem("Сетевая служба"))
            port_num = getattr(port_info, 'port', None)
            if port_num is None and isinstance(port_info, dict):
                port_num = port_info.get("port", "Неизвестно")
            self.software_table.setItem(row, 1, QTableWidgetItem(f"Служба на порту {port_num}"))
            self.software_table.setItem(row, 2, QTableWidgetItem(str(port_num)))
            row += 1
            
        for sw in getattr(system_info, 'installed_software', []):
            self.software_table.insertRow(row)
            self.software_table.setItem(row, 0, QTableWidgetItem("Установленное ПО"))
            sw_name = getattr(sw, 'name', None)
            if sw_name is None and isinstance(sw, dict):
                sw_name = sw.get("name", "Неизвестное ПО")
            sw_version = getattr(sw, 'version', None)
            if sw_version is None and isinstance(sw, dict):
                sw_version = sw.get("version", "")
            self.software_table.setItem(row, 1, QTableWidgetItem(str(sw_name)))
            self.software_table.setItem(row, 2, QTableWidgetItem(str(sw_version)))
            row += 1

    def _build_vuln_tab(self):
        vt = QWidget()
        vtl = QVBoxLayout(vt)
        self.vuln_table = QTableWidget(0, 5)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "Серьёзность", "Статус", "Категория", "Описание"])
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        self.vuln_table.setColumnWidth(0, 70)
        self.vuln_table.setColumnWidth(1, 85)
        self.vuln_table.setColumnWidth(2, 100)
        self.vuln_table.setColumnWidth(3, 80)
        self.vuln_table.verticalHeader().setVisible(False)
        self.vuln_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vtl.addWidget(self.vuln_table)
        self.vuln_summary_label = QLabel("")
        self.vuln_summary_label.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        vtl.addWidget(self.vuln_summary_label)
        self.tabs.addTab(vt, "🔍 Локальный скан")
    def _build_correlation_tab(self):
        rt = QWidget()
        rtl = QVBoxLayout(rt)
        info = QLabel("📊 Результаты корреляции атак. Двойной клик для деталей. Отчёт открывается кнопкой 'Открыть последний отчёт'")
        info.setStyleSheet("color:#888;font-size:10px;padding:4px;")
        info.setWordWrap(True)
        rtl.addWidget(info)
        
        # Прогресс корреляции
        self.correlation_progress_label = QLabel("⚪ Ожидание данных от атакующего...")
        self.correlation_progress_label.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        rtl.addWidget(self.correlation_progress_label)
        
        self.correlation_progress_bar = QProgressBar()
        self.correlation_progress_bar.setFixedHeight(20)
        self.correlation_progress_bar.setVisible(False)
        self.correlation_progress_bar.setValue(0)
        rtl.addWidget(self.correlation_progress_bar)
        
        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["CVE", "Серьёзность", "Реализуемость", "Атака", "Описание"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 130)
        self.results_table.setColumnWidth(1, 85)
        self.results_table.setColumnWidth(2, 130)
        self.results_table.setColumnWidth(3, 180)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_table.doubleClicked.connect(self._on_result_double_click)
        rtl.addWidget(self.results_table)
        self.correlation_summary = QLabel("")
        self.correlation_summary.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        rtl.addWidget(self.correlation_summary)
        self.tabs.addTab(rt, "📊 Корреляция")
    def _build_attack_selector_tab(self):
        """Вкладка ручного выбора вектора атаки."""
        at = QWidget()
        atl = QVBoxLayout(at)
        # Заголовок
        title = QLabel("⚔️ Ручной выбор вектора атаки (учебные цели)")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        atl.addWidget(title)
        warn = QLabel("⚠️ Только для авторизованных учебных Red Team / Blue Team учений!")
        warn.setStyleSheet("color:#c44;font-size:11px;padding:4px 0;")
        atl.addWidget(warn)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        # Левая часть — выбор
        left_w = QWidget()
        left_l = QVBoxLayout(left_w)
        left_l.setContentsMargins(0, 0, 0, 0)
        # Фильтр по типу атаки
        filter_g = QGroupBox("Фильтр")
        filter_l = QVBoxLayout(filter_g)
        filter_l.addWidget(QLabel("Тип атаки:"))
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItem("Все типы")
        self.attack_type_combo.currentTextChanged.connect(self._filter_attack_vectors)
        filter_l.addWidget(self.attack_type_combo)
        filter_l.addWidget(QLabel("Поиск по CVE / названию:"))
        self.attack_search = QLineEdit()
        self.attack_search.setPlaceholderText("Введите CVE ID или название...")
        self.attack_search.textChanged.connect(self._filter_attack_vectors)
        filter_l.addWidget(self.attack_search)
        left_l.addWidget(filter_g)
        # Список векторов атак
        vectors_g = QGroupBox("Доступные векторы атак")
        vectors_l = QVBoxLayout(vectors_g)
        self.attack_vectors_list = QListWidget()
        self.attack_vectors_list.currentItemChanged.connect(self._on_attack_vector_selected)
        vectors_l.addWidget(self.attack_vectors_list)
        left_l.addWidget(vectors_g)
        # IP цели
        ip_g = QGroupBox("Параметры атаки")
        ip_l = QFormLayout(ip_g)
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("192.168.1.100")
        self.target_ip_edit.setText("<TARGET_IP>")
        ip_l.addRow("IP цели:", self.target_ip_edit)
        left_l.addWidget(ip_g)
        self.btn_show_attack = QPushButton("🔍 Показать инструменты атаки")
        self.btn_show_attack.clicked.connect(self._show_attack_details)
        self.btn_show_attack.setEnabled(False)
        left_l.addWidget(self.btn_show_attack)
        self.btn_gen_attack_report = QPushButton("📄 Создать отчёт по выбранному вектору")
        self.btn_gen_attack_report.clicked.connect(self._generate_attack_report)
        self.btn_gen_attack_report.setEnabled(False)
        left_l.addWidget(self.btn_gen_attack_report)
        splitter.addWidget(left_w)
        # Правая часть — детали
        right_w = QWidget()
        right_l = QVBoxLayout(right_w)
        right_l.setContentsMargins(0, 0, 0, 0)
        details_g = QGroupBox("Детали вектора атаки")
        details_l = QVBoxLayout(details_g)
        self.attack_details_text = QTextEdit()
        self.attack_details_text.setReadOnly(True)
        self.attack_details_text.setFont(QFont("Consolas", 10))
        details_l.addWidget(self.attack_details_text)
        right_l.addWidget(details_g)
        splitter.addWidget(right_w)
        splitter.setSizes([350, 650])
        atl.addWidget(splitter, 1)
        self.tabs.addTab(at, "⚔️ Выбор атаки")
        self._attack_vectors_data = []
    def _build_history_tab(self):
        """Вкладка истории отчётов."""
        ht = QWidget()
        htl = QVBoxLayout(ht)
        title = QLabel("📋 История отчётов")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        htl.addWidget(title)
        # Панель управления историей
        ctrl = QHBoxLayout()
        self.btn_refresh_history = QPushButton("🔄 Обновить")
        self.btn_refresh_history.clicked.connect(self._refresh_history)
        ctrl.addWidget(self.btn_refresh_history)
        self.btn_open_history_report = QPushButton("📂 Открыть")
        self.btn_open_history_report.clicked.connect(self._open_history_report)
        self.btn_open_history_report.setEnabled(False)
        ctrl.addWidget(self.btn_open_history_report)
        self.btn_delete_history = QPushButton("🗑️ Удалить запись")
        self.btn_delete_history.clicked.connect(self._delete_history_record)
        self.btn_delete_history.setEnabled(False)
        ctrl.addWidget(self.btn_delete_history)
        self.btn_delete_with_files = QPushButton("🗑️ Удалить с файлами")
        self.btn_delete_with_files.clicked.connect(self._delete_history_with_files)
        self.btn_delete_with_files.setEnabled(False)
        ctrl.addWidget(self.btn_delete_with_files)
        ctrl.addStretch()
        htl.addLayout(ctrl)
        # Таблица истории
        self.history_table = QTableWidget(0, 8)
        self.history_table.setHorizontalHeaderLabels([
            "Дата", "Хост", "ОС", "Всего", "Реализуемых", "CRITICAL", "HIGH", "Уровень риска"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(False)
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.history_table.setColumnWidth(2, 80)
        self.history_table.setColumnWidth(3, 60)
        self.history_table.setColumnWidth(4, 90)
        self.history_table.setColumnWidth(5, 70)
        self.history_table.setColumnWidth(6, 55)
        self.history_table.setColumnWidth(7, 100)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.itemSelectionChanged.connect(self._on_history_selection_changed)
        self.history_table.doubleClicked.connect(self._open_history_report)
        htl.addWidget(self.history_table, 1)
        # Детали выбранной записи
        self.history_detail = QLabel("Выберите запись для просмотра деталей")
        self.history_detail.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        self.history_detail.setWordWrap(True)
        htl.addWidget(self.history_detail)
        self.tabs.addTab(ht, "📋 История")
    def _build_log_tab(self):
        lt = QWidget()
        ltl = QVBoxLayout(lt)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        ltl.addWidget(self.log_output)
        self.tabs.addTab(lt, "📝 Лог")
    # ─────────────────────────────────────────
    #  Логирование
    # ─────────────────────────────────────────
    def _on_log_message(self, msg, level):
        self.log_signal.emit(msg, level)
    def _append_log(self, msg, level):
        c = {"ERROR": "#b55", "WARNING": "#a85", "CRITICAL": "#c44"}.get(level, "#888")
        self.log_output.append(f'<span style="color:{c}">{msg}</span>')
        self.log_output.moveCursor(QTextCursor.MoveOperation.End)
    # ─────────────────────────────────────────
    #  Проверка порта
    # ─────────────────────────────────────────
    def _check_port_availability(self):
        p = self.port_spin.value()
        ok, d = is_port_available(p)
        if ok:
            self.port_status_label.setText(f"Порт {p} свободен")
            self.port_status_label.setStyleSheet("color:#8a8;font-size:10px;")
        else:
            self.port_status_label.setText(f"ЗАНЯТ: {d}")
            self.port_status_label.setStyleSheet("color:#b55;font-size:10px;")
    # ─────────────────────────────────────────
    #  Анализ системы
    # ─────────────────────────────────────────
    def _start_analysis(self):
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Анализ системы...")
        self.analysis_worker = AnalysisWorker()
        self.analysis_worker.finished.connect(self._on_analysis_done)
        self.analysis_worker.error.connect(self._on_analysis_error)
        self.analysis_worker.start()
    def _on_analysis_done(self, result):
        self.system_info = result["info"]
        self.system_summary = result["summary"]
        self.system_analyzer = result["analyzer"]  # Сохраняем анализатор для Trivy
        self.sys_table.setRowCount(0)
        rows = [
            ("ОС", self.system_summary.get("os", "?")),
            ("Имя хоста", self.system_summary.get("hostname", "?")),
            ("IP-адреса", ", ".join(self.system_summary.get("ip_addresses", []))),
            ("ПО", str(self.system_summary.get("installed_software_count", 0))),
            ("Службы", str(self.system_summary.get("running_services_count", 0))),
            ("Порты", str(self.system_summary.get("open_ports_count", 0))),
            ("Файрвол", "Активен" if self.system_summary.get("firewall") else "Не активен"),
            ("Антивирус", "Активен" if self.system_summary.get("antivirus") else "Не активен"),
            ("RDP", "Вкл" if self.system_summary.get("has_rdp") else "Выкл"),
            ("SMB", "Да" if self.system_summary.get("has_smb") else "Нет"),
            ("БД", ", ".join(self.system_summary.get("database_types", [])) or "Нет"),
        ]
        for p, v in rows:
            r = self.sys_table.rowCount()
            self.sys_table.insertRow(r)
            self.sys_table.setItem(r, 0, QTableWidgetItem(str(p)))
            self.sys_table.setItem(r, 1, QTableWidgetItem(str(v)))

        self._update_software_tab(self.system_info) # Обновляем вкладку ПО

        # Сохраняем результат сканирования в историю
        import time
        scan_start = time.time()
        record = ScanHistory.from_system_info(
            self.system_info, 
            self.system_summary,
            scan_duration=0.0,  # Время анализа не измеряется точно здесь
            notes="Автоматическое сканирование системы"
        )
        self.scan_history.add_record(record)
        self._update_stats()

        self.btn_analyze.setText("1. Анализ системы (выполнен)")
        self.btn_analyze.setEnabled(True)
        self.btn_load_db.setEnabled(True)
        self.btn_load_toolkit.setEnabled(True)
        self.btn_trivy_scan.setEnabled(True)  # Включаем кнопку Trivy
    def _on_analysis_error(self, e):
        self.btn_analyze.setText("1. Анализ системы")
        self.btn_analyze.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка анализа:\n{e}")
    # ─────────────────────────────────────────
    #  Загрузка баз данных
    # ─────────────────────────────────────────
    def _load_databases(self):
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.setText("Загрузка...")
        self.db_worker = DBLoadWorker()
        self.db_worker.finished.connect(self._on_db_loaded)
        self.db_worker.error.connect(self._on_db_error)
        self.db_worker.start()
    def _on_db_loaded(self, db):
        self.vuln_db = db
        self.btn_load_db.setText("2. Базы (загружены)")
        self.btn_load_db.setEnabled(True)
        self.btn_vuln_scan.setEnabled(True)
        # НЕ разблокируем кнопку сервера здесь - ждём Trivy
        self._update_stats()
    def _on_db_error(self, e):
        self.btn_load_db.setText("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка БД:\n{e}")
    # ─────────────────────────────────────────
    #  Загрузка Toolkit (инструменты атак/защиты)
    # ─────────────────────────────────────────
    def _load_toolkit(self):
        self.btn_load_toolkit.setEnabled(False)
        self.btn_load_toolkit.setText("Загрузка инструментов...")
        self.tk_worker = ToolkitLoadWorker()
        self.tk_worker.finished.connect(self._on_toolkit_loaded)
        self.tk_worker.error.connect(self._on_toolkit_error)
        self.tk_worker.start()
    def _on_toolkit_loaded(self, tk):
        self.toolkit = tk
        api_state.toolkit = tk
        self.btn_load_toolkit.setText("2б. Инструменты (загружены)")
        self.btn_load_toolkit.setEnabled(True)
        self.btn_generate_manual.setEnabled(True)
        # Заполняем вкладку выбора вектора атаки
        self._populate_attack_selector()
        logger.info(f"[TOOLKIT] Загружено {len(tk.tools_db)} инструментов атаки, {len(tk.defense_db)} мер защиты")
    def _on_toolkit_error(self, e):
        self.btn_load_toolkit.setText("2б. Загрузить базу инструментов")
        self.btn_load_toolkit.setEnabled(True)
        QMessageBox.warning(self, "Предупреждение", f"Не удалось загрузить базу инструментов:\n{e}\n\nОтчёты будут создаваться без детальных инструкций.")
    # ─────────────────────────────────────────
    #  Вкладка выбора вектора атаки
    # ─────────────────────────────────────────
    def _populate_attack_selector(self):
        """Заполнить список векторов атак из toolkit."""
        if not self.toolkit:
            return
        # Типы атак в фильтр
        self.attack_type_combo.blockSignals(True)
        self.attack_type_combo.clear()
        self.attack_type_combo.addItem("Все типы")
        for at in self.toolkit.get_all_attack_types():
            self.attack_type_combo.addItem(at)
        self.attack_type_combo.blockSignals(False)
        # Векторы
        self._attack_vectors_data = self.toolkit.get_available_attack_vectors()
        self._update_attack_vectors_list(self._attack_vectors_data)
    def _update_attack_vectors_list(self, vectors: list):
        self.attack_vectors_list.clear()
        for v in vectors:
            cve = v.get("cve_id", "")
            tool = v.get("tool_name", "")
            skill = v.get("skill_level", "")
            label = f"{cve}  —  {tool}  [{skill}]"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, v)
            skill_colors = {
                "Beginner": QColor("#3fb950"),
                "Intermediate": QColor("#d29922"),
                "Advanced": QColor("#e67e22"),
                "Expert": QColor("#e74c3c"),
            }
            item.setForeground(skill_colors.get(skill, QColor("#888")))
            self.attack_vectors_list.addItem(item)
    def _filter_attack_vectors(self):
        if not self._attack_vectors_data:
            return
        attack_type = self.attack_type_combo.currentText()
        search = self.attack_search.text().lower()
        filtered = []
        for v in self._attack_vectors_data:
            if attack_type != "Все типы" and attack_type not in v.get("attack_types", []):
                continue
            if search and search not in v.get("cve_id", "").lower() and search not in v.get("tool_name", "").lower():
                continue
            filtered.append(v)
        self._update_attack_vectors_list(filtered)
    def _on_attack_vector_selected(self, current, previous):
        if not current:
            self.btn_show_attack.setEnabled(False)
            self.btn_gen_attack_report.setEnabled(False)
            return
        self.btn_show_attack.setEnabled(True)
        self.btn_gen_attack_report.setEnabled(bool(self.vuln_db and self.system_info))
    def _show_attack_details(self):
        item = self.attack_vectors_list.currentItem()
        if not item:
            return
        v = item.data(Qt.ItemDataRole.UserRole)
        if not v:
            return
        cve_id = v.get("cve_id", "")
        tool_name = v.get("tool_name", "")
        target_ip = self.target_ip_edit.text().strip() or "<TARGET_IP>"
        text = f"═══════════════════════════════════════\n"
        text += f"  ВЕКТОР АТАКИ: {cve_id}\n"
        text += f"  Инструмент:   {tool_name}\n"
        text += f"  Уровень:      {v.get('skill_level', '?')}\n"
        text += f"  Фазы:         {', '.join(v.get('phases', []))}\n"
        text += f"═══════════════════════════════════════\n\n"
        if self.toolkit:
            tools = self.toolkit.get_attack_commands(cve_id, target_ip)
            if tools:
                for tool in tools:
                    text += f"▸ Инструмент: {tool['tool_name']}\n"
                    text += f"  Тип: {tool['tool_type']}\n"
                    text += f"  Описание: {tool['description']}\n"
                    text += f"  URL: {tool.get('url', '—')}\n"
                    text += f"\n  Команды:\n"
                    for cmd in tool.get("commands", []):
                        text += f"  {cmd}\n"
                    text += "\n"
            # Меры защиты
            defense = self.toolkit.get_defense_tools(cve_id)
            if defense:
                text += "═══════════════════════════════════════\n"
                text += "  МЕРЫ ЗАЩИТЫ:\n"
                text += "═══════════════════════════════════════\n\n"
                for d in defense:
                    text += f"▸ {d.get('tool_name', '')} — {d.get('defense_name', '')}\n"
                    text += f"  Приоритет: {d.get('priority', '?')}\n"
                    text += f"  Описание: {d.get('tool_description', d.get('description', ''))}\n"
                    cmds = d.get("commands", [])
                    if cmds:
                        text += "\n  Команды защиты:\n"
                        for cmd in cmds:
                            text += f"  {cmd}\n"
                    text += "\n"
        self.attack_details_text.setPlainText(text)
    def _generate_attack_report(self):
        """Генерировать отчёт по выбранному вектору атаки."""
        item = self.attack_vectors_list.currentItem()
        if not item or not self.vuln_db or not self.system_info:
            QMessageBox.warning(self, "Предупреждение", "Сначала выполните анализ системы и загрузите базы данных.")
            return
        v = item.data(Qt.ItemDataRole.UserRole)
        cve_id = v.get("cve_id", "")
        target_ip = self.target_ip_edit.text().strip() or "<TARGET_IP>"
        # Создаём ScanResult с одним вектором
        from common.models import ScanResult, AttackVector as AV
        scan_result = ScanResult(
            scanner_ip=target_ip,
            target_ip=self.system_summary.get("ip_addresses", [""])[0] if self.system_summary else "",
            scan_timestamp=datetime.now().isoformat(),
        )
        scan_result.attack_vectors.append(AV(
            id=cve_id,
            name=f"Ручной выбор: {cve_id}",
            description=f"Вектор атаки выбран вручную: {cve_id}",
            target_service=v.get("attack_types", [""])[0] if v.get("attack_types") else "",
        ))
        cor = AttackCorrelator(self.system_info, self.vuln_db,
                               trivy_result=getattr(self, 'trivy_result', None))
        results = cor.correlate(scan_result)
        summary = cor.get_summary()
        rd = os.path.join(PROJECT_DIR, "reports")
        os.makedirs(rd, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rep = ReportGenerator(
            self.system_summary or {},
            results,
            summary,
            toolkit=self.toolkit,
            attacker_scan_data={"target_ip": target_ip},
        )
        hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
        rep.generate_json(os.path.join(rd, f"report_{ts}.json"))
        self.last_report_path = hp
        self.btn_open_report.setEnabled(True)
        self._add_to_history(results, summary, ts, hp, os.path.join(rd, f"report_{ts}.json"))
        self.update_results_signal.emit(results)
        webbrowser.open(f"file:///{hp}")
    # ─────────────────────────────────────────
    #  Локальное сканирование
    # ─────────────────────────────────────────
    def _start_vuln_scan(self):
        self.btn_vuln_scan.setEnabled(False)
        self.btn_vuln_scan.setText("Сканирование...")
        self.vuln_progress.setVisible(True)
        self.vuln_progress.setValue(0)
        self.vuln_table.setRowCount(0)
        self.vuln_worker = VulnScanWorker()
        self.vuln_worker.finished.connect(self._on_vuln_scan_done)
        self.vuln_worker.progress.connect(self._on_vuln_scan_progress)
        self.vuln_worker.error.connect(self._on_vuln_scan_error)
        self.vuln_worker.start()
    def _on_vuln_scan_progress(self, c, t, m):
        self.vuln_progress.setValue(int(c / t * 100) if t else 0)
        self.vuln_progress.setFormat(f"{m} ({c}/{t})")
    def _on_vuln_scan_done(self, report):
        self.vuln_scan_report = report
        api_state.local_scan_report = report
        self.vuln_progress.setValue(100)
        self.vuln_progress.setVisible(False)
        self.vuln_table.setRowCount(0)
        so = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for f in sorted(report.findings, key=lambda x: so.get(x.severity, 5)):
            r = self.vuln_table.rowCount()
            self.vuln_table.insertRow(r)
            self.vuln_table.setItem(r, 0, QTableWidgetItem(str(f.check_id)))
            si = QTableWidgetItem(str(f.severity))
            si.setForeground(QColor({"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "INFO": "#668"}.get(f.severity, "#888")))
            self.vuln_table.setItem(r, 1, si)
            sti = QTableWidgetItem(str(f.status))
            sti.setForeground(QColor({"VULNERABLE": "#b55", "SECURE": "#696", "UNKNOWN": "#888"}.get(f.status, "#888")))
            self.vuln_table.setItem(r, 2, sti)
            self.vuln_table.setItem(r, 3, QTableWidgetItem(str(f.category)))
            d = str(f.title) + (f" | {f.recommendation}" if f.recommendation else "")
            self.vuln_table.setItem(r, 4, QTableWidgetItem(d))
        self.vuln_summary_label.setText(
            f"Проверок:{report.total_checks}  Уязвимо:{report.vulnerable}  "
            f"Защищено:{report.secure}  Риск:{report.risk_score:.1f}/100"
        )
        self.btn_vuln_scan.setText("3. Локальный скан (выполнен)")
        self.btn_vuln_scan.setEnabled(True)
        self.tabs.setCurrentIndex(1)
    def _on_vuln_scan_error(self, e):
        self.vuln_progress.setVisible(False)
        self.btn_vuln_scan.setText("3. Локальное сканирование")
        self.btn_vuln_scan.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", str(e))
    
    # ─────────────────────────────────────────
    #  Trivy сканирование
    # ─────────────────────────────────────────
    def _start_trivy_scan(self):
        """Запуск сканирования Trivy"""
        if not self.system_info:
            QMessageBox.warning(self, "Предупреждение", "Сначала выполните анализ системы!")
            return
        
        self.btn_trivy_scan.setEnabled(False)
        self.btn_trivy_scan.setText("Сканирование Trivy...")
        self.trivy_progress.setVisible(True)
        self.trivy_progress.setValue(0)
        self.trivy_table.setRowCount(0)
        self.trivy_status_label.setText("🔄 Сканирование Trivy...")
        self.trivy_status_label.setStyleSheet("color:#a85;font-size:11px;padding:4px;")
        
        self.trivy_worker = TrivyScanWorker(self.system_analyzer if hasattr(self, 'system_analyzer') else None)
        self.trivy_worker.finished.connect(self._on_trivy_scan_done)
        self.trivy_worker.progress.connect(self._on_trivy_scan_progress)
        self.trivy_worker.error.connect(self._on_trivy_scan_error)
        self.trivy_worker.start()
    
    def _on_trivy_scan_progress(self, percent, message):
        """Обновление прогресса Trivy"""
        self.trivy_progress.setValue(percent)
        self.trivy_progress.setFormat(f"{message} ({percent}%)")
    
    def _on_trivy_scan_done(self, summary):
        """Обработка результатов Trivy"""
        self.trivy_progress.setValue(100)
        self.trivy_progress.setVisible(False)
        
        if summary.get("error"):
            self.trivy_status_label.setText(f"❌ Ошибка: {summary['error']}")
            self.trivy_status_label.setStyleSheet("color:#b55;font-size:11px;padding:4px;")
            QMessageBox.warning(self, "Ошибка Trivy", f"Не удалось выполнить сканирование:\n{summary['error']}")
            self.btn_trivy_scan.setText("3б. Сканирование Trivy (ошибка)")
            self.btn_trivy_scan.setEnabled(True)
            return
        
        # Сохраняем сводку
        self.trivy_summary = summary
        
        # Сохраняем полный результат Trivy для корреляции
        if hasattr(self, 'system_analyzer') and self.system_analyzer:
            self.trivy_result = getattr(self.system_analyzer.system_info, 'trivy_scan_result', None)
            api_state.trivy_result = self.trivy_result

        # Обновляем статус
        total = summary.get("total_vulns", 0)
        self.trivy_status_label.setText(f"✅ Сканирование завершено! Найдено {total} уязвимостей")
        self.trivy_status_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")

        # Разблокируем кнопку запуска сервера
        if self.system_info and self.vuln_db:
            self.btn_server.setEnabled(True)
        
        # Заполняем таблицу
        self.trivy_table.setRowCount(0)
        
        # Получаем уязвимости из system_info
        if self.system_info and self.system_info.trivy_scan_result:
            vulnerabilities = self.system_info.trivy_scan_result.get("vulnerabilities", [])
            
            # Сортируем по серьёзности
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
            sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get("severity", "UNKNOWN"), 4))
            
            for vuln in sorted_vulns:
                row = self.trivy_table.rowCount()
                self.trivy_table.insertRow(row)
                
                # CVE-ID
                self.trivy_table.setItem(row, 0, QTableWidgetItem(vuln.get("vuln_id", "")))
                
                # ПО
                self.trivy_table.setItem(row, 1, QTableWidgetItem(vuln.get("pkg_name", "")))
                
                # Версия
                self.trivy_table.setItem(row, 2, QTableWidgetItem(vuln.get("installed_version", "")))
                
                # Исправлено
                fixed = vuln.get("fixed_version", "")
                fixed_item = QTableWidgetItem(fixed if fixed else "Нет исправления")
                if not fixed:
                    fixed_item.setForeground(QColor("#888"))
                self.trivy_table.setItem(row, 3, fixed_item)
                
                # Серьёзность
                sev = vuln.get("severity", "UNKNOWN")
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "UNKNOWN": "#888", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.trivy_table.setItem(row, 4, sev_item)
                
                # Заголовок
                self.trivy_table.setItem(row, 5, QTableWidgetItem(vuln.get("title", "")[:200]))
                
                # CWE/CAPEC
                cwe_capec = ""
                cwe_ids = vuln.get("cwe_ids", [])
                capec_ids = vuln.get("capec_ids", [])
                if cwe_ids:
                    cwe_capec += "CWE: " + ", ".join(cwe_ids[:3])
                if capec_ids:
                    if cwe_capec:
                        cwe_capec += " | "
                    cwe_capec += "CAPEC: " + ", ".join(capec_ids[:3])
                self.trivy_table.setItem(row, 6, QTableWidgetItem(cwe_capec if cwe_capec else "—"))
        
        # Обновляем сводку
        self.trivy_summary_label.setText(
            f"Всего уязвимостей: {summary.get('total_vulns', 0)}  |  "
            f"🔴 CRITICAL: {summary.get('critical', 0)}  |  "
            f"🟠 HIGH: {summary.get('high', 0)}  |  "
            f"🟡 MEDIUM: {summary.get('medium', 0)}  |  "
            f"🟢 LOW: {summary.get('low', 0)}  |  "
            f"Время: {summary.get('scan_duration', '?')}"
        )
        
        self.btn_trivy_scan.setText("3б. Сканирование Trivy (выполнено)")
        self.btn_trivy_scan.setEnabled(True)
        
        # Переключаемся на вкладку Trivy
        # Находим индекс вкладки Trivy
        for i in range(self.tabs.count()):
            if "Trivy" in self.tabs.tabText(i):
                self.tabs.setCurrentIndex(i)
                break
    
    def _on_trivy_scan_error(self, e):
        """Обработка ошибки Trivy"""
        self.trivy_progress.setVisible(False)
        self.trivy_status_label.setText(f"❌ Ошибка: {str(e)}")
        self.trivy_status_label.setStyleSheet("color:#b55;font-size:11px;padding:4px;")
        self.btn_trivy_scan.setText("3б. Сканирование Trivy (ошибка)")
        self.btn_trivy_scan.setEnabled(True)
        QMessageBox.critical(self, "Ошибка Trivy", str(e))

    def _load_trivy_report(self):
        """Загрузка результатов Trivy из сохраненного JSON-файла."""
        path, _ = QFileDialog.getOpenFileName(self, "Загрузить отчёт Trivy", PROJECT_DIR, "JSON Files (*.json)")
        if not path:
            return
        self._process_trivy_file(path)

    def _refresh_trivy_history(self):
        """Обновляет таблицу истории Trivy из папки data"""
        self.trivy_hist_table.setRowCount(0)
        data_dir = os.path.join(PROJECT_DIR, "data")
        if not os.path.exists(data_dir):
            return
        for fname in sorted(os.listdir(data_dir), reverse=True):
            if fname.startswith("trivy_scan_") and fname.endswith(".json"):
                fpath = os.path.join(data_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    summary = data.get("summary", {})
                    total = summary.get("total_vulns", 0)
                    crit = summary.get("critical", 0)
                    date_part = fname.replace("trivy_scan_", "").replace(".json", "")
                    row = self.trivy_hist_table.rowCount()
                    self.trivy_hist_table.insertRow(row)
                    self.trivy_hist_table.setItem(row, 0, QTableWidgetItem(date_part))
                    self.trivy_hist_table.setItem(row, 1, QTableWidgetItem(str(total)))
                    self.trivy_hist_table.setItem(row, 2, QTableWidgetItem(str(crit)))
                    file_item = QTableWidgetItem(fname)
                    file_item.setData(Qt.ItemDataRole.UserRole, fpath)
                    self.trivy_hist_table.setItem(row, 3, file_item)
                except Exception as e:
                    logger.error(f"Ошибка чтения файла истории Trivy {fname}: {e}")

    def _load_selected_trivy_history(self):
        """Загрузка отчета Trivy выбранного в таблице истории"""
        row = self.trivy_hist_table.currentRow()
        if row < 0: return
        fpath = self.trivy_hist_table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath): return
        self._process_trivy_file(fpath)

    def _process_trivy_file(self, path):
        """Общая логика парсинга JSON от Trivy и заполнения интерфейса"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Проверка формата (поддержка сырого Trivy или нашего отформатированного)
            vulns = data.get("vulnerabilities") or []
            if not vulns and "Results" in data:
                for res in data.get("Results", []):
                    for v in res.get("Vulnerabilities", []):
                        vulns.append({
                            "vuln_id": v.get("VulnerabilityID", ""),
                            "pkg_name": v.get("PkgName", ""),
                            "installed_version": v.get("InstalledVersion", ""),
                            "fixed_version": v.get("FixedVersion", ""),
                            "severity": v.get("Severity", "UNKNOWN"),
                            "title": v.get("Title", "") or "Без названия",
                            "cwe_ids": v.get("CweIDs") or []
                        })
            
            # Считаем статистику
            crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
            high = sum(1 for v in vulns if v.get("severity") == "HIGH")
            med = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
            low = sum(1 for v in vulns if v.get("severity") == "LOW")
            
            self.trivy_summary = {
                "total_vulns": len(vulns),
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "scan_duration": "Загружено из истории"
            }
            
            # Сохраняем в формат, понятный коррелятору
            self.trivy_result = {"vulnerabilities": vulns}
            api_state.trivy_result = self.trivy_result
            
            # Заполняем таблицу
            self.trivy_table.setRowCount(0)
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
            sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.get("severity", "UNKNOWN"), 4))
            
            for vuln in sorted_vulns:
                row = self.trivy_table.rowCount()
                self.trivy_table.insertRow(row)
                self.trivy_table.setItem(row, 0, QTableWidgetItem(vuln.get("vuln_id", "")))
                self.trivy_table.setItem(row, 1, QTableWidgetItem(vuln.get("pkg_name", "")))
                self.trivy_table.setItem(row, 2, QTableWidgetItem(vuln.get("installed_version", "")))
                
                fixed = vuln.get("fixed_version", "")
                fixed_item = QTableWidgetItem(str(fixed) if fixed else "Нет исправления")
                if not fixed: fixed_item.setForeground(QColor("#888"))
                self.trivy_table.setItem(row, 3, fixed_item)
                
                sev = vuln.get("severity", "UNKNOWN")
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "UNKNOWN": "#888", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.trivy_table.setItem(row, 4, sev_item)
                self.trivy_table.setItem(row, 5, QTableWidgetItem(str(vuln.get("title", ""))[:200]))
                
                cwe_list = vuln.get("cwe_ids") or []
                cwe = ", ".join(cwe_list[:3])
                self.trivy_table.setItem(row, 6, QTableWidgetItem(f"CWE: {cwe}" if cwe else "—"))
                
            # Обновляем сводку и переключаем вкладку напрямую, без вызова _on_trivy_scan_done
            self.trivy_summary_label.setText(
                f"Всего уязвимостей: {self.trivy_summary.get('total_vulns', 0)}  |  "
                f"🔴 CRITICAL: {self.trivy_summary.get('critical', 0)}  |  "
                f"🟠 HIGH: {self.trivy_summary.get('high', 0)}  |  "
                f"🟡 MEDIUM: {self.trivy_summary.get('medium', 0)}  |  "
                f"🟢 LOW: {self.trivy_summary.get('low', 0)}  |  "
                f"Время: {self.trivy_summary.get('scan_duration', '?')}"
            )
            for i in range(self.tabs.count()):
                if "Trivy" in self.tabs.tabText(i):
                    self.tabs.setCurrentIndex(i)
                    break
                    
            self.trivy_status_label.setText(f"✅ Загружено из истории: {len(vulns)} уязвимостей")
            self.btn_trivy_scan.setText("3б. Сканирование Trivy (загружено из истории)")
            self.btn_trivy_scan.setEnabled(True)
            
            # Принудительно разблокируем кнопку запуска сервера после подгрузки
            self.btn_server.setEnabled(True)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки Trivy: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить файл:\n{e}")

    # ─────────────────────────────────────────
    #  HTTP Сервер
    # ─────────────────────────────────────────
    def _toggle_server(self):
        # Проверяем что Trivy был запущен
        if not self.trivy_summary:
            reply = QMessageBox.warning(
                self,
                "⚠️ Trivy не запущен",
                "⚠️ Сканирование Trivy не было выполнено!\n\n"
                "Без данных Trivy корреляция атак будет неполной:\n"
                "• Реализуемость атак НЕ будет подтверждена\n"
                "• Уязвимости ПО не будут учтены\n"
                "• Отчёт будет менее точным\n\n"
                "Рекомендуется выполнить сканирование Trivy перед запуском сервера.\n\n"
                "Всё равно запустить сервер?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return
        
        if self.server_running:
            self._stop_server()
        else:
            self._start_server()
    def _start_server(self):
        port = self.port_spin.value()
        ok, desc = is_port_available(port)
        if not ok:
            QMessageBox.critical(self, "Порт занят", f"Порт {port} уже используется!\n\nВыберите другой порт.")
            return
        gui = self
        api_state.base_dir = PROJECT_DIR
        api_state.system_info = self.system_info
        api_state.system_summary = self.system_summary if isinstance(self.system_summary, dict) else {}
        api_state.vuln_db = self.vuln_db
        api_state.toolkit = self.toolkit
        api_state.local_scan_report = self.vuln_scan_report
        api_state.trivy_result = getattr(self, 'trivy_result', None)  # Результаты Trivy
        api_state.ready = bool(self.system_info and self.vuln_db)
        api_state.on_client_connected = lambda ip: gui.client_connected_signal.emit(ip)
        api_state.on_analysis_complete = lambda s, p: gui.analysis_done_signal.emit(s, p)
        api_state.on_correlation_progress = lambda p, m: gui.correlation_progress_signal.emit(p, m)

        # Безопасность API: токен + TLS
        try:
            self._regenerate_token(show_message=False)
            self.http_server = create_api_server(port)
        except RuntimeError as e:
            QMessageBox.critical(self, "Ошибка TLS", str(e))
            logger.error(f"[SRV] Ошибка инициализации TLS: {e}")
            return
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
            logger.error(f"[SRV] Ошибка запуска: {e}")
            return

        fingerprint = get_cert_fingerprint(os.path.join(PROJECT_DIR, CERTS_DIR))
        try:
            self.actual_server_port = port
            self.server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.status_icon.setText("● Сервер запущен (HTTPS)")
            self.status_icon.setStyleSheet("color:#8a8;")
            self._update_connection_info(fingerprint)
            self.port_display.setStyleSheet("color:#8a8;")
            self.btn_server.setText("4. Остановить сервер")
            self.btn_open_report.setEnabled(True)
            self.port_spin.setEnabled(False)
            self.statusBar().showMessage(f"Сервер на порту {port}. Ожидание подключений...")
            logger.info(f"[SRV] HTTPS-сервер запущен на порту {port}")
            logger.info(f"[SRV] Отпечаток сертификата (SHA-256): {fingerprint}")
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
            logger.error(f"[SRV] Ошибка запуска: {e}")

    def _update_connection_info(self, fingerprint: str = ""):
        """Обновление отображения порта, токена и отпечатка."""
        fp = fingerprint or get_cert_fingerprint(os.path.join(PROJECT_DIR, CERTS_DIR))
        self.port_display.setText(
            f"Порт: {self.actual_server_port}\n"
            f"URL: https://0.0.0.0:{self.actual_server_port}\n"
            f"Токен: {api_state.api_token}\n"
            f"Отпечаток: {fp[:47]}..."
        )

    def _regenerate_token(self, show_message: bool = True):
        """Генерация нового токена доступа к API."""
        token, _ = init_api_security()
        logger.info(f"[SRV] Сгенерирован новый токен доступа: {token}")
        if self.server_running:
            self._update_connection_info()
        if show_message:
            QMessageBox.information(
                self, "Новый токен",
                f"Сгенерирован новый токен доступа:\n\n{token}\n\n"
                "Передайте его атакующему агенту."
            )

    def _stop_server(self):
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
        self.server_running = False
        self.actual_server_port = None
        self.status_icon.setText("● Сервер остановлен")
        self.status_icon.setStyleSheet("color:#666;")
        self.port_display.setText("")
        self.btn_server.setText("4. Запустить сервер")
        self.port_spin.setEnabled(True)
        logger.info("[SRV] HTTPS-сервер остановлен")
    # ─────────────────────────────────────────
    #  Подключение клиента
    # ─────────────────────────────────────────
    def _on_client_connected(self, ip):
        n = len(api_state.connected_clients)
        cs = ", ".join(api_state.connected_clients[-3:])
        self.connection_label.setText(f"Клиентов: {n}\nПоследние: {cs}")
        self.statusBar().showMessage(f"Клиент подключён: {ip}")
    def _on_server_analysis_done(self, summary, path):
        self.last_report_path = path
        # Синхронизируем последние результаты из общего состояния
        self._last_results = api_state.last_results
        self._last_scan_data = api_state.last_scan_data
        if self._last_results:
            self.update_results_signal.emit(self._last_results)
        self.tabs.setCurrentIndex(2)  # Вкладка корреляции
        self.btn_open_report.setEnabled(True)
    
    def _on_correlation_progress_update(self, percent, message):
        """Обновление прогресса корреляции из GUI потока."""
        self.correlation_progress_label.setText(f"🔄 {message}")
        self.correlation_progress_label.setStyleSheet("color:#a85;font-size:11px;padding:4px;")
        self.correlation_progress_bar.setVisible(True)
        self.correlation_progress_bar.setValue(percent)
        self.correlation_progress_bar.setFormat(f"{message} ({percent}%)")
        
        if percent >= 100:
            # Скрываем прогресс бар через 2 секунды после завершения
            QTimer.singleShot(2000, lambda: self.correlation_progress_bar.setVisible(False))
            self.correlation_progress_label.setText("✅ Корреляция завершена")
            self.correlation_progress_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")
    # ─────────────────────────────────────────
    #  Таблица корреляции
    # ─────────────────────────────────────────
    def _update_results_table_slot(self, results):
        try:
            self.results_table.setRowCount(0)
            # Дедупликация для таблицы GUI
            seen = set()
            unique_results = []
            for r in results:
                cve = str(r.cve_id or "Нет CVE")
                name = str(r.attack_name or "Неизвестная атака")
                key = f"{cve}_{name}"
                if key not in seen:
                    seen.add(key)
                    unique_results.append(r)
            logger.debug(f"[UI] Обновление таблицы. Уникальных строк: {len(unique_results)} из {len(results)}")
            feasible_cnt = 0
            not_feasible_cnt = 0
            for r in unique_results:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                cve = str(r.cve_id or "Нет CVE")
                sev = str(r.severity or "INFO")
                feas = str(r.feasibility or "UNKNOWN")
                name = str(r.attack_name or "Неизвестная атака")
                desc = str(r.description or "")[:150]
                self.results_table.setItem(row, 0, QTableWidgetItem(cve))
                si = QTableWidgetItem(sev)
                si.setForeground(QColor({"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696"}.get(sev, "#888")))
                self.results_table.setItem(row, 1, si)
                fi = QTableWidgetItem(feas)
                if "НЕ РЕАЛИЗУЕМА" in feas:
                    fi.setForeground(QColor("#696"))
                    not_feasible_cnt += 1
                elif "РЕАЛИЗУЕМА" in feas:
                    fi.setForeground(QColor("#b55"))
                    feasible_cnt += 1
                self.results_table.setItem(row, 2, fi)
                self.results_table.setItem(row, 3, QTableWidgetItem(name))
                self.results_table.setItem(row, 4, QTableWidgetItem(desc))
            self.correlation_summary.setText(
                f"Всего (уникальных): {len(unique_results)}  |  "
                f"🔴 Реализуемых: {feasible_cnt}  |  "
                f"🟢 Нереализуемых: {not_feasible_cnt}"
            )
        except Exception as e:
            logger.error(f"[UI] Сбой при заполнении таблицы: {e}", exc_info=True)
    def _on_result_double_click(self, index):
        """Двойной клик на строке результата — показываем детали."""
        row = index.row()
        if row < 0:
            return
        cve = self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else ""
        sev = self.results_table.item(row, 1).text() if self.results_table.item(row, 1) else ""
        feas = self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else ""
        name = self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else ""
        desc = self.results_table.item(row, 4).text() if self.results_table.item(row, 4) else ""
        msg = f"CVE: {cve}\nСерьёзность: {sev}\nСтатус: {feas}\nАтака: {name}\nОписание: {desc}"
        QMessageBox.information(self, f"Детали: {cve}", msg)
    # ─────────────────────────────────────────
    #  История отчётов
    # ─────────────────────────────────────────
    def _sync_history(self):
        """Синхронизация истории с файлами на диске."""
        rd = os.path.join(PROJECT_DIR, "reports")
        self.report_history.sync_from_disk(rd)
        self._refresh_history_table()
        self._refresh_trivy_history()
        self._update_stats()
        
    def _update_stats(self):
        """Обновление общей статистики."""
        stats = self.report_history.stats
        scan_stats = self.scan_history.stats
        
        stats_text = ""
        if self.vuln_db:
            stats_text = f"CVE:{len(self.vuln_db.cve_db)} CWE:{len(self.vuln_db.cwe_db)} CAPEC:{len(self.vuln_db.capec_db)}"
        else:
            stats_text = "Базы не загружены"
        self.lbl_stats.setText(stats_text)
        
        self.lbl_history_stats.setText(
            f"История: {stats['total']} отчётов "
            f"({stats['critical_reports']} с CRITICAL)\n"
            f"Сканирования: {scan_stats['total']} | "
            f"Хостов: {scan_stats['unique_hosts']}"
        )
    def _refresh_history(self):
        """Обновить историю отчётов."""
        rd = os.path.join(PROJECT_DIR, "reports")
        self.report_history.sync_from_disk(rd)
        self._refresh_history_table()
    def _refresh_history_table(self):
        """Обновить таблицу истории."""
        self.history_table.setRowCount(0)
        records = self.report_history.get_all()
        for rec in records:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            # Дата
            dt_item = QTableWidgetItem(rec.formatted_timestamp)
            if not rec.exists_on_disk:
                dt_item.setForeground(QColor("#555"))  # Файл не существует
            self.history_table.setItem(row, 0, dt_item)
            self.history_table.setItem(row, 1, QTableWidgetItem(rec.hostname or "—"))
            self.history_table.setItem(row, 2, QTableWidgetItem(rec.os_name[:15] if rec.os_name else "—"))
            self.history_table.setItem(row, 3, QTableWidgetItem(str(rec.total_vulnerabilities)))
            self.history_table.setItem(row, 4, QTableWidgetItem(str(rec.feasible_count)))
            ci = QTableWidgetItem(str(rec.critical_count))
            if rec.critical_count > 0:
                ci.setForeground(QColor("#c44"))
            self.history_table.setItem(row, 5, ci)
            hi = QTableWidgetItem(str(rec.high_count))
            if rec.high_count > 0:
                hi.setForeground(QColor("#a85"))
            self.history_table.setItem(row, 6, hi)
            ri = QTableWidgetItem(rec.risk_level)
            ri.setForeground(QColor(rec.risk_color))
            self.history_table.setItem(row, 7, ri)
            # Сохраняем ID в данных строки
            self.history_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, rec.report_id)
        stats = self.report_history.stats
        self.lbl_history_stats.setText(
            f"История: {stats['total']} отчётов | C файлами: {stats['with_files']}"
        )
    def _on_history_selection_changed(self):
        selected = self.history_table.selectedItems()
        has_selection = bool(selected)
        self.btn_open_history_report.setEnabled(has_selection)
        self.btn_delete_history.setEnabled(has_selection)
        self.btn_delete_with_files.setEnabled(has_selection)
        if has_selection:
            row = self.history_table.currentRow()
            report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
            if report_id:
                rec = self.report_history.get_by_id(report_id)
                if rec:
                    detail = (
                        f"ID: {rec.report_id} | "
                        f"Дата: {rec.formatted_timestamp} | "
                        f"Хост: {rec.hostname} | "
                        f"Атакующий: {rec.scanner_ip or '—'} | "
                        f"Файл: {'✅ Существует' if rec.exists_on_disk else '❌ Не найден'}"
                    )
                    self.history_detail.setText(detail)
    def _open_history_report(self):
        row = self.history_table.currentRow()
        if row < 0:
            return
        report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
        if not report_id:
            return
        rec = self.report_history.get_by_id(report_id)
        if not rec:
            return
        if rec.exists_on_disk:
            webbrowser.open(f"file:///{rec.html_path}")
        else:
            QMessageBox.warning(self, "Файл не найден", f"Файл отчёта не найден:\n{rec.html_path}")
    def _delete_history_record(self):
        row = self.history_table.currentRow()
        if row < 0:
            return
        report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
        if not report_id:
            return
        reply = QMessageBox.question(
            self, "Удаление", "Удалить запись из истории? (Файлы отчёта останутся на диске)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.report_history.delete_record(report_id)
            self._refresh_history_table()
    def _delete_history_with_files(self):
        row = self.history_table.currentRow()
        if row < 0:
            return
        report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
        if not report_id:
            return
        reply = QMessageBox.question(
            self, "Удаление с файлами",
            "Удалить запись И файлы отчёта (HTML + JSON) с диска?\nЭто действие необратимо!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.report_history.delete_with_files(report_id)
            self._refresh_history_table()
    def _add_to_history(self, results, summary, ts, html_path, json_path=""):
        """Добавить результат в историю отчётов."""
        try:
            from dataclasses import asdict
            rec = ReportRecord(
                report_id=ts,
                timestamp=datetime.now().isoformat(),
                html_path=html_path,
                json_path=json_path,
                hostname=self.system_summary.get("hostname", "") if self.system_summary else "",
                os_name=self.system_summary.get("os", "") if self.system_summary else "",
                target_ip=summary.get("target_ip", ""),
                scanner_ip=summary.get("scanner_ip", ""),
                total_vulnerabilities=len(results),
                feasible_count=summary.get("feasible_attacks", 0),
                not_feasible_count=summary.get("not_feasible_attacks", 0),
                critical_count=summary.get("critical_count", 0),
                high_count=summary.get("high_count", 0),
                medium_count=summary.get("medium_count", 0),
                low_count=summary.get("low_count", 0),
            )
            self.report_history.add_record(rec)
            self._refresh_history_table()
        except Exception as e:
            logger.error(f"[HISTORY] Ошибка добавления записи: {e}")
    # ─────────────────────────────────────────
    #  Открытие отчётов
    # ─────────────────────────────────────────
    def _open_report(self):
        if self.last_report_path and os.path.exists(self.last_report_path):
            webbrowser.open(f"file:///{self.last_report_path}")
            return
        rd = os.path.join(PROJECT_DIR, "reports")
        if os.path.exists(rd):
            fs = sorted([f for f in os.listdir(rd) if f.endswith(".html")], reverse=True)
            if fs:
                webbrowser.open(f"file:///{os.path.join(rd, fs[0])}")
                return
        QMessageBox.information(self, "Отчёт", "Отчёт не создан.")
    def _generate_manual_report(self):
        """Генерировать отчёт на основе последних результатов с инструментами."""
        if not self._last_results and not self.vuln_db:
            QMessageBox.warning(self, "Нет данных", "Нет данных для генерации. Запустите анализ и отправьте данные с атакующего агента.")
            return
        results = self._last_results or []
        summary = {}
        if self.vuln_db and self.system_info and not results:
            from common.models import ScanResult
            sr = ScanResult(scanner_ip="manual", target_ip="manual", scan_timestamp=datetime.now().isoformat())
            cor = AttackCorrelator(self.system_info, self.vuln_db,
                                   trivy_result=getattr(self, 'trivy_result', None))
            results = cor.correlate(sr)
            summary = cor.get_summary()
        rd = os.path.join(PROJECT_DIR, "reports")
        os.makedirs(rd, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rep = ReportGenerator(
            self.system_summary or {},
            results,
            summary,
            toolkit=self.toolkit,
            local_scan_report=self.vuln_scan_report,
            attacker_scan_data=self._last_scan_data,
        )
        hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
        jp = rep.generate_json(os.path.join(rd, f"report_{ts}.json"))
        self.last_report_path = hp
        self._add_to_history(results, summary, ts, hp, jp)
        webbrowser.open(f"file:///{hp}")
    # ─────────────────────────────────────────
    #  Экспорт лога
    # ─────────────────────────────────────────
    def _export_log(self):
        t = self.log_output.toPlainText()
        if not t:
            QMessageBox.information(self, "Экспорт", "Лог пуст.")
            return
        p, _ = QFileDialog.getSaveFileName(
            self, "Сохранить лог",
            f"server_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        if p:
            open(p, "w", encoding="utf-8").write(t)
    # ─────────────────────────────────────────
    #  Закрытие
    # ─────────────────────────────────────────
    def closeEvent(self, e):
        if self.server_running:
            reply = QMessageBox.question(
                self, "Выход", "Остановить сервер и выйти?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                e.ignore()
                return
            self._stop_server()
        e.accept()
# ─────────────────────────────────────────
#  Запуск
# ─────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = ServerGUI()
    w.show()
    sys.exit(app.exec())
if __name__ == "__main__":
    main()
