"""
Продвинутая система логирования.
Пишет в файл и предоставляет сигналы для GUI.
ИСПРАВЛЕНИЯ: При каждом запуске файл лога полностью очищается (перезаписывается).
"""

import logging
import os
import sys

# Директория для логов
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

def setup_logger(name: str, log_file: str = None, level=logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)

    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] [%(module)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Убираем дату из названия, чтобы лог всегда писался в один файл
    if not log_file:
        log_file = f"{name}.log"
    file_path = os.path.join(LOG_DIR, log_file)

    # Используем FileHandler в режиме 'w' (write), чтобы файл обнулялся при старте
    file_handler = logging.FileHandler(file_path, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logger.info(f"Логгер '{name}' инициализирован. Файл: {file_path}")
    return logger

class GUILogHandler(logging.Handler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(message)s",
            datefmt="%H:%M:%S"
        ))

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            self.callback(msg, level)
        except Exception:
            self.handleError(record)

def get_server_logger() -> logging.Logger:
    return setup_logger("server", "server.log")

def get_attacker_logger() -> logging.Logger:
    return setup_logger("attacker", "attacker.log")