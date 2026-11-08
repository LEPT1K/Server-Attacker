"""
Точка входа — Серверный агент.
Запускается на защищаемом сервере (Windows 10).

Использование:
    python run_server.py
"""

import os
import sys

# Добавляем корневую директорию проекта в путь
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

from server.api_server import start_server

if __name__ == "__main__":
    start_server(project_dir)
