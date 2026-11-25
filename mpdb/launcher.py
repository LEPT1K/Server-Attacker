#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Точка входа веб-интерфейса MPDB (MITRE Parser Databases).

Запуск из корня репозитория:
    python -m mpdb.launcher

Открывает браузер с локальным GUI (Flask + SocketIO) на свободном порту.
Привязка только к 127.0.0.1: локальный инструмент без авторизации не должен
слушать на всех интерфейсах LAN.

В собранном .exe этот же файл служит "обёрткой" для шагов парсера:
gui/app.py запускает их как <exe> -u -m mpdb.stepN_*, и launcher
выполняет указанный модуль внутри себя через runpy, не поднимая GUI.
"""

import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def is_frozen():
    return getattr(sys, 'frozen', False)


def run_step_module(module_name: str):
    """Выполнить модуль mpdb.* внутри собранного .exe (замена python -u -m ...)."""
    import runpy
    sys.argv = [module_name] + sys.argv[4:]
    runpy.run_module(module_name, run_name='__main__', alter_sys=True)


def _port_is_free(port: int) -> bool:
    """Проверяет, свободен ли порт на localhost (пробное связывание)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_gui():
    if not is_frozen():
        # Запуск из исходников: корень репозитория в sys.path,
        # чтобы пакет mpdb импортировался и при вызове python mpdb/launcher.py
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from mpdb.gui.app import socketio, app

    print("=" * 50)
    print("  MPDB (MITRE Parser Databases) - Графический интерфейс")
    print("=" * 50)
    print()
    print("Для остановки нажмите Ctrl+C")
    print()

    # Выбираем свободный порт ДО старта сервера, чтобы не открывать браузер
    # на занятый порт (иначе всплывала мёртвая вкладка localhost:5000).
    chosen = next((p for p in (5000, 5001) if _port_is_free(p)), None)
    if chosen is None:
        print("\nНе удалось запустить сервер. Порты 5000 и 5001 заняты.")
        sys.exit(1)

    print("Откройте браузер и перейдите по адресу:")
    print(f"   http://localhost:{chosen}")
    print()

    def open_browser(p=chosen):
        time.sleep(1.5)
        webbrowser.open(f"http://localhost:{p}")

    threading.Thread(target=open_browser, daemon=True).start()

    # host=127.0.0.1: локальный инструмент не должен слушать на всех интерфейсах LAN
    socketio.run(app, host='127.0.0.1', port=chosen, debug=False, allow_unsafe_werkzeug=True)


def main():
    if sys.platform == 'win32':
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')

    # Переинвокация для шагов парсера: <exe> -u -m mpdb.stepN_* [...]
    if is_frozen() and len(sys.argv) >= 4 and sys.argv[1] == '-u' and sys.argv[2] == '-m':
        run_step_module(sys.argv[3])
        return

    run_gui()


if __name__ == '__main__':
    main()
