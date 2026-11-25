#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запуск графического интерфейса MPDB (MITRE Parser Databases)
"""

import sys
import io
from pathlib import Path

# Установка кодировки вывода в UTF-8 для Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from .app import socketio, app

if __name__ == '__main__':
    print("=" * 50)
    print("  MPDB (MITRE Parser Databases) - Графический интерфейс")
    print("=" * 50)
    print()
    print("📂 Директория данных: ../output/")
    print()
    print("Для остановки нажмите Ctrl+C")
    print()
    
    # Пробуем запустить на порту 5000, если занят - на 5001
    ports = [5000, 5001]
    for port in ports:
        try:
            print(f"🌐 Откройте браузер и перейдите по адресу:")
            print(f"   http://localhost:{port}")
            print()
            # allow_unsafe_werkzeug: GUI — локальный инструмент, продакшен-сервер не требуется
            socketio.run(app, host='127.0.0.1', port=port, debug=False, allow_unsafe_werkzeug=True)
            break
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10048:  # Port already in use
                print(f"⚠️  Порт {port} занят. Пробуем порт {ports[ports.index(port)+1] if ports.index(port)+1 < len(ports) else '...'}...")
                if port == ports[-1]:
                    print("\n❌ Не удалось запустить сервер. Проверьте, не заняты ли порты 5000 и 5001.")
                    print("   Закройте другие приложения, использующие эти порты, и попробуйте снова.")
                    sys.exit(1)
            else:
                raise
