"""
Точка входа — Атакующий агент.
Запускается на компьютере атакующей команды (Windows 10).

Использование:
    python run_attacker.py --target <IP_СЕРВЕРА>
    python run_attacker.py --target 192.168.1.100 --scan-end 10000
    python run_attacker.py -t 127.0.0.1
"""

import os
import sys

# Добавляем корневую директорию проекта в путь
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

from attacker.attacker_agent import run_attacker

if __name__ == "__main__":
    import argparse
    from common.config import TARGET_SERVER_HOST, TARGET_SERVER_PORT, SCAN_PORT_START, SCAN_PORT_END

    parser = argparse.ArgumentParser(
        description="Атакующий агент — сканирование и анализ уязвимостей",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Примеры:
  python run_attacker.py --target 192.168.1.100
  python run_attacker.py --target 10.0.0.5 --scan-end 10000
  python run_attacker.py -t 127.0.0.1 -p 8443
"""
    )
    parser.add_argument(
        "--target", "-t",
        default=TARGET_SERVER_HOST,
        help=f"IP-адрес целевого сервера (по умолчанию: {TARGET_SERVER_HOST})"
    )
    parser.add_argument(
        "--port", "-p",
        type=int, default=TARGET_SERVER_PORT,
        help=f"Порт API серверного агента (по умолчанию: {TARGET_SERVER_PORT})"
    )
    parser.add_argument(
        "--scan-start",
        type=int, default=SCAN_PORT_START,
        help=f"Начальный порт для сканирования (по умолчанию: {SCAN_PORT_START})"
    )
    parser.add_argument(
        "--scan-end",
        type=int, default=SCAN_PORT_END,
        help=f"Конечный порт для сканирования (по умолчанию: {SCAN_PORT_END})"
    )
    parser.add_argument(
        "--token",
        default="",
        help="Токен доступа к API серверного агента (отображается на сервере при запуске)"
    )

    args = parser.parse_args()
    run_attacker(args.target, args.port, args.scan_start, args.scan_end, token=args.token)
