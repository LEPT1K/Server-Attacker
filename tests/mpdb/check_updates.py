#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Диагностический скрипт для проверки доступности источников новостной ленты
(UpdatesChecker) и состояния локальных баз данных.

Запуск из корня репозитория: python tests/mpdb/check_updates.py
"""

import sys
from pathlib import Path

# Установка кодировки вывода для Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Добавляем корень репозитория в путь (tests/mpdb/ -> tests/ -> root)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from mpdb.updates_checker import UpdatesChecker

def check_updates():
    """Диагностика UpdatesChecker"""

    print("=" * 60)
    print("ДИАГНОСТИКА: Новостная лента обновлений MITRE баз")
    print("=" * 60)
    print()

    # Инициализация
    print("[1] Инициализация UpdatesChecker...")
    try:
        checker = UpdatesChecker()
        print("    ✓ UpdatesChecker инициализирован успешно")
    except Exception as e:
        print(f"    ✗ Ошибка: {e}")
        return False

    print()

    # Проверка источников
    print("[2] Проверка доступности официальных источников...")
    print()

    all_success = True
    for source_key, source_info in UpdatesChecker.SOURCES.items():
        available, has_updates, info, metadata = checker._check_source_freshness(source_key, timeout=5)
        status_symbol = "✓" if metadata else "✗"
        print(f"    {status_symbol} {source_info['name']}")
        print(f"       URL: {source_info['url'][:60]}...")
        print(f"       Статус: {info}")
        if metadata:
            print(f"       Размер: {metadata.get('content_length', 'N/A')}")
            print(f"       Дата: {metadata.get('last_modified', 'N/A')}")
        print()

        if not metadata:
            all_success = False

    print("[3] Получение информации об обновлениях...")
    try:
        updates = checker.check_updates(force_refresh=True)
        print(f"    ✓ Получено {len(updates.get('updates', []))} обновлений")
        print(f"    Время проверки: {updates.get('timestamp', 'unknown')}")
    except Exception as e:
        print(f"    ✗ Ошибка: {e}")
        return False

    print()

    # Отображение результатов
    print("[4] Результаты проверки:")
    print()

    updates_list = updates.get('updates', [])
    for update in updates_list:
        status_icons = {
            'up_to_date': '🟢',
            'outdated': '🟡',
            'missing': '🔴'
        }
        icon = status_icons.get(update['status'], '⚪')

        print(f"    {icon} {update['name']}")
        print(f"       Статус: {update['status_text']}")
        print(f"       Записей: {update.get('local_stats', {}).get('count', 'N/A')}")
        print(f"       Обновлено: {update.get('timestamp', 'N/A')}")
        print()

    print("[5] Сохранение кэша...")
    try:
        cache_file = UpdatesChecker.CACHE_FILE
        print(f"    ✓ Кэш сохранен в: {cache_file}")
        print(f"    Размер: {cache_file.stat().st_size if cache_file.exists() else 0} байт")
    except Exception as e:
        print(f"    ✗ Ошибка при сохранении: {e}")
        return False

    print()

    # Тест сравнения источников
    print("[6] Тест детального сравнения источника (CAPEC)...")
    try:
        comparison = checker.get_db_comparison('capec')
        print("    ✓ Сравнение получено:")
        print(f"       Устарела: {comparison.get('is_outdated', False)}")
        print(f"       Записей локально: {comparison.get('local_stats', {}).get('count', 0)}")
        print(f"       Проверено: {comparison.get('last_checked', 'never')}")
    except Exception as e:
        print(f"    ✗ Ошибка: {e}")
        return False

    print()
    print("=" * 60)
    if all_success:
        print("✓ ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО")
    else:
        print("⚠ НЕКОТОРЫЕ ИСТОЧНИКИ НЕДОСТУПНЫ (проверьте интернет)")
    print("=" * 60)

    return True


if __name__ == '__main__':
    success = check_updates()
    sys.exit(0 if success else 1)
