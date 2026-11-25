# mpdb/menu.py
import subprocess
import sys
import re
import json
from pathlib import Path
from .config import Config

def update_translation_params(workers, delay, max_retries):
    """Обновляет параметры перевода в config.py"""
    config_path = Path(__file__).parent / 'config.py'
    with open(config_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Замена TRANSLATION_WORKERS
    content = re.sub(
        r'^(TRANSLATION_WORKERS\s*=\s*).*',
        f'\\g<1>{workers}',
        content,
        flags=re.MULTILINE
    )
    # Замена TRANSLATION_DELAY
    content = re.sub(
        r'^(TRANSLATION_DELAY\s*=\s*).*',
        f'\\g<1>{delay}',
        content,
        flags=re.MULTILINE
    )
    # Замена TRANSLATION_MAX_RETRIES
    content = re.sub(
        r'^(TRANSLATION_MAX_RETRIES\s*=\s*).*',
        f'\\g<1>{max_retries}',
        content,
        flags=re.MULTILINE
    )

    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(content)

    # Перезагружаем Config
    import importlib
    from . import config
    importlib.reload(config)
    from .config import Config
    globals()['Config'] = Config

def configure_translation_params():
    """Интерактивная настройка параметров перевода (потоки, задержка, повторы)"""
    print("\n--- Настройка параметров перевода ---")
    print(f"Текущие значения: workers={Config.TRANSLATION_WORKERS}, delay={Config.TRANSLATION_DELAY}, max_retries={Config.TRANSLATION_MAX_RETRIES}")
    try:
        workers = int(input("Число параллельных потоков перевода (напр. 8): ").strip())
        delay = float(input("Задержка перед запросом в потоке, в секундах (напр. 0.2): ").strip())
        max_retries = int(input("Число повторных попыток при ошибке (напр. 5): ").strip())
    except ValueError:
        print("Ошибка ввода. Параметры не изменены.")
        return

    update_translation_params(workers, delay, max_retries)
    print("Параметры перевода обновлены и сохранены в config.py")

def run_script(script_name, extra_args=None):
    """Запустить шаг пайплайна как модуль пакета (python -m mpdb.<шаг>)."""
    module = 'mpdb.' + Path(script_name).stem
    cmd = [sys.executable, '-u', '-m', module]
    if extra_args:
        cmd.extend(extra_args)
    # cwd = корень репозитория (mpdb/menu.py -> mpdb -> root)
    subprocess.run(cmd, cwd=str(Path(__file__).resolve().parent.parent))

def clear_translation_cache():
    cache_file = Config.OUTPUT_DIR / "translate_cache.json"
    if cache_file.exists():
        cache_file.unlink()
        print("🧹 Кэш перевода удалён.")
    else:
        print("📭 Кэш перевода не найден.")

def clear_bad_translations():
    """Удаляет из кэша записи, где перевод явно некачественный"""
    cache_file = Config.OUTPUT_DIR / "translate_cache.json"
    if not cache_file.exists():
        print("📭 Кэш перевода не найден.")
        return

    with open(cache_file, "r", encoding="utf-8") as f:
        cache = json.load(f)

    removed = 0
    keys_to_remove = []
    for orig, trans in cache.items():
        if trans.count('_') > 2 or trans == orig or len(trans.strip()) < 2:
            keys_to_remove.append(orig)

    for key in keys_to_remove:
        del cache[key]
        removed += 1

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

    print(f"🧹 Удалено {removed} некачественных переводов из кэша.")

def main():
    while True:
        print("\n" + "="*40)
        print("   MPDB (MITRE Parser Databases) - МЕНЮ")
        print("="*40)
        print("1. Скачать и распарсить базы (без перевода)")
        print("2. Связать данные (заполнить перекрёстные ссылки)")
        print("3. Перевести выбранные поля (Google Translate)")
        print("4. Автозаполнение пустых полей (связи/факты/STIX/шаблоны)")
        print("5. Запустить все этапы последовательно")
        print("6. Очистить кэш перевода")
        print("7. Очистить некачественные переводы из кэша")
        print("8. Настроить параметры перевода")
        print("0. Выход")
        choice = input("Ваш выбор: ").strip()

        if choice == "1":
            run_script("step1_parse.py")
        elif choice == "2":
            run_script("step2_link.py")
        elif choice == "3":
            run_script("translate_fields.py")
        elif choice == "4":
            # Автозаполнение работает на русском языке — запускать после перевода
            run_script("step4_autofill.py")
        elif choice == "5":
            print("Запуск всех этапов...")
            # Перевод идёт ДО автозаполнения (автозаполнение работает на русском)
            run_script("step1_parse.py")
            run_script("step2_link.py")
            run_script("translate_fields.py")
            run_script("step4_autofill.py")
        elif choice == "6":
            clear_translation_cache()
        elif choice == "7":
            clear_bad_translations()
        elif choice == "8":
            configure_translation_params()
        elif choice == "0":
            print("Выход.")
            break
        else:
            print("Неверный ввод, попробуйте снова.")

if __name__ == "__main__":
    main()
