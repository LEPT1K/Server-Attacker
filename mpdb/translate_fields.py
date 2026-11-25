#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для выборочного перевода полей в JSON-файлах MPDB.
Использует онлайн-переводчик (Google Translate) для быстрой работы.
Запускать после генерации английских JSON.
"""
import json
from pathlib import Path
from .config import Config
from .translator import Translator
from . import progress

# Поля, которые нужно перевести в каждом типе файла
FIELDS_TO_TRANSLATE = {
    "capec_database.json": ["name", "description", "severity", "prerequisites", "mitigations"],
    "cwe_database.json": ["name", "description", "mitigation", "category", "detection_methods"],
    "cve_database.json": ["description", "severity", "mitigations", "affected_software", "attack_type", "requires_service"],
    "mitre_attack.json": ["name", "description", "requires_service", "mitigations", "detection", "tactic"]
}

def collect_texts(data: list, fields: list):
    """Собирает все строки для перевода вместе с указателями для обратной записи"""
    texts = []
    pointers = []  # (item_idx, field, list_idx или None)
    for idx, item in enumerate(data):
        for field in fields:
            if field not in item:
                continue
            value = item[field]
            if isinstance(value, str):
                texts.append(value)
                pointers.append((idx, field, None))
            elif isinstance(value, list):
                for li, sub in enumerate(value):
                    if isinstance(sub, str):
                        texts.append(sub)
                        pointers.append((idx, field, li))
    return texts, pointers

def apply_translations(data: list, pointers: list, originals: list, translated: list) -> int:
    """Записывает переведённые строки обратно в данные, возвращает число изменённых элементов"""
    updated_items = set()
    for (idx, field, li), original, new_value in zip(pointers, originals, translated):
        if new_value == original:
            continue
        if li is None:
            data[idx][field] = new_value
        else:
            data[idx][field][li] = new_value
        updated_items.add(idx)
    return len(updated_items)

def translate_file(filepath: Path, fields: list, translator: Translator, file_progress=None):
    progress.info(f"Обработка {filepath.name}...", progress=file_progress)
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    texts, pointers = collect_texts(data, fields)
    unique_count = len(set(t.strip() for t in texts if isinstance(t, str) and t.strip()))
    progress.info(f"  {filepath.name}: найдено {len(texts)} строк ({unique_count} уникальных) для перевода")

    translated = translator.translate_batch(texts)
    updated = apply_translations(data, pointers, texts, translated)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    progress.success(f"{filepath.name}: переведено элементов — {updated} из {len(data)}")

def main():
    progress.info("Выборочный перевод полей JSON-файлов (онлайн-режим)", progress=5)
    translator = Translator(force_enable=True)   # принудительное включение перевода
    if not translator.enabled:
        progress.error("Не удалось включить переводчик")
        return

    output_dir = Config.OUTPUT_DIR
    files = list(FIELDS_TO_TRANSLATE.items())
    for i, (filename, fields) in enumerate(files):
        filepath = output_dir / filename
        # равномерный прогресс по числу файлов (5 → 95)
        file_progress = 5 + int((i / max(1, len(files))) * 90)
        if filepath.exists():
            translate_file(filepath, fields, translator, file_progress=file_progress)
        else:
            progress.warning(f"Файл {filename} не найден, пропущен")

    translator._save_cache()
    progress.success("Готово! Все указанные поля переведены.", progress=100)

if __name__ == "__main__":
    main()
