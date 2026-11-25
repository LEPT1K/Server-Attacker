#!/usr/bin/env python3
"""Этап 1: Скачивание и парсинг исходных данных (без перевода и связей)"""
import json
import sys
from pathlib import Path


from .config import Config
from .loader import DataLoader
from .translator import Translator
from .parsers.capec_parser import CAPECParser
from .parsers.cwe_parser import CWEParser
from .parsers.cve_parser import CVEParser
from .parsers.attack_parser import ATTCKParser
from . import progress

def main():
    Config.ENABLE_TRANSLATION = False
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    loader = DataLoader()
    translator = Translator(force_enable=False)  # без перевода

    # CAPEC
    progress.info("CAPEC: загрузка и разбор...", progress=10)
    content = loader.fetch_with_retry(Config.SOURCES["capec"])
    if content:
        data = CAPECParser(translator).parse(content)
        with open(Config.OUTPUT_DIR / "capec_database.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        progress.success(f"CAPEC: {len(data)} записей", progress=25)

    # CWE
    progress.info("CWE: загрузка и разбор...", progress=30)
    content = loader.fetch_zip_with_retry(Config.SOURCES["cwe"], target_extension=".xml")
    if content:
        data = CWEParser(translator).parse(content)
        with open(Config.OUTPUT_DIR / "cwe_database.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        progress.success(f"CWE: {len(data)} записей", progress=45)

    # CVE
    progress.info("CVE: загрузка и разбор...", progress=50)
    cve_data = loader.fetch_gz_json(Config.SOURCES["cve_latest"])
    if cve_data:
        data = CVEParser(translator).parse(cve_data)
        with open(Config.OUTPUT_DIR / "cve_database.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        progress.success(f"CVE: {len(data)} записей", progress=70)

    # ATT&CK
    progress.info("MITRE ATT&CK: загрузка и разбор...", progress=75)
    content = loader.fetch_with_retry(Config.SOURCES["attack_stix"])
    if content:
        data = ATTCKParser(translator).parse(content)
        with open(Config.OUTPUT_DIR / "mitre_attack.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        progress.success(f"ATT&CK: {len(data)} записей", progress=90)

    # Снимок состава баз для дельта-обновлений / changelog
    try:
        from .db_history import DBHistory
        entry = DBHistory().snapshot()
        if entry:
            kind = "базовый снимок" if entry.get('is_baseline') else "изменения"
            summary = ", ".join(
                f"{ch['label']} +{ch['added']}/-{ch['removed']}"
                for ch in entry['changes'].values()
            )
            progress.info(f"Changelog обновлён ({kind}): {summary}")
        else:
            progress.info("Состав баз не изменился — changelog без изменений")
    except Exception as e:
        progress.warning(f"Не удалось обновить changelog: {e}")

    progress.success("Этап 1 завершён. Файлы сохранены в output/", progress=100)

if __name__ == "__main__":
    main()
