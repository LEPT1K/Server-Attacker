#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MITRE Data Parser - Main Entry Point"""

import json
import sys
from pathlib import Path


from .config import Config

def main():
    print(f"🚀 MPDB (MITRE Parser Databases) | Вывод: {Config.OUTPUT_DIR}")
    print(f"🌐 Перевод: {'✅ ВКЛЮЧЁН' if Config.ENABLE_TRANSLATION else '⚡ ОТКЛЮЧЁН (быстрый режим)'}")
    
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    try:
        from .translator import Translator
        from .loader import DataLoader
        from .parsers.capec_parser import CAPECParser
        from .parsers.cwe_parser import CWEParser
        from .parsers.cve_parser import CVEParser
        from .cross_linker import CrossLinker
        from .normalizer import DataNormalizer
        
        translator = Translator()
        loader = DataLoader()
        
        # === Обработка CAPEC ===
        print("\n🔹 Обработка CAPEC...")
        content = loader.fetch_with_retry(Config.SOURCES["capec"])
        if content:
            parser = CAPECParser(translator)
            data = parser.parse(content)
            output_file = Config.OUTPUT_DIR / "capec_database.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ Сохранено {len(data)} записей CAPEC в {output_file}")
        else:
            print("⚠️ Не удалось загрузить CAPEC")
        
        # === Обработка CWE ===
        print("\n🔹 Обработка CWE...")
        content = loader.fetch_zip_with_retry(Config.SOURCES["cwe"], target_extension=".xml")
        if content:
            parser = CWEParser(translator)
            data = parser.parse(content)
            output_file = Config.OUTPUT_DIR / "cwe_database.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ Сохранено {len(data)} записей CWE в {output_file}")
        else:
            print("⚠️ Не удалось загрузить CWE")
        
        # === Обработка CVE ===
        print("\n🔹 Обработка CVE...")
        from .parsers.cve_parser import CVEParser
        cve_data = loader.fetch_gz_json(Config.SOURCES["cve_latest"])
        if cve_data:
            parser = CVEParser(translator)
            data = parser.parse(cve_data)
            output_file = Config.OUTPUT_DIR / "cve_database.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ Сохранено {len(data)} записей CVE в {output_file}")
        else:
            print("⚠️ Не удалось загрузить CVE")

                # === Обработка MITRE ATT&CK ===
        print("\n🔹 Обработка MITRE ATT&CK...")
        from .parsers.attack_parser import ATTCKParser
        content = loader.fetch_with_retry(Config.SOURCES["attack_stix"])
        if content:
            parser = ATTCKParser(translator)
            data = parser.parse(content)
            output_file = Config.OUTPUT_DIR / "mitre_attack.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ Сохранено {len(data)} записей ATT&CK в {output_file}")
        else:
            print("⚠️ Не удалось загрузить MITRE ATT&CK")

        # 2. Нормализация СРАЗУ после парсинга
        print("\n🧹 Нормализация данных...")
        for filename in ["capec_database.json", "cwe_database.json", "cve_database.json", "mitre_attack.json"]:
            filepath = Config.OUTPUT_DIR / filename
            if filepath.exists():
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                clean_data = DataNormalizer.process_database(data)
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(clean_data, f, ensure_ascii=False, indent=2)
                print(f"  ✅ {filename}: {len(clean_data)} записей очищено")

        # 3. Cross-Link
        linker = CrossLinker(Config.OUTPUT_DIR)
        if linker.load_databases():
            stats = linker.run()
            print("📊 Статистика обогащения:", stats)
            linker.save_databases()
            
    except ImportError as e:
        print(f"❌ Ошибка импорта: {e}")
        print("💡 Убедитесь: pip install -r requirements.txt")
        return
    except Exception as e:
        print(f"❌ Ошибка выполнения: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n🎉 Готово! Проверьте папку output/")
    

if __name__ == "__main__":
    main()
