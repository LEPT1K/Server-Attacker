#!/usr/bin/env python3
"""Этап 2: Обогащение перекрёстными ссылками и мерами защиты"""
import sys
from pathlib import Path


from .config import Config
from .cross_linker import CrossLinker
from . import progress

def main():
    progress.info("Запуск связывания баз...", progress=10)
    linker = CrossLinker(Config.OUTPUT_DIR)
    if not linker.load_databases():
        progress.error("Не удалось загрузить базы")
        return
    stats = linker.run()
    progress.info(f"Статистика обогащения: {stats}", progress=80)
    linker.save_databases()
    progress.success("Этап 2 завершён. Связи заполнены.", progress=100)

if __name__ == "__main__":
    main()
