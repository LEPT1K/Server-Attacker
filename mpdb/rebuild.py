#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Медленный режим MPDB: перестройка графового кэша.

  python -m mpdb.rebuild              # граф из снапшотов + EPSS с FIRST
  python -m mpdb.rebuild --no-epss    # только граф (без сети)
  python -m mpdb.rebuild --check      # состояние кэша, ничего не строит
  python -m mpdb.rebuild --output-dir PATH   # нестандартные снапшоты

Запускается при обновлении снапшотов (раз в ~30 дней) из веб-интерфейса MPDB
или вручную. Быстрый режим (analyze()) сети не касается — читает только
построенный здесь кэш mpdb/data/graph_cache.sqlite.
"""

import argparse
import csv
import gzip
import io
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Tuple

from .config import Config
from .graph import DB_FILES, GraphCache
from . import progress


def _parse_epss_csv(raw: bytes) -> Iterator[Tuple[str, float, float]]:
    """Разобрать epss_scores-current.csv.gz: (cve, score, percentile).

    Первая строка — комментарий с версией модели (#model_version:...),
    далее заголовок cve,epss,percentile.
    """
    with gzip.open(io.BytesIO(raw), "rt", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            reader = csv.DictReader(f, fieldnames=line.strip().split(","))
            for row in reader:
                try:
                    yield (
                        row["cve"].strip(),
                        float(row["epss"]),
                        float(row["percentile"]),
                    )
                except (KeyError, TypeError, ValueError, AttributeError):
                    continue
            return


def fetch_epss_scores() -> Iterator[Tuple[str, float, float]]:
    """Скачать bulk-фид EPSS с FIRST и отдать строки (с повторами)."""
    import requests

    last_error = None
    for attempt in range(Config.RETRY_ATTEMPTS):
        try:
            response = requests.get(Config.EPSS_URL, timeout=Config.REQUEST_TIMEOUT * 4)
            response.raise_for_status()
            return _parse_epss_csv(response.content)
        except Exception as e:  # сеть/архив — повторяем как в loader.py
            last_error = e
            progress.warning(
                f"EPSS: попытка {attempt + 1}/{Config.RETRY_ATTEMPTS} не удалась: {e}"
            )
            import time

            time.sleep(Config.RETRY_DELAY)
    raise RuntimeError(f"Не удалось скачать EPSS-фид FIRST: {last_error}")


def rebuild(output_dir: Path, cache_path: Path, with_epss: bool = True) -> int:
    """Перестроить кэш. Возвращает код выхода (0 — успех)."""
    missing = [f for f in DB_FILES.values() if not (output_dir / f).exists()]
    if missing:
        progress.error(
            f"В {output_dir} нет снапшотов: {', '.join(missing)}. "
            f"Сначала обновите базы (веб-интерфейс MPDB или python -m mpdb.run_all)."
        )
        return 1

    progress.info(f"Строю графовый кэш из {output_dir}")
    cache = GraphCache.create(cache_path)
    try:
        counts = cache.fill_from_snapshots(
            output_dir,
            progress_cb=lambda db, n: progress.info(f"  {db}: {n} записей"),
        )
        if sum(counts.values()) == 0:
            progress.error("Снапшоты пусты — кэш не построен.")
            return 1
        progress.success(
            f"Граф построен: {sum(counts.values())} узлов, "
            f"{cache.stats()['edges']} связей"
        )

        if with_epss:
            progress.info(f"Скачиваю EPSS-фид FIRST: {Config.EPSS_URL}")
            try:
                total = cache.fill_epss(fetch_epss_scores())
                progress.success(f"EPSS: {total} оценок загружено в кэш")
            except RuntimeError as e:
                # Граф уже построен — EPSS можно добить позже тем же вызовом
                progress.warning(f"{e}. Кэш сохранён без EPSS.")
        else:
            progress.info("EPSS пропущен (--no-epss)")
    finally:
        cache.close()

    progress.success(f"Кэш готов: {cache_path}")
    return 0


def check(cache_path: Path) -> int:
    """Показать состояние кэша. Код выхода 1 = кэша нет или он устарел."""
    try:
        cache = GraphCache.open(cache_path)
    except (FileNotFoundError, RuntimeError) as e:
        progress.error(str(e))
        return 1

    with cache:
        stats = cache.stats()
        stale = cache.is_stale()
        print(f"Кэш:       {cache_path}")
        print(f"Собран:    {stats['built_at']} ({stats['age_days']} дн. назад)")
        print(f"Узлы:      {stats['nodes']}")
        print(f"Связи:     {stats['edges']}")
        print(f"EPSS:      {stats['epss_scores']} оценок"
              f" (обновлено {cache.meta('epss_updated_at', '—')})")
        print(f"Статус:    {'УСТАРЕЛ — нужен python -m mpdb.rebuild' if stale else 'актуален'}")
    return 1 if stale else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m mpdb.rebuild",
        description="Медленный режим MPDB: графовый кэш из снапшотов + EPSS.",
    )
    parser.add_argument(
        "--no-epss", action="store_true",
        help="не скачивать EPSS с FIRST (только граф)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="показать состояние кэша, ничего не строя",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Config.OUTPUT_DIR,
        help="директория со снапшотами (по умолчанию data/snapshots)",
    )
    parser.add_argument(
        "--cache", type=Path, default=Config.GRAPH_CACHE_FILE,
        help="путь к файлу кэша (по умолчанию data/graph_cache.sqlite)",
    )
    args = parser.parse_args(argv)

    if args.check:
        return check(args.cache)
    return rebuild(args.output_dir, args.cache, with_epss=not args.no_epss)


if __name__ == "__main__":
    sys.exit(main())
