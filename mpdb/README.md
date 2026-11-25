# MPDB — пакет в составе Server-Attacker

Это MPDB (MITRE Parser Databases), перенесённый в монорепозиторий
Server-Attacker как пакет `mpdb/` (Этап 0 интеграции, см. `docs/ANALYSIS.md`).
Полное описание пайплайна и GUI — в исходном репозитории `LEPT1K/MPDB`.

Запуск из корня репозитория:

- `python -m mpdb.run_all` — полный пайплайн (парсинг → связывание → перевод → автозаполнение)
- `python -m mpdb.menu` — консольное меню
- `python -m mpdb.launcher` — веб-интерфейс (открывает браузер, только 127.0.0.1)
- `pytest tests/mpdb` — тесты пакета

Данные и снапшоты: `mpdb/data/snapshots/` (каталог `data` в .gitignore).
Контракт для комплекса: `mpdb.analyze()` (пока заглушка, реализация — Этап 2).

Графовый кэш (Этап 1, медленный режим — запускать после обновления снапшотов,
раз в ~30 дней):

- `python -m mpdb.rebuild` — построить `mpdb/data/graph_cache.sqlite`
  из снапшотов + скачать EPSS-оценки с FIRST;
- `python -m mpdb.rebuild --no-epss` — только граф, без сети;
- `python -m mpdb.rebuild --check` — состояние кэша (актуален/устарел).

Быстрый режим (`analyze()`) читает только кэш: сеть и разбор JSON ему не нужны.
