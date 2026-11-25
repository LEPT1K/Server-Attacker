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
