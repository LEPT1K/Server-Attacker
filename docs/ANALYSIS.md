# ANALYSIS — рабочий журнал анализа Server-Attacker

> Файл создан 2026-11-25 в рамках Этапа 0 интеграции MPDB.
> Ранее `docs/ANALYSIS.md` в репозитории отсутствовал — см. «Отклонения и находки».

## Интеграция MPDB (Mitre Parser Databases)

Дизайн: «Дизайн интеграции MPDB в Server-Attacker.md» (утверждён 2026-11-25).

Суть: MPDB живёт внутри репозитория как пакет `mpdb/`. Комплекс вызывает только
`mpdb.analyze()`; MPDB не импортирует код комплекса. Два режима работы:

- медленный — обновление снапшотов и перестройка графового кэша
  (`mpdb/data/graph_cache.sqlite`); только по команде пользователя, никогда в горячем пути;
- быстрый — `analyze()` загружает кэш и обходит список CVE за миллисекунды.

Формула веса цепочки: `W = (a·CVSS_norm + b·EPSS + c·COMPLETENESS) × CONTEXT`,
коэффициенты — в `mpdb/weights.yaml` (стартовые: a=0.4, b=0.3, c=0.3).

Решённые вопросы (2026-11-25):

- EPSS — онлайн с FIRST при обновлении снапшотов (медленный режим), кэшируется в `mpdb/data/`;
- порог устаревания снапшотов — 30 дней;
- управление MPDB — существующий веб-интерфейс MPDB, запуск через
  `python -m mpdb.launcher`; нового экрана в комплексе не создаётся.

### Статус этапов

- [x] **Этап 0 — перенос** `LEPT1K/MPDB` → `mpdb/`: относительные импорты вместо
  sys.path-хаков, `OUTPUT_DIR = mpdb/data/snapshots`, заглушка `mpdb.analyze()`,
  smoke-тесты `tests/mpdb/`.
- [x] **Этап 1 — графовый кэш** `mpdb/graph.py` + `python -m mpdb.rebuild`:
  SQLite-кэш `mpdb/data/graph_cache.sqlite` (nodes/edges/epss/meta), обход
  цепочек CVE→CWE→CAPEC→ATT&CK с допуском неполных данных, EPSS bulk-фид FIRST
  (412 861 оценка на 2026-11-25), проверка устаревания (30 дней или смена
  снапшотов), `MAX_*_RECORDS = 0`. Тесты `tests/mpdb/test_graph.py` (8 шт.).
- [ ] Этап 2 — `analyzer.py` + `weights.yaml` (полная реализация analyze()).
- [ ] Этап 3 — раздел «Взвешенные цепочки атак» в HTML-отчёте (details/summary, без JS).
- [ ] Этап 4 — калибровка коэффициентов на исторических данных.

### Отклонения и находки при переносе

1. **`docs/ANALYSIS.md` отсутствовал в репозитории** — создан заново этим коммитом;
   прежний анализ архитектуры существовал только в чатах.
2. **Тестов парсеров не существовало** (ни в MPDB, ни в комплексе) — добавлены
   smoke-тесты `tests/mpdb/test_mpdb_smoke.py` как минимальный зелёный критерий Этапа 0.
3. **`tests/check_updates.py` (MPDB) содержал ошибку распаковки**: ожидал 3 значения,
   `_check_source_freshness` возвращает 4 — исправлено при переносе.
4. **`gui/run_gui.py` слушал `0.0.0.0`** — исправлено на `127.0.0.1` (локальный
   инструмент без авторизации не должен быть виден в LAN).
5. ~~**`Config.MAX_*_RECORDS` (CAPEC/CWE/ATT&CK = 1000, CVE = 4000)**~~ — в Этапе 1
   выставлено в 0 (все записи): усечённая база ломает цепочки, т.к. NVD ссылается
   на CWE вне первой тысячи.
6. **Не перенесены**: `MPDB.spec`, `build_exe.ps1` (сборка standalone exe), `docs/`
   MPDB — до стабилизации структуры. Готовые JSON-базы комплекса остаются в `databases/`.

### Находки Этапа 1 (реальные данные `databases/`)

7. **CVE ссылаются на CAPEC и ATT&CK напрямую** (в тестовых базах до 28 CAPEC на
   одну CVE), а связка CWE→CAPEC в данных разрежена. Поэтому обход цепочек в
   `graph.py` идёт «вперёд по порядку баз» (CVE→{CWE,CAPEC,ATT&CK}→…), а не по
   строгой схеме; полнота цепочки (0.25/0.5/1.0) вычисляется в Этапе 2.
8. **Веерный фактор связей**: лимит ветвления применяется к числу целей на шаг
   цепочки (`MAX_BRANCH_PER_DB = 10`), а не к сырому списку соседей — иначе
   CVE с 28 CAPEC теряла бы связь на CWE.
9. **`GraphCache.is_stale()` сверяет mtime снапшотов с той директорией, из которой
   кэш строился** (путь хранится в meta), а не с `Config.OUTPUT_DIR` — иначе кэш,
   собранный из нестандартного `--output-dir`, всегда выглядел бы устаревшим.
10. **EPSS-фид FIRST**: первая строка — комментарий с версией модели
    (`#model_version:...`), парсер её пропускает; битые строки пропускаются
    (ловятся KeyError/TypeError/ValueError).

### ТЗ для Этапа 2 (`analyzer.py` + `weights.yaml`) — исполнение в Kimi Code

Контракт `mpdb.analyze(payload: dict) -> dict` — единственная точка входа
комплекса, внутренности (graph.py, analyzer.py) снаружи не импортируются.

Вход:

```json
{
  "scan_id": "uuid",
  "target_context": {"os": "linux", "host_role": "web", "exposed_to_network": true},
  "findings": [{"cve": "CVE-…", "source": "nmap|trivy|nuclei", "component": "…", "service": "…", "port": 80}]
}
```

Выход:

```json
{
  "meta": {"mpdb_version": "…", "cache": {"built_at": "…", "age_days": 0.0},
           "status": "ok|no_cache|stale_cache"},
  "results": [{"cve": "…", "in_base": true, "epss": 0.0,
               "chains": [{"steps": [{"id": "…", "db": "…", "name": "…", "via": "…"}],
                           "completeness": 1.0, "weight": 0.0,
                           "breakdown": {"cvss_norm": 0.0, "epss": 0.0,
                                         "completeness": 1.0, "context": 1.0}}]}],
  "gaps": [{"cve": "…", "reason": "not_in_base"}]
}
```

Правила исполнения:

- только быстрый режим: `GraphCache.open()`, без сети и без разбора JSON;
  `FileNotFoundError` → `status=no_cache`, `results=[]` — отчёт всё равно строится;
- `is_stale()` → `status=stale_cache`, но анализ выполняется полностью;
- вес цепочки `W = (a·CVSS_norm + b·EPSS + c·COMPLETENESS) × CONTEXT`;
  `CVSS_norm = cvss/10`; `COMPLETENESS`: 1.0 — дошли до ATT&CK, 0.5 — до CAPEC,
  0.25 — только CWE или прямая CVE→ATT&CK; стартовые a=0.4, b=0.3, c=0.3 —
  всё в `weights.yaml`, правка формулы = правка YAML, код не трогаем;
- `CONTEXT` — произведение множителей из `weights.yaml` (`exposed_to_network`,
  совпадение `service`/`port` находки с полями `requires_service`/`requires_port`
  CVE и т.п.); нет данных — множитель 1.0;
- `results` сортируются по максимальному весу цепочки; топ-3 помечаются
  (`"top": true`) для подсветки в отчёте (Этап 3);
- неизвестная CVE → в `gaps` с причиной, исключений не бросаем;
- обход цепочек — только через `GraphCache.chains_from_cve()` (Этап 1),
  свою ходилку не писать;
- тесты `tests/mpdb/test_analyzer.py` на синтетических снапшотах
  (по образцу `test_graph.py`), `pytest tests/mpdb` должен остаться зелёным;
- после правок обновить этот файл: отметить Этап 2 и добавить находки.
