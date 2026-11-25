#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Графовый кэш MPDB (SQLite) — быстрый режим интеграции.

Медленный режим (`python -m mpdb.rebuild`) строит этот кэш из снапшотов
`mpdb/data/snapshots/*.json` и EPSS-фида FIRST. Быстрый режим (analyze(),
Этап 2) только открывает кэш и обходит цепочки — без сети и без разбора JSON.

Схема:
- meta(key, value)          — дата сборки, отпечатки снапшотов, версии
- nodes(id, db, name, cvss, severity)
- edges(src, dst, field)    — направленные связи из полей related_*
- epss(cve, score, percentile)
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .config import Config

# Поля перекрёстных ссылок и базы, на которые они указывают (как в link_graph.py)
LINK_FIELDS = {
    "related_capec": "capec",
    "related_cwe": "cwe",
    "related_mitre": "attack",
    "related_cve": "cve",
}

DB_FILES = {
    "capec": "capec_database.json",
    "cwe": "cwe_database.json",
    "attack": "mitre_attack.json",
    "cve": "cve_database.json",
}

# Канонический порядок цепочки атаки: CVE -> CWE -> CAPEC -> ATT&CK
CHAIN_ORDER = ["cve", "cwe", "capec", "attack"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS nodes (
    id       TEXT PRIMARY KEY,
    db       TEXT NOT NULL,
    name     TEXT,
    cvss     REAL,
    severity TEXT
);
CREATE TABLE IF NOT EXISTS edges (
    src   TEXT NOT NULL,
    dst   TEXT NOT NULL,
    field TEXT NOT NULL,
    PRIMARY KEY (src, dst, field)
);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE TABLE IF NOT EXISTS epss (
    cve        TEXT PRIMARY KEY,
    score      REAL,
    percentile REAL
);
"""

SCHEMA_VERSION = "1"

# Ограничения обхода: защита от комбинаторного взрыва на «хабовых» записях
DEFAULT_MAX_CHAINS = 10
MAX_BRANCH_PER_DB = 10  # ветвей на один шаг цепочки (CVE может ссылаться на 20+ CAPEC)


def _db_for_id(node_id: str) -> Optional[str]:
    """Определить базу узла по формату id (CAPEC-xxx, CWE-xxx, CVE-xxxx-*, Txxxx)."""
    if node_id.startswith("CAPEC-"):
        return "capec"
    if node_id.startswith("CWE-"):
        return "cwe"
    if node_id.startswith("CVE-"):
        return "cve"
    if node_id.startswith("T"):
        return "attack"
    return None


class GraphCache:
    """Постоянный граф связей + EPSS. Открывается за миллисекунды."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row

    # -------------------- жизненный цикл --------------------

    @classmethod
    def open(cls, path: Optional[Path] = None) -> "GraphCache":
        """Открыть существующий кэш. FileNotFoundError, если кэш ещё не построен."""
        path = Path(path) if path else Config.GRAPH_CACHE_FILE
        if not path.exists():
            raise FileNotFoundError(
                f"Графовый кэш не найден: {path}. "
                f"Запустите медленный режим: python -m mpdb.rebuild"
            )
        cache = cls(path)
        if cache.meta("schema_version") != SCHEMA_VERSION:
            cache.close()
            raise RuntimeError(
                f"Несовместимая версия кэша в {path}. "
                f"Перестройте его: python -m mpdb.rebuild"
            )
        return cache

    @classmethod
    def create(cls, path: Path) -> "GraphCache":
        """Создать (пересоздать) пустой кэш по указанному пути."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        cache = cls(path)
        cache._conn.executescript(SCHEMA)
        cache.set_meta("schema_version", SCHEMA_VERSION)
        return cache

    def close(self):
        self._conn.close()

    def __enter__(self) -> "GraphCache":
        return self

    def __exit__(self, *exc):
        self.close()

    # -------------------- метаданные --------------------

    def meta(self, key: str, default=None):
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value):
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, str(value)),
        )

    def built_at(self) -> Optional[datetime]:
        raw = self.meta("built_at")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    def age_days(self) -> Optional[float]:
        built = self.built_at()
        if built is None:
            return None
        return (datetime.now(timezone.utc) - built).total_seconds() / 86400

    def snapshots_changed(self, output_dir: Optional[Path] = None) -> bool:
        """True, если снапшоты на диске изменились с момента сборки кэша."""
        if output_dir is None:
            # По умолчанию сверяемся с той директорией, из которой строили кэш
            saved_dir = self.meta("output_dir")
            output_dir = Path(saved_dir) if saved_dir else Config.OUTPUT_DIR
        output_dir = Path(output_dir)
        raw = self.meta("snapshot_mtimes", "{}")
        try:
            saved = json.loads(raw)
        except json.JSONDecodeError:
            return True
        for filename in DB_FILES.values():
            filepath = output_dir / filename
            mtime = filepath.stat().st_mtime if filepath.exists() else 0
            if saved.get(filename) != mtime:
                return True
        return False

    def is_stale(self, max_age_days: int = Config.SNAPSHOT_MAX_AGE_DAYS) -> bool:
        """Кэш устарел: старше порога (30 дней) или снапшоты изменились."""
        age = self.age_days()
        if age is None or age > max_age_days:
            return True
        return self.snapshots_changed()

    def stats(self) -> dict:
        """Сводка содержимого кэша (для --check и meta analyze())."""
        nodes = dict(
            self._conn.execute("SELECT db, COUNT(*) AS c FROM nodes GROUP BY db")
        )
        edges = self._conn.execute("SELECT COUNT(*) AS c FROM edges").fetchone()["c"]
        epss = self._conn.execute("SELECT COUNT(*) AS c FROM epss").fetchone()["c"]
        return {
            "built_at": self.meta("built_at"),
            "age_days": round(self.age_days(), 1) if self.age_days() is not None else None,
            "nodes": nodes,
            "edges": edges,
            "epss_scores": epss,
        }

    # -------------------- запросы (быстрый режим) --------------------

    def node(self, node_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT id, db, name, cvss, severity FROM nodes WHERE id = ?",
            (node_id,),
        ).fetchone()
        return dict(row) if row else None

    def neighbors(self, node_id: str, direction: str = "out") -> List[Tuple[str, str]]:
        """Соседи узла: список (id, поле связи). direction = out|in."""
        if direction == "out":
            rows = self._conn.execute(
                "SELECT dst, field FROM edges WHERE src = ?", (node_id,)
            )
            return [(r["dst"], r["field"]) for r in rows]
        rows = self._conn.execute(
            "SELECT src, field FROM edges WHERE dst = ?", (node_id,)
        )
        return [(r["src"], r["field"]) for r in rows]

    def epss(self, cve_id: str) -> Optional[Tuple[float, float]]:
        """(score, percentile) для CVE или None, если оценки нет."""
        row = self._conn.execute(
            "SELECT score, percentile FROM epss WHERE cve = ?", (cve_id,)
        ).fetchone()
        return (row["score"], row["percentile"]) if row else None

    def chains_from_cve(
        self, cve_id: str, max_chains: int = DEFAULT_MAX_CHAINS
    ) -> List[List[dict]]:
        """
        Цепочки от CVE в сторону ATT&CK по каноническому порядку баз
        CVE -> CWE -> CAPEC -> ATT&CK (DFS).

        Шаг может идти на ЛЮБУЮ более позднюю базу порядка: реальные данные
        неполные, и CVE часто ссылается на CAPEC/ATT&CK напрямую. Полноту
        цепочки (0.25/0.5/1.0) оценивает анализатор (Этап 2), здесь же
        возвращаются и оборванные цепочки.

        Цепочка — список шагов {"id", "db", "name", "via"} (via — поле связи,
        по которому пришли; у первого шага via=None).
        """
        if self.node(cve_id) is None:
            return []

        chains: List[List[dict]] = []
        # (текущий id, индекс базы в CHAIN_ORDER, путь, посещённые)
        stack: List[Tuple[str, int, List[dict], set]] = [
            (cve_id, 0, [self._step(cve_id, None)], {cve_id})
        ]

        while stack and len(chains) < max_chains:
            node_id, order_idx, path, visited = stack.pop()
            advanced = False
            per_db: Dict[str, int] = {}
            for dst, field in self.neighbors(node_id, "out"):
                dst_db = _db_for_id(dst)
                if dst_db is None or dst in visited:
                    continue
                try:
                    dst_idx = CHAIN_ORDER.index(dst_db)
                except ValueError:
                    continue
                if dst_idx <= order_idx:  # только вперёд по порядку баз
                    continue
                if per_db.get(dst_db, 0) >= MAX_BRANCH_PER_DB:
                    continue
                if self.node(dst) is None:
                    continue
                per_db[dst_db] = per_db.get(dst_db, 0) + 1
                advanced = True
                stack.append(
                    (dst, dst_idx, path + [self._step(dst, field)], visited | {dst})
                )
            if not advanced:
                # Конец цепочки: дошли до ATT&CK или дальше связей нет
                chains.append(path)

        return chains

    def _step(self, node_id: str, via: Optional[str]) -> dict:
        node = self.node(node_id) or {"id": node_id, "db": _db_for_id(node_id), "name": node_id}
        return {
            "id": node["id"],
            "db": node.get("db"),
            "name": node.get("name") or node["id"],
            "via": via,
        }

    # -------------------- построение (медленный режим) --------------------

    def fill_from_snapshots(
        self, output_dir: Optional[Path] = None, progress_cb=None
    ) -> Dict[str, int]:
        """Заполнить nodes/edges из снапшотов output/*.json. Возвращает счётчики."""
        output_dir = Path(output_dir) if output_dir else Config.OUTPUT_DIR
        counts: Dict[str, int] = {}
        mtimes: Dict[str, float] = {}

        with self._conn:  # одна транзакция на всю заливку
            for db_key, filename in DB_FILES.items():
                filepath = output_dir / filename
                mtimes[filename] = filepath.stat().st_mtime if filepath.exists() else 0
                if not filepath.exists():
                    counts[db_key] = 0
                    continue

                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
                if not isinstance(records, list):
                    counts[db_key] = 0
                    continue

                node_rows = []
                edge_rows = []
                for record in records:
                    node_id = record.get("id")
                    if not node_id:
                        continue
                    node_rows.append((
                        node_id,
                        db_key,
                        record.get("name", node_id),
                        _as_float(record.get("cvss_score")),
                        record.get("severity"),
                    ))
                    for field in LINK_FIELDS:
                        targets = record.get(field)
                        if not isinstance(targets, list):
                            continue
                        for target_id in targets:
                            if target_id:
                                edge_rows.append((node_id, target_id, field))

                self._conn.executemany(
                    "INSERT OR REPLACE INTO nodes (id, db, name, cvss, severity)"
                    " VALUES (?, ?, ?, ?, ?)",
                    node_rows,
                )
                self._conn.executemany(
                    "INSERT OR IGNORE INTO edges (src, dst, field) VALUES (?, ?, ?)",
                    edge_rows,
                )
                counts[db_key] = len(node_rows)
                if progress_cb:
                    progress_cb(db_key, len(node_rows))

            self.set_meta("built_at", datetime.now(timezone.utc).isoformat())
            self.set_meta("output_dir", str(output_dir))
            self.set_meta("snapshot_mtimes", json.dumps(mtimes))
        return counts

    def fill_epss(
        self, rows: Iterator[Tuple[str, float, float]], progress_cb=None
    ) -> int:
        """Залить EPSS-оценки (итератор кортежей cve, score, percentile)."""
        total = 0
        chunk: List[Tuple[str, float, float]] = []
        with self._conn:
            self._conn.execute("DELETE FROM epss")
            for row in rows:
                chunk.append(row)
                if len(chunk) >= 5000:
                    self._conn.executemany(
                        "INSERT OR REPLACE INTO epss (cve, score, percentile)"
                        " VALUES (?, ?, ?)",
                        chunk,
                    )
                    total += len(chunk)
                    if progress_cb:
                        progress_cb(total)
                    chunk = []
            if chunk:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO epss (cve, score, percentile)"
                    " VALUES (?, ?, ?)",
                    chunk,
                )
                total += len(chunk)
        self.set_meta("epss_updated_at", datetime.now(timezone.utc).isoformat())
        if progress_cb:
            progress_cb(total)
        return total


def _as_float(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
