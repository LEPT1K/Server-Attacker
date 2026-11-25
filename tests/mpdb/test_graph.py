#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тесты Этапа 1 интеграции: графовый кэш (mpdb/graph.py) и rebuild.

Работают на маленьких синтетических снапшотах во временной директории —
реальные базы не нужны, сеть не используется.
"""

import gzip
import json
import time
from pathlib import Path

import pytest

from mpdb.graph import GraphCache
from mpdb import rebuild as rebuild_mod


@pytest.fixture()
def snapshots(tmp_path: Path) -> Path:
    """Миниатюрные снапшоты с одной полной и одной оборванной цепочкой."""
    out = tmp_path / "snapshots"
    out.mkdir()

    cve = [
        {
            "id": "CVE-2099-0001",
            "description": "Тестовая уязвимость с полной цепочкой",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "related_cwe": ["CWE-79"],
            "related_capec": ["CAPEC-66"],
            "related_mitre": ["T1190"],
        },
        {
            "id": "CVE-2099-0002",
            "description": "Уязвимость с обрывом цепочки (только CWE)",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "related_cwe": ["CWE-999"],
        },
    ]
    cwe = [
        {
            "id": "CWE-79",
            "name": "Improper Neutralization of Input",
            "related_capec": ["CAPEC-66"],
        },
        {"id": "CWE-999", "name": "CWE без продолжения"},
    ]
    capec = [
        {
            "id": "CAPEC-66",
            "name": "SQL Injection",
            "related_cwe": ["CWE-79"],
            "related_mitre": ["T1190"],
        }
    ]
    attack = [
        {"id": "T1190", "name": "Exploit Public-Facing Application"}
    ]

    (out / "cve_database.json").write_text(json.dumps(cve), encoding="utf-8")
    (out / "cwe_database.json").write_text(json.dumps(cwe), encoding="utf-8")
    (out / "capec_database.json").write_text(json.dumps(capec), encoding="utf-8")
    (out / "mitre_attack.json").write_text(json.dumps(attack), encoding="utf-8")
    return out


def _build(snapshots: Path, cache_path: Path) -> GraphCache:
    cache = GraphCache.create(cache_path)
    cache.fill_from_snapshots(snapshots)
    return cache


def test_open_missing_cache_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        GraphCache.open(tmp_path / "нет_кэша.sqlite")


def test_build_and_query_graph(snapshots: Path, tmp_path: Path):
    cache = _build(snapshots, tmp_path / "graph.sqlite")
    with cache:
        stats = cache.stats()
        assert stats["nodes"] == {"cve": 2, "cwe": 2, "capec": 1, "attack": 1}
        # CVE-2099-0001: 3 исходящие; CVE-2099-0002: 1; CWE-79->CAPEC-66;
        # CAPEC-66->CWE-79 и CAPEC-66->T1190
        assert stats["edges"] == 7

        node = cache.node("CVE-2099-0001")
        assert node["cvss"] == 9.8
        assert node["severity"] == "CRITICAL"

        out_fields = {f: d for d, f in cache.neighbors("CVE-2099-0001", "out")}
        assert out_fields["related_cwe"] == "CWE-79"
        assert out_fields["related_mitre"] == "T1190"

        incoming = [s for s, _ in cache.neighbors("T1190", "in")]
        assert "CVE-2099-0001" in incoming and "CAPEC-66" in incoming


def test_chains_full_and_broken(snapshots: Path, tmp_path: Path):
    cache = _build(snapshots, tmp_path / "graph.sqlite")
    with cache:
        chains = cache.chains_from_cve("CVE-2099-0001")
        as_ids = [tuple(s["id"] for s in ch) for ch in chains]
        # Полная каноническая цепочка присутствует
        assert ("CVE-2099-0001", "CWE-79", "CAPEC-66", "T1190") in as_ids
        # И «укороченные» ветви тоже: реальные данные неполные,
        # оценку полноты считает анализатор (Этап 2)
        assert ("CVE-2099-0001", "CAPEC-66", "T1190") in as_ids
        assert ("CVE-2099-0001", "T1190") in as_ids

        full = next(ch for ch in chains if len(ch) == 4)
        assert full[0]["via"] is None
        assert full[1]["via"] == "related_cwe"
        assert full[2]["via"] == "related_capec"
        assert full[3]["via"] == "related_mitre"

        broken = cache.chains_from_cve("CVE-2099-0002")
        assert len(broken) == 1
        assert [s["id"] for s in broken[0]] == ["CVE-2099-0002", "CWE-999"]

        assert cache.chains_from_cve("CVE-0000-0000") == []


def test_epss_fill_and_lookup(snapshots: Path, tmp_path: Path):
    cache = _build(snapshots, tmp_path / "graph.sqlite")
    with cache:
        total = cache.fill_epss(iter([
            ("CVE-2099-0001", 0.94, 0.99),
            ("CVE-2099-0002", 0.05, 0.30),
        ]))
        assert total == 2
        assert cache.epss("CVE-2099-0001") == (0.94, 0.99)
        assert cache.epss("CVE-2099-0002") == (0.05, 0.30)
        assert cache.epss("CVE-2099-9999") is None


def test_staleness_fresh_and_changed_snapshot(snapshots: Path, tmp_path: Path):
    cache_path = tmp_path / "graph.sqlite"
    cache = _build(snapshots, cache_path)
    cache.close()

    cache = GraphCache.open(cache_path)  # open() проверяет версию схемы
    with cache:
        assert not cache.is_stale()
        assert cache.age_days() is not None and cache.age_days() < 1

        # Изменили снапшот — кэш должен «протухнуть»
        cve_file = snapshots / "cve_database.json"
        data = json.loads(cve_file.read_text(encoding="utf-8"))
        cve_file.write_text(json.dumps(data), encoding="utf-8")
        future = time.time() + 5
        import os
        os.utime(cve_file, (future, future))
        assert cache.is_stale()


def test_parse_epss_csv_skips_comment_and_bad_rows():
    payload = (
        "#model_version:v2025.01.01,score_date:2026-11-26T00:00:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2099-0001,0.94,0.99012\n"
        "CVE-2099-0002,0.05,0.30000\n"
        "BROKEN-ROW\n"
    ).encode()
    rows = list(rebuild_mod._parse_epss_csv(gzip.compress(payload)))
    assert rows == [
        ("CVE-2099-0001", 0.94, 0.99012),
        ("CVE-2099-0002", 0.05, 0.30000),
    ]


def test_rebuild_cli_no_epss(snapshots: Path, tmp_path: Path):
    cache_path = tmp_path / "graph.sqlite"
    rc = rebuild_mod.main([
        "--no-epss",
        "--output-dir", str(snapshots),
        "--cache", str(cache_path),
    ])
    assert rc == 0
    assert cache_path.exists()

    # --check по свежему кэшу: код 0 (актуален)
    assert rebuild_mod.main(["--check", "--cache", str(cache_path)]) == 0


def test_rebuild_cli_missing_snapshots(tmp_path: Path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = rebuild_mod.main([
        "--no-epss",
        "--output-dir", str(empty),
        "--cache", str(tmp_path / "graph.sqlite"),
    ])
    assert rc == 1
    # --check без кэша: код 1 и сообщение об ошибке
    assert rebuild_mod.main(["--check", "--cache", str(tmp_path / "нет.sqlite")]) == 1
    assert "не найден" in capsys.readouterr().out
