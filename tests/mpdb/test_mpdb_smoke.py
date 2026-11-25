"""Smoke-тесты пакета mpdb после переноса в Server-Attacker (Этап 0)."""

import sys
from pathlib import Path

# Корень репозитория (tests/mpdb/ -> tests/ -> root)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_analyze_stub_contract():
    """Заглушка analyze() соблюдает контракт: meta + results."""
    from mpdb import __version__, analyze

    result = analyze({"scan_id": "smoke", "target_context": {}, "findings": []})

    assert result["meta"]["status"] == "not_implemented"
    assert result["meta"]["mpdb_version"] == __version__
    assert result["results"] == []


def test_config_paths_inside_package():
    """Снапшоты лежат внутри пакета: mpdb/data/snapshots."""
    from mpdb.config import Config

    out = Path(Config.OUTPUT_DIR)
    assert out.name == "snapshots"
    assert out.parent.name == "data"
    assert out.parent.parent.name == "mpdb"


def test_parsers_importable():
    """Все парсеры импортируются как часть пакета (без sys.path-хаков)."""
    import mpdb.parsers.attack_parser
    import mpdb.parsers.capec_parser
    import mpdb.parsers.cve_parser
    import mpdb.parsers.cwe_parser
