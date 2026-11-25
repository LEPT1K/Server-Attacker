"""MPDB (MITRE Parser Databases) — пакет баз знаний MITRE в составе Server-Attacker.

Скачивает и парсит базы CAPEC / CWE / CVE / MITRE ATT&CK, связывает их
(CVE -> CWE -> CAPEC -> ATT&CK), переводит и автозаполняет поля.

Комплекс Server-Attacker взаимодействует с пакетом только через analyze()
(см. docs/ANALYSIS.md, раздел «Интеграция MPDB»).
"""

__version__ = "0.1.0"
__all__ = ["analyze"]


def analyze(payload: dict) -> dict:
    """Контракт analyze() для комплекса Server-Attacker.

    Этап 0: заглушка. Полная реализация — Этап 2 интеграции
    (analyzer.py + weights.yaml + graph_cache.sqlite).
    """
    return {
        "meta": {
            "mpdb_version": __version__,
            "snapshots": {},
            "status": "not_implemented",
        },
        "results": [],
    }
