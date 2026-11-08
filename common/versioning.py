"""
Утилиты сравнения версий ПО.

Формат спецификации уязвимого диапазона (affected_versions в базе CVE):
    {"lt": "2.4.50"}                      — версии ниже 2.4.50
    {"gte": "2.4.49", "lte": "2.4.50"}    — диапазон включительно
    {"eq": "2.3.4"}                       — точная версия
Ключи: lt, lte, gt, gte, eq (любой набор). Пустая спецификация = без ограничений.
"""

import re

_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}([a-zA-Z])?")


def parse_version(text):
    """
    Извлекает первую версию вида X.Y[.Z[.W]] из строки. Возвращает кортеж чисел или None.
    Буквенный суффикс (например, OpenSSL 1.1.1l) учитывается как дополнительный
    числовой компонент: 1.1.1l -> (1, 1, 1, 12), поэтому 1.1.1 < 1.1.1l.
    """
    if text is None:
        return None
    if isinstance(text, (tuple, list)):
        return tuple(int(x) for x in text)
    match = _VERSION_RE.search(str(text))
    if not match:
        return None
    core = match.group(0)[:-1] if match.group(1) else match.group(0)
    parts = [int(x) for x in core.split(".")]
    if match.group(1):
        parts.append(ord(match.group(1).lower()) - ord("a") + 1)
    return tuple(parts)


def compare_versions(v1, v2) -> int:
    """Сравнение версий: -1 если v1 < v2, 0 если равны, 1 если v1 > v2."""
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    if p1 is None and p2 is None:
        return 0
    if p1 is None:
        return -1
    if p2 is None:
        return 1
    n = max(len(p1), len(p2))
    a = p1 + (0,) * (n - len(p1))
    b = p2 + (0,) * (n - len(p2))
    return (a > b) - (a < b)


def version_in_range(version, spec: dict) -> bool:
    """
    Проверяет, попадает ли версия в диапазон spec.
    spec пустой/None -> True (ограничений нет).
    Версия неизвестна -> False.
    """
    if not spec:
        return True
    parsed = parse_version(version)
    if parsed is None:
        return False
    checks = (
        ("lt", lambda c: c < 0),
        ("lte", lambda c: c <= 0),
        ("gt", lambda c: c > 0),
        ("gte", lambda c: c >= 0),
        ("eq", lambda c: c == 0),
    )
    for key, accept in checks:
        bound = spec.get(key)
        if bound is None:
            continue
        if not accept(compare_versions(parsed, parse_version(bound))):
            return False
    return True
