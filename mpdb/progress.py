# src/progress.py
"""
Структурные события прогресса для шагов пайплайна.

Когда шаг запускается из GUI (переменная окружения MPDB_STRUCTURED=1),
функции emit()/info()/success()/... печатают строки вида:
    MPDB-EVENT {"level": "info", "message": "...", "progress": 42}
а gui/app.py разбирает их через parse_event() и шлёт в веб-интерфейс.
Без MPDB_STRUCTURED вывод остаётся обычным человекочитаемым.
"""

import os
import sys
import json

_PREFIX = "MPDB-EVENT "


def _structured() -> bool:
    return os.environ.get("MPDB_STRUCTURED") == "1"


def emit(level: str, message: str, progress: int = None) -> None:
    """Отправить структурное событие (или просто напечатать сообщение)."""
    if _structured():
        event = {"level": level, "message": message}
        if progress is not None:
            event["progress"] = progress
        print(_PREFIX + json.dumps(event, ensure_ascii=False), flush=True)
    else:
        icons = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "❌"}
        print(f"{icons.get(level, 'ℹ️')} {message}", flush=True)


def info(message: str, progress: int = None) -> None:
    emit("info", message, progress)


def success(message: str, progress: int = None) -> None:
    emit("success", message, progress)


def warning(message: str, progress: int = None) -> None:
    emit("warning", message, progress)


def error(message: str, progress: int = None) -> None:
    emit("error", message, progress)


def parse_event(line: str):
    """Разобрать строку вывода шага. Возвращает dict события или None."""
    if not line.startswith(_PREFIX):
        return None
    try:
        return json.loads(line[len(_PREFIX):])
    except json.JSONDecodeError:
        return None
