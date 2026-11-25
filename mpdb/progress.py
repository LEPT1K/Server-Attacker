#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Структурные события процессов для GUI.

Шаги парсера печатают события через emit(level, message, progress=...).
Когда скрипт запущен из GUI (переменная окружения MPDB_STRUCTURED=1), событие
выводится машиночитаемой строкой "MPDB-EVENT {json}", которую app.py разбирает
напрямую — без угадывания уровня по эмодзи. В обычном (консольном) режиме
печатается привычная человекочитаемая строка с иконкой.
"""
import os
import sys
import json

EVENT_PREFIX = "MPDB-EVENT "
_STRUCTURED = os.environ.get("MPDB_STRUCTURED") == "1"

LEVELS = ("info", "success", "warning", "error", "progress")

_ICONS = {
    "info": "ℹ️",
    "success": "✅",
    "warning": "⚠️",
    "error": "❌",
    "progress": "⏳",
}


def emit(level: str, message: str, progress=None):
    """Отправить структурное событие (или печать в консоль в обычном режиме)."""
    if level not in LEVELS:
        level = "info"
    if _STRUCTURED:
        payload = {"level": level, "msg": str(message)}
        if progress is not None:
            payload["progress"] = int(progress)
        print(EVENT_PREFIX + json.dumps(payload, ensure_ascii=False), flush=True)
    else:
        icon = _ICONS.get(level, "")
        line = f"{icon} {message}".strip() if icon else str(message)
        print(line, flush=True)


def info(message, progress=None):
    emit("info", message, progress)


def success(message, progress=None):
    emit("success", message, progress)


def warning(message, progress=None):
    emit("warning", message, progress)


def error(message, progress=None):
    emit("error", message, progress)


def progress(percent: int, message: str = ""):
    """Явное событие прогресса (0-100) — точнее, чем оценка по числу строк."""
    emit("progress", message, progress=percent)


def parse_event(line: str):
    """Разобрать строку события. Возвращает dict или None, если это не событие."""
    if not line.startswith(EVENT_PREFIX):
        return None
    try:
        data = json.loads(line[len(EVENT_PREFIX):])
        if isinstance(data, dict) and "level" in data:
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return None
