#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
История изменений баз (дельта-обновления и changelog).

После каждого парсинга снимает «снимок» состава каждой базы (множество id) и
сравнивает его с предыдущим снимком: сколько записей добавилось/удалилось и
какие именно. Результат накапливается в output/db_history.json как changelog,
который показывается в GUI (что нового появилось между прогонами парсера).
"""
import json
from datetime import datetime
from pathlib import Path

from .config import Config

DB_FILES = {
    'capec': 'capec_database.json',
    'cwe': 'cwe_database.json',
    'attack': 'mitre_attack.json',
    'cve': 'cve_database.json',
}

DB_LABELS = {
    'capec': 'CAPEC',
    'cwe': 'CWE',
    'attack': 'MITRE ATT&CK',
    'cve': 'CVE',
}

MAX_CHANGELOG_ENTRIES = 50   # сколько записей changelog хранить
MAX_EXAMPLE_IDS = 100        # сколько id-примеров сохранять на каждое изменение


class DBHistory:
    """Снимки состава баз и журнал изменений между прогонами парсера."""

    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir) if output_dir else Config.OUTPUT_DIR
        self.history_file = self.output_dir / 'db_history.json'
        self.data = self._load()

    def _load(self) -> dict:
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                data.setdefault('snapshots', {})
                data.setdefault('changelog', [])
                return data
            except (json.JSONDecodeError, OSError):
                pass
        return {'snapshots': {}, 'changelog': []}

    def _save(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.history_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def _current_ids(self, db_key: str):
        """Множество id текущей базы или None, если файл отсутствует/повреждён."""
        filepath = self.output_dir / DB_FILES[db_key]
        if not filepath.exists():
            return None
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                records = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(records, list):
            return None
        return {r.get('id') for r in records if isinstance(r, dict) and r.get('id')}

    def snapshot(self) -> dict | None:
        """Снять снимок состава баз и записать дельту в changelog.

        Возвращает новую запись changelog либо None, если изменений нет.
        """
        snapshots = self.data['snapshots']
        changes = {}
        is_baseline = not snapshots  # самый первый снимок — базовая точка

        for db_key in DB_FILES:
            current = self._current_ids(db_key)
            if current is None:
                continue  # базы нет — прежний снимок не трогаем

            prev_ids = set(snapshots.get(db_key, {}).get('ids', []))
            added = sorted(current - prev_ids)
            removed = sorted(prev_ids - current)

            if added or removed or db_key not in snapshots:
                changes[db_key] = {
                    'label': DB_LABELS[db_key],
                    'total': len(current),
                    'added': len(added),
                    'removed': len(removed),
                    'added_ids': added[:MAX_EXAMPLE_IDS],
                    'removed_ids': removed[:MAX_EXAMPLE_IDS],
                }

            # обновляем снимок состава базы
            snapshots[db_key] = {'count': len(current), 'ids': sorted(current)}

        # Нет ни одной реальной дельты (и это не первый снимок) — changelog не растим
        meaningful = any(c['added'] or c['removed'] for c in changes.values())
        if not changes or (not meaningful and not is_baseline):
            self._save()
            return None

        entry = {
            'timestamp': datetime.now().isoformat(),
            'is_baseline': is_baseline,
            'changes': changes,
        }
        self.data['changelog'].insert(0, entry)
        self.data['changelog'] = self.data['changelog'][:MAX_CHANGELOG_ENTRIES]
        self._save()
        return entry

    def get_changelog(self, limit: int = 20) -> dict:
        """Последние записи журнала изменений для отображения в интерфейсе."""
        limit = max(1, min(int(limit or 20), MAX_CHANGELOG_ENTRIES))
        return {
            'changelog': self.data.get('changelog', [])[:limit],
            'snapshots': {
                k: {'count': v.get('count', 0)} for k, v in self.data.get('snapshots', {}).items()
            },
        }


def record_snapshot(output_dir=None) -> dict | None:
    """Удобная обёртка: снять снимок и вернуть запись changelog (или None)."""
    return DBHistory(output_dir).snapshot()


if __name__ == '__main__':
    entry = record_snapshot()
    if entry is None:
        print("📋 Изменений в составе баз нет — changelog не обновлён")
    else:
        kind = "Базовый снимок" if entry.get('is_baseline') else "Изменения"
        print(f"📋 {kind} записаны в changelog:")
        for db_key, ch in entry['changes'].items():
            print(f"  {ch['label']}: всего {ch['total']}, +{ch['added']} / -{ch['removed']}")
