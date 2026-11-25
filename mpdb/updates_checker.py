#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модуль для получения последних обновлений из MITRE базы и проверки актуальности данных
"""

import json
import requests
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import List, Optional, Tuple
import time

from .config import Config


class UpdatesChecker:
    """Проверка обновлений в MITRE базах данных и кэширование результатов"""

    # Официальные источники MITRE и NVD.
    # check_url — тот же файл, который скачивает парсер (см. src/config.py),
    # поэтому статус ленты соответствует реальному источнику данных.
    SOURCES = {
        'capec': {
            'url': 'https://capec.mitre.org/',
            'name': 'CAPEC',
            'description': 'Common Attack Pattern Enumeration and Classification',
            'check_url': 'https://capec.mitre.org/data/xml/capec_latest.xml'
        },
        'cwe': {
            'url': 'https://cwe.mitre.org/',
            'name': 'CWE',
            'description': 'Common Weakness Enumeration',
            'check_url': 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'
        },
        'attack': {
            'url': 'https://attack.mitre.org/',
            'name': 'MITRE ATT&CK',
            'description': 'Adversarial Tactics, Techniques & Common Knowledge',
            'check_url': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
            # raw.githubusercontent.com не отдаёт Last-Modified — дату берём из последнего коммита
            'date_api_url': 'https://api.github.com/repos/mitre-attack/attack-stix-data/commits?path=enterprise-attack/enterprise-attack.json&per_page=1'
        },
        'cve': {
            'url': 'https://nvd.nist.gov/',
            'name': 'CVE',
            'description': 'Common Vulnerabilities and Exposures (NVD)',
            'check_url': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz'
        }
    }

    # Соответствие источника локальному файлу БД в output/
    DB_FILES = {
        'capec': 'capec_database.json',
        'cwe': 'cwe_database.json',
        'attack': 'mitre_attack.json',
        'cve': 'cve_database.json'
    }

    REQUEST_HEADERS = {'User-Agent': 'MPDB-UpdateChecker/1.0'}

    # Кэш обновлений
    CACHE_FILE = Config.OUTPUT_DIR / 'updates_cache.json'
    CACHE_LIFETIME = 3600  # 1 час в секундах

    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir) if output_dir else Config.OUTPUT_DIR
        self.cache = self._load_cache()

    def _load_cache(self) -> dict:
        """Загрузить кэш обновлений"""
        if self.CACHE_FILE.exists():
            try:
                with open(self.CACHE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {'updates': [], 'last_checked': None}
        return {'updates': [], 'last_checked': None}

    def _save_cache(self, data: dict):
        """Сохранить кэш обновлений"""
        self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(self.CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _local_db_path(self, source_key: str) -> Optional[Path]:
        """Путь к локальному файлу БД для источника"""
        filename = self.DB_FILES.get(source_key)
        return self.output_dir / filename if filename else None

    def _local_db_mtimes(self) -> dict:
        """Время изменения локальных файлов БД (для определения устаревания кэша)"""
        mtimes = {}
        for source_key in self.DB_FILES:
            path = self._local_db_path(source_key)
            mtimes[source_key] = path.stat().st_mtime if path and path.exists() else 0
        return mtimes

    def _load_local_db(self, db_name: str) -> dict:
        """Загрузить локальную БД из output/"""
        filepath = self._local_db_path(db_name)
        if filepath and filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return None
        return None

    @staticmethod
    def _parse_http_date(value: Optional[str]) -> Optional[datetime]:
        """Разобрать дату из заголовка Last-Modified (RFC 2822)"""
        if not value:
            return None
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except (TypeError, ValueError):
            return None

    def _fetch_last_commit_date(self, api_url: str, timeout=10) -> Optional[datetime]:
        """Дата последнего коммита файла через GitHub API"""
        try:
            headers = dict(self.REQUEST_HEADERS, Accept='application/vnd.github+json')
            response = requests.get(api_url, timeout=timeout, headers=headers)
            if response.status_code != 200:
                return None
            commits = response.json()
            date_str = commits[0]['commit']['committer']['date']
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return None

    def _check_source_freshness(self, source_key: str, timeout=10) -> Tuple[bool, bool, str, dict]:
        """
        Проверить доступность источника и наличие обновлений.
        Источник считается обновлённым, если его дата изменения новее даты
        последнего парсинга локальной БД.
        Returns: (available, has_updates, info, metadata)
        """
        source = self.SOURCES.get(source_key)
        if not source:
            return False, False, f"Неизвестный источник: {source_key}", {}

        check_url = source.get('check_url', source['url'])

        try:
            # HEAD запрос — получаем метаданные без скачивания файла
            response = requests.head(check_url, timeout=timeout, allow_redirects=True,
                                     headers=self.REQUEST_HEADERS)
            if response.status_code != 200:
                # Если HEAD не поддерживается, пробуем GET с потоковой передачей
                response = requests.get(check_url, timeout=timeout, stream=True,
                                        headers=self.REQUEST_HEADERS)
                response.close()
            if response.status_code != 200:
                return False, False, f"{source['name']}: источник недоступен (HTTP {response.status_code})", {}
        except requests.exceptions.Timeout:
            return False, False, f"{source['name']}: таймаут при проверке источника", {}
        except requests.exceptions.RequestException as e:
            return False, False, f"{source['name']}: ошибка доступа ({e})", {}

        remote_dt = self._parse_http_date(response.headers.get('Last-Modified'))
        if remote_dt is None and source.get('date_api_url'):
            remote_dt = self._fetch_last_commit_date(source['date_api_url'], timeout)

        content_length = response.headers.get('Content-Length')
        try:
            content_length = int(content_length) if content_length else None
        except (TypeError, ValueError):
            content_length = None

        metadata = {
            'content_length': content_length,
            'last_modified': remote_dt.isoformat() if remote_dt else None,
            'checked_at': datetime.now().isoformat()
        }

        # Локальная БД старше даты обновления источника — есть обновления
        has_updates = False
        local_path = self._local_db_path(source_key)
        if local_path and local_path.exists() and remote_dt is not None:
            local_dt = datetime.fromtimestamp(local_path.stat().st_mtime, tz=timezone.utc)
            has_updates = local_dt < remote_dt

        info = f"{source['name']}: источник доступен"
        if remote_dt:
            info += f", последнее обновление {remote_dt.strftime('%d.%m.%Y')}"
        return True, has_updates, info, metadata

    def _fetch_recent_updates(self) -> List[dict]:
        """Получить список недавних обновлений (имитация RSS)"""
        updates = []

        for source_key, source_info in self.SOURCES.items():
            available, has_updates, info, metadata = self._check_source_freshness(source_key)

            # Определяем статус актуальности
            local_db = self._load_local_db(source_key)

            if not local_db:
                status = 'missing'
                status_text = 'База не распарсена'
                status_color = 'danger'
            elif not available:
                status = 'unavailable'
                status_text = 'Источник недоступен'
                status_color = 'secondary'
            elif has_updates:
                status = 'outdated'
                status_text = 'Доступны обновления'
                status_color = 'warning'
            else:
                status = 'up_to_date'
                status_text = 'Актуальна'
                status_color = 'success'

            # Получаем статистику локальной БД
            local_stats = self._get_db_stats(local_db)

            update_entry = {
                'id': f"{source_key}_{datetime.now().timestamp()}",
                'source': source_key,
                'name': source_info['name'],
                'description': source_info.get('description', ''),
                'url': source_info['url'],  # Основной URL для пользователя
                'status': status,
                'status_text': status_text,
                'status_color': status_color,
                'timestamp': datetime.now().isoformat(),
                'metadata': metadata,
                'local_stats': local_stats,
                'info': info
            }

            updates.append(update_entry)

        return updates

    def _get_db_stats(self, db: dict) -> dict:
        """Получить статистику БД"""
        if not db:
            return {'count': 0, 'type': 'empty'}

        if isinstance(db, list):
            return {'count': len(db), 'type': 'list'}
        elif isinstance(db, dict):
            # Подсчитываем значимые элементы
            if 'objects' in db and isinstance(db['objects'], list):
                return {'count': len(db['objects']), 'type': 'stix'}
            else:
                # Если это словарь с записями
                count = len([v for v in db.values() if isinstance(v, (dict, list))])
                return {'count': count, 'type': 'dict'}

        return {'count': 0, 'type': 'unknown'}

    def check_updates(self, force_refresh=False) -> dict:
        """
        Проверить обновления в источниках
        force_refresh: пересчитать даже если кэш еще свежий
        """
        current_time = time.time()
        last_checked = self.cache.get('last_checked')
        current_mtimes = self._local_db_mtimes()

        # Проверяем кэш: считаем его устаревшим, если истекло время жизни,
        # локальные файлы БД изменились после последней проверки
        # (например, парсинг/связывание было перезапущено вручную),
        # или в прошлый раз источники были недоступны (например, не было
        # интернета) — в этом случае повторяем проверку при следующей
        # загрузке страницы, не дожидаясь истечения CACHE_LIFETIME
        had_unavailable = any(u.get('status') == 'unavailable' for u in self.cache.get('updates', []))
        if not force_refresh and last_checked and not had_unavailable:
            cache_fresh = current_time - float(last_checked) < self.CACHE_LIFETIME
            files_unchanged = self.cache.get('db_mtimes') == current_mtimes
            if cache_fresh and files_unchanged:
                return self.cache

        # Получаем свежие данные
        updates = self._fetch_recent_updates()

        result = {
            'updates': updates,
            'last_checked': str(current_time),
            'sources_count': len(self.SOURCES),
            'timestamp': datetime.now().isoformat(),
            'db_mtimes': current_mtimes
        }

        # Сохраняем в кэш
        self.cache = result
        self._save_cache(result)

        return result

    def get_db_comparison(self, source_key: str) -> dict:
        """Получить детальное сравнение локальной БД с источником"""
        source = self.SOURCES.get(source_key)
        if not source:
            return {'error': 'Источник не найден'}

        local_db = self._load_local_db(source_key)
        local_stats = self._get_db_stats(local_db)

        available, has_updates, info, metadata = self._check_source_freshness(source_key)

        return {
            'source_key': source_key,
            'source_name': source['name'],
            'source_url': source['url'],
            'local_stats': local_stats,
            'available': available,
            'is_outdated': has_updates,
            'metadata': metadata,
            'info': info,
            'last_checked': metadata.get('checked_at') or datetime.now().isoformat()
        }


def create_updates_checker(output_dir=None) -> UpdatesChecker:
    """Фабрика для создания проверочника обновлений"""
    return UpdatesChecker(output_dir)
