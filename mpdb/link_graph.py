#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Граф перекрёстных связей между базами CAPEC, CWE, CVE и MITRE ATT&CK.

Строит лёгкий индекс узлов (id -> имя/база) и рёбер (на основе полей
related_capec, related_cwe, related_mitre, related_cve), чтобы:
- показать общую статистику связей между базами (для обзорной диаграммы)
- искать узлы по id/имени
- строить эго-сеть конкретного узла (его связи на 1 шаг)
"""

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config


# Поля, описывающие перекрёстные ссылки, и базы, на которые они указывают
LINK_FIELDS = {
    'related_capec': 'capec',
    'related_cwe': 'cwe',
    'related_mitre': 'attack',
    'related_cve': 'cve',
}

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

# Ожидаемые перекрёстные связи каждой базы (по схеме FIELD_MAPPING) — основа для
# отчёта о покрытии (gap-analysis): какой % записей реально дотянут до смежных баз.
EXPECTED_LINKS = {
    'capec': ['related_cwe', 'related_mitre'],
    'cve':   ['related_cwe', 'related_capec', 'related_mitre'],
    'attack': ['related_cwe', 'related_capec'],
    'cwe':   ['related_capec'],
}

# Человекочитаемые подписи полей-связей
LINK_FIELD_LABELS = {
    'related_capec': 'CAPEC',
    'related_cwe': 'CWE',
    'related_mitre': 'ATT&CK',
    'related_cve': 'CVE',
}

# Сколько входящих связей показывать в эго-сети для сильно цитируемых узлов
MAX_INCOMING_NEIGHBORS = 25
MAX_OUTGOING_NEIGHBORS = 50
TOP_REFERENCED_LIMIT = 10

# Многошаговый граф (depth > 1): ограничения на узлах второго и следующих уровней
MAX_HOP_NEIGHBORS = 6
MAX_NETWORK_NODES = 150
MAX_DEPTH = 3

# Поиск пути между узлами: максимальная длина пути (в шагах)
MAX_PATH_DEPTH = 6


def _db_for_id(node_id: str) -> Optional[str]:
    """Определить базу узла по формату его id (CAPEC-xxx, CWE-xxx, CVE-xxxx-xxxx, Txxxx)"""
    if node_id.startswith('CAPEC-'):
        return 'capec'
    if node_id.startswith('CWE-'):
        return 'cwe'
    if node_id.startswith('CVE-'):
        return 'cve'
    if node_id.startswith('T'):
        return 'attack'
    return None


class LinkGraph:
    """Индекс перекрёстных связей между базами MITRE, с кэшем по mtime файлов"""

    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir) if output_dir else Config.OUTPUT_DIR
        self._nodes: Dict[str, dict] = {}
        self._outgoing: Dict[str, List[tuple]] = {}
        self._incoming: Dict[str, List[str]] = {}
        self._mtimes: Dict[str, float] = {}
        self._build_index()

    def _files_changed(self) -> bool:
        for filename in DB_FILES.values():
            filepath = self.output_dir / filename
            mtime = filepath.stat().st_mtime if filepath.exists() else 0
            if self._mtimes.get(filename) != mtime:
                return True
        return False

    def _ensure_fresh(self):
        if self._files_changed():
            self._build_index()

    def _build_index(self):
        nodes: Dict[str, dict] = {}
        outgoing: Dict[str, List[tuple]] = {}
        incoming: Dict[str, List[str]] = {}
        mtimes: Dict[str, float] = {}

        for db_key, filename in DB_FILES.items():
            filepath = self.output_dir / filename
            mtimes[filename] = filepath.stat().st_mtime if filepath.exists() else 0

            if not filepath.exists():
                continue
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    records = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(records, list):
                continue

            for record in records:
                node_id = record.get('id')
                if not node_id:
                    continue

                nodes[node_id] = {
                    'id': node_id,
                    'name': record.get('name', node_id),
                    'db': db_key,
                }

                for field in LINK_FIELDS:
                    targets = record.get(field)
                    if not isinstance(targets, list):
                        continue
                    for target_id in targets:
                        if not target_id:
                            continue
                        outgoing.setdefault(node_id, []).append((target_id, field))
                        incoming.setdefault(target_id, []).append(node_id)

        self._nodes = nodes
        self._outgoing = outgoing
        self._incoming = incoming
        self._mtimes = mtimes

    def get_link_statistics(self) -> dict:
        """Статистика для обзорной диаграммы: узлы по базам и связи между базами"""
        self._ensure_fresh()

        node_counts = {db_key: 0 for db_key in DB_FILES}
        for node in self._nodes.values():
            node_counts[node['db']] += 1

        # Считаем рёбра, сгруппированные по (база-источник, база-цель, поле)
        edge_counts: Dict[tuple, int] = {}
        for source_id, targets in self._outgoing.items():
            source_node = self._nodes.get(source_id)
            if not source_node:
                continue
            source_db = source_node['db']
            for target_id, field in targets:
                target_db = LINK_FIELDS[field]
                key = (source_db, target_db, field)
                edge_counts[key] = edge_counts.get(key, 0) + 1

        edges = [
            {'source': source_db, 'target': target_db, 'field': field, 'count': count}
            for (source_db, target_db, field), count in edge_counts.items()
        ]

        # Самые цитируемые узлы (по числу входящих связей)
        top_referenced = sorted(
            self._incoming.items(), key=lambda kv: len(kv[1]), reverse=True
        )[:TOP_REFERENCED_LIMIT]

        top_referenced_list = []
        for node_id, sources in top_referenced:
            node = self._nodes.get(node_id, {'id': node_id, 'name': node_id, 'db': _db_for_id(node_id)})
            top_referenced_list.append({
                'id': node['id'],
                'name': node['name'],
                'db': node['db'],
                'count': len(sources),
            })

        return {
            'nodes': node_counts,
            'edges': edges,
            'total_links': sum(len(v) for v in self._outgoing.values()),
            'top_referenced': top_referenced_list,
        }

    def get_coverage_report(self) -> dict:
        """Отчёт о покрытии связей (gap-analysis).

        Для каждой базы считает, какой процент записей реально дотянут до смежных
        баз по ожидаемым полям-связям, сколько записей вообще без перекрёстных
        связей (orphans), и сквозное покрытие цепочки CVE → CWE → CAPEC → ATT&CK.
        """
        self._ensure_fresh()

        totals = {db: 0 for db in DB_FILES}
        field_hits = {db: {f: 0 for f in EXPECTED_LINKS.get(db, [])} for db in DB_FILES}
        linked_any = {db: 0 for db in DB_FILES}

        for node_id, node in self._nodes.items():
            db = node['db']
            if db not in totals:
                continue
            totals[db] += 1
            fields_present = {field for _t, field in self._outgoing.get(node_id, [])}
            if fields_present:
                linked_any[db] += 1
            for field in EXPECTED_LINKS.get(db, []):
                if field in fields_present:
                    field_hits[db][field] += 1

        def pct(count: int, total: int) -> float:
            return round(count * 100 / total, 1) if total else 0.0

        databases = {}
        for db in DB_FILES:
            total = totals[db]
            databases[db] = {
                'label': DB_LABELS[db],
                'total': total,
                'fields': {
                    field: {
                        'label': LINK_FIELD_LABELS.get(field, field),
                        'count': field_hits[db][field],
                        'missing': total - field_hits[db][field],
                        'percent': pct(field_hits[db][field], total),
                    }
                    for field in EXPECTED_LINKS.get(db, [])
                },
                'linked_any': {'count': linked_any[db], 'percent': pct(linked_any[db], total)},
                'orphans': {'count': total - linked_any[db], 'percent': pct(total - linked_any[db], total)},
            }

        # Сквозная цепочка CVE → CWE → CAPEC → ATT&CK (по полям записей CVE)
        cve_fields = databases['cve']['fields']
        chain = {
            'cve_to_cwe': cve_fields.get('related_cwe', {'count': 0, 'percent': 0.0, 'missing': totals['cve']}),
            'cve_to_capec': cve_fields.get('related_capec', {'count': 0, 'percent': 0.0, 'missing': totals['cve']}),
            'cve_to_attack': cve_fields.get('related_mitre', {'count': 0, 'percent': 0.0, 'missing': totals['cve']}),
        }

        return {'databases': databases, 'chain': chain, 'cve_total': totals['cve']}

    def search_nodes(self, query: str, limit: int = 20) -> List[dict]:
        """Поиск узлов по id или названию"""
        self._ensure_fresh()

        query = (query or '').strip().lower()
        if not query:
            return []

        exact, prefix, contains = [], [], []
        for node in self._nodes.values():
            node_id_lower = node['id'].lower()
            name_lower = (node['name'] or '').lower()

            if node_id_lower == query:
                exact.append(node)
            elif node_id_lower.startswith(query):
                prefix.append(node)
            elif query in node_id_lower or query in name_lower:
                contains.append(node)

        results = exact + prefix + contains
        return [
            {'id': n['id'], 'name': n['name'], 'db': n['db'], 'links': len(self._outgoing.get(n['id'], [])) + len(self._incoming.get(n['id'], []))}
            for n in results[:limit]
        ]

    def _node_or_stub(self, node_id: str) -> Optional[dict]:
        """Вернуть узел из индекса или заглушку по распознанному формату id"""
        node = self._nodes.get(node_id)
        if node:
            return node
        db = _db_for_id(node_id)
        if db is None:
            return None
        return {'id': node_id, 'name': node_id, 'db': db}

    def _resolve_id(self, query: str) -> Optional[str]:
        """Найти id узла по запросу: точное совпадение, без учёта регистра, формат id или поиск по названию"""
        query = (query or '').strip()
        if not query:
            return None
        if query in self._nodes:
            return query
        upper = query.upper()
        if upper in self._nodes or _db_for_id(upper) is not None:
            return upper
        matches = self.search_nodes(query, limit=1)
        if matches:
            return matches[0]['id']
        return None

    def _neighbors(self, node_id: str) -> List[tuple]:
        """Все соседи узла (входящие и исходящие связи) как (id_соседа, ребро)"""
        result = []
        for target_id, field in self._outgoing.get(node_id, []):
            result.append((target_id, {'from': node_id, 'to': target_id, 'field': field}))
        for source_id in self._incoming.get(node_id, []):
            field = next((f for t, f in self._outgoing.get(source_id, []) if t == node_id), 'related')
            result.append((source_id, {'from': source_id, 'to': node_id, 'field': field}))
        return result

    def get_network(self, node_id: str, depth: int = 1) -> dict:
        """Построить локальный граф связей для узла на глубину depth шагов (1-3)"""
        self._ensure_fresh()
        depth = max(1, min(int(depth), MAX_DEPTH))

        center = self._node_or_stub(node_id)
        if center is None:
            return {'error': f'Неизвестный узел: {node_id}'}
        node_id = center['id']

        nodes_by_id = {node_id: center}
        edges = []
        edge_seen = set()
        truncated = {'outgoing': 0, 'incoming': 0, 'nodes': False}

        frontier = [node_id]
        for level in range(depth):
            next_frontier = []
            out_limit = MAX_OUTGOING_NEIGHBORS if level == 0 else MAX_HOP_NEIGHBORS
            in_limit = MAX_INCOMING_NEIGHBORS if level == 0 else MAX_HOP_NEIGHBORS

            for nid in frontier:
                outgoing = self._outgoing.get(nid, [])
                for target_id, field in outgoing[:out_limit]:
                    edge_key = (nid, target_id, field)
                    if edge_key not in edge_seen:
                        edge_seen.add(edge_key)
                        edges.append({'from': nid, 'to': target_id, 'field': field})
                    if target_id not in nodes_by_id:
                        if len(nodes_by_id) >= MAX_NETWORK_NODES:
                            truncated['nodes'] = True
                            continue
                        nodes_by_id[target_id] = self._node_or_stub(target_id)
                        next_frontier.append(target_id)
                if len(outgoing) > out_limit:
                    truncated['outgoing'] += len(outgoing) - out_limit

                incoming = self._incoming.get(nid, [])
                for source_id in incoming[:in_limit]:
                    field = next((f for t, f in self._outgoing.get(source_id, []) if t == nid), 'related')
                    edge_key = (source_id, nid, field)
                    if edge_key not in edge_seen:
                        edge_seen.add(edge_key)
                        edges.append({'from': source_id, 'to': nid, 'field': field})
                    if source_id not in nodes_by_id:
                        if len(nodes_by_id) >= MAX_NETWORK_NODES:
                            truncated['nodes'] = True
                            continue
                        nodes_by_id[source_id] = self._node_or_stub(source_id)
                        next_frontier.append(source_id)
                if len(incoming) > in_limit:
                    truncated['incoming'] += len(incoming) - in_limit

            frontier = next_frontier
            if not frontier or truncated['nodes']:
                break

        return {
            'center': center,
            'nodes': list(nodes_by_id.values()),
            'edges': edges,
            'truncated': truncated,
            'depth': depth,
        }

    def find_path(self, from_id: str, to_id: str) -> dict:
        """Найти кратчайший путь между двумя узлами (BFS по неориентированному графу связей)"""
        self._ensure_fresh()

        resolved_from = self._resolve_id(from_id)
        resolved_to = self._resolve_id(to_id)
        if resolved_from is None:
            return {'error': f'Запись не найдена: {from_id}'}
        if resolved_to is None:
            return {'error': f'Запись не найдена: {to_id}'}

        start = self._node_or_stub(resolved_from)
        end = self._node_or_stub(resolved_to)
        from_id, to_id = start['id'], end['id']
        if from_id == to_id:
            return {'found': True, 'nodes': [start], 'edges': [], 'length': 0}

        parent: Dict[str, tuple] = {from_id: None}
        depth: Dict[str, int] = {from_id: 0}
        queue = deque([from_id])

        while queue:
            current = queue.popleft()
            if current == to_id:
                break
            if depth[current] >= MAX_PATH_DEPTH:
                continue
            for neighbor_id, edge in self._neighbors(current):
                if neighbor_id not in parent:
                    parent[neighbor_id] = (current, edge)
                    depth[neighbor_id] = depth[current] + 1
                    queue.append(neighbor_id)

        if to_id not in parent:
            isolated = [n['id'] for n in (start, end) if not self._neighbors(n['id'])]
            if isolated:
                message = (
                    f"Запись {isolated[0]} не имеет известных перекрёстных связей с другими базами"
                    if len(isolated) == 1
                    else f"Записи {isolated[0]} и {isolated[1]} не имеют известных перекрёстных связей с другими базами"
                )
            else:
                message = f'Путь длиной до {MAX_PATH_DEPTH} шагов между записями не найден'
            return {'found': False, 'from': start, 'to': end, 'message': message}

        edges = []
        node_ids = []
        cur = to_id
        while cur is not None:
            node_ids.append(cur)
            entry = parent.get(cur)
            if entry is None:
                break
            prev, edge = entry
            edges.append(edge)
            cur = prev
        node_ids.reverse()
        edges.reverse()

        return {
            'found': True,
            'nodes': [self._node_or_stub(nid) for nid in node_ids],
            'edges': edges,
            'length': len(edges),
        }


def create_link_graph(output_dir=None) -> LinkGraph:
    """Фабрика для создания графа связей"""
    return LinkGraph(output_dir)
