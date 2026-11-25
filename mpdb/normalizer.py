# src/normalizer.py
import re
from typing import Any, Dict, List


class DataNormalizer:
    """Нормализатор данных: очистка и приведение к единому формату"""
    
    @staticmethod
    def clean_item(item: Dict[str, Any]) -> Dict[str, Any]:
        """Очищает элемент от пустых значений"""
        return {k: v for k, v in item.items() if v not in [None, "", [], {}]}
    
    @staticmethod
    def normalize_ids(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Нормализует ID в списке элементов"""
        normalized = []
        for item in items:
            if 'id' in item:
                # Приводим ID к стандартному виду
                item['id'] = str(item['id']).strip().upper()
            normalized.append(item)
        return normalized
    
    @staticmethod
    def process_database(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Полная обработка базы данных"""
        # Очистка
        cleaned = [DataNormalizer.clean_item(item) for item in items]
        # Нормализация ID
        normalized = DataNormalizer.normalize_ids(cleaned)
        # Сортировка по ID
        return sorted(normalized, key=lambda x: x.get('id', ''))
