# src/normalizer.py
import re
from typing import Any, Dict, List

class DataNormalizer:
    """Жёсткая очистка и приведение данных к единому стандарту"""
    
    @staticmethod
    def clean_item(item: dict) -> dict:
        if not isinstance(item, dict):
            return item
            
        cleaned = {}
        for k, v in item.items():
            key = k.strip()
            if isinstance(v, str):
                cleaned[key] = v.strip()
            elif isinstance(v, list):
                cleaned[key] = [x.strip() if isinstance(x, str) else x for x in v]
            elif isinstance(v, dict):
                cleaned[key] = DataNormalizer.clean_item(v)
            else:
                cleaned[key] = v
        return cleaned

    @staticmethod
    def normalize_ids(item: dict) -> dict:
        """Приводит все ID к каноническому виду без пробелов и лишних суффиксов"""
        for field in ["id", "related_cwe", "related_capec", "related_mitre", "related_cve"]:
            if field in item:
                if isinstance(item[field], str):
                    item[field] = re.sub(r'\s+', '', item[field]).upper()
                elif isinstance(item[field], list):
                    item[field] = [re.sub(r'\s+', '', x).upper() if isinstance(x, str) else x for x in item[field]]
        return item

    @classmethod
    def process_database(cls, records: List[dict]) -> List[dict]:
        return [cls.normalize_ids(cls.clean_item(rec)) for rec in records]
