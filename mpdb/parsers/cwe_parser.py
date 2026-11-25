# src/parsers/cwe_parser.py
import xml.etree.ElementTree as ET
import re
from ..config import Config
from .base import BaseParser


class CWEParser(BaseParser):
    """Парсер для CWE (XML формат из ZIP-архива)"""
    
    NAMESPACE = "http://cwe.mitre.org/cwe-7"
    
    def parse(self, xml_content: bytes) -> list:
        """Парсит XML-содержимое CWE и возвращает список записей"""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            print(f"❌ Ошибка парсинга CWE XML: {e}")
            return []
        
        results = []
        weaknesses = root.findall(f'.//{{{self.NAMESPACE}}}Weakness')
        print(f"🔍 Найдено элементов Weakness: {len(weaknesses)}")

        limit = Config.MAX_CWE_RECORDS
        if limit and limit > 0 and len(weaknesses) > limit:
            weaknesses = weaknesses[:limit]
            print(f"⏱️ Применяем лимит: обрабатываем {limit}/{len(weaknesses)} записей")
        
        for idx, weakness in enumerate(weaknesses):
            item = self._parse_weakness(weakness)
            if item:
                results.append(item)
            if (idx + 1) % 100 == 0:
                print(f"  📊 Обработано: {idx + 1}/{len(weaknesses)}")
        
        print(f"📊 Итого записей CWE: {len(results)}")
        return results
    
    def _get_text_content(self, elem) -> str:
        """Извлекает текстовый контент из элемента и всех вложенных тегов"""
        if elem is None:
            return ""
        texts = []
        if elem.text and elem.text.strip():
            texts.append(elem.text.strip())
        for child in elem:
            texts.extend(self._get_text_content(child).split('\n'))
            if child.tail and child.tail.strip():
                texts.append(child.tail.strip())
        return ' '.join(t for t in texts if t and t.strip()).strip()
    
    def _find_elements(self, parent, tag_name):
        """Находит элементы по имени тега с учётом namespace"""
        full_tag = f'{{{self.NAMESPACE}}}{tag_name}'
        return parent.findall(f'.//{full_tag}')
    
    def _parse_weakness(self, weakness) -> dict | None:
        try:
            weakness_id = weakness.get("ID", "").strip()
            if not weakness_id:
                return None
            
            item = {
                "id": f"CWE-{weakness_id}",
                "name": weakness.get("Name", "").strip(),
                "description": "",
                "category": weakness.get("Class", weakness.get("Type", "unknown")).strip().lower(),
                "related_capec": [],
                "mitigation": "",
                "requires_technology": [],
                "detection_methods": []
            }
            
            # === Description ===
            desc_elems = self._find_elements(weakness, "Description")
            if desc_elems:
                item["description"] = self._get_text_content(desc_elems[0])
            
            # === Related CAPEC (исправлено: Related_Attack_Patterns) ===
            for rap_container in self._find_elements(weakness, "Related_Attack_Patterns"):
                for rap in self._find_elements(rap_container, "Related_Attack_Pattern"):
                    capec_id = rap.get("CAPEC_ID")
                    if capec_id:
                        item["related_capec"].append(f"CAPEC-{capec_id}")
            
            # === Mitigation (из Potential_Mitigations) ===
            mitigation_texts = []
            for mitigation_container in self._find_elements(weakness, "Potential_Mitigations"):
                for mitigation in self._find_elements(mitigation_container, "Mitigation"):
                    text = self._get_text_content(mitigation)
                    if text:
                        mitigation_texts.append(text)
            if mitigation_texts:
                # Объединяем первые 3 меры защиты
                item["mitigation"] = "; ".join(mitigation_texts[:3])
            
            # === Requires Technology (из Applicable_Platforms) ===
            for platform_container in self._find_elements(weakness, "Applicable_Platforms"):
                for platform in self._find_elements(platform_container, "Platform"):
                    platform_name = platform.get("Name", "").strip().lower()
                    if platform_name:
                        item["requires_technology"].append(platform_name)
            
            # === Detection Methods ===
            for detection_container in self._find_elements(weakness, "Detection_Methods"):
                for detection in self._find_elements(detection_container, "Detection_Method"):
                    method = self._get_text_content(detection).lower().strip()
                    if method:
                        formatted = method.replace(" ", "_").replace(",", "").replace(".", "")
                        item["detection_methods"].append(formatted)
            
            # === Перевод (если включён) ===
            if Config.ENABLE_TRANSLATION:
                if item["name"] and not self._is_russian(item["name"]):
                    item["name"] = self.translator.translate(item["name"])
                if item["description"] and not self._is_russian(item["description"]):
                    item["description"] = self.translator.translate(item["description"])
                if item["mitigation"] and not self._is_russian(item["mitigation"]):
                    item["mitigation"] = self.translator.translate(item["mitigation"])
                item["requires_technology"] = self.translator.translate_list(item["requires_technology"])
            
            # === Очистка значений ===
            cleaned = {}
            for k, v in item.items():
                if isinstance(v, str):
                    cleaned[k] = v.strip()
                elif isinstance(v, list):
                    cleaned[k] = [x.strip() if isinstance(x, str) else x for x in v]
                else:
                    cleaned[k] = v
            
            return cleaned
            
        except Exception as e:
            print(f"⚠️ Ошибка парсинга CWE-{weakness.get('ID', 'UNKNOWN')}: {e}")
            return None
    
    def _is_russian(self, text: str) -> bool:
        return bool(re.search(r'[а-яА-ЯёЁ]', text))
