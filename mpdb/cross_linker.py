# src/cross_linker.py
import json
from pathlib import Path
from typing import Dict, List, Any
from .normalizer import DataNormalizer
from .config import Config


class CrossLinker:
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.capec: Dict[str, dict] = {}
        self.cwe: Dict[str, dict] = {}
        self.cve: Dict[str, dict] = {}
        self.attack: Dict[str, dict] = {}

    def load_databases(self) -> bool:
        try:
            for db_name, attr_name in [
                ("capec_database.json", "capec"),
                ("cwe_database.json", "cwe"),
                ("cve_database.json", "cve"),
                ("mitre_attack.json", "attack")
            ]:
                filepath = self.output_dir / db_name
                if not filepath.exists():
                    continue
                with open(filepath, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                normalized = DataNormalizer.process_database(raw_data)
                setattr(self, attr_name, {item["id"]: item for item in normalized})
            return True
        except Exception as e:
            print(f"❌ Ошибка загрузки/нормализации: {e}")
            return False

    def _propagate_field(self, source_db: Dict, target_db: Dict,
                         src_field: str, tgt_field: str, link_field: str) -> int:
        updated = 0
        for src_id, src_rec in source_db.items():
            links = src_rec.get(link_field, [])
            if not links:
                continue
            values_to_add = []
            for link_id in links:
                if link_id in target_db:
                    val = target_db[link_id].get(tgt_field, "")
                    if isinstance(val, list):
                        values_to_add.extend(val)
                    elif isinstance(val, str) and val:
                        values_to_add.append(val)
            if values_to_add:
                current = src_rec.get(tgt_field, [])
                if isinstance(current, str):
                    current = [current] if current else []
                merged = list(dict.fromkeys(current + values_to_add))[:10]
                if merged != current:
                    src_rec[tgt_field] = merged
                    updated += 1
        return updated

    def _enrich_cve_from_cwe(self) -> int:
        """Обогащает CVE данными mitigations из связанных CWE"""
        updated = 0
        for cve_id, cve_rec in self.cve.items():
            cwe_ids = cve_rec.get("related_cwe", [])
            if not cwe_ids:
                continue
            mitigations = []
            for cwe_id in cwe_ids:
                if cwe_id in self.cwe:
                    mit = self.cwe[cwe_id].get("mitigation", "")
                    if mit:
                        mitigations.append(mit)
            if mitigations:
                existing = cve_rec.get("mitigations", [])
                if isinstance(existing, str):
                    existing = [existing] if existing else []
                combined = list(dict.fromkeys(existing + mitigations))[:10]
                if combined != existing:
                    cve_rec["mitigations"] = combined
                    cve_rec.pop("mitigation", None)
                    updated += 1
        return updated

    def _enrich_capec_related_mitre(self) -> int:
        """Заполняет related_mitre в CAPEC на основе related_capec из ATT&CK"""
        updated = 0
        for attack_id, attack_rec in self.attack.items():
            capec_ids = attack_rec.get("related_capec", [])
            for capec_id in capec_ids:
                if capec_id in self.capec:
                    capec_rec = self.capec[capec_id]
                    existing = capec_rec.get("related_mitre", [])
                    if attack_id not in existing:
                        existing.append(attack_id)
                        capec_rec["related_mitre"] = existing
                        updated += 1
        return updated
    
    def _enrich_cwe_from_capec(self) -> int:
        updated = 0
        for cwe_id, cwe_rec in self.cwe.items():
            capec_ids = cwe_rec.get("related_capec", [])
            if not capec_ids:
                continue
            mitigations = []
            for capec_id in capec_ids:
                if capec_id in self.capec:
                    mits = self.capec[capec_id].get("mitigations", [])
                    if isinstance(mits, list):
                        mitigations.extend(mits)
                    elif isinstance(mits, str) and mits:
                        mitigations.append(mits)
            if mitigations:
                existing = cwe_rec.get("mitigation", "")
                new_mit = existing
                if existing:
                    new_mit += "\n\n" + "\n".join(mitigations)
                else:
                    new_mit = "\n".join(mitigations)
                if new_mit != existing:
                    cwe_rec["mitigation"] = new_mit
                    updated += 1
        return updated

    def _enrich_attack_related_capec_from_capec(self) -> int:
        updated = 0
        for capec_id, capec_rec in self.capec.items():
            attack_ids = capec_rec.get("related_mitre", [])
            for attack_id in attack_ids:
                if attack_id in self.attack:
                    attack_rec = self.attack[attack_id]
                    existing = attack_rec.get("related_capec", [])
                    if capec_id not in existing:
                        existing.append(capec_id)
                        attack_rec["related_capec"] = existing
                        updated += 1
        return updated

    def _enrich_cve_full_chain(self) -> int:
        """Цепочка обогащения CVE: CVE → CWE → CAPEC → ATT&CK"""
        updated = 0
        for cve_id, cve_rec in self.cve.items():
            cwe_ids = cve_rec.get("related_cwe", [])
            if not cwe_ids:
                continue
            related_capec = set()
            related_mitre = set()
            mitigations = set()

            for cwe_id in cwe_ids:
                cwe = self.cwe.get(cwe_id)
                if not cwe:
                    continue
                for capec_id in cwe.get("related_capec", []):
                    if capec_id in self.capec:
                        related_capec.add(capec_id)
                        capec = self.capec[capec_id]
                        for mit in capec.get("mitigations", []):
                            mitigations.add(mit)
                        for attack_id in capec.get("related_mitre", []):
                            if attack_id in self.attack:
                                related_mitre.add(attack_id)
                                for mit in self.attack[attack_id].get("mitigations", []):
                                    mitigations.add(mit)
            if related_capec:
                cur_capec = set(cve_rec.get("related_capec", []))
                if not cur_capec.issuperset(related_capec):
                    cve_rec["related_capec"] = list(cur_capec | related_capec)
                    updated += 1
            if related_mitre:
                cur_mitre = set(cve_rec.get("related_mitre", []))
                if not cur_mitre.issuperset(related_mitre):
                    cve_rec["related_mitre"] = list(cur_mitre | related_mitre)
                    updated += 1
            if mitigations:
                cur_mit = set(cve_rec.get("mitigations", []))
                new_mit = cur_mit | mitigations
                if new_mit != cur_mit:
                    cve_rec["mitigations"] = list(new_mit)[:10]
                    cve_rec.pop("mitigation", None)
                    updated += 1
        return updated

    def run(self) -> Dict[str, int]:
        print("\n🔗 Запуск двунаправленного связывания...")
        stats = {"capec": 0, "cwe": 0, "cve": 0, "attack": 0}

    # 1. Заполняем related_mitre в CAPEC на основе related_capec из ATT&CK
        stats["capec"] += self._enrich_capec_related_mitre()

    # 2. Обогащаем CVE из CWE
        stats["cve"] += self._enrich_cve_from_cwe()

    # 3. Обогащаем CWE из CAPEC
        stats["cwe"] += self._enrich_cwe_from_capec()

    # 4. Обратное связывание: ATT&CK related_capec ← CAPEC.related_mitre
        stats["attack"] += self._enrich_attack_related_capec_from_capec()

    # 5. Полная цепочка CVE → CWE → CAPEC → ATT&CK
        stats["cve"] += self._enrich_cve_full_chain()

    # 6. Перенос mitigations из ATT&CK в CAPEC и обратно
    #    (stats считается по source_db, т.к. _propagate_field изменяет именно его записи)
        stats["attack"] += self._propagate_field(
        self.attack, self.capec,
        "related_capec", "mitigations", "related_capec"
    )
        stats["attack"] += self._propagate_field(
        self.attack, self.capec,
        "related_capec", "detection", "related_capec"
    )
        stats["capec"] += self._propagate_field(
        self.capec, self.attack,
        "related_mitre", "mitigations", "related_mitre"
    )

        return stats

    def save_databases(self) -> bool:
        try:
            for db_name, data_dict in [
                ("capec_database.json", self.capec),
                ("cwe_database.json", self.cwe),
                ("cve_database.json", self.cve),
                ("mitre_attack.json", self.attack)
            ]:
                records = list(data_dict.values())
                records = DataNormalizer.process_database(records)
                with open(self.output_dir / db_name, "w", encoding="utf-8") as f:
                    json.dump(records, f, ensure_ascii=False, indent=2)
            print("✅ Все базы сохранены с заполненными полями")
            return True
        except Exception as e:
            print(f"❌ Ошибка сохранения: {e}")
