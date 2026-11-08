"""
Модуль базы данных инструментов атаки и защиты.
Предоставляет:
  - Поиск инструментов атаки по типу атаки / CVE
  - Поиск мер защиты по типу атаки / CVE
  - Генерацию пошаговых инструкций атаки (учебные цели)
  - Структурированные данные для схем в отчёте
"""
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.logger import get_server_logger
logger = get_server_logger()
TOOLS_DB_PATH = "databases/tools_database.json"
DEFENSE_DB_PATH = "databases/defense_database.json"
class AttackToolkit:
    """
    База данных инструментов атаки и защиты.
    Используется для обогащения отчётов пошаговыми инструкциями.
    """
    def __init__(self, base_dir: str = ""):
        self.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tools_db: list[dict] = []
        self.defense_db: list[dict] = []
    def load(self):
        """Загрузка баз данных инструментов."""
        tools_path = os.path.join(self.base_dir, TOOLS_DB_PATH)
        defense_path = os.path.join(self.base_dir, DEFENSE_DB_PATH)
        self.tools_db = self._load_json(tools_path, "Tools")
        self.defense_db = self._load_json(defense_path, "Defense")
    def _load_json(self, path: str, name: str) -> list:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"[TOOLKIT] {name}: загружено {len(data)} записей")
            return data
        except FileNotFoundError:
            logger.warning(f"[TOOLKIT] Файл не найден: {path}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"[TOOLKIT] Ошибка JSON в {path}: {e}")
            return []
    # ─── Поиск инструментов атаки ───
    def get_tools_for_cve(self, cve_id: str) -> list[dict]:
        """Найти инструменты атаки для конкретного CVE."""
        result = []
        for tool in self.tools_db:
            if cve_id in tool.get("applicable_cve", []):
                result.append(tool)
        return result
    def get_tools_for_attack_type(self, attack_type: str) -> list[dict]:
        """Найти инструменты атаки по типу атаки."""
        result = []
        for tool in self.tools_db:
            if attack_type in tool.get("applicable_attack_types", []):
                result.append(tool)
        return result
    def get_attack_commands(self, cve_id: str, target_ip: str = "<TARGET_IP>") -> list[dict]:
        """
        Получить пошаговые команды атаки для CVE.
        Возвращает список словарей с инструментом и командами.
        """
        results = []
        for tool in self.tools_db:
            if cve_id not in tool.get("applicable_cve", []):
                continue
            commands = tool.get("commands", {})
            # Проверяем наличие команд для конкретного CVE или "default"
            cmd_list = commands.get(cve_id) or commands.get("default", [])
            if cmd_list:
                # Подставляем IP адрес если он известен
                processed_cmds = [
                    c.replace("<TARGET_IP>", target_ip) if not c.startswith("#") else c
                    for c in cmd_list
                ]
                results.append({
                    "tool_id": tool["id"],
                    "tool_name": tool["name"],
                    "tool_type": tool["type"],
                    "description": tool["description"],
                    "skill_level": tool.get("skill_level", "Unknown"),
                    "phases": tool.get("phases", []),
                    "commands": processed_cmds,
                    "url": tool.get("url", ""),
                    "os": tool.get("os", []),
                })
        return results
    # ─── Поиск мер защиты ───
    def get_defense_for_cve(self, cve_id: str) -> list[dict]:
        """Найти меры защиты для конкретного CVE."""
        result = []
        for defense in self.defense_db:
            if cve_id in defense.get("cve_ids", []):
                result.append(defense)
        return result
    def get_defense_for_attack_type(self, attack_type: str) -> list[dict]:
        """Найти меры защиты по типу атаки."""
        result = []
        for defense in self.defense_db:
            if defense.get("attack_type") == attack_type:
                result.append(defense)
        return result
    def get_defense_tools(self, cve_id: str) -> list[dict]:
        """
        Получить инструменты защиты и команды для CVE.
        """
        results = []
        for defense in self.defense_db:
            if cve_id not in defense.get("cve_ids", []):
                continue
            for tool in defense.get("tools", []):
                results.append({
                    "defense_id": defense["id"],
                    "attack_type": defense["attack_type"],
                    "defense_name": defense["name"],
                    "defense_description": defense["description"],
                    "priority": defense.get("priority", "MEDIUM"),
                    "effort": defense.get("effort", "Medium"),
                    "effectiveness": defense.get("effectiveness", "Medium"),
                    "tool_name": tool.get("name", ""),
                    "tool_description": tool.get("description", ""),
                    "commands": tool.get("commands", []),
                })
        return results
    # ─── Получение всех инструментов для списка CVE ───
    def enrich_vulnerability_match(self, match: dict, target_ip: str = "<TARGET_IP>") -> dict:
        """
        Обогатить запись уязвимости данными об инструментах атаки и защиты.
        match должен содержать: cve_id, attack_name, attack_type (опционально)
        """
        cve_id = match.get("cve_id", "")
        attack_type = match.get("attack_type", "")
        enriched = dict(match)
        # Инструменты атаки
        attack_tools = self.get_attack_commands(cve_id, target_ip)
        if not attack_tools and attack_type:
            # Fallback по типу атаки
            for tool in self.get_tools_for_attack_type(attack_type):
                cmds = tool.get("commands", {}).get("default", [])
                if cmds:
                    attack_tools.append({
                        "tool_name": tool["name"],
                        "tool_type": tool["type"],
                        "description": tool["description"],
                        "skill_level": tool.get("skill_level", "Unknown"),
                        "phases": tool.get("phases", []),
                        "commands": cmds,
                        "url": tool.get("url", ""),
                    })
        enriched["attack_tools"] = attack_tools
        # Инструменты защиты
        defense_tools = self.get_defense_tools(cve_id)
        if not defense_tools and attack_type:
            for defense in self.get_defense_for_attack_type(attack_type):
                for tool in defense.get("tools", []):
                    defense_tools.append({
                        "defense_name": defense["name"],
                        "priority": defense.get("priority", "MEDIUM"),
                        "tool_name": tool.get("name", ""),
                        "commands": tool.get("commands", []),
                    })
        enriched["defense_tools"] = defense_tools
        return enriched
    # ─── Схема 1: Сравнение уязвимостей ───
    def build_comparison_schema(
        self,
        server_vulns: list[dict],
        attacker_vulns: list[dict],
    ) -> dict:
        """
        Схема 1: Сравнение уязвимостей найденных на сервере vs найденных атакующим.
        server_vulns — список CVE из локального сканирования сервера
        attacker_vulns — список CVE из сканирования атакующего
        """
        server_ids = {v.get("cve_id") or v.get("id", "") for v in server_vulns}
        attacker_ids = {v.get("cve_id") or v.get("id", "") for v in attacker_vulns}
        both = server_ids & attacker_ids        # Нашли обе стороны
        only_server = server_ids - attacker_ids  # Только на сервере
        only_attacker = attacker_ids - server_ids  # Только у атакующего
        return {
            "server_only": [v for v in server_vulns if (v.get("cve_id") or v.get("id")) in only_server],
            "attacker_only": [v for v in attacker_vulns if (v.get("cve_id") or v.get("id")) in only_attacker],
            "both": [v for v in server_vulns if (v.get("cve_id") or v.get("id")) in both],
            "stats": {
                "server_total": len(server_ids),
                "attacker_total": len(attacker_ids),
                "confirmed_by_both": len(both),
                "server_only_count": len(only_server),
                "attacker_only_count": len(only_attacker),
                "overlap_percent": round(
                    len(both) / max(len(server_ids | attacker_ids), 1) * 100, 1
                ),
            },
        }
    # ─── Список всех доступных векторов атак ───
    def get_available_attack_vectors(self) -> list[dict]:
        """
        Получить список всех доступных векторов атак из базы инструментов.
        Используется для ручного выбора вектора атаки в GUI.
        """
        vectors = []
        for tool in self.tools_db:
            for cve_id in tool.get("applicable_cve", []):
                if not any(v["cve_id"] == cve_id and v["tool_id"] == tool["id"] for v in vectors):
                    vectors.append({
                        "tool_id": tool["id"],
                        "tool_name": tool["name"],
                        "cve_id": cve_id,
                        "attack_types": tool.get("applicable_attack_types", []),
                        "skill_level": tool.get("skill_level", "Unknown"),
                        "phases": tool.get("phases", []),
                    })
        return vectors
    def get_all_attack_types(self) -> list[str]:
        """Получить все уникальные типы атак."""
        types = set()
        for tool in self.tools_db:
            types.update(tool.get("applicable_attack_types", []))
        return sorted(types)
    def get_all_cve_ids(self) -> list[str]:
        """Получить все CVE IDs, для которых есть инструменты."""
        ids = set()
        for tool in self.tools_db:
            ids.update(tool.get("applicable_cve", []))
        return sorted(ids)
