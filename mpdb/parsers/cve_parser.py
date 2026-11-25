import re
from typing import List, Dict, Any, Tuple
from ..config import Config
from .base import BaseParser

class CVEParser(BaseParser):
    def parse(self, nvd_data: dict) -> List[Dict[str, Any]]:
        results = []
        vulns = nvd_data.get("vulnerabilities", [])
        print(f"🔍 Найдено CVE в фиде NVD: {len(vulns)}")
        
        # 🔹 Лимит применяется ДО парсинга 🔹
        limit = Config.MAX_CVE_RECORDS
        if limit and limit > 0 and len(vulns) > limit:
            vulns = vulns[:limit]
            print(f"⏱️ Лимит: обрабатываем {limit}/{len(vulns)} записей")
            
        for idx, wrapper in enumerate(vulns):
            cve_obj = wrapper.get("cve", {})
            item = self._parse_nvd_cve(cve_obj)
            if item:
                results.append(item)
            if (idx + 1) % 100 == 0:
                print(f"  📊 Обработано: {idx + 1}/{len(vulns)}")
                
        print(f"📊 Итого записей CVE: {len(results)}")
        return results

    def _parse_nvd_cve(self, cve: dict) -> dict | None:
        try:
            cve_id = cve.get("id", "")
            if not cve_id: return None

            # Описание (предпочитаем английский)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang", "").startswith("en"):
                    desc = d.get("value", "").strip()
                    break
            if not desc and cve.get("descriptions"):
                desc = cve["descriptions"][0].get("value", "").strip()

            # CVSS и Severity
            cvss_score = 0.0
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    data = metrics[key][0].get("cvssData", {})
                    cvss_score = data.get("baseScore", 0.0)
                    severity = data.get("baseSeverity", "UNKNOWN").upper()
                    break

            # Связанные CWE
            related_cwe = []
            for w in cve.get("weaknesses", []):
                for desc_w in w.get("description", []):
                    val = desc_w.get("value", "").strip()
                    if val.startswith("CWE-"):
                        related_cwe.append(val)

            # Затронутое ПО (из CPE-конфигураций)
            affected = set()
            for conf in cve.get("configurations", []):
                for node in conf.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            cpe = match.get("criteria", "")
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                affected.add(f"{parts[3]} {parts[4]}")
            affected_software = list(affected)[:5]

            # Эвристики
            desc_lower = desc.lower()
            attack_type = self._detect_attack_type(desc_lower)
            services, ports = self._extract_services_ports(desc_lower, affected_software)

            item = {
                "id": cve_id,
                "description": desc,
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_software": affected_software,
                "attack_type": attack_type,
                "related_cwe": related_cwe,
                "related_capec": [],
                "related_mitre": [],
                "mitigations": [],
                "requires_service": services,
                "requires_port": ports,
                "prerequisites": []
            }

            # Перевод
            if Config.ENABLE_TRANSLATION and item["description"]:
                item["description"] = self.translator.translate(item["description"])

            # Очистка
            return {k: v.strip() if isinstance(v, str) else [x.strip() if isinstance(x, str) else x for x in v] if isinstance(v, list) else v for k, v in item.items()}
        except Exception:
            return None

    def _detect_attack_type(self, desc: str) -> str:
        if any(kw in desc for kw in ['sql injection', 'sqli']): return "sql_injection"
        elif any(kw in desc for kw in ['xss', 'cross-site scripting']): return "cross_site_scripting"
        elif any(kw in desc for kw in ['remote code execution', 'rce']): return "remote_code_execution"
        elif any(kw in desc for kw in ['brute force', 'password guessing']): return "brute_force"
        elif any(kw in desc for kw in ['denial of service', 'dos', 'ddos']): return "denial_of_service"
        elif any(kw in desc for kw in ['privilege escalation']): return "privilege_escalation"
        elif any(kw in desc for kw in ['deserialization']): return "deserialization_attack"
        return "unknown"

    def _extract_services_ports(self, desc: str, software: list) -> Tuple[list, list]:
        services, ports = set(), set()
        for match in re.finditer(r'(?:port|порт)\s*(\d{1,5})', desc):
            p = int(match.group(1))
            if 1 <= p <= 65535: ports.add(p)
            
        svc_map = {'apache':'web_server','nginx':'web_server','mysql':'database','postgres':'database',
                   'ssh':'ssh','rdp':'rdp','smb':'smb','ftp':'ftp','exchange':'exchange_server','jenkins':'jenkins'}
        for k, v in svc_map.items():
            if k in desc: services.add(v)
        return list(services), list(ports)
