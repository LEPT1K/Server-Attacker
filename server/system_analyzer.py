"""
Модуль анализа системы сервера.
Собирает информацию об ОС, ПО, сервисах, средствах защиты.
Включает встроенный OVAL-парсер базы ФСТЭК (без внешнего OVALDI)
и опциональную интеграцию с Trivy.
"""

import subprocess
import socket
import platform
import os
import re
import sys
import xml.etree.ElementTree as ET
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.models import SystemInfo, InstalledSoftware, SecurityMeasure, OpenPort
from common.config import KNOWN_PORTS
from common.logger import get_server_logger
from server.trivy_scanner import TrivyScanner

logger = get_server_logger()


class SystemAnalyzer:
    """Анализатор серверной системы Windows."""

    def __init__(self, progress_callback=None):
        self.system_info = SystemInfo()
        self.progress_callback = progress_callback or (lambda percent, text: None)

    def analyze(self) -> SystemInfo:
        """Полный анализ системы с передачей прогресса."""
        logger.info("=" * 50)
        logger.info("НАЧАЛО АНАЛИЗА СЕРВЕРНОЙ СИСТЕМЫ")
        logger.info("=" * 50)
        
        self.progress_callback(5, "Сбор информации об ОС...")
        self._collect_os_info()
        
        self.progress_callback(15, "Анализ реестра и установленного ПО...")
        self._collect_installed_software()
        
        self.progress_callback(30, "Сканирование запущенных сервисов...")
        self._collect_running_services()
        
        self.progress_callback(40, "Проверка открытых локальных портов...")
        self._collect_open_ports()
        
        self.progress_callback(50, "Оценка встроенных средств защиты Windows...")
        self._collect_security_measures()
        self._detect_databases()
        self._detect_web_servers()
        self._detect_remote_access()
        
        self.progress_callback(60, "Встроенный быстрый анализ базы уязвимостей ФСТЭК...")
        self._run_fast_fstec_scanner()
        
        self.progress_callback(100, "Анализ системы успешно завершен!")
        logger.info("АНАЛИЗ СИСТЕМЫ ЗАВЕРШЁН")
        return self.system_info

    def _collect_os_info(self):
        self.system_info.os_name = platform.system()
        self.system_info.os_version = platform.version()
        self.system_info.hostname = socket.gethostname()
        try:
            self.system_info.ip_addresses = list(set(
                addr[4][0] for addr in socket.getaddrinfo(socket.gethostname(), None) if addr[0] == socket.AF_INET
            ))
        except Exception:
            self.system_info.ip_addresses = ["127.0.0.1"]

    def _collect_installed_software(self):
        software_list = []
        registry_paths = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        for reg_path in registry_paths:
            try:
                result = subprocess.run(["reg", "query", reg_path, "/s"], capture_output=True, text=True, timeout=30, encoding="cp866", errors="replace")
                if result.returncode == 0:
                    current = {}
                    for line in result.stdout.split("\n"):
                        line = line.strip()
                        if line.startswith("HKEY_"):
                            if current.get("name"):
                                software_list.append(InstalledSoftware(name=current.get("name", ""), version=current.get("version", "")))
                            current = {}
                        elif "DisplayName" in line and "REG_SZ" in line:
                            current["name"] = line.split("REG_SZ")[-1].strip()
                        elif "DisplayVersion" in line and "REG_SZ" in line:
                            current["version"] = line.split("REG_SZ")[-1].strip()
                    if current.get("name"):
                        software_list.append(InstalledSoftware(name=current["name"], version=current.get("version", "")))
            except Exception:
                pass

        seen = set()
        unique = []
        for sw in software_list:
            if sw.name and sw.name.lower() not in seen:
                seen.add(sw.name.lower())
                unique.append(sw)
        self.system_info.installed_software = unique

    def _collect_running_services(self):
        services = []
        try:
            result = subprocess.run(["powershell", "-Command", "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                services = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        except Exception:
            pass
        self.system_info.running_services = services

    def _collect_open_ports(self):
        open_ports = []
        try:
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=30, encoding="cp866", errors="replace")
            if result.returncode == 0:
                seen = set()
                for line in result.stdout.split("\n"):
                    if "LISTENING" in line:
                        parts = line.split()
                        if len(parts) >= 2 and ":" in parts[1]:
                            try:
                                port = int(parts[1].rsplit(":", 1)[-1])
                                if port not in seen:
                                    seen.add(port)
                                    open_ports.append(OpenPort(port=port, service=KNOWN_PORTS.get(port, "Unknown"), protocol="TCP"))
                            except ValueError:
                                pass
        except Exception:
            pass
        self.system_info.open_ports = open_ports

    # ─── Вспомогательные методы запуска команд ───

    @staticmethod
    def _run_ps(command: str, timeout: int = 30):
        """Запуск PowerShell-команды, возвращает распарсенный JSON или None."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True, text=True, timeout=timeout,
                encoding="cp866", errors="replace"
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            return json.loads(result.stdout)
        except Exception:
            return None

    # ─── Средства защиты ───

    def _check_firewall(self) -> tuple:
        """
        Реальная проверка состояния брандмауэра Windows.
        Возвращает (status, details): status = active / inactive / unknown.
        """
        data = self._run_ps(
            "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"
        )
        if data:
            profiles = data if isinstance(data, list) else [data]
            enabled = [p.get("Name", "?") for p in profiles if p.get("Enabled")]
            disabled = [p.get("Name", "?") for p in profiles if not p.get("Enabled")]
            if enabled and not disabled:
                return "active", f"Включён для всех профилей ({', '.join(enabled)})"
            if enabled:
                return "active", f"Включён: {', '.join(enabled)}; выключен: {', '.join(disabled)}"
            return "inactive", f"Выключен для всех профилей ({', '.join(disabled)})"

        # Fallback: netsh
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=15,
                encoding="cp866", errors="replace"
            )
            if result.returncode == 0 and result.stdout:
                states_on = len(re.findall(r"(ON|ВКЛ)", result.stdout, re.IGNORECASE))
                states_off = len(re.findall(r"(OFF|ВЫКЛ)", result.stdout, re.IGNORECASE))
                if states_on or states_off:
                    if states_on and not states_off:
                        return "active", "Включён для всех профилей (netsh)"
                    if states_on:
                        return "active", f"Частично включён (netsh: {states_on} вкл, {states_off} выкл)"
                    return "inactive", "Выключен для всех профилей (netsh)"
        except Exception:
            pass
        return "unknown", "Не удалось определить состояние брандмауэра"

    def _check_antivirus(self) -> tuple:
        """
        Реальная проверка антивирусных продуктов через SecurityCenter2
        и состояния Windows Defender.
        Возвращает (status, details): status = active / inactive / unknown.
        """
        products = self._run_ps(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
            "| Select-Object displayName,productState | ConvertTo-Json"
        )

        defender = self._run_ps(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled "
            "| ConvertTo-Json"
        )
        defender_note = ""
        if isinstance(defender, dict):
            av_on = defender.get("AntivirusEnabled")
            rtp_on = defender.get("RealTimeProtectionEnabled")
            defender_note = f"Defender: AV={'вкл' if av_on else 'выкл'}, защита в реальном времени={'вкл' if rtp_on else 'выкл'}"

        if products:
            items = products if isinstance(products, list) else [products]
            names = []
            any_enabled = False
            for p in items:
                name = p.get("displayName", "Неизвестный продукт")
                names.append(name)
                try:
                    state = int(p.get("productState", 0))
                    if state & 0x1000:  # бит «защита включена»
                        any_enabled = True
                except (TypeError, ValueError):
                    pass
            details = f"Продукты: {', '.join(names)}"
            if defender_note:
                details += f". {defender_note}"
            return ("active" if any_enabled else "inactive"), details

        if defender_note:
            av_on = defender.get("AntivirusEnabled") if isinstance(defender, dict) else None
            return ("active" if av_on else "inactive"), defender_note

        return "unknown", "Антивирусные продукты не обнаружены или состояние недоступно"

    def _collect_security_measures(self):
        fw_status, fw_details = self._check_firewall()
        self.system_info.firewall_active = fw_status == "active"

        av_status, av_details = self._check_antivirus()
        self.system_info.antivirus_active = av_status == "active"

        self.system_info.security_measures = [
            SecurityMeasure("Брандмауэр Windows", "firewall", fw_status, fw_details),
            SecurityMeasure("Антивирус", "antivirus", av_status, av_details),
        ]

    # Сигнатуры: имя -> (подстроки в ПО, подстроки в службах, порты)
    DB_SIGNATURES = {
        "Microsoft SQL Server": (["sql server"], ["mssql"], [1433]),
        "MySQL": (["mysql"], ["mysql"], [3306]),
        "PostgreSQL": (["postgresql"], ["postgresql"], [5432]),
        "Oracle Database": (["oracle"], ["oracleservice", "oradb", "tnslistener"], [1521]),
        "MongoDB": (["mongodb"], ["mongodb"], [27017]),
        "Redis": (["redis"], ["redis"], [6379]),
    }

    WEB_SERVER_SIGNATURES = {
        "Microsoft IIS": (["internet information services", " iis"], ["w3svc", "was", "iisadmin"], []),
        "Apache": (["apache", "httpd"], ["apache", "httpd"], []),
        "nginx": (["nginx"], ["nginx"], []),
    }

    WEB_PORTS = (80, 443, 8080, 8443)

    def _software_names(self) -> list:
        names = []
        for sw in self.system_info.installed_software:
            if hasattr(sw, "name") and sw.name:
                names.append(sw.name.lower())
            elif isinstance(sw, dict) and sw.get("name"):
                names.append(sw["name"].lower())
        return names

    def _open_port_nums(self) -> set:
        ports = set()
        for p in self.system_info.open_ports:
            if hasattr(p, "port"):
                ports.add(p.port)
            elif isinstance(p, dict):
                ports.add(p.get("port", 0))
        return ports

    def _detect_databases(self):
        sw_names = self._software_names()
        services = [s.lower() for s in self.system_info.running_services]
        ports = self._open_port_nums()

        found = []
        for db_name, (sw_sig, svc_sig, db_ports) in self.DB_SIGNATURES.items():
            by_sw = any(sig in name for sig in sw_sig for name in sw_names)
            by_svc = any(sig in svc for sig in svc_sig for svc in services)
            by_port = bool(set(db_ports) & ports)
            if by_sw or by_svc or by_port:
                found.append(db_name)

        self.system_info.has_database = bool(found)
        self.system_info.database_types = found

    def _detect_web_servers(self):
        sw_names = self._software_names()
        services = [s.lower() for s in self.system_info.running_services]
        ports = self._open_port_nums()

        found = []
        for srv_name, (sw_sig, svc_sig, _) in self.WEB_SERVER_SIGNATURES.items():
            by_sw = any(sig in name for sig in sw_sig for name in sw_names)
            by_svc = any(sig in svc for sig in svc_sig for svc in services)
            if by_sw or by_svc:
                found.append(srv_name)

        web_ports = sorted(set(self.WEB_PORTS) & ports)
        if web_ports and not found:
            found.append(f"Веб-сервер (порты: {', '.join(map(str, web_ports))})")

        self.system_info.has_web_server = bool(found)
        self.system_info.web_server_types = found

    def _detect_remote_access(self):
        self.system_info.has_rdp_enabled = any(p.port == 3389 for p in self.system_info.open_ports)
        self.system_info.has_smb_enabled = any(p.port == 445 for p in self.system_info.open_ports)
        self.system_info.has_ftp_enabled = any(p.port == 21 for p in self.system_info.open_ports)

    def _run_fast_fstec_scanner(self):
        """Встроенный потоковый парсер XML-базы ФСТЭК (без внешнего OVALDI)."""
        logger.info("Запуск встроенного Python-сканера OVAL (ФСТЭК)...")

        base_dir = os.path.dirname(os.path.dirname(__file__))
        tools_dir = os.path.join(base_dir, "tools")

        # Ищем любой XML файл базы в папке tools
        definitions_path = None
        for root_dir, _, files in os.walk(tools_dir):
            for file in files:
                if file.endswith(".xml") and ("fstec" in file.lower() or "oval" in file.lower()) and "patched" not in file.lower():
                    definitions_path = os.path.join(root_dir, file)
                    break
            if definitions_path: break

        if not definitions_path:
            logger.warning("  [!] База уязвимостей (XML-файл) не найдена в папке tools/. Пропуск.")
            self.progress_callback(95, "Сканирование пропущено (нет базы данных XML).")
            return

        try:
            self.progress_callback(70, "Анализ базы ФСТЭК в оперативной памяти...")
            logger.info(f"  Используется база: {definitions_path}")

            # Подготавливаем списки установленного ПО для поиска
            sw_list = [sw.name.lower() for sw in self.system_info.installed_software if sw.name and len(sw.name) > 3]
            os_info = f"{self.system_info.os_name} {self.system_info.os_version}".lower()

            findings = []
            seen_keys = set()

            # iterparse читает файл потоково, не загружая его целиком в память
            context = ET.iterparse(definitions_path, events=('end',))
            for event, elem in context:
                if elem.tag.endswith('definition') and elem.get('class') == 'vulnerability':
                    title = ""
                    refs = []
                    for child in elem.iter():
                        if child.tag.endswith('title') and child.text:
                            title = child.text
                        elif child.tag.endswith('reference'):
                            ref_id = child.get('ref_id')
                            if ref_id and (ref_id.startswith('CVE') or ref_id.startswith('BDU')):
                                refs.append(ref_id)

                    if title and refs:
                        t_lower = title.lower()
                        matched_sw = None

                        # Уязвимости самой ОС
                        if "windows 10" in t_lower and "windows 10" in os_info:
                            matched_sw = f"{self.system_info.os_name} {self.system_info.os_version}"
                        else:
                            # Уязвимости стороннего ПО
                            for sw in sw_list:
                                if sw in t_lower:
                                    matched_sw = sw
                                    break

                        if matched_sw:
                            for ref in refs:
                                key = (ref, matched_sw)
                                if key not in seen_keys:
                                    seen_keys.add(key)
                                    findings.append({
                                        "id": ref,
                                        "title": title[:300],
                                        "matched_software": matched_sw,
                                    })

                    elem.clear()

            self.system_info.fstec_vulnerabilities = findings

            self.system_info.security_measures.append(
                SecurityMeasure(
                    name="Встроенный OVAL-сканер",
                    category="vulnerability_scanner",
                    status="active",
                    details=f"База: ФСТЭК. Найдено потенциальных уязвимостей локального ПО: {len(findings)}"
                )
            )

            self.progress_callback(95, f"Успешно! Найдено {len(findings)} совпадений в базе.")
            logger.info(f"  [+] Встроенный сканер завершил работу. Найдено совпадений: {len(findings)}")

        except Exception as e:
            logger.error(f"  [!] Ошибка встроенного сканера: {e}")
            self.progress_callback(95, "Ошибка при чтении базы данных.")

    def run_trivy_scan(self, trivy_path: str = "") -> dict:
        """
        Запускает сканирование Trivy и сохраняет результаты в system_info.
        
        Args:
            trivy_path: Путь к исполняемому файлу Trivy
            
        Returns:
            dict: Сводка результатов сканирования
        """
        logger.info("=" * 60)
        logger.info(" TRIVY: ЗАПУСК СКАНИРОВАНИЯ УЯЗВИМОСТЕЙ")
        logger.info("=" * 60)
        
        self.progress_callback(0, "Инициализация Trivy...")
        
        try:
            scanner = TrivyScanner(
                trivy_path=trivy_path,
                progress_callback=self.progress_callback
            )
            
            if not scanner.is_available():
                logger.warning("[TRIVY] Trivy недоступен или не найден")
                self.progress_callback(100, "Trivy недоступен")
                return {"error": "Trivy не найден или недоступен"}
            
            # Запускаем сканирование
            scan_result = scanner.scan_local_system(security_checks=False)
            
            # Сохраняем результаты в system_info
            self.system_info.trivy_scan_result = {
                "vulnerabilities": [
                    {
                        "vuln_id": v.vuln_id,
                        "pkg_name": v.pkg_name,
                        "installed_version": v.installed_version,
                        "fixed_version": v.fixed_version,
                        "severity": v.severity,
                        "title": v.title,
                        "description": v.description[:300],
                        "cwe_ids": v.cwe_ids,
                        "capec_ids": v.capec_ids,
                    }
                    for v in scan_result.vulnerabilities
                ],
                "summary": scanner.get_summary()
            }
            
            # Добавляем информацию о сканировании в security_measures
            summary = scanner.get_summary()
            if not summary.get("error"):
                self.system_info.security_measures.append(
                    SecurityMeasure(
                        name="Trivy Scanner",
                        category="vulnerability_scanner",
                        status="active",
                        details=f"Найдено уязвимостей: {summary.get('total_vulns', 0)} "
                                f"(CRITICAL: {summary.get('critical', 0)}, "
                                f"HIGH: {summary.get('high', 0)})"
                    )
                )
            
            # Сохраняем историю сканирования Trivy в папку data
            try:
                data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
                os.makedirs(data_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                save_path = os.path.join(data_dir, f"trivy_scan_{timestamp}.json")
                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(self.system_info.trivy_scan_result, f, ensure_ascii=False, indent=4)
                logger.info(f"Успех: История Trivy успешно сохранена в файл {save_path}")
            except Exception as save_err:
                logger.error(f"Ошибка при сохранении истории Trivy: {save_err}")

            logger.info(f"[TRIVY] Сканирование завершено. Найдено {summary.get('total_vulns', 0)} уязвимостей")
            return summary
            
        except Exception as e:
            logger.error(f"[TRIVY] Ошибка сканирования: {e}", exc_info=True)
            self.progress_callback(100, f"Ошибка Trivy: {str(e)}")
            return {"error": str(e)}

    def get_summary(self) -> dict:
        summary = {
            "os": f"{self.system_info.os_name} {self.system_info.os_version}",
            "hostname": self.system_info.hostname,
            "ip_addresses": self.system_info.ip_addresses,
            "installed_software_count": len(self.system_info.installed_software),
            "running_services_count": len(self.system_info.running_services),
            "open_ports_count": len(self.system_info.open_ports),
            "has_database": self.system_info.has_database,
            "database_types": self.system_info.database_types,
            "has_web_server": self.system_info.has_web_server,
            "web_server_types": self.system_info.web_server_types,
            "has_rdp": self.system_info.has_rdp_enabled,
            "has_smb": self.system_info.has_smb_enabled,
            "has_ftp": self.system_info.has_ftp_enabled,
            "firewall": self.system_info.firewall_active,
            "antivirus": self.system_info.antivirus_active,
            "security_measures": [
                {"name": m.name, "status": m.status, "details": m.details}
                for m in self.system_info.security_measures
            ]
        }
        
        # Добавляем информацию о ФСТЭК-находках
        summary["fstec_findings_count"] = len(self.system_info.fstec_vulnerabilities or [])

        # Добавляем информацию о Trivy если есть результаты
        if self.system_info.trivy_scan_result:
            trivy_summary = self.system_info.trivy_scan_result.get("summary", {})
            summary["trivy_scan"] = {
                "completed": True,
                "total_vulns": trivy_summary.get("total_vulns", 0),
                "critical": trivy_summary.get("critical", 0),
                "high": trivy_summary.get("high", 0),
                "medium": trivy_summary.get("medium", 0),
                "low": trivy_summary.get("low", 0),
                "scan_duration": trivy_summary.get("scan_duration", ""),
            }
        else:
            summary["trivy_scan"] = {
                "completed": False,
                "total_vulns": 0,
            }
        
        return summary