"""
Модуль корреляции атак.
Сопоставляет обнаруженные атакующим агентом векторы атак
с реальной конфигурацией сервера и базами CVE/CWE/CAPEC/MITRE ATT&CK.
Определяет реализуемость каждой атаки.
Дополнительно использует результаты Trivy и встроенного ФСТЭК-сканера.
"""

import os
import sys
import time
from dataclasses import asdict
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.models import (
    SystemInfo, ScanResult, VulnerabilityMatch,
    AttackFeasibility, Severity, AttackVector
)
from common.versioning import parse_version, version_in_range
from server.vulnerability_db import VulnerabilityDatabase
from server.trivy_correlator import TrivyCorrelator
from server.trivy_scanner import TrivyScanResult
from common.logger import get_server_logger

logger = get_server_logger()


class AttackCorrelator:
    """Движок корреляции атак с конфигурацией сервера."""

    def __init__(self, system_info: SystemInfo, vuln_db: VulnerabilityDatabase, trivy_result=None):
        self.system_info = system_info
        self.vuln_db = vuln_db
        self.trivy_result = trivy_result  # Результаты сканирования Trivy
        self.results: list[VulnerabilityMatch] = []
        self.progress_callback = None  # Callback для прогресса

    def set_progress_callback(self, callback):
        """Устанавливает callback для отслеживания прогресса."""
        self.progress_callback = callback
    
    def _report_progress(self, percent: int, message: str):
        """Отправляет прогресс через callback."""
        if self.progress_callback:
            self.progress_callback(percent, message)

    def correlate(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """Основной метод корреляции."""
        start_time = time.time()
        logger.info("=" * 70)
        logger.info(" НАЧАЛО КОРРЕЛЯЦИИ АТАК С КОНФИГУРАЦИЕЙ СЕРВЕРА")
        logger.info("=" * 70)
        
        self._report_progress(0, "Начало корреляции атак...")
        self.results = []

        # 1. Анализ каждого вектора атаки от атакующего агента
        total_vectors = len(scan_result.attack_vectors)
        logger.info(f"[1/3] Векторов атак для анализа: {total_vectors}")
        self._report_progress(5, f"Анализ {total_vectors} векторов атак...")
        
        vector_start = time.time()
        for i, av in enumerate(scan_result.attack_vectors, 1):
            if isinstance(av, dict):
                av = AttackVector(**av)
            
            # Прогресс: 5-50% для анализа векторов
            percent = 5 + int((i / total_vectors) * 45) if total_vectors > 0 else 5
            self._report_progress(percent, f"Анализ вектора {i}/{total_vectors}...")
            
            # Логируем каждые 10 векторов для отслеживания прогресса
            if i % 10 == 0 or i == total_vectors:
                elapsed = time.time() - vector_start
                logger.info(f"  [{i}/{total_vectors}] Векторов обработано ({elapsed:.2f}s)...")
            
            matches = self._analyze_attack_vector(av)
            self.results.extend(matches)
        
        vector_elapsed = time.time() - vector_start
        logger.info(f"[1/3] Завершено: {len(self.results)} результатов за {vector_elapsed:.2f}s")

        # 2. Дополнительно: анализ на основе открытых портов и CVE
        logger.info("[2/3] Анализ уязвимостей по портам...")
        self._report_progress(55, "Анализ уязвимостей по портам...")
        port_start = time.time()
        port_based = self._analyze_port_based_vulnerabilities(scan_result)
        self.results.extend(port_based)
        port_elapsed = time.time() - port_start
        logger.info(f"[2/3] Завершено: +{len(port_based)} результатов за {port_elapsed:.2f}s")

        # 3. Анализ на основе установленного ПО и известных CVE
        logger.info("[3/3] Анализ уязвимостей установленного ПО...")
        self._report_progress(75, "Анализ уязвимостей установленного ПО...")
        sw_start = time.time()
        sw_based = self._analyze_software_vulnerabilities()
        self.results.extend(sw_based)
        sw_elapsed = time.time() - sw_start
        logger.info(f"[3/3] Завершено: +{len(sw_based)} результатов за {sw_elapsed:.2f}s")

        # 3.5. Находки встроенного ФСТЭК-сканера (внутреннее сканирование)
        logger.info("[3.5] Интеграция находок ФСТЭК-сканера...")
        self._report_progress(85, "Интеграция находок ФСТЭК-сканера...")
        fstec_based = self._analyze_fstec_vulnerabilities()
        self.results.extend(fstec_based)
        logger.info(f"[3.5] Завершено: +{len(fstec_based)} результатов")

        # Убираем дубликаты
        logger.info("Дедупликация результатов...")
        self._report_progress(90, "Дедупликация результатов...")
        dedup_start = time.time()
        before_count = len(self.results)
        self.results = self._deduplicate(self.results)
        dedup_elapsed = time.time() - dedup_start
        logger.info(f"Дедупликация: {before_count} -> {len(self.results)} за {dedup_elapsed:.2f}s")

        # 4. КОРРЕЛЯЦИЯ С TRIVY (если есть данные)
        if self.trivy_result:
            logger.info("[4/4] Корреляция с данными Trivy...")
            self._report_progress(92, "Корреляция с Trivy...")
            trivy_start = time.time()
            trivy_enhanced = self._correlate_with_trivy(scan_result)
            self.results = trivy_enhanced
            trivy_elapsed = time.time() - trivy_start
            logger.info(f"[4/4] Корреляция с Trivy завершена за {trivy_elapsed:.2f}s")
        else:
            logger.warning("[4/4] Данные Trivy отсутствуют - корреляция без подтверждения уязвимостей")
            self._report_progress(92, "ВНИМАНИЕ: Trivy не запущен - корреляция без подтверждения")

        # Присвоение обнаруженного ПО к уязвимостям (Умная корреляция)
        logger.info("Присвоение целевого ПО к уязвимостям...")
        self._report_progress(95, "Присвоение целевого ПО к уязвимостям...")
        
        # Шаг 1: Строим карту CVE -> ПО из всех доступных источников
        software_map = self._build_software_map(scan_result)
        
        # Шаг 2: Применяем карту к результатам
        for match in self.results:
            if match.target_software:  # Уже установлено из предыдущих шагов
                continue
            
            # Пробуем найти ПО для каждого CVE в списке
            if match.cve_id:
                for cve in match.cve_id.split(","):
                    cve = cve.strip()
                    if cve in software_map:
                        match.target_software = software_map[cve]
                        break
                
                # Если не нашли по CVE, пробуем по attack_vector_id
                if not match.target_software and match.attack_vector_id:
                    # Ищем ПО по имени атаки/вектора
                    for key, sw in software_map.items():
                        if match.attack_name.lower() in sw.lower() or sw.lower() in match.attack_name.lower():
                            match.target_software = sw
                            break
            
            # Фоллбэк: если всё ещё нет ПО, используем эвристику по порту
            if not match.target_software:
                match.target_software = self._guess_software_from_port(match, scan_result)
        
        logger.info(f"Присвоено ПО: {sum(1 for m in self.results if m.target_software)}/{len(self.results)} результатов")

        total_elapsed = time.time() - start_time
        self._report_progress(100, f"Корреляция завершена. Найдено {len(self.results)} уникальных результатов")
        logger.info("=" * 70)
        logger.info(f" КОРРЕЛЯЦИЯ ЗАВЕРШЕНА ЗА {total_elapsed:.2f} СЕК")
        logger.info(f" Уникальных результатов: {len(self.results)}")
        if self.trivy_result:
            logger.info(f" ✅ Trivy подтвердил уязвимости")
        else:
            logger.warning(f" ⚠️ Trivy НЕ запущен - реализуемость атак НЕ подтверждена!")
        logger.info("=" * 70)
        return self.results

    def _analyze_attack_vector(self, av: AttackVector) -> list[VulnerabilityMatch]:
        """Анализ одного вектора атаки."""
        matches = []

        # Поиск соответствующих CVE по типу атаки и сервису
        related_cves = []
        if av.target_service:
            related_cves.extend(self.vuln_db.find_cves_by_service(av.target_service))
        if av.target_port:
            related_cves.extend(self.vuln_db.find_cves_by_port(av.target_port))

        # Убираем дубликаты CVE
        seen_ids = set()
        unique_cves = []
        for cve in related_cves:
            if cve["id"] not in seen_ids:
                seen_ids.add(cve["id"])
                unique_cves.append(cve)

        for cve in unique_cves:
            feasibility, reason = self._evaluate_feasibility(cve, av)
            chain = self.vuln_db.get_full_chain(cve)
            mitigations = self.vuln_db.get_all_mitigations(cve)

            cwe_ids = ", ".join(cve.get("related_cwe", []))
            capec_ids = ", ".join(cve.get("related_capec", []))
            mitre_ids = ", ".join(cve.get("related_mitre", []))

            recommendation = self._generate_recommendation(cve, feasibility, mitigations)

            match = VulnerabilityMatch(
                cve_id=cve["id"],
                cwe_id=cwe_ids,
                capec_id=capec_ids,
                mitre_technique=mitre_ids,
                attack_vector_id=av.id,
                attack_name=av.name,
                description=cve["description"],
                severity=cve.get("severity", Severity.MEDIUM.value),
                feasibility=feasibility.value,
                reason=reason,
                recommendation=recommendation,
            )
            matches.append(match)

        return matches

    def _evaluate_feasibility(self, cve: dict, av: AttackVector) -> tuple:
        """
        Оценка реализуемости атаки на основе конфигурации сервера.
        Это ключевая логика — сопоставление «что нашёл атакующий» с «что реально есть на сервере».
        """
        prerequisites = cve.get("prerequisites", [])
        required_services = cve.get("requires_service", [])
        required_ports = cve.get("requires_port", [])
        attack_type = cve.get("attack_type", "")

        # Собираем информацию о сервере
        open_port_nums = set()
        if isinstance(self.system_info.open_ports, list):
            for p in self.system_info.open_ports:
                if hasattr(p, 'port'):
                    open_port_nums.add(p.port)
                elif isinstance(p, dict):
                    open_port_nums.add(p.get("port", 0))

        running_svc_lower = set(s.lower() for s in self.system_info.running_services)
        sw_names_lower = set()
        sw_versions = {}
        if isinstance(self.system_info.installed_software, list):
            for sw in self.system_info.installed_software:
                if hasattr(sw, 'name'):
                    sw_names_lower.add(sw.name.lower())
                    sw_versions[sw.name.lower()] = getattr(sw, "version", "") or ""
                elif isinstance(sw, dict):
                    name = sw.get("name", "").lower()
                    sw_names_lower.add(name)
                    sw_versions[name] = sw.get("version", "") or ""

        reasons = []

        # === Проверка SQL-инъекций ===
        if attack_type == "sql_injection":
            if not self.system_info.has_database:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "На сервере не обнаружено ни одной СУБД. SQL-инъекция невозможна при отсутствии базы данных."
                )
            if not self.system_info.has_web_server:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "На сервере нет веб-сервера. SQL-инъекция через веб-интерфейс невозможна."
                )

        # === Проверка XSS ===
        if attack_type == "cross_site_scripting":
            if not self.system_info.has_web_server:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "На сервере нет веб-сервера. XSS-атака невозможна."
                )

        # === Проверка RDP-атак ===
        if "rdp" in required_services:
            if not self.system_info.has_rdp_enabled:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "RDP отключён на сервере. Атаки через RDP невозможны."
                )
            if 3389 not in open_port_nums:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Порт 3389 (RDP) закрыт. Удалённый доступ по RDP недоступен."
                )
            reasons.append("RDP включён и порт 3389 открыт")

        # === Проверка SMB-атак ===
        if "smb" in required_services:
            if not self.system_info.has_smb_enabled:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "SMB не обнаружен (порт 445 закрыт). Атаки через SMB невозможны."
                )
            reasons.append("SMB активен (порт 445 открыт)")

        # === Проверка FTP-атак ===
        if "ftp" in required_services:
            if not self.system_info.has_ftp_enabled:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "FTP-сервер не обнаружен (порт 21 закрыт). Атаки через FTP невозможны."
                )
            reasons.append("FTP-сервер активен")

        # === Проверка SSH-атак ===
        if "ssh" in required_services:
            if 22 not in open_port_nums:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "SSH-сервер не обнаружен (порт 22 закрыт). Атаки через SSH невозможны."
                )
            reasons.append("SSH-сервер активен")

        # === Проверка веб-атак ===
        if "web_server" in required_services or "web_application" in required_services:
            if not self.system_info.has_web_server:
                web_ports = {80, 443, 8080, 8443}
                if not web_ports.intersection(open_port_nums):
                    return (
                        AttackFeasibility.NOT_FEASIBLE,
                        "Веб-сервер не обнаружен. Веб-атаки невозможны."
                    )
            reasons.append("Веб-сервер обнаружен")

        # === Проверка Exchange ===
        if "exchange_server" in required_services:
            exchange_found = any("exchange" in sw for sw in sw_names_lower)
            if not exchange_found:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Microsoft Exchange Server не установлен. Атака не применима."
                )
            reasons.append("Exchange Server обнаружен")

        # === Проверка Active Directory ===
        if "active_directory" in required_services or "domain_controller" in prerequisites:
            ad_services = {"ntds", "kdc", "dns", "adws"}
            if not ad_services.intersection(running_svc_lower):
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Сервер не является контроллером домена Active Directory. Атака не применима."
                )
            reasons.append("Active Directory обнаружен")

        # === Проверка Print Spooler ===
        if "print_spooler" in required_services:
            if "spooler" not in running_svc_lower:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Служба Print Spooler не запущена. Атака PrintNightmare не применима."
                )
            reasons.append("Print Spooler запущен")

        # === Проверка Java / Log4j ===
        if "java_application" in required_services:
            java_found = any("java" in sw or "jre" in sw or "jdk" in sw for sw in sw_names_lower)
            if not java_found:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Java не установлена. Атаки на Java-приложения невозможны."
                )
            reasons.append("Java обнаружена")

        # === Проверка специфичного ПО (с учётом версий) ===
        version_spec = cve.get("affected_versions") or {}
        version_excluded = False
        version_unknown = False
        for sw_name in cve.get("affected_software", []):
            sw_lower = sw_name.lower()
            matched_name = next(
                (n for n in sw_names_lower if sw_lower in n or n in sw_lower),
                None
            )
            if not matched_name:
                continue
            installed_ver = sw_versions.get(matched_name, "")
            if version_spec:
                if parse_version(installed_ver) is None:
                    version_unknown = True
                    reasons.append(f"Обнаружено ПО: {sw_name} (версия не определена — требуется проверка)")
                elif version_in_range(installed_ver, version_spec):
                    reasons.append(f"Обнаружено уязвимое ПО: {sw_name} v.{installed_ver}")
                else:
                    version_excluded = True
            else:
                reasons.append(f"Обнаружено уязвимое ПО: {sw_name}")

        # Если все найденные экземпляры ПО имеют версии вне уязвимого диапазона
        if version_excluded and not version_unknown and not any("уязвимое ПО" in r for r in reasons):
            return (
                AttackFeasibility.NOT_FEASIBLE,
                f"Установленные версии ПО ({', '.join(cve.get('affected_software', []))}) "
                f"вне уязвимого диапазона ({self._format_version_spec(version_spec)}). Атака не реализуема."
            )

        # === Проверка необходимых портов ===
        for port in required_ports:
            if port not in open_port_nums:
                reasons.append(f"Порт {port} закрыт")

        if required_ports and not any(p in open_port_nums for p in required_ports):
            return (
                AttackFeasibility.NOT_FEASIBLE,
                f"Необходимые порты ({', '.join(map(str, required_ports))}) закрыты. Атака не может быть проведена."
            )

        # === Учёт средств защиты (по реальным статусам) ===
        sec_status = {}
        for m in (self.system_info.security_measures or []):
            if isinstance(m, dict):
                cat, st = m.get("category"), m.get("status")
            else:
                cat, st = getattr(m, "category", None), getattr(m, "status", None)
            if cat:
                sec_status[cat] = st

        protection_notes = []
        fw_status = sec_status.get("firewall")
        if fw_status == "active" or (fw_status is None and self.system_info.firewall_active):
            protection_notes.append("Брандмауэр активен (может блокировать часть атак)")
        elif fw_status == "inactive":
            protection_notes.append("Брандмауэр ВЫКЛЮЧЕН — повышенный риск")
        av_status = sec_status.get("antivirus")
        if av_status == "active" or (av_status is None and self.system_info.antivirus_active):
            protection_notes.append("Антивирус активен (может обнаружить эксплоит)")
        elif av_status == "inactive":
            protection_notes.append("Антивирус ВЫКЛЮЧЕН — повышенный риск")

        # === Финальная оценка ===
        if reasons:
            reason_text = ". ".join(reasons)
            if protection_notes:
                reason_text += ". Средства защиты: " + "; ".join(protection_notes)

            if any("уязвимое ПО" in r for r in reasons):
                return (AttackFeasibility.FEASIBLE, reason_text)
            else:
                return (AttackFeasibility.PARTIALLY_FEASIBLE, reason_text)

        # Если нет определённой оценки
        return (
            AttackFeasibility.REQUIRES_ANALYSIS,
            "Недостаточно данных для автоматической оценки. Требуется ручной анализ."
            + (f" Средства защиты: {'; '.join(protection_notes)}" if protection_notes else "")
        )

    def _analyze_port_based_vulnerabilities(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """Анализ уязвимостей на основе обнаруженных открытых портов."""
        matches = []
        seen_cves = set(m.cve_id for m in self.results)

        for port_info in scan_result.open_ports:
            port = port_info.port if hasattr(port_info, 'port') else port_info.get("port", 0)
            cves = self.vuln_db.find_cves_by_port(port)
            for cve in cves:
                if cve["id"] in seen_cves:
                    continue
                seen_cves.add(cve["id"])

                dummy_av = AttackVector(
                    id=f"port-{port}",
                    name=f"Атака через порт {port}",
                    description=f"Вектор атаки через открытый порт {port}",
                    target_port=port,
                )
                feasibility, reason = self._evaluate_feasibility(cve, dummy_av)
                mitigations = self.vuln_db.get_all_mitigations(cve)
                recommendation = self._generate_recommendation(cve, feasibility, mitigations)

                match = VulnerabilityMatch(
                    cve_id=cve["id"],
                    cwe_id=", ".join(cve.get("related_cwe", [])),
                    capec_id=", ".join(cve.get("related_capec", [])),
                    mitre_technique=", ".join(cve.get("related_mitre", [])),
                    attack_vector_id=dummy_av.id,
                    attack_name=dummy_av.name,
                    description=cve["description"],
                    severity=cve.get("severity", "MEDIUM"),
                    feasibility=feasibility.value,
                    reason=reason,
                    recommendation=recommendation,
                )
                matches.append(match)

        return matches

    def _analyze_software_vulnerabilities(self) -> list[VulnerabilityMatch]:
        """Анализ уязвимостей установленного ПО (с фильтрацией по версиям)."""
        matches = []
        seen_cves = set(m.cve_id for m in self.results)

        for sw in self.system_info.installed_software:
            sw_name = sw.name if hasattr(sw, 'name') else sw.get("name", "")
            sw_version = (sw.version if hasattr(sw, 'version') else sw.get("version", "")) or ""
            cves = self.vuln_db.find_cves_by_software(sw_name)
            for cve in cves:
                if cve["id"] in seen_cves:
                    continue
                # Если у CVE задан уязвимый диапазон и версия известна —
                # пропускаем ПО вне диапазона
                spec = cve.get("affected_versions") or {}
                if spec and parse_version(sw_version) is not None \
                        and not version_in_range(sw_version, spec):
                    continue
                seen_cves.add(cve["id"])

                dummy_av = AttackVector(
                    id=f"sw-{sw_name[:20]}",
                    name=f"Атака на {sw_name}",
                    description=f"Эксплуатация уязвимости в {sw_name}",
                    target_service=sw_name,
                )
                feasibility, reason = self._evaluate_feasibility(cve, dummy_av)
                mitigations = self.vuln_db.get_all_mitigations(cve)
                recommendation = self._generate_recommendation(cve, feasibility, mitigations)

                match = VulnerabilityMatch(
                    cve_id=cve["id"],
                    cwe_id=", ".join(cve.get("related_cwe", [])),
                    capec_id=", ".join(cve.get("related_capec", [])),
                    mitre_technique=", ".join(cve.get("related_mitre", [])),
                    attack_vector_id=dummy_av.id,
                    attack_name=dummy_av.name,
                    description=cve["description"],
                    severity=cve.get("severity", "MEDIUM"),
                    feasibility=feasibility.value,
                    reason=reason,
                    recommendation=recommendation,
                )
                matches.append(match)

        return matches

    @staticmethod
    def _format_version_spec(spec: dict) -> str:
        """Человекочитаемое представление уязвимого диапазона версий."""
        labels = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "eq": "="}
        return " и ".join(
            f"{labels[k]} {v}" for k, v in spec.items() if v is not None and k in labels
        )

    def _analyze_fstec_vulnerabilities(self) -> list[VulnerabilityMatch]:
        """Интеграция находок встроенного ФСТЭК/OVAL-сканера в результаты."""
        matches = []
        seen_cves = set(m.cve_id for m in self.results)

        findings = getattr(self.system_info, "fstec_vulnerabilities", None) or []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            fid = finding.get("id", "")
            if not fid or not fid.startswith("CVE") or fid in seen_cves:
                continue
            seen_cves.add(fid)

            sw = finding.get("matched_software", "")
            title = finding.get("title", "")

            # Связываем с локальной базой CVE для цепочки CWE/CAPEC/MITRE
            local = self.vuln_db.get_cve_by_id(fid)
            if local:
                cwe_ids = ", ".join(local.get("related_cwe", []))
                capec_ids = ", ".join(local.get("related_capec", []))
                mitre_ids = ", ".join(local.get("related_mitre", []))
                severity = local.get("severity", "MEDIUM")
                description = local.get("description") or title
                mitigations = self.vuln_db.get_all_mitigations(local)
            else:
                cwe_ids = capec_ids = mitre_ids = ""
                severity = "MEDIUM"
                description = title
                mitigations = []

            recommendation = "Обновить ПО до актуальной версии; проверить наличие исправления у вендора."
            if mitigations:
                recommendation += "\nРекомендуемые меры защиты:\n" + "\n".join(
                    f"  {i}. {m}" for i, m in enumerate(mitigations, 1)
                )

            matches.append(VulnerabilityMatch(
                cve_id=fid,
                cwe_id=cwe_ids,
                capec_id=capec_ids,
                mitre_technique=mitre_ids,
                attack_vector_id=f"fstec-{fid}",
                attack_name=f"ФСТЭК: {fid}",
                description=f"[Внутреннее сканирование ФСТЭК] {description}",
                severity=severity,
                feasibility=AttackFeasibility.PARTIALLY_FEASIBLE.value,
                reason=(f"Обнаружено внутренним ФСТЭК-сканером на сервере"
                        + (f" (ПО: {sw})" if sw else "")
                        + ". Требуется подтверждение версии."),
                recommendation=recommendation,
                target_software=sw,
            ))

        return matches

    def _generate_recommendation(self, cve: dict, feasibility: AttackFeasibility, mitigations: list) -> str:
        """Генерация рекомендации по защите."""
        if feasibility == AttackFeasibility.NOT_FEASIBLE:
            return (
                "Атака не реализуема в текущей конфигурации. "
                "Рекомендуется поддерживать текущие настройки безопасности."
            )

        recommendations = []
        if feasibility in (AttackFeasibility.FEASIBLE, AttackFeasibility.PARTIALLY_FEASIBLE):
            recommendations.append("ВНИМАНИЕ: Атака потенциально реализуема!")

        if mitigations:
            recommendations.append("Рекомендуемые меры защиты:")
            for i, mit in enumerate(mitigations, 1):
                recommendations.append(f"  {i}. {mit}")

        # Добавляем общие рекомендации
        if cve.get("severity") in ("CRITICAL", "HIGH"):
            recommendations.append("ПРИОРИТЕТ: Высокий. Требуется немедленное внимание!")

        return "\n".join(recommendations) if recommendations else "Требуется ручной анализ."


    # =========================================================================
    # НОВЫЙ БЛОК: УМНАЯ АГРЕГАЦИЯ ДУБЛИКАТОВ
    # =========================================================================

    def _get_max_severity(self, sev1: str, sev2: str) -> str:
        """Сравнение критичности (возвращает наивысшую)."""
        weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        w1 = weights.get(str(sev1).upper(), 0)
        w2 = weights.get(str(sev2).upper(), 0)
        return sev1 if w1 >= w2 else sev2

    def _get_worst_feasibility(self, feas1: str, feas2: str) -> str:
        """Сравнение реализуемости (возвращает наихудший/самый опасный статус)."""
        weights = {
            AttackFeasibility.FEASIBLE.value: 4,
            AttackFeasibility.PARTIALLY_FEASIBLE.value: 3,
            AttackFeasibility.REQUIRES_ANALYSIS.value: 2,
            AttackFeasibility.NOT_FEASIBLE.value: 1
        }
        w1 = weights.get(feas1, 0)
        w2 = weights.get(feas2, 0)
        return feas1 if w1 >= w2 else feas2

    def _deduplicate(self, results: list[VulnerabilityMatch]) -> list[VulnerabilityMatch]:
        """
        Удаление дубликатов с умной агрегацией.
        Вместо создания 100 записей для одного порта/вектора, этот метод
        схлопывает их в 1 запись, объединяя все CVE через запятую
        и выбирая максимальный уровень угрозы.
        """
        groups = {}
        for r in results:
            # Схлопываем по Названию атаки + CAPEC (чтобы объединить одинаковые векторы)
            key = f"{r.attack_name}_{r.capec_id}"
            
            if key not in groups:
                groups[key] = {
                    'match': r, 
                    'cves': set([r.cve_id]) if r.cve_id and r.cve_id != "N/A" else set(),
                    'count': 1
                }
            else:
                groups[key]['count'] += 1
                if r.cve_id and r.cve_id != "N/A":
                    groups[key]['cves'].add(r.cve_id)
                
                existing_match = groups[key]['match']
                # Берем наивысшую критичность и реализуемость из всех дубликатов
                existing_match.severity = self._get_max_severity(existing_match.severity, r.severity)
                existing_match.feasibility = self._get_worst_feasibility(existing_match.feasibility, r.feasibility)
                
                # Если у нового дубликата критичность выше, забираем его описание, так как оно важнее
                w_existing = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}.get(str(existing_match.severity).upper(), 0)
                w_new = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}.get(str(r.severity).upper(), 0)
                if w_new > w_existing:
                    existing_match.description = r.description
                    existing_match.reason = r.reason
                    existing_match.recommendation = r.recommendation
            if hasattr(r, 'target_software') and r.target_software:
                existing_match.target_software = r.target_software

        unique = []
        for g in groups.values():
            match = g['match']
            cves = sorted(list(g['cves']))
            
            if cves:
                # Если CVE очень много, обрезаем строку, чтобы не сломать таблицы в UI
                if len(cves) > 10:
                    match.cve_id = ", ".join(cves[:10]) + f" ... (+ ещё {len(cves)-10})"
                else:
                    match.cve_id = ", ".join(cves)
            else:
                match.cve_id = "N/A"
                
            unique.append(match)
            
        return unique

    def _correlate_with_trivy(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """
        Корреляция результатов с данными Trivy.
        Усиливает реализуемость атак если Trivy подтвердил уязвимость.
        """
        if not self.trivy_result:
            return self.results
        
        logger.info("[TRIVY] Запуск корреляции с данными Trivy...")
        
        correlator = TrivyCorrelator()
        
        # Коррелируем Trivy с атаками атакующего
        corr_result = correlator.correlate(
            trivy_result=self.trivy_result,
            attacker_vectors=scan_result.attack_vectors,
            open_ports=self.system_info.open_ports,
            existing_matches=self.results
        )
        
        # Объединяем результаты
        trivy_matches = correlator.get_enhanced_matches()
        merged = correlator.merge_with_existing(self.results, trivy_matches)
        
        logger.info(f"[TRIVY] Корреляция завершена:")
        logger.info(f"  - Совпадений с атаками: {corr_result.matched_with_attacks}")
        logger.info(f"  - Усилено атак: {corr_result.enhanced_attacks}")
        logger.info(f"  - Новых критических находок: {len(corr_result.new_critical_findings)}")
        
        return merged

    def _build_software_map(self, scan_result: ScanResult) -> dict:
        """
        Строит карту CVE -> ПО из всех доступных источников.
        
        Приоритеты:
        1. Trivy (самый надежный источник - реальные уязвимости в ПО)
        2. CVE база данных (affected_software из описания CVE)
        3. Установленное ПО на сервере
        4. Сопоставление по портам
        """
        software_map = {}
        
        # 1. Приоритет: Данные из Trivy (самый надежный источник)
        if self.trivy_result:
            trivy_vulns = []
            if isinstance(self.trivy_result, dict):
                trivy_vulns = self.trivy_result.get("vulnerabilities", [])
            elif hasattr(self.trivy_result, "vulnerabilities"):
                trivy_vulns = self.trivy_result.vulnerabilities
            
            for v in trivy_vulns:
                v_id = v.get("vuln_id") if isinstance(v, dict) else getattr(v, "vuln_id", "")
                pkg = v.get("pkg_name") if isinstance(v, dict) else getattr(v, "pkg_name", "")
                ver = v.get("installed_version") if isinstance(v, dict) else getattr(v, "installed_version", "")
                
                if v_id and pkg:
                    software_name = f"{pkg} v.{ver}" if ver else pkg
                    software_map[v_id] = software_name
                    
                    # Также добавляем варианты без версии для гибкого поиска
                    if ver:
                        software_map[f"{v_id}_base"] = pkg
            
            logger.info(f"[SOFTWARE_MAP] Из Trivy добавлено {len(software_map)} записей")
        
        # 2. CVE база данных (affected_software)
        if hasattr(self.vuln_db, 'cve_db'):
            cve_list = self.vuln_db.cve_db if isinstance(self.vuln_db.cve_db, list) else []
            for cve_info in cve_list:
                cve_id = cve_info.get("id", "")
                if cve_id in software_map:
                    continue  # Уже есть из Trivy
                
                affected = cve_info.get("affected_software", [])
                if affected:
                    # Берем первое affected ПО как наиболее вероятное
                    software_map[cve_id] = affected[0]
        
        # 3. Сопоставление по установленному ПО
        for sw in self.system_info.installed_software:
            sw_name = sw.name if hasattr(sw, 'name') else sw.get("name", "")
            sw_version = sw.version if hasattr(sw, 'version') else sw.get("version", "")
            
            if not sw_name:
                continue
            
            # Ищем CVE для этого ПО
            cves = self.vuln_db.find_cves_by_software(sw_name)
            for cve in cves:
                cve_id = cve.get("id", "")
                if cve_id and cve_id not in software_map:
                    software_name = f"{sw_name} v.{sw_version}" if sw_version else sw_name
                    software_map[cve_id] = software_name
        
        # 4. Сопоставление по портам из scan_result
        if hasattr(scan_result, 'open_ports'):
            ports = scan_result.open_ports
        elif isinstance(scan_result, dict):
            ports = scan_result.get("open_ports", [])
        else:
            ports = []
        
        port_service_map = {
            21: "FTP Server",
            22: "OpenSSH",
            25: "SMTP Server",
            53: "DNS Server",
            80: "HTTP Server (Apache/Nginx/IIS)",
            110: "POP3 Server",
            143: "IMAP Server",
            443: "HTTPS Server (Apache/Nginx/IIS)",
            445: "Windows SMB",
            993: "IMAPS Server",
            995: "POP3S Server",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            3306: "MySQL",
            3389: "Microsoft RDP",
            5432: "PostgreSQL",
            5900: "VNC Server",
            6379: "Redis",
            8080: "HTTP Proxy (Tomcat/Jenkins)",
            8443: "HTTPS Alt (Tomcat)",
            27017: "MongoDB",
        }
        
        for port_info in ports:
            port_num = port_info.port if hasattr(port_info, 'port') else port_info.get("port", 0)
            service = port_info.service if hasattr(port_info, 'service') else port_info.get("service", "")
            
            # Если есть конкретный сервис от сканера
            if service and service.lower() not in ["unknown", ""]:
                # Находим CVE для этого порта
                cves = self.vuln_db.find_cves_by_port(port_num)
                for cve in cves:
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in software_map:
                        software_map[cve_id] = service
            
            # Если есть стандартный сервис для порта
            elif port_num in port_service_map:
                cves = self.vuln_db.find_cves_by_port(port_num)
                for cve in cves:
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in software_map:
                        software_map[cve_id] = port_service_map[port_num]
        
        logger.info(f"[SOFTWARE_MAP] Всего записей в карте ПО: {len(software_map)}")
        return software_map

    def _guess_software_from_port(self, match: VulnerabilityMatch, scan_result: ScanResult) -> str:
        """
        Эвристическое определение ПО по порту из scan_result.
        Используется как фоллбэк когда нет точных данных.
        """
        # Стандартные маппинги портов
        port_service_map = {
            21: "FTP Server",
            22: "OpenSSH",
            25: "SMTP Server",
            53: "DNS Server",
            80: "HTTP Server (Apache/Nginx/IIS)",
            110: "POP3 Server",
            143: "IMAP Server",
            443: "HTTPS Server (Apache/Nginx/IIS)",
            445: "Windows SMB",
            993: "IMAPS Server",
            995: "POP3S Server",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            3306: "MySQL",
            3389: "Microsoft RDP",
            5432: "PostgreSQL",
            5900: "VNC Server",
            6379: "Redis",
            8080: "HTTP Proxy (Tomcat/Jenkins)",
            8443: "HTTPS Alt (Tomcat)",
            27017: "MongoDB",
        }
        
        # Получаем порт из match
        target_port = match.cve_id  # Может быть в CVE_ID если формат особый
        port = None
        
        # Пробуем извлечь порт из attack_vector_id
        if match.attack_vector_id:
            av_id = match.attack_vector_id
            if av_id.startswith("port-"):
                try:
                    port = int(av_id.replace("port-", ""))
                except ValueError:
                    pass
        
        # Если не нашли, пробуем из target_port в CVE базе
        if port is None:
            cve_id = match.cve_id.split(",")[0].strip()
            # Ищем CVE в списке
            if hasattr(self.vuln_db, 'cve_db') and isinstance(self.vuln_db.cve_db, list):
                for cve in self.vuln_db.cve_db:
                    if cve.get("id") == cve_id:
                        requires_port = cve.get("requires_port", [])
                        if requires_port:
                            port = requires_port[0]
                        break
        
        if port and port in port_service_map:
            return port_service_map[port]
        
        # Последняя попытка: используем информацию из имени атаки
        attack_name_lower = match.attack_name.lower() if match.attack_name else ""
        
        if "веб" in attack_name_lower or "http" in attack_name_lower:
            return "Web Server (Apache/Nginx/IIS)"
        elif "ssh" in attack_name_lower:
            return "OpenSSH"
        elif "rdp" in attack_name_lower or "удаленный рабочий стол" in attack_name_lower:
            return "Microsoft RDP"
        elif "smb" in attack_name_lower:
            return "Windows SMB"
        elif "ftp" in attack_name_lower:
            return "FTP Server"
        elif "sql" in attack_name_lower or "база данных" in attack_name_lower:
            return "Database Server"
        elif "почт" in attack_name_lower or "smtp" in attack_name_lower:
            return "Mail Server"
        
        return "Неидентифицированное ПО"

    def get_summary(self) -> dict:
        """Сводка результатов корреляции."""
        total = len(self.results)
        feasible = sum(1 for r in self.results if r.feasibility == AttackFeasibility.FEASIBLE.value)
        not_feasible = sum(1 for r in self.results if r.feasibility == AttackFeasibility.NOT_FEASIBLE.value)
        partial = sum(1 for r in self.results if r.feasibility == AttackFeasibility.PARTIALLY_FEASIBLE.value)
        unknown = sum(1 for r in self.results if r.feasibility == AttackFeasibility.REQUIRES_ANALYSIS.value)

        critical = sum(1 for r in self.results if str(r.severity).upper() == "CRITICAL" and r.feasibility != AttackFeasibility.NOT_FEASIBLE.value)
        high = sum(1 for r in self.results if str(r.severity).upper() == "HIGH" and r.feasibility != AttackFeasibility.NOT_FEASIBLE.value)

        return {
            "total_vulnerabilities_analyzed": total,
            "feasible_attacks": feasible,
            "not_feasible_attacks": not_feasible,
            "partially_feasible": partial,
            "requires_analysis": unknown,
            "critical_actionable": critical,
            "high_actionable": high,
        }
