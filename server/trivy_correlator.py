"""
Модуль корреляции данных Trivy с атаками атакующего.
Сопоставляет уязвимости ПО (найденные Trivy) с векторами атак (найденными атакующим).

Логика работы:
1. Trivy находит CVE в установленном ПО на сервере
2. Атакующий находит открытые порты и векторы атак на эти порты
3. Этот модуль сопоставляет: если атакующий атакует порт X, а Trivy нашёл CVE в ПО на порту X → атака РЕАЛИЗУЕМА
"""

import os
import sys
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.models import (
    VulnerabilityMatch, AttackFeasibility, Severity, AttackVector, OpenPort
)
from common.logger import get_server_logger
from server.trivy_scanner import TrivyScanResult, TrivyVulnerability

logger = get_server_logger()


@dataclass
class TrivyCorrelationResult:
    """Результат корреляции Trivy с атаками."""
    total_trivy_vulns: int = 0
    matched_with_attacks: int = 0
    enhanced_attacks: int = 0
    new_critical_findings: List[str] = field(default_factory=list)
    correlations: List[VulnerabilityMatch] = field(default_factory=list)


class TrivyCorrelator:
    """
    Коррелятор данных Trivy с векторами атак атакующего.
    
    Основная идея:
    - Trivy знает какие CVE есть в ПО на сервере
    - Атакующий знает какие порты открыты и какие атаки возможны
    - Если атакующий атакует порт, на котором работает ПО с CVE из Trivy → 
      это подтверждает реализуемость атаки
    """

    def __init__(self):
        self.results: List[VulnerabilityMatch] = []

    def _dict_to_trivy_result(self, data: dict) -> Optional[TrivyScanResult]:
        """Преобразует dict в TrivyScanResult."""
        try:
            if not data:
                return None
            
            # Если это уже TrivyScanResult
            if isinstance(data, TrivyScanResult):
                return data
            
            # Преобразуем dict в TrivyScanResult
            result = TrivyScanResult(
                timestamp=data.get("timestamp", ""),
                hostname=data.get("hostname", ""),
                os_name=data.get("os_name", ""),
                os_version=data.get("os_version", ""),
                total_vulns=data.get("total_vulns", 0),
                scan_duration_seconds=data.get("scan_duration_seconds", 0.0),
            )
            
            # Преобразуем уязвимости
            vulns_data = data.get("vulnerabilities", [])
            for v_data in vulns_data:
                vuln = TrivyVulnerability(
                    vuln_id=v_data.get("vuln_id", ""),
                    pkg_name=v_data.get("pkg_name", ""),
                    installed_version=v_data.get("installed_version", ""),
                    fixed_version=v_data.get("fixed_version", ""),
                    severity=v_data.get("severity", "UNKNOWN"),
                    title=v_data.get("title", ""),
                    description=v_data.get("description", ""),
                    references=v_data.get("references", []),
                    cwe_ids=v_data.get("cwe_ids", []),
                    capec_ids=v_data.get("capec_ids", []),
                )
                result.vulnerabilities.append(vuln)
            
            logger.info(f"[TRIVY-CORR] Преобразован dict в TrivyScanResult: {result.total_vulns} уязвимостей")
            return result
        except Exception as e:
            logger.error(f"[TRIVY-CORR] Ошибка преобразования dict: {e}")
            return None

    def correlate(
        self,
        trivy_result,
        attacker_vectors: List[AttackVector],
        open_ports: List[OpenPort],
        existing_matches: List[VulnerabilityMatch] = None
    ) -> TrivyCorrelationResult:
        """
        Основная корреляция Trivy с атаками атакующего.
        
        Args:
            trivy_result: Результаты сканирования Trivy (TrivyScanResult или dict)
            attacker_vectors: Векторы атак от атакующего агента
            open_ports: Открытые порты на сервере
            existing_matches: Существующие результаты корреляции (для объединения)
            
        Returns:
            TrivyCorrelationResult с результатами корреляции
        """
        logger.info("=" * 70)
        logger.info(" КОРРЕЛЯЦИЯ ДАННЫХ TRIVY С АТАКАМИ АТАКУЮЩЕГО")
        logger.info("=" * 70)
        
        corr_result = TrivyCorrelationResult()
        self.results = list(existing_matches) if existing_matches else []
        
        # Преобразуем dict в TrivyScanResult если нужно
        if isinstance(trivy_result, dict):
            trivy_result = self._dict_to_trivy_result(trivy_result)
        
        if not trivy_result:
            logger.warning("[TRIVY-CORR] Нет данных Trivy для корреляции")
            corr_result.total_trivy_vulns = 0
            return corr_result
        
        corr_result.total_trivy_vulns = trivy_result.total_vulns
        logger.info(f"[TRIVY-CORR] Уязвимостей от Trivy: {trivy_result.total_vulns}")
        logger.info(f"[TRIVY-CORR] Векторов атак от атакующего: {len(attacker_vectors)}")
        logger.info(f"[TRIVY-CORR] Открытых портов: {len(open_ports)}")
        
        # Создаём маппинг порт -> сервисы/ПО
        port_to_services = self._build_port_service_map(open_ports, trivy_result)
        logger.info(f"[TRIVY-CORR] Порт-сервис маппинг: {len(port_to_services)} портов")
        
        # Коррелируем каждую уязвимость Trivy с атаками
        for trivy_vuln in trivy_result.vulnerabilities:
            self._correlate_trivy_vulnerability(
                trivy_vuln, 
                attacker_vectors, 
                port_to_services,
                corr_result
            )
        
        logger.info(f"[TRIVY-CORR] Найдено совпадений с атаками: {corr_result.matched_with_attacks}")
        logger.info(f"[TRIVY-CORR] Усилено атак: {corr_result.enhanced_attacks}")
        
        if corr_result.new_critical_findings:
            logger.warning("[TRIVY-CORR] Новые критические находки:")
            for finding in corr_result.new_critical_findings[:5]:
                logger.warning(f"  - {finding}")
        
        logger.info("=" * 70)
        return corr_result

    def _build_port_service_map(
        self, 
        open_ports: List[OpenPort], 
        trivy_result: TrivyScanResult
    ) -> Dict[int, List[str]]:
        """
        Создаёт маппинг порт -> список ПО/сервисов.
        
        Логика:
        - Стандартные порты имеют известные сервисы (80=HTTP, 443=HTTPS, etc.)
        - Trivy знает какое ПО установлено
        - Сопоставляем: если порт 80 открыт и Trivy нашёл Apache/Nginx → связываем
        """
        port_map = {}
        
        # Стандартные маппинги порт-сервис
        standard_services = {
            21: ["ftp", "vsftpd", "proftpd"],
            22: ["ssh", "openssh"],
            25: ["smtp", "exchange", "postfix"],
            53: ["dns", "bind"],
            80: ["http", "apache", "nginx", "iis", "tomcat"],
            110: ["pop3"],
            143: ["imap"],
            443: ["https", "apache", "nginx", "iis"],
            445: ["smb", "samba"],
            993: ["imaps"],
            995: ["pop3s"],
            1433: ["mssql", "sql server"],
            1521: ["oracle"],
            3306: ["mysql", "mariadb"],
            3389: ["rdp", "remote desktop"],
            5432: ["postgresql", "postgres"],
            5900: ["vnc"],
            6379: ["redis"],
            8080: ["http-proxy", "tomcat", "jenkins"],
            8443: ["https-alt", "tomcat"],
            27017: ["mongodb"],
        }
        
        for port_info in open_ports:
            port_num = port_info.port if hasattr(port_info, 'port') else port_info.get("port", 0)
            service_name = port_info.service if hasattr(port_info, 'service') else port_info.get("service", "")
            
            services = []
            
            # Добавляем стандартные сервисы для порта
            if port_num in standard_services:
                services.extend(standard_services[port_num])
            
            # Добавляем обнаруженный сервис
            if service_name and service_name.lower() not in ["unknown", ""]:
                services.append(service_name.lower())
            
            # Пытаемся сопоставить с ПО из Trivy
            for trivy_vuln in trivy_result.vulnerabilities:
                pkg_lower = trivy_vuln.pkg_name.lower()
                # Если имя пакета похоже на сервис порта
                for svc in services:
                    if svc in pkg_lower or pkg_lower in svc:
                        services.append(pkg_lower)
                        break
            
            port_map[port_num] = list(set(services))
        
        return port_map

    def _correlate_trivy_vulnerability(
        self,
        trivy_vuln: TrivyVulnerability,
        attacker_vectors: List[AttackVector],
        port_to_services: Dict[int, List[str]],
        corr_result: TrivyCorrelationResult
    ):
        """
        Коррелирует одну уязвимость Trivy с атаками атакующего.
        
        Логика:
        1. Берём CVE из Trivy
        2. Смотрим какое ПО затронуто
        3. Ищем атаки атакующего на это ПО/порт
        4. Если нашли совпадение → атака подтверждена Trivy
        """
        pkg_lower = trivy_vuln.pkg_name.lower()
        vuln_id = trivy_vuln.vuln_id
        
        # Ищем векторы атак атакующего, которые могут использовать эту уязвимость
        matched_vectors = []
        
        for av in attacker_vectors:
            av_target_port = av.target_port
            
            # Проверяем совпадение по порту
            if av_target_port and av_target_port in port_to_services:
                port_services = port_to_services[av_target_port]
                
                # Проверяем совпадение ПО
                for svc in port_services:
                    if svc in pkg_lower or pkg_lower in svc:
                        matched_vectors.append(av)
                        break
            
            # Проверяем совпадение по названию атаки/сервису
            if av.target_service:
                av_svc_lower = av.target_service.lower()
                if av_svc_lower in pkg_lower or pkg_lower in av_svc_lower:
                    if av not in matched_vectors:
                        matched_vectors.append(av)
        
        # Если нашли совпадения - создаём усиленные результаты
        for av in matched_vectors:
            corr_result.matched_with_attacks += 1
            
            # Определяем реализуемость на основе Trivy
            if trivy_vuln.severity in ["CRITICAL", "HIGH"]:
                feasibility = AttackFeasibility.FEASIBLE
                reason = (
                    f"✅ ПОДТВЕРЖДЕНО Trivy: уязвимость {vuln_id} "
                    f"обнаружена в ПО '{trivy_vuln.pkg_name}' "
                    f"(версия {trivy_vuln.installed_version}). "
                    f"Порт {av.target_port or 'N/A'} открыт. "
                    f"Атака РЕАЛИЗУЕМА."
                )
                
                finding = f"🔴 {vuln_id} в {trivy_vuln.pkg_name} на порту {av.target_port} - КРИТИЧНО"
                corr_result.new_critical_findings.append(finding)
            else:
                feasibility = AttackFeasibility.PARTIALLY_FEASIBLE
                reason = (
                    f"⚠️ Trivy: уязвимость {vuln_id} "
                    f"в ПО '{trivy_vuln.pkg_name}'. "
                    f"Требует дополнительной проверки."
                )
            
            # Создаём усиленный результат с target_software
            enhanced_match = VulnerabilityMatch(
                cve_id=vuln_id,
                cwe_id=", ".join(trivy_vuln.cwe_ids) if trivy_vuln.cwe_ids else "N/A",
                capec_id=", ".join(trivy_vuln.capec_ids) if trivy_vuln.capec_ids else "N/A",
                mitre_technique="N/A",
                attack_vector_id=av.id,
                attack_name=f"[TRIVY+АТАКА] {av.name}",
                description=(
                    f"{trivy_vuln.title}\n\n"
                    f"Trivy подтвердил: {trivy_vuln.description[:300]}"
                ),
                severity=trivy_vuln.severity,
                feasibility=feasibility.value,
                reason=reason,
                recommendation=self._generate_trivy_recommendation(trivy_vuln, feasibility),
                target_software=f"{trivy_vuln.pkg_name} v.{trivy_vuln.installed_version}" if trivy_vuln.installed_version else trivy_vuln.pkg_name,
            )
            
            self.results.append(enhanced_match)
            corr_result.enhanced_attacks += 1

    def _generate_trivy_recommendation(
        self, 
        vuln: TrivyVulnerability, 
        feasibility: AttackFeasibility
    ) -> str:
        """Генерирует рекомендацию на основе данных Trivy."""
        recommendations = []
        
        if feasibility == AttackFeasibility.FEASIBLE:
            recommendations.append("🔴 КРИТИЧНО: Атака подтверждена данными Trivy!")
            recommendations.append("")
            recommendations.append("Необходимые действия:")
            
            if vuln.fixed_version:
                recommendations.append(
                    f"  1. ОБНОВИТЬ {vuln.pkg_name} до версии {vuln.fixed_version} или новее"
                )
            else:
                recommendations.append(
                    f"  1. Найти и установить патч для {vuln.pkg_name} ({vuln.vuln_id})"
                )
            
            recommendations.append(f"  2. Проверить логи на предмет попыток эксплуатации")
            recommendations.append(f"  3. Временно ограничить доступ к уязвимому сервису")
            recommendations.append(f"  4. Включить мониторинг на предмет атак")
            
            if vuln.cwe_ids:
                recommendations.append(f"  5. Изучить CWE: {', '.join(vuln.cwe_ids)}")
        
        elif feasibility == AttackFeasibility.PARTIALLY_FEASIBLE:
            recommendations.append("⚠️ ВНИМАНИЕ: Trivy обнаружил уязвимость")
            recommendations.append(f"  - ПО: {vuln.pkg_name} {vuln.installed_version}")
            recommendations.append(f"  - CVE: {vuln.vuln_id}")
            recommendations.append(f"  - Рекомендуется обновить до {vuln.fixed_version or 'последней версии'}")
        
        return "\n".join(recommendations)

    def get_enhanced_matches(self) -> List[VulnerabilityMatch]:
        """Возвращает усиленные результаты корреляции."""
        return self.results

    def merge_with_existing(
        self,
        existing_matches: List[VulnerabilityMatch],
        trivy_matches: List[VulnerabilityMatch]
    ) -> List[VulnerabilityMatch]:
        """
        Объединяет существующие результаты корреляции с результатами Trivy.
        
        Логика:
        - Если CVE уже есть в existing_matches, обновляем реализуемость
        - Если CVE новый, добавляем как новый результат
        """
        existing_cves = {m.cve_id for m in existing_matches}
        merged = list(existing_matches)
        
        for trivy_match in trivy_matches:
            # Проверяем есть ли уже этот CVE
            cve_id = trivy_match.cve_id
            
            # Если CVE уже есть, обновляем если Trivy подтверждает реализуемость
            existing_match = next((m for m in merged if cve_id in m.cve_id), None)
            if existing_match:
                # Если Trivy подтверждает реализуемость - обновляем
                if trivy_match.feasibility == AttackFeasibility.FEASIBLE.value:
                    existing_match.feasibility = AttackFeasibility.FEASIBLE.value
                    existing_match.reason = (
                        f"{existing_match.reason}\n\n"
                        f"✅ ПОДТВЕРЖДЕНО Trivy: {trivy_match.reason}"
                    )
                    # Берём более высокую критичность
                    sev_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                    if sev_weights.get(trivy_match.severity, 0) > sev_weights.get(existing_match.severity, 0):
                        existing_match.severity = trivy_match.severity
            else:
                # Новый CVE от Trivy - добавляем
                merged.append(trivy_match)
        
        return merged
