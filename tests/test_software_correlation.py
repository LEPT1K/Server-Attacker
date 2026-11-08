#!/usr/bin/env python3
"""
Тест для проверки корреляции ПО с атаками.
Проверяет, что поле target_software правильно устанавливается и используется.
"""

import sys
import os
import json
from dataclasses import asdict

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from common.models import (
    SystemInfo, ScanResult, VulnerabilityMatch,
    AttackFeasibility, Severity, AttackVector, OpenPort, InstalledSoftware
)
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import SoftwareEnricher


def create_test_data():
    """Создает тестовые данные для проверки."""
    
    # 1. Создаем системную информацию
    system_info = SystemInfo(
        os_name="Windows Server 2019",
        os_version="10.0.17763",
        hostname="TEST-SERVER",
        ip_addresses=["192.168.1.100"],
        installed_software=[
            InstalledSoftware(name="Apache HTTP Server", version="2.4.54", publisher="Apache Software Foundation"),
            InstalledSoftware(name="Microsoft SQL Server", version="14.0.3381.3", publisher="Microsoft"),
            InstalledSoftware(name="OpenSSH", version="8.9p1", publisher="OpenBSD"),
        ],
        running_services=["Apache", "MSSQLSERVER", "sshd"],
        open_ports=[
            OpenPort(port=80, service="Apache", banner="Apache/2.4.54 (Win64)"),
            OpenPort(port=443, service="Apache", banner="Apache/2.4.54 (Win64)"),
            OpenPort(port=1433, service="MSSQL", banner="Microsoft SQL Server"),
            OpenPort(port=22, service="SSH", banner="OpenSSH 8.9"),
        ],
        has_database=True,
        database_types=["Microsoft SQL Server"],
        has_web_server=True,
        web_server_types=["Apache"],
        has_rdp_enabled=True,
        has_smb_enabled=True,
        has_ftp_enabled=False,
        firewall_active=True,
        antivirus_active=True,
        updates_installed=True,
    )
    
    # 2. Создаем результаты сканирования атакующего
    scan_result = ScanResult(
        scanner_ip="192.168.1.50",
        target_ip="192.168.1.100",
        open_ports=[
            OpenPort(port=80, service="Apache", banner="Apache/2.4.54 (Win64)"),
            OpenPort(port=443, service="Apache", banner="Apache/2.4.54 (Win64)"),
            OpenPort(port=1433, service="MSSQL", banner="Microsoft SQL Server"),
            OpenPort(port=22, service="SSH", banner="OpenSSH 8.9"),
        ],
        discovered_services=["Apache", "MSSQL", "SSH"],
        attack_vectors=[
            AttackVector(
                id="web-001",
                name="SQL Injection через веб-форму",
                description="Атака SQL Injection через веб-интерфейс",
                target_port=80,
                target_service="Apache",
                attack_type="sql_injection",
                severity=Severity.HIGH.value,
                tools_used="SQLMap, Burp Suite"
            ),
            AttackVector(
                id="ssh-001",
                name="SSH Brute Force",
                description="Подбор пароля SSH",
                target_port=22,
                target_service="SSH",
                attack_type="brute_force",
                severity=Severity.MEDIUM.value,
                tools_used="Hydra, John the Ripper"
            ),
            AttackVector(
                id="mssql-001",
                name="SQL Server Exploitation",
                description="Эксплуатация уязвимостей MSSQL",
                target_port=1433,
                target_service="MSSQL",
                attack_type="sql_server_exploit",
                severity=Severity.CRITICAL.value,
                tools_used="Metasploit, SQLNinja"
            ),
        ],
        os_detection="Windows Server 2019",
        scan_timestamp="2024-01-15T10:30:00Z"
    )
    
    # 3. Создаем данные Trivy
    trivy_result = {
        "timestamp": "2024-01-15T10:35:00Z",
        "hostname": "TEST-SERVER",
        "os_name": "Windows",
        "os_version": "Server 2019",
        "total_vulns": 3,
        "vulnerabilities": [
            {
                "vuln_id": "CVE-2022-22965",
                "pkg_name": "Apache HTTP Server",
                "installed_version": "2.4.54",
                "fixed_version": "2.4.55",
                "severity": "CRITICAL",
                "title": "Spring4Shell vulnerability",
                "description": "Remote code execution vulnerability in Apache HTTP Server",
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965"],
                "cwe_ids": ["CWE-78"],
                "capec_ids": ["CAPEC-209"]
            },
            {
                "vuln_id": "CVE-2022-23222",
                "pkg_name": "Microsoft SQL Server",
                "installed_version": "14.0.3381.3",
                "fixed_version": "14.0.3381.4",
                "severity": "HIGH",
                "title": "SQL Server privilege escalation",
                "description": "Privilege escalation vulnerability in Microsoft SQL Server",
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23222"],
                "cwe_ids": ["CWE-269"],
                "capec_ids": ["CAPEC-4"]
            },
            {
                "vuln_id": "CVE-2022-23218",
                "pkg_name": "OpenSSH",
                "installed_version": "8.9p1",
                "fixed_version": "9.0p1",
                "severity": "MEDIUM",
                "title": "OpenSSH buffer overflow",
                "description": "Buffer overflow vulnerability in OpenSSH",
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23218"],
                "cwe_ids": ["CWE-121"],
                "capec_ids": ["CAPEC-14"]
            }
        ]
    }
    
    return system_info, scan_result, trivy_result


def test_software_correlation():
    """Тестирует корреляцию ПО с атаками."""
    print("🧪 Тест: Корреляция ПО с атаками")
    print("=" * 60)
    
    # Создаем тестовые данные
    system_info, scan_result, trivy_result = create_test_data()
    
    # Создаем базу уязвимостей
    vuln_db = VulnerabilityDatabase()
    
    # Создаем коррелятор
    correlator = AttackCorrelator(system_info, vuln_db, trivy_result)
    
    # Запускаем корреляцию
    print("🔍 Запуск корреляции атак...")
    results = correlator.correlate(scan_result)
    
    print(f"✅ Корреляция завершена. Найдено {len(results)} результатов.")
    print()
    
    # Проверяем результаты
    print("📊 Результаты корреляции:")
    print("-" * 60)
    
    for i, result in enumerate(results, 1):
        print(f"{i}. Атака: {result.attack_name}")
        print(f"   CVE: {result.cve_id}")
        print(f"   Целевое ПО: {result.target_software}")
        print(f"   Порт: {getattr(result, 'target_port', 'N/A')}")
        print(f"   Критичность: {result.severity}")
        print(f"   Реализуемость: {result.feasibility}")
        print(f"   Причина: {result.reason}")
        print()
    
    # Проверяем, что target_software установлен
    results_with_software = [r for r in results if r.target_software and r.target_software != "Неидентифицированное ПО"]
    
    print(f"🎯 Результаты с определенным ПО: {len(results_with_software)}/{len(results)}")
    
    if len(results_with_software) > 0:
        print("✅ Тест пройден: ПО успешно определено!")
        for r in results_with_software:
            print(f"   - {r.target_software} (CVE: {r.cve_id})")
    else:
        print("❌ Тест не пройден: ПО не определено")
    
    print()
    
    # Тестируем SoftwareEnricher
    print("🧪 Тест: SoftwareEnricher")
    print("-" * 30)
    
    enricher = SoftwareEnricher(system_info, vuln_db.cve_db, {}, trivy_result)
    
    # Тестируем определение ПО для каждого результата
    for result in results:
        if result.cve_id and result.cve_id != "N/A":
            identified_sw = enricher.identify_real_software(result, str(getattr(result, 'target_port', 'N/A')))
            print(f"   CVE {result.cve_id}: {identified_sw}")
    
    print()
    print("🎉 Тест завершен!")


if __name__ == "__main__":
    test_software_correlation()