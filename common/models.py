"""
Общие модели данных для серверного и атакующего агентов.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackFeasibility(str, Enum):
    FEASIBLE = "РЕАЛИЗУЕМА"
    NOT_FEASIBLE = "НЕ РЕАЛИЗУЕМА"
    PARTIALLY_FEASIBLE = "ЧАСТИЧНО РЕАЛИЗУЕМА"
    REQUIRES_ANALYSIS = "ТРЕБУЕТ АНАЛИЗА"


@dataclass
class OpenPort:
    port: int
    service: str
    banner: str = ""
    protocol: str = "TCP"


@dataclass
class InstalledSoftware:
    name: str
    version: str
    publisher: str = ""
    install_date: str = ""


@dataclass
class SecurityMeasure:
    name: str
    category: str  # firewall, antivirus, ids, encryption, etc.
    status: str  # active, inactive, not_configured
    details: str = ""


@dataclass
class SystemInfo:
    os_name: str = ""
    os_version: str = ""
    hostname: str = ""
    ip_addresses: list = field(default_factory=list)
    installed_software: list = field(default_factory=list)
    running_services: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    security_measures: list = field(default_factory=list)
    has_database: bool = False
    database_types: list = field(default_factory=list)
    has_web_server: bool = False
    web_server_types: list = field(default_factory=list)
    has_rdp_enabled: bool = False
    has_smb_enabled: bool = False
    has_ftp_enabled: bool = False
    firewall_active: bool = False
    antivirus_active: bool = False
    updates_installed: bool = False
    trivy_scan_result: dict = field(default_factory=dict)  # Результаты сканирования Trivy
    fstec_vulnerabilities: list = field(default_factory=list)  # Находки встроенного ФСТЭК/OVAL-сканера


@dataclass
class AttackVector:
    id: str
    name: str
    description: str
    target_port: Optional[int] = None
    target_service: str = ""
    attack_type: str = ""
    severity: str = Severity.MEDIUM.value
    tools_used: str = ""


@dataclass
class ScanResult:
    """Результат сканирования от атакующего агента."""
    scanner_ip: str
    target_ip: str
    open_ports: list = field(default_factory=list)
    discovered_services: list = field(default_factory=list)
    attack_vectors: list = field(default_factory=list)
    os_detection: str = ""
    scan_timestamp: str = ""


@dataclass
class VulnerabilityMatch:
    """Сопоставление уязвимости с конфигурацией сервера."""
    cve_id: str = ""
    cwe_id: str = ""
    capec_id: str = ""
    mitre_technique: str = ""
    attack_vector_id: str = ""
    attack_name: str = ""
    description: str = ""
    severity: str = Severity.MEDIUM.value
    feasibility: str = AttackFeasibility.REQUIRES_ANALYSIS.value
    reason: str = ""
    recommendation: str = ""
    target_software: str = ""


def to_json(obj):
    """Сериализация объекта в JSON."""
    if hasattr(obj, '__dataclass_fields__'):
        return json.dumps(asdict(obj), ensure_ascii=False, indent=2)
    elif isinstance(obj, list):
        return json.dumps(
            [asdict(item) if hasattr(item, '__dataclass_fields__') else item for item in obj],
            ensure_ascii=False, indent=2
        )
    return json.dumps(obj, ensure_ascii=False, indent=2)


def from_json_scan_result(data: dict) -> ScanResult:
    """Десериализация ScanResult из JSON."""
    result = ScanResult(
        scanner_ip=data.get("scanner_ip", ""),
        target_ip=data.get("target_ip", ""),
        os_detection=data.get("os_detection", ""),
        scan_timestamp=data.get("scan_timestamp", ""),
    )
    for p in data.get("open_ports", []):
        if isinstance(p, dict):
            result.open_ports.append(OpenPort(**p))
        else:
            result.open_ports.append(p)
    for s in data.get("discovered_services", []):
        result.discovered_services.append(s)
    for a in data.get("attack_vectors", []):
        if isinstance(a, dict):
            result.attack_vectors.append(AttackVector(**a))
        else:
            result.attack_vectors.append(a)
    return result
