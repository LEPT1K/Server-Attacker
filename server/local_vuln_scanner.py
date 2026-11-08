"""
Локальный сканер уязвимостей (замена OVALDI).

Комплексный анализ безопасности Windows-системы:
  - Проверка установленных обновлений (KB)
  - Анализ политик безопасности (secpol, audit, password policy)
  - Проверка конфигурации служб (автозапуск, привилегии)
  - Анализ сетевых настроек (открытые порты, правила файрвола)
  - Проверка прав доступа к критичным директориям
  - Анализ учётных записей и групп
  - Проверка реестра на известные уязвимые конфигурации
  - Оценка соответствия базовым стандартам безопасности (CIS Benchmark)

Не требует внешних зависимостей — только стандартная библиотека Python + PowerShell/WMI.
"""

import subprocess
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.logger import get_server_logger

logger = get_server_logger()


# ─── Модели данных ───

@dataclass
class VulnFinding:
    """Результат проверки локальной уязвимости."""
    check_id: str
    category: str          # patch, config, policy, service, network, account, registry
    title: str
    description: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status: str            # VULNERABLE, SECURE, UNKNOWN, NOT_APPLICABLE
    details: str = ""
    recommendation: str = ""
    cve_refs: list = field(default_factory=list)
    cis_ref: str = ""      # CIS Benchmark reference


@dataclass
class ScanReport:
    """Итоговый отчёт локального сканирования."""
    scan_time: str = ""
    total_checks: int = 0
    vulnerable: int = 0
    secure: int = 0
    unknown: int = 0
    findings: list = field(default_factory=list)
    risk_score: float = 0.0  # 0-100, чем выше — тем хуже


# ─── Утилиты запуска команд ───

def _run_cmd(cmd: list[str], timeout: int = 30, encoding: str = "cp866") -> tuple[int, str, str]:
    """Безопасный запуск команды с таймаутом."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding=encoding, errors="replace"
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def _run_ps(script: str, timeout: int = 30) -> tuple[int, str, str]:
    """Запуск PowerShell-скрипта."""
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    return _run_cmd(cmd, timeout=timeout, encoding="utf-8")


# ─── Основной сканер ───

class LocalVulnScanner:
    """
    Комплексный локальный сканер уязвимостей.
    Заменяет OVALDI, работает на чистом Python + PowerShell/WMI.
    """

    def __init__(self):
        self.findings: list[VulnFinding] = []
        self.progress_callback = None  # callback(current, total, message)

    def scan_all(self) -> ScanReport:
        """Запуск полного сканирования."""
        logger.info("=" * 60)
        logger.info("  ЛОКАЛЬНЫЙ СКАНЕР УЯЗВИМОСТЕЙ — ЗАПУСК")
        logger.info("=" * 60)

        self.findings = []
        checks = [
            ("Проверка обновлений Windows", self._check_windows_updates),
            ("Проверка политики паролей", self._check_password_policy),
            ("Проверка политики блокировки", self._check_lockout_policy),
            ("Проверка политики аудита", self._check_audit_policy),
            ("Проверка конфигурации UAC", self._check_uac_config),
            ("Проверка Windows Defender", self._check_defender_status),
            ("Проверка файрвола", self._check_firewall_profiles),
            ("Проверка RDP", self._check_rdp_security),
            ("Проверка SMB", self._check_smb_security),
            ("Проверка WinRM", self._check_winrm),
            ("Проверка автозапуска служб", self._check_service_permissions),
            ("Проверка гостевых аккаунтов", self._check_guest_accounts),
            ("Проверка админских долей", self._check_admin_shares),
            ("Проверка PowerShell-политик", self._check_powershell_policy),
            ("Проверка LSA Protection", self._check_lsa_protection),
            ("Проверка Credential Guard", self._check_credential_guard),
            ("Проверка LLMNR/NBT-NS", self._check_llmnr_nbtns),
            ("Проверка WDigest", self._check_wdigest),
            ("Проверка автологона", self._check_autologon),
            ("Проверка SSL/TLS протоколов", self._check_tls_config),
            ("Проверка NTP-конфигурации", self._check_ntp_config),
            ("Проверка SNMP", self._check_snmp_config),
        ]

        total = len(checks)
        for i, (name, func) in enumerate(checks, 1):
            if self.progress_callback:
                self.progress_callback(i, total, name)
            logger.info(f"[{i}/{total}] {name}...")
            try:
                func()
            except Exception as e:
                logger.warning(f"  Ошибка в проверке '{name}': {e}")
                self.findings.append(VulnFinding(
                    check_id=f"ERR-{i:03d}",
                    category="error",
                    title=f"Ошибка: {name}",
                    description=f"Не удалось выполнить проверку: {e}",
                    severity="INFO",
                    status="UNKNOWN",
                ))

        # Формируем отчёт
        report = ScanReport(
            scan_time=datetime.now().isoformat(),
            total_checks=len(self.findings),
            vulnerable=sum(1 for f in self.findings if f.status == "VULNERABLE"),
            secure=sum(1 for f in self.findings if f.status == "SECURE"),
            unknown=sum(1 for f in self.findings if f.status == "UNKNOWN"),
            findings=self.findings,
        )
        report.risk_score = self._calculate_risk_score()

        logger.info("=" * 60)
        logger.info(f"  СКАНИРОВАНИЕ ЗАВЕРШЕНО")
        logger.info(f"  Всего проверок: {report.total_checks}")
        logger.info(f"  Уязвимо: {report.vulnerable}")
        logger.info(f"  Защищено: {report.secure}")
        logger.info(f"  Риск-оценка: {report.risk_score:.1f}/100")
        logger.info("=" * 60)

        return report

    def _calculate_risk_score(self) -> float:
        """Расчёт общей оценки риска (0-100)."""
        if not self.findings:
            return 0.0
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        total_weight = 0
        vuln_weight = 0
        for f in self.findings:
            w = weights.get(f.severity, 0)
            total_weight += w
            if f.status == "VULNERABLE":
                vuln_weight += w
        if total_weight == 0:
            return 0.0
        return min(100.0, (vuln_weight / total_weight) * 100)

    # ─── Проверки ───

    def _check_windows_updates(self):
        """Проверка установленных обновлений и давности последнего обновления."""
        rc, out, _ = _run_ps(
            "Get-HotFix | Sort-Object InstalledOn -Descending | "
            "Select-Object -First 10 HotFixID, InstalledOn, Description | "
            "ConvertTo-Json -Compress",
            timeout=45
        )
        if rc != 0 or not out.strip():
            self.findings.append(VulnFinding(
                check_id="UPD-001", category="patch",
                title="Проверка обновлений Windows",
                description="Не удалось получить информацию об обновлениях",
                severity="MEDIUM", status="UNKNOWN",
                recommendation="Проверьте доступ к сервису Windows Update"
            ))
            return

        try:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]

            # Проверяем давность последнего обновления
            last_date = None
            for item in data:
                installed = item.get("InstalledOn", "")
                if installed:
                    # PowerShell возвращает дату в формате /Date(timestamp)/
                    m = re.search(r'/Date\((\d+)\)', str(installed))
                    if m:
                        ts = int(m.group(1)) / 1000
                        dt = datetime.fromtimestamp(ts)
                        if last_date is None or dt > last_date:
                            last_date = dt

            hotfix_list = ", ".join(item.get("HotFixID", "?") for item in data[:5])
            days_since = (datetime.now() - last_date).days if last_date else 999

            if days_since > 90:
                self.findings.append(VulnFinding(
                    check_id="UPD-001", category="patch",
                    title="Обновления Windows устарели",
                    description=f"Последнее обновление установлено {days_since} дней назад",
                    severity="HIGH", status="VULNERABLE",
                    details=f"Последние KB: {hotfix_list}",
                    recommendation="Установите актуальные обновления Windows через Windows Update",
                    cis_ref="CIS 18.9.108"
                ))
            elif days_since > 30:
                self.findings.append(VulnFinding(
                    check_id="UPD-001", category="patch",
                    title="Обновления Windows требуют внимания",
                    description=f"Последнее обновление: {days_since} дней назад",
                    severity="MEDIUM", status="VULNERABLE",
                    details=f"Последние KB: {hotfix_list}",
                    recommendation="Рекомендуется обновлять систему ежемесячно",
                    cis_ref="CIS 18.9.108"
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="UPD-001", category="patch",
                    title="Обновления Windows актуальны",
                    description=f"Последнее обновление: {days_since} дней назад",
                    severity="INFO", status="SECURE",
                    details=f"Последние KB: {hotfix_list}",
                ))
        except (json.JSONDecodeError, KeyError, TypeError):
            self.findings.append(VulnFinding(
                check_id="UPD-001", category="patch",
                title="Проверка обновлений Windows",
                description="Не удалось разобрать данные обновлений",
                severity="LOW", status="UNKNOWN",
            ))

    def _check_password_policy(self):
        """Проверка политики паролей через net accounts."""
        rc, out, _ = _run_cmd(["net", "accounts"])
        if rc != 0:
            self.findings.append(VulnFinding(
                check_id="POL-001", category="policy",
                title="Политика паролей", description="Не удалось получить",
                severity="MEDIUM", status="UNKNOWN",
            ))
            return

        # Минимальная длина пароля
        m = re.search(r"Minimum password length\s+(\d+)", out, re.IGNORECASE)
        if not m:
            m = re.search(r"Минимальная длина пароля\s+(\d+)", out)
        min_len = int(m.group(1)) if m else 0

        if min_len < 8:
            self.findings.append(VulnFinding(
                check_id="POL-001", category="policy",
                title="Слабая политика длины пароля",
                description=f"Минимальная длина пароля: {min_len} (рекомендуется >= 12)",
                severity="HIGH" if min_len < 6 else "MEDIUM",
                status="VULNERABLE",
                recommendation="Установите минимальную длину пароля 12+ символов через secpol.msc",
                cis_ref="CIS 1.1.4"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="POL-001", category="policy",
                title="Политика длины пароля",
                description=f"Минимальная длина пароля: {min_len}",
                severity="INFO", status="SECURE",
                cis_ref="CIS 1.1.4"
            ))

        # Максимальный срок действия пароля
        m2 = re.search(r"Maximum password age.*?(\d+)", out, re.IGNORECASE)
        if not m2:
            m2 = re.search(r"Макс.*?срок.*?пароля.*?(\d+)", out)
        max_age = int(m2.group(1)) if m2 else 0

        if max_age == 0 or max_age > 90:
            self.findings.append(VulnFinding(
                check_id="POL-002", category="policy",
                title="Пароли не требуют регулярной смены",
                description=f"Максимальный срок пароля: {'Неограничен' if max_age == 0 else f'{max_age} дней'}",
                severity="MEDIUM", status="VULNERABLE",
                recommendation="Установите срок действия пароля <= 90 дней",
                cis_ref="CIS 1.1.2"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="POL-002", category="policy",
                title="Политика срока действия пароля",
                description=f"Максимальный срок пароля: {max_age} дней",
                severity="INFO", status="SECURE",
                cis_ref="CIS 1.1.2"
            ))

    def _check_lockout_policy(self):
        """Проверка политики блокировки учётных записей."""
        rc, out, _ = _run_cmd(["net", "accounts"])
        if rc != 0:
            return

        m = re.search(r"Lockout threshold\s+(\w+)", out, re.IGNORECASE)
        if not m:
            m = re.search(r"Блокировка.*?(\d+|Never|Никогда)", out, re.IGNORECASE)
        threshold = m.group(1) if m else "Unknown"

        if threshold.lower() in ("never", "никогда", "0", "unknown"):
            self.findings.append(VulnFinding(
                check_id="POL-003", category="policy",
                title="Блокировка аккаунтов отключена",
                description="Нет ограничения на количество неудачных попыток входа",
                severity="HIGH", status="VULNERABLE",
                recommendation="Включите блокировку после 5 неудачных попыток (secpol.msc → Account Lockout Policy)",
                cis_ref="CIS 1.2.1"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="POL-003", category="policy",
                title="Политика блокировки аккаунтов",
                description=f"Порог блокировки: {threshold} попыток",
                severity="INFO", status="SECURE",
                cis_ref="CIS 1.2.1"
            ))

    def _check_audit_policy(self):
        """Проверка политики аудита."""
        rc, out, _ = _run_cmd(["auditpol", "/get", "/category:*"])
        if rc != 0:
            self.findings.append(VulnFinding(
                check_id="AUD-001", category="policy",
                title="Политика аудита", description="Не удалось получить",
                severity="LOW", status="UNKNOWN",
            ))
            return

        # Считаем «No Auditing» записи
        no_audit = out.lower().count("no auditing") + out.lower().count("нет аудита")
        total_lines = len([l for l in out.strip().split("\n") if l.strip() and "  " in l])

        if no_audit > total_lines * 0.5:
            self.findings.append(VulnFinding(
                check_id="AUD-001", category="policy",
                title="Аудит безопасности слабо настроен",
                description=f"Более 50% категорий аудита отключены ({no_audit} из ~{total_lines})",
                severity="MEDIUM", status="VULNERABLE",
                recommendation="Включите аудит входов, изменений политик и доступа к объектам (auditpol /set)",
                cis_ref="CIS 17.x"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="AUD-001", category="policy",
                title="Политика аудита настроена",
                description=f"Отключённых категорий: {no_audit}",
                severity="INFO", status="SECURE",
                cis_ref="CIS 17.x"
            ))

    def _check_uac_config(self):
        """Проверка конфигурации UAC (уровень, behavior)."""
        rc, out, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        ])
        if rc != 0:
            self.findings.append(VulnFinding(
                check_id="UAC-001", category="config",
                title="UAC", description="Не удалось проверить",
                severity="MEDIUM", status="UNKNOWN",
            ))
            return

        enable_lua = "0x1" in out if "EnableLUA" in out else False
        # ConsentPromptBehaviorAdmin: 0=Elevate without prompting (уязвимо)
        consent_match = re.search(r"ConsentPromptBehaviorAdmin\s+REG_DWORD\s+(0x[0-9a-fA-F]+)", out)
        consent_val = int(consent_match.group(1), 16) if consent_match else -1

        if not enable_lua:
            self.findings.append(VulnFinding(
                check_id="UAC-001", category="config",
                title="UAC отключён",
                description="User Account Control полностью отключён",
                severity="CRITICAL", status="VULNERABLE",
                recommendation="Включите UAC: reg add HKLM\\...\\Policies\\System /v EnableLUA /t REG_DWORD /d 1",
                cis_ref="CIS 2.3.17.1"
            ))
        elif consent_val == 0:
            self.findings.append(VulnFinding(
                check_id="UAC-001", category="config",
                title="UAC: автоповышение без запроса",
                description="Администраторы повышают привилегии без подтверждения",
                severity="HIGH", status="VULNERABLE",
                recommendation="Установите ConsentPromptBehaviorAdmin = 2 (запрашивать)",
                cis_ref="CIS 2.3.17.1"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="UAC-001", category="config",
                title="UAC включён и настроен",
                description=f"EnableLUA=1, ConsentBehavior={consent_val}",
                severity="INFO", status="SECURE",
                cis_ref="CIS 2.3.17.1"
            ))

    def _check_defender_status(self):
        """Проверка Windows Defender."""
        rc, out, _ = _run_ps(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled, "
            "RealTimeProtectionEnabled, AntivirusSignatureAge, "
            "AMServiceEnabled | ConvertTo-Json -Compress",
            timeout=20
        )
        if rc != 0 or not out.strip():
            self.findings.append(VulnFinding(
                check_id="DEF-001", category="config",
                title="Windows Defender", description="Не удалось проверить",
                severity="MEDIUM", status="UNKNOWN",
            ))
            return

        try:
            data = json.loads(out)
            av_enabled = data.get("AntivirusEnabled", False)
            rtp_enabled = data.get("RealTimeProtectionEnabled", False)
            sig_age = data.get("AntivirusSignatureAge", 999)

            issues = []
            if not av_enabled:
                issues.append("Антивирус отключён")
            if not rtp_enabled:
                issues.append("Защита реального времени отключена")
            if isinstance(sig_age, (int, float)) and sig_age > 7:
                issues.append(f"Сигнатуры устарели ({sig_age} дней)")

            if issues:
                self.findings.append(VulnFinding(
                    check_id="DEF-001", category="config",
                    title="Windows Defender: проблемы",
                    description="; ".join(issues),
                    severity="HIGH" if not av_enabled else "MEDIUM",
                    status="VULNERABLE",
                    recommendation="Включите Windows Defender и обновите базы сигнатур",
                    cis_ref="CIS 18.9.47"
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="DEF-001", category="config",
                    title="Windows Defender активен",
                    description=f"AV=вкл, RTP=вкл, Сигнатуры: {sig_age}д. назад",
                    severity="INFO", status="SECURE",
                    cis_ref="CIS 18.9.47"
                ))
        except (json.JSONDecodeError, TypeError):
            self.findings.append(VulnFinding(
                check_id="DEF-001", category="config",
                title="Windows Defender", description="Ошибка разбора",
                severity="LOW", status="UNKNOWN",
            ))

    def _check_firewall_profiles(self):
        """Проверка всех профилей файрвола."""
        rc, out, _ = _run_ps(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress",
            timeout=15
        )
        if rc != 0:
            self.findings.append(VulnFinding(
                check_id="FW-001", category="network",
                title="Файрвол Windows", description="Не удалось проверить",
                severity="MEDIUM", status="UNKNOWN",
            ))
            return

        try:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]

            disabled_profiles = [p["Name"] for p in data if not p.get("Enabled", True)]
            if disabled_profiles:
                self.findings.append(VulnFinding(
                    check_id="FW-001", category="network",
                    title="Файрвол: отключены профили",
                    description=f"Отключены: {', '.join(disabled_profiles)}",
                    severity="HIGH", status="VULNERABLE",
                    recommendation="Включите файрвол для всех профилей: Set-NetFirewallProfile -Enabled True",
                    cis_ref="CIS 9.1.1"
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="FW-001", category="network",
                    title="Файрвол включён на всех профилях",
                    description="Domain, Private, Public — все активны",
                    severity="INFO", status="SECURE",
                    cis_ref="CIS 9.1.1"
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    def _check_rdp_security(self):
        """Проверка безопасности RDP."""
        rc, out, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
        ])
        rdp_enabled = rc == 0 and "fDenyTSConnections" in out and "0x0" in out

        if not rdp_enabled:
            self.findings.append(VulnFinding(
                check_id="RDP-001", category="network",
                title="RDP отключён", description="Remote Desktop выключен",
                severity="INFO", status="SECURE",
            ))
            return

        # Проверяем NLA
        rc2, out2, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "/v", "UserAuthentication"
        ])
        nla_enabled = rc2 == 0 and "0x1" in out2

        # Проверяем уровень шифрования
        rc3, out3, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "/v", "MinEncryptionLevel"
        ])

        issues = []
        if not nla_enabled:
            issues.append("Network Level Authentication (NLA) отключена")
        # MinEncryptionLevel: 3 = High, 2 = Client Compatible, 1 = Low
        enc_match = re.search(r"0x([0-9a-fA-F]+)", out3) if rc3 == 0 else None
        if enc_match and int(enc_match.group(1), 16) < 3:
            issues.append("Уровень шифрования RDP ниже High")

        if issues:
            self.findings.append(VulnFinding(
                check_id="RDP-001", category="network",
                title="RDP: небезопасная конфигурация",
                description="RDP включён. " + "; ".join(issues),
                severity="HIGH", status="VULNERABLE",
                recommendation="Включите NLA и установите шифрование High. "
                               "Ограничьте доступ по IP через файрвол.",
                cve_refs=["CVE-2019-0708"],
                cis_ref="CIS 18.9.65"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="RDP-001", category="network",
                title="RDP включён с NLA",
                description="RDP активен, NLA включена",
                severity="LOW", status="SECURE",
                cis_ref="CIS 18.9.65"
            ))

    def _check_smb_security(self):
        """Проверка безопасности SMB (SMBv1, подпись)."""
        # SMBv1
        rc, out, _ = _run_ps(
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, "
            "RequireSecuritySignature, EncryptData | ConvertTo-Json -Compress",
            timeout=15
        )
        if rc != 0:
            # Альтернатива через реестр
            rc2, out2, _ = _run_cmd([
                "reg", "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "/v", "SMB1"
            ])
            smb1_disabled = rc2 == 0 and "0x0" in out2
            if not smb1_disabled:
                self.findings.append(VulnFinding(
                    check_id="SMB-001", category="network",
                    title="SMBv1 потенциально включён",
                    description="Не удалось однозначно определить статус SMBv1",
                    severity="HIGH", status="VULNERABLE",
                    recommendation="Отключите SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                    cve_refs=["CVE-2017-0144", "CVE-2017-0145"],
                    cis_ref="CIS 18.3.3"
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="SMB-001", category="network",
                    title="SMBv1 отключён", description="SMBv1 отключён в реестре",
                    severity="INFO", status="SECURE",
                    cis_ref="CIS 18.3.3"
                ))
            return

        try:
            data = json.loads(out)
            issues = []
            if data.get("EnableSMB1Protocol", False):
                issues.append("SMBv1 включён (уязвим для EternalBlue)")
            if not data.get("RequireSecuritySignature", False):
                issues.append("Подпись SMB не обязательна (SMB Relay)")
            if not data.get("EncryptData", False):
                issues.append("Шифрование SMB отключено")

            if issues:
                sev = "CRITICAL" if "SMBv1" in issues[0] else "HIGH"
                self.findings.append(VulnFinding(
                    check_id="SMB-001", category="network",
                    title="SMB: небезопасная конфигурация",
                    description="; ".join(issues),
                    severity=sev, status="VULNERABLE",
                    recommendation="Отключите SMBv1, включите подпись и шифрование SMB",
                    cve_refs=["CVE-2017-0144"],
                    cis_ref="CIS 18.3.3"
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="SMB-001", category="network",
                    title="SMB настроен безопасно",
                    description="SMBv1 отключён, подпись и шифрование включены",
                    severity="INFO", status="SECURE",
                    cis_ref="CIS 18.3.3"
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    def _check_winrm(self):
        """Проверка WinRM (Windows Remote Management)."""
        rc, out, _ = _run_cmd(["sc", "query", "WinRM"])
        running = rc == 0 and "RUNNING" in out.upper()

        if running:
            # Проверяем HTTP listener (небезопасный)
            rc2, out2, _ = _run_cmd(["winrm", "enumerate", "winrm/config/listener"])
            has_http = "Transport = HTTP" in out2 if rc2 == 0 else False

            if has_http:
                self.findings.append(VulnFinding(
                    check_id="WRM-001", category="network",
                    title="WinRM: HTTP-слушатель активен",
                    description="WinRM настроен на незашифрованный HTTP-транспорт",
                    severity="HIGH", status="VULNERABLE",
                    recommendation="Переключите WinRM на HTTPS или отключите если не используется",
                    cis_ref="CIS 18.9.102"
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="WRM-001", category="network",
                    title="WinRM активен (HTTPS)",
                    description="WinRM работает через защищённый транспорт",
                    severity="LOW", status="SECURE",
                    cis_ref="CIS 18.9.102"
                ))
        else:
            self.findings.append(VulnFinding(
                check_id="WRM-001", category="network",
                title="WinRM не запущен",
                description="Служба WinRM не активна",
                severity="INFO", status="SECURE",
            ))

    def _check_service_permissions(self):
        """Проверка служб с избыточными привилегиями."""
        rc, out, _ = _run_ps(
            "Get-WmiObject Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.StartName -eq 'LocalSystem'} | "
            "Select-Object Name, DisplayName, PathName | ConvertTo-Json -Compress",
            timeout=30
        )
        if rc != 0:
            return

        try:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]

            # Ищем службы из неизвестных путей (не System32)
            suspicious = []
            for svc in data:
                path = svc.get("PathName", "")
                name = svc.get("Name", "")
                if path and "system32" not in path.lower() and "syswow64" not in path.lower():
                    if not any(x in path.lower() for x in ["windows", "microsoft", "program files"]):
                        suspicious.append(f"{name} → {path[:80]}")

            if suspicious:
                self.findings.append(VulnFinding(
                    check_id="SVC-001", category="service",
                    title="Службы с LocalSystem из нестандартных путей",
                    description=f"Найдено {len(suspicious)} подозрительных служб",
                    severity="MEDIUM", status="VULNERABLE",
                    details="\n".join(suspicious[:10]),
                    recommendation="Проверьте подозрительные службы и ограничьте их привилегии",
                ))
            else:
                self.findings.append(VulnFinding(
                    check_id="SVC-001", category="service",
                    title="Службы с LocalSystem",
                    description="Все службы LocalSystem из стандартных путей",
                    severity="INFO", status="SECURE",
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    def _check_guest_accounts(self):
        """Проверка гостевых и неактивных учётных записей."""
        rc, out, _ = _run_cmd(["net", "user", "Guest"])
        guest_active = rc == 0 and "Yes" in out and "Account active" in out

        if not guest_active:
            # Проверяем русскую локализацию
            guest_active = rc == 0 and "Да" in out

        if guest_active:
            self.findings.append(VulnFinding(
                check_id="ACC-001", category="account",
                title="Гостевая учётная запись активна",
                description="Учётная запись Guest включена",
                severity="HIGH", status="VULNERABLE",
                recommendation="Отключите Guest: net user Guest /active:no",
                cis_ref="CIS 1.1.1"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="ACC-001", category="account",
                title="Гостевая учётная запись",
                description="Guest отключена или недоступна",
                severity="INFO", status="SECURE",
                cis_ref="CIS 1.1.1"
            ))

    def _check_admin_shares(self):
        """Проверка административных общих ресурсов (C$, ADMIN$)."""
        rc, out, _ = _run_cmd(["net", "share"])
        if rc != 0:
            return

        admin_shares = []
        for line in out.split("\n"):
            line = line.strip()
            if "$" in line and any(x in line for x in ["C$", "D$", "ADMIN$", "IPC$"]):
                admin_shares.append(line.split()[0] if line.split() else line)

        if "C$" in admin_shares or "ADMIN$" in admin_shares:
            self.findings.append(VulnFinding(
                check_id="NET-001", category="network",
                title="Административные общие ресурсы включены",
                description=f"Активны: {', '.join(admin_shares)}",
                severity="MEDIUM", status="VULNERABLE",
                recommendation="Отключите C$ и ADMIN$ если не используются (через реестр AutoShareServer=0)",
                cis_ref="CIS 18.3.1"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="NET-001", category="network",
                title="Административные ресурсы",
                description="Стандартные админ-доли не обнаружены",
                severity="INFO", status="SECURE",
            ))

    def _check_powershell_policy(self):
        """Проверка политики выполнения PowerShell-скриптов."""
        rc, out, _ = _run_ps("Get-ExecutionPolicy", timeout=10)
        if rc != 0:
            return

        policy = out.strip()
        if policy.lower() in ("unrestricted", "bypass"):
            self.findings.append(VulnFinding(
                check_id="PS-001", category="config",
                title="PowerShell: политика выполнения небезопасна",
                description=f"ExecutionPolicy = {policy}",
                severity="MEDIUM", status="VULNERABLE",
                recommendation="Установите: Set-ExecutionPolicy RemoteSigned",
                cis_ref="CIS 18.9.100"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="PS-001", category="config",
                title="PowerShell ExecutionPolicy",
                description=f"Политика: {policy}",
                severity="INFO", status="SECURE",
                cis_ref="CIS 18.9.100"
            ))

    def _check_lsa_protection(self):
        """Проверка LSA Protection (RunAsPPL)."""
        rc, out, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "/v", "RunAsPPL"
        ])
        protected = rc == 0 and "0x1" in out

        if not protected:
            self.findings.append(VulnFinding(
                check_id="LSA-001", category="config",
                title="LSA Protection отключена",
                description="RunAsPPL не включён — процесс LSASS уязвим для дампа памяти",
                severity="HIGH", status="VULNERABLE",
                recommendation="Включите LSA Protection: reg add HKLM\\...\\Lsa /v RunAsPPL /t REG_DWORD /d 1",
                cis_ref="CIS 18.3.1"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="LSA-001", category="config",
                title="LSA Protection включена",
                description="LSASS защищён как Protected Process Light",
                severity="INFO", status="SECURE",
                cis_ref="CIS 18.3.1"
            ))

    def _check_credential_guard(self):
        """Проверка Credential Guard."""
        rc, out, _ = _run_ps(
            "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "| Select-Object SecurityServicesRunning | ConvertTo-Json -Compress",
            timeout=15
        )
        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
                services = data.get("SecurityServicesRunning", [])
                if 1 in services:
                    self.findings.append(VulnFinding(
                        check_id="CG-001", category="config",
                        title="Credential Guard активен",
                        description="Виртуализация учётных данных включена",
                        severity="INFO", status="SECURE",
                    ))
                    return
            except (json.JSONDecodeError, TypeError):
                pass

        self.findings.append(VulnFinding(
            check_id="CG-001", category="config",
            title="Credential Guard не активен",
            description="Учётные данные не защищены виртуализацией",
            severity="MEDIUM", status="VULNERABLE",
            recommendation="Включите Credential Guard через Group Policy",
        ))

    def _check_llmnr_nbtns(self):
        """Проверка LLMNR и NetBIOS Name Service (часто используются для атак)."""
        # LLMNR
        rc, out, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "/v", "EnableMulticast"
        ])
        llmnr_disabled = rc == 0 and "0x0" in out

        if not llmnr_disabled:
            self.findings.append(VulnFinding(
                check_id="DNS-001", category="network",
                title="LLMNR включён",
                description="Link-Local Multicast Name Resolution — вектор для Responder/MITM",
                severity="MEDIUM", status="VULNERABLE",
                recommendation="Отключите LLMNR через GPO: EnableMulticast = 0",
                cis_ref="CIS 18.6.4.1"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="DNS-001", category="network",
                title="LLMNR отключён",
                description="LLMNR отключён через политику",
                severity="INFO", status="SECURE",
                cis_ref="CIS 18.6.4.1"
            ))

    def _check_wdigest(self):
        """Проверка WDigest (хранение паролей в памяти открытым текстом)."""
        rc, out, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "/v", "UseLogonCredential"
        ])
        wdigest_disabled = rc == 0 and "0x0" in out

        if not wdigest_disabled:
            self.findings.append(VulnFinding(
                check_id="WDG-001", category="config",
                title="WDigest: пароли могут храниться в памяти",
                description="UseLogonCredential не установлен в 0 — Mimikatz может извлечь пароли",
                severity="HIGH", status="VULNERABLE",
                recommendation="Установите UseLogonCredential = 0 в реестре WDigest",
                cis_ref="CIS 18.3.6"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="WDG-001", category="config",
                title="WDigest: пароли не хранятся открытым текстом",
                description="UseLogonCredential = 0",
                severity="INFO", status="SECURE",
                cis_ref="CIS 18.3.6"
            ))

    def _check_autologon(self):
        """Проверка автологона (пароль в реестре)."""
        rc, out, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "/v", "DefaultPassword"
        ])
        has_autologon_password = rc == 0 and "DefaultPassword" in out

        if has_autologon_password:
            self.findings.append(VulnFinding(
                check_id="ALG-001", category="account",
                title="Автологон с паролем в реестре",
                description="Пароль хранится открытым текстом в ключе Winlogon",
                severity="CRITICAL", status="VULNERABLE",
                recommendation="Удалите DefaultPassword из реестра Winlogon",
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="ALG-001", category="account",
                title="Автологон не настроен",
                description="Пароль в Winlogon не обнаружен",
                severity="INFO", status="SECURE",
            ))

    def _check_tls_config(self):
        """Проверка конфигурации SSL/TLS (отключены ли старые протоколы)."""
        old_protocols = {
            "SSL 2.0": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
            "SSL 3.0": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
            "TLS 1.0": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
            "TLS 1.1": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        }

        enabled_old = []
        for proto, key in old_protocols.items():
            rc, out, _ = _run_cmd(["reg", "query", key, "/v", "Enabled"])
            # Если ключ не существует или Enabled != 0, протокол может быть доступен
            if rc != 0 or "0x0" not in out:
                enabled_old.append(proto)

        if enabled_old:
            self.findings.append(VulnFinding(
                check_id="TLS-001", category="config",
                title="Устаревшие SSL/TLS протоколы не отключены",
                description=f"Потенциально доступны: {', '.join(enabled_old)}",
                severity="MEDIUM" if "SSL" not in ", ".join(enabled_old) else "HIGH",
                status="VULNERABLE",
                recommendation="Отключите SSL 2.0/3.0 и TLS 1.0/1.1 через реестр SCHANNEL",
                cis_ref="CIS 18.4"
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="TLS-001", category="config",
                title="Устаревшие SSL/TLS отключены",
                description="SSL 2.0, 3.0, TLS 1.0, 1.1 — отключены",
                severity="INFO", status="SECURE",
                cis_ref="CIS 18.4"
            ))

    def _check_ntp_config(self):
        """Проверка конфигурации синхронизации времени."""
        rc, out, _ = _run_cmd(["w32tm", "/query", "/status"])
        if rc != 0:
            self.findings.append(VulnFinding(
                check_id="NTP-001", category="config",
                title="Синхронизация времени",
                description="Не удалось проверить W32Time",
                severity="LOW", status="UNKNOWN",
            ))
            return

        if "free-running" in out.lower() or "error" in out.lower():
            self.findings.append(VulnFinding(
                check_id="NTP-001", category="config",
                title="Синхронизация времени не настроена",
                description="W32Time не синхронизирован с NTP-сервером",
                severity="LOW", status="VULNERABLE",
                recommendation="Настройте синхронизацию: w32tm /config /manualpeerlist:time.windows.com /syncfromflags:manual",
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="NTP-001", category="config",
                title="Время синхронизировано",
                description="W32Time работает",
                severity="INFO", status="SECURE",
            ))

    def _check_snmp_config(self):
        """Проверка SNMP (если установлен)."""
        rc, out, _ = _run_cmd(["sc", "query", "SNMP"])
        if rc != 0 or "RUNNING" not in out.upper():
            self.findings.append(VulnFinding(
                check_id="SNMP-001", category="network",
                title="SNMP не запущен",
                description="Служба SNMP не активна",
                severity="INFO", status="SECURE",
            ))
            return

        # Проверяем community string
        rc2, out2, _ = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
        ])
        if rc2 == 0 and ("public" in out2.lower() or "private" in out2.lower()):
            self.findings.append(VulnFinding(
                check_id="SNMP-001", category="network",
                title="SNMP: стандартные community strings",
                description="Используются 'public' или 'private' — легко угадать",
                severity="HIGH", status="VULNERABLE",
                recommendation="Смените community strings на сложные значения или отключите SNMP",
            ))
        else:
            self.findings.append(VulnFinding(
                check_id="SNMP-001", category="network",
                title="SNMP запущен",
                description="SNMP активен, стандартные community strings не обнаружены",
                severity="LOW", status="SECURE",
            ))
