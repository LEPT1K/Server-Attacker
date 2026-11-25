# src/step4_autofill.py
# -*- coding: utf-8 -*-
"""
Шаг 4: Автозаполнение пустых полей в JSON-базах (output/*.json).

Ярусная стратегия (от точного к шаблонному):
  Ярус A — связи (related_*): реверс и транзитивность по реальным ID,
           шаблонами НЕ заполняются.
  Ярус B — факты из описаний: порты/сервисы (regex), attack_type (ключевые
           слова), категория CWE (ключевые слова), severity из CVSS.
  Ярус C — detection для ATT&CK из STIX-первоисточника
           (x-mitre-detection-strategy → x-mitre-analytic), с переводом.
  Ярус D — шаблонные фразы (Config.AUTOFILL_TEMPLATES) для оставшихся
           пустых текстовых полей.

Запуск:  python step4_autofill.py [--stix FILE] [--no-detection] [--no-translate]
"""
import json
import re
import html
import argparse
from pathlib import Path
from .config import Config
from . import progress

MAX_LINKS = 10          # максимум ссылок в поле-связи (как в cross_linker)
MAX_DETECTION_CHARS = 1200  # ограничение длины собранного detection

# Маркеры «пустого» значения (вкл. переведённые)
EMPTY_MARKERS = {"", "unknown", "n/a", "none",
                 "неизвестно", "неизвестный", "неизвестная", "неизвестные"}

DB_FILES = ["capec_database.json", "cwe_database.json",
            "cve_database.json", "mitre_attack.json"]

# --- Ключевые слова для attack_type CVE (значения соответствуют уже принятой в базе таксономии) ---
ATTACK_TYPE_KEYWORDS = [
    ("SQL-инъекция", [r"sql[\s-]?инъекц", r"sql[\s-]?injection", r"\bsqli\b"]),
    ("межсайтовый скриптинг", [r"межсайтов\w+ скриптинг", r"cross[\s-]?site scripting", r"\bxss\b"]),
    ("удаленное выполнение кода", [r"удал[её]нн\w+ выполнени\w+ кода", r"выполнени\w+ произвольн\w+ кода",
                                   r"remote code execution", r"\brce\b", r"внедрени\w+ команд", r"инъекци\w+ команд"]),
    ("отказ в обслуживании", [r"отказ\w* в обслуживани", r"denial of service", r"\bdos\b", r"\bddos\b",
                              r"сбо\w+ службы", r"аварийн\w+ завершени"]),
    ("повышение привилегий", [r"повышени\w+ привилеги", r"privilege escalation", r"эскалаци\w+ привилеги"]),
    ("атака десериализации", [r"десериализац", r"deserialization"]),
    ("грубая сила", [r"перебор\w* парол", r"brute[\s-]?force", r"подбор\w* парол"]),
    ("переполнение буфера", [r"переполнени\w+ буфера", r"buffer overflow", r"переполнени\w+ кучи", r"переполнени\w+ стека"]),
    ("обход каталога", [r"обход\w* каталог", r"path traversal", r"directory traversal", r"выход\w* за пределы каталог"]),
    ("раскрытие информации", [r"раскрыти\w+ информаци", r"утечк\w+ информаци", r"information disclosure"]),
    ("подделка межсайтовых запросов", [r"подделк\w+ межсайтовых запросов", r"\bcsrf\b", r"\bssrf\b"]),
]

# --- Ключевые слова для категории CWE (по имени/описанию) ---
CWE_CATEGORY_KEYWORDS = [
    ("инъекция", [r"инъекц", r"нейтрализаци\w+ специальных элементов", r"внедрени"]),
    ("проверка ввода", [r"проверк\w+ ввод", r"валидаци"]),
    ("управление памятью", [r"буфер", r"памят", r"указател", r"переполнени", r"использовани\w+ после освобождени"]),
    ("аутентификация", [r"аутентификаци", r"парол", r"учетн\w+ данн"]),
    ("авторизация и контроль доступа", [r"авторизаци", r"контрол\w+ доступа", r"разрешени", r"привилеги"]),
    ("криптография", [r"криптограф", r"шифровани", r"хеш", r"сертификат", r"случайн"]),
    ("раскрытие информации", [r"раскрыти\w+ информаци", r"утечк", r"конфиденциальн"]),
    ("обработка ошибок", [r"обработк\w+ ошибок", r"исключени"]),
    ("состояние гонки", [r"состояни\w+ гонки", r"синхронизаци", r"одновременн"]),
    ("конфигурация", [r"конфигураци", r"настройк\w+ по умолчанию"]),
]

# --- Сервисные ключевые слова (латиница сохраняется при переводе) ---
SERVICE_KEYWORDS = {
    "apache": "web_server", "nginx": "web_server", "iis": "web_server", "tomcat": "web_server",
    "mysql": "database", "postgresql": "database", "postgres": "database", "mssql": "database",
    "oracle": "database", "mongodb": "database", "redis": "database",
    "ssh": "ssh", "rdp": "rdp", "smb": "smb", "ftp": "ftp", "telnet": "telnet",
    "smtp": "mail_server", "imap": "mail_server", "pop3": "mail_server",
    "exchange": "exchange_server", "ldap": "ldap", "vpn": "vpn",
    "jenkins": "jenkins", "wordpress": "cms", "drupal": "cms", "joomla": "cms",
    "kubernetes": "kubernetes", "docker": "docker",
}

SEVERITY_FROM_CVSS = [
    (9.0, "КРИТИЧЕСКИЙ"),
    (7.0, "ВЫСОКИЙ"),
    (4.0, "СЕРЕДИНА"),
    (0.1, "НИЗКИЙ"),
]


def is_empty(value) -> bool:
    """Пустое значение: None, '', [], {} или маркер 'неизвестно'."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in EMPTY_MARKERS
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def clean_html(text: str) -> str:
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\(Citation:[^)]*\)", "", clean)
    clean = re.sub(r"\s+", " ", clean)
    return html.unescape(clean).strip()


class AutoFiller:
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.dbs = {}
        self.stats = {}

    # ---------- загрузка/сохранение ----------
    def load(self) -> bool:
        for fn in DB_FILES:
            fp = self.output_dir / fn
            if not fp.exists():
                print(f"⚠️ {fn} не найден — пропускается")
                continue
            with open(fp, "r", encoding="utf-8") as f:
                self.dbs[fn] = json.load(f)
            print(f"📂 {fn}: {len(self.dbs[fn])} записей")
        return bool(self.dbs)

    def save(self):
        for fn, data in self.dbs.items():
            with open(self.output_dir / fn, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        print("💾 Все базы сохранены")

    def _bump(self, key: str, n: int = 1):
        self.stats[key] = self.stats.get(key, 0) + n

    # ---------- Ярус A: связи ----------
    def fill_links(self):
        print("\n🔗 Ярус A: восстановление связей (реверс/транзитивность)...")
        capec = self.dbs.get("capec_database.json", [])
        cwe = self.dbs.get("cwe_database.json", [])
        cve = self.dbs.get("cve_database.json", [])
        attack = self.dbs.get("mitre_attack.json", [])

        capec_by_id = {i["id"]: i for i in capec}
        cwe_by_id = {i["id"]: i for i in cwe}
        attack_by_id = {i["id"]: i for i in attack}

        # 1) cwe.related_capec ← реверс capec.related_cwe
        for cap in capec:
            for cwe_id in cap.get("related_cwe", []):
                rec = cwe_by_id.get(cwe_id)
                if rec is None:
                    continue
                links = rec.setdefault("related_capec", [])
                if cap["id"] not in links and len(links) < MAX_LINKS:
                    links.append(cap["id"])
                    self._bump("A: cwe.related_capec")

        # 2) capec.related_mitre ← реверс attack.related_capec
        for tech in attack:
            for cap_id in tech.get("related_capec", []):
                rec = capec_by_id.get(cap_id)
                if rec is None:
                    continue
                links = rec.setdefault("related_mitre", [])
                if tech["id"] not in links and len(links) < MAX_LINKS:
                    links.append(tech["id"])
                    self._bump("A: capec.related_mitre")

        # 3) attack.related_cwe ← транзитивно через related_capec → capec.related_cwe
        for tech in attack:
            if not is_empty(tech.get("related_cwe")):
                continue
            found = []
            for cap_id in tech.get("related_capec", []):
                cap = capec_by_id.get(cap_id)
                if cap:
                    found.extend(cap.get("related_cwe", []))
            if found:
                tech["related_cwe"] = list(dict.fromkeys(found))[:MAX_LINKS]
                self._bump("A: attack.related_cwe")

        # 4) Цепочка CVE → CWE → CAPEC → ATT&CK (использует уже дозаполненные связи)
        for rec in cve:
            new_capec, new_mitre = set(), set()
            for cwe_id in rec.get("related_cwe", []):
                w = cwe_by_id.get(cwe_id)
                if not w:
                    continue
                for cap_id in w.get("related_capec", []):
                    cap = capec_by_id.get(cap_id)
                    if not cap:
                        continue
                    new_capec.add(cap_id)
                    for t_id in cap.get("related_mitre", []):
                        if t_id in attack_by_id:
                            new_mitre.add(t_id)
            cur_capec = rec.get("related_capec", [])
            add_capec = [c for c in new_capec if c not in cur_capec]
            if add_capec:
                rec["related_capec"] = (cur_capec + sorted(add_capec))[:MAX_LINKS]
                self._bump("A: cve.related_capec")
            cur_mitre = rec.get("related_mitre", [])
            add_mitre = [m for m in new_mitre if m not in cur_mitre]
            if add_mitre:
                rec["related_mitre"] = (cur_mitre + sorted(add_mitre))[:MAX_LINKS]
                self._bump("A: cve.related_mitre")

        for k in sorted(self.stats):
            if k.startswith("A:"):
                print(f"  ✅ {k} → обновлено {self.stats[k]}")

    # ---------- Ярус B: факты из описаний ----------
    def extract_facts(self):
        print("\n🔎 Ярус B: извлечение фактов из описаний...")
        cve = self.dbs.get("cve_database.json", [])
        cwe = self.dbs.get("cwe_database.json", [])
        attack = self.dbs.get("mitre_attack.json", [])

        port_patterns = [
            re.compile(r"(?:port|порт\w{0,3})\s+(\d{1,5})", re.IGNORECASE),
            re.compile(r"(\d{1,5})\s*/\s*(?:tcp|udp)", re.IGNORECASE),
            re.compile(r"(?:tcp|udp)[\s-]?порт\w{0,3}\s+(\d{1,5})", re.IGNORECASE),
        ]

        def extract_ports(desc: str) -> list:
            ports = set()
            for pat in port_patterns:
                for m in pat.finditer(desc):
                    p = int(m.group(1))
                    if 1 <= p <= 65535:
                        ports.add(p)
            return sorted(ports)

        def extract_services(desc_lower: str) -> list:
            found = set()
            for kw, svc in SERVICE_KEYWORDS.items():
                if re.search(rf"\b{kw}\b", desc_lower):
                    found.add(svc)
            return sorted(found)

        for rec in cve:
            desc = rec.get("description", "") or ""
            desc_lower = desc.lower()
            # порты
            if is_empty(rec.get("requires_port")):
                ports = extract_ports(desc)
                if ports:
                    rec["requires_port"] = ports
                    self._bump("B: cve.requires_port")
            # сервисы
            if is_empty(rec.get("requires_service")):
                services = extract_services(desc_lower)
                if services:
                    rec["requires_service"] = services
                    self._bump("B: cve.requires_service")
            # тип атаки
            if is_empty(rec.get("attack_type")):
                for atype, patterns in ATTACK_TYPE_KEYWORDS:
                    if any(re.search(p, desc_lower) for p in patterns):
                        rec["attack_type"] = atype
                        self._bump("B: cve.attack_type")
                        break
            # severity из CVSS
            if is_empty(rec.get("severity")) and rec.get("cvss_score"):
                for threshold, label in SEVERITY_FROM_CVSS:
                    if rec["cvss_score"] >= threshold:
                        rec["severity"] = label
                        self._bump("B: cve.severity")
                        break

        for rec in cwe:
            if is_empty(rec.get("category")):
                text = f"{rec.get('name', '')} {rec.get('description', '')}".lower()
                for cat, patterns in CWE_CATEGORY_KEYWORDS:
                    if any(re.search(p, text) for p in patterns):
                        rec["category"] = cat
                        self._bump("B: cwe.category")
                        break

        for rec in attack:
            if is_empty(rec.get("requires_service")):
                services = extract_services((rec.get("description", "") or "").lower())
                if services:
                    rec["requires_service"] = services
                    self._bump("B: attack.requires_service")

        for k in sorted(self.stats):
            if k.startswith("B:"):
                print(f"  ✅ {k} → заполнено {self.stats[k]}")

    # ---------- Ярус C: detection из STIX ----------
    def fill_attack_detection(self, stix_path: str = None, translate: bool = True):
        print("\n🧬 Ярус C: восстановление detection из ATT&CK STIX...")
        attack = self.dbs.get("mitre_attack.json", [])
        need = [r for r in attack if is_empty(r.get("detection"))]
        if not need:
            print("  ✅ Все detection уже заполнены")
            return

        stix = self._load_stix(stix_path)
        if not stix:
            print("  ⚠️ STIX недоступен — detection заполнится шаблоном (ярус D)")
            return

        detection_map = self._build_detection_map(stix)
        print(f"  📋 Стратегий обнаружения в STIX: техник с detection — {len(detection_map)}")

        filled = []
        for rec in need:
            text = detection_map.get(rec["id"])
            # для подтехник — fallback на родителя
            if not text and "." in rec["id"]:
                text = detection_map.get(rec["id"].split(".")[0])
            if text:
                rec["detection"] = text
                filled.append(rec)
        self._bump("C: attack.detection", len(filled))
        print(f"  ✅ Заполнено detection из первоисточника: {len(filled)} из {len(need)}")

        if filled and translate:
            self._translate_detections(filled)

    def _load_stix(self, stix_path: str = None) -> dict | None:
        if stix_path:
            fp = Path(stix_path)
            if fp.exists():
                print(f"  📂 Чтение локального STIX: {fp}")
                with open(fp, "r", encoding="utf-8") as f:
                    return json.load(f)
            print(f"  ⚠️ Файл {fp} не найден")
            return None
        url = Config.SOURCES.get("attack_stix")
        try:
            import requests
            print(f"  🌐 Загрузка STIX (~50 МБ): {url}")
            r = requests.get(url, timeout=180)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"  ⚠️ Не удалось скачать STIX: {e}")
            return None

    def _build_detection_map(self, stix: dict) -> dict:
        """T-ID техники → собранный текст detection из стратегий и аналитик."""
        objs = stix.get("objects", [])
        by_id = {o["id"]: o for o in objs if "id" in o}

        # attack-pattern STIX-id → внешний T-ID
        tid_of = {}
        for o in objs:
            if o.get("type") == "attack-pattern":
                for ref in o.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid_of[o["id"]] = ref.get("external_id", "")

        detection_map = {}
        for rel in objs:
            if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
                continue
            strategy = by_id.get(rel.get("source_ref"))
            t_id = tid_of.get(rel.get("target_ref"))
            if not strategy or not t_id or strategy.get("type") != "x-mitre-detection-strategy":
                continue
            parts = []
            for an_ref in strategy.get("x_mitre_analytic_refs", []):
                an = by_id.get(an_ref)
                if not an:
                    continue
                desc = clean_html(an.get("description", ""))
                if not desc:
                    continue
                platforms = an.get("x_mitre_platforms", [])
                prefix = f"[{', '.join(platforms)}] " if platforms else ""
                parts.append(prefix + desc)
                if sum(len(p) for p in parts) > MAX_DETECTION_CHARS:
                    break
            if parts:
                text = "\n".join(parts)[:MAX_DETECTION_CHARS]
                # если несколько стратегий — берём самую содержательную
                if len(text) > len(detection_map.get(t_id, "")):
                    detection_map[t_id] = text
        return detection_map

    def _translate_detections(self, records: list):
        try:
            from .translator import Translator
            # Detection-тексты длинные и многочисленные, поэтому переводим
            # с меньшей нагрузкой, чтобы не упереться в лимит Google Translate
            translator = Translator(force_enable=True, workers=3, delay=0.6)
            if not translator.enabled:
                print("  ⚠️ Переводчик недоступен — detection останется на английском")
                return
            texts = [r["detection"] for r in records]
            print(f"  🌐 Перевод {len(texts)} detection-текстов...")
            translated = translator.translate_batch(texts)
            for rec, tr in zip(records, translated):
                rec["detection"] = tr
            translator._save_cache()
            print("  ✅ Перевод detection завершён")
        except Exception as e:
            print(f"  ⚠️ Ошибка перевода detection (останется английский текст): {e}")

    # ---------- Ярус D: шаблоны ----------
    def apply_templates(self):
        print("\n📝 Ярус D: шаблонные фразы для оставшихся пустых полей...")
        templates = getattr(Config, "AUTOFILL_TEMPLATES", {})
        for fn, fields in templates.items():
            data = self.dbs.get(fn)
            if not data:
                continue
            for rec in data:
                for field, template in fields.items():
                    if field not in rec or not is_empty(rec[field]):
                        continue
                    if isinstance(rec[field], list):
                        rec[field] = [template]
                    else:
                        rec[field] = template
                    self._bump(f"D: {fn.split('_')[0]}.{field}")
        for k in sorted(self.stats):
            if k.startswith("D:"):
                print(f"  ✅ {k} → заполнено шаблоном {self.stats[k]}")

    # ---------- отчёт ----------
    def report(self):
        print("\n📊 Итог: оставшиеся пустые поля (легитимно пустые связи related_*):")
        for fn, data in self.dbs.items():
            total = len(data)
            counts = {}
            for rec in data:
                for k, v in rec.items():
                    if is_empty(v):
                        counts[k] = counts.get(k, 0) + 1
            line = ", ".join(f"{k}: {c} ({c * 100 // total}%)" for k, c in
                             sorted(counts.items(), key=lambda x: -x[1])) or "пустых полей нет 🎉"
            print(f"  {fn}: {line}")


def main():
    parser = argparse.ArgumentParser(description="Автозаполнение пустых полей в JSON-базах")
    parser.add_argument("--stix", help="Путь к локальному файлу enterprise-attack.json (иначе скачивается)")
    parser.add_argument("--no-detection", action="store_true", help="Пропустить ярус C (detection из STIX)")
    parser.add_argument("--no-translate", action="store_true", help="Не переводить заполненные detection")
    args = parser.parse_args()

    progress.info("Автозаполнение пустых полей (Шаг 4)", progress=5)
    filler = AutoFiller()
    if not filler.load():
        progress.error("Базы не найдены в output/")
        return 1

    filler.fill_links()
    progress.info("Ярус A (связи) завершён", progress=30)
    filler.extract_facts()
    progress.info("Ярус B (факты из описаний) завершён", progress=50)
    if not args.no_detection:
        filler.fill_attack_detection(stix_path=args.stix, translate=not args.no_translate)
        progress.info("Ярус C (detection из STIX) завершён", progress=75)
    filler.apply_templates()
    filler.save()
    filler.report()
    progress.success("Автозаполнение завершено", progress=100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
