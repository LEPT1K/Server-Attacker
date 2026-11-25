# src/loader.py
import time
import gzip
import json
import requests
import zipfile
from io import BytesIO
from .config import Config


class DataLoader:
    """Загрузчик данных с повторными попытками"""

    @staticmethod
    def fetch_with_retry(url: str) -> bytes | None:
        """Скачивает обычный файл (XML/JSON) с повторными попытками"""
        for attempt in range(Config.RETRY_ATTEMPTS):
            try:
                print(f"📥 Загрузка: {url} (попытка {attempt + 1})")
                response = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
                response.raise_for_status()
                return response.content
            except requests.RequestException as e:
                print(f"⚠️ Ошибка загрузки: {e}")
                if attempt < Config.RETRY_ATTEMPTS - 1:
                    time.sleep(Config.RETRY_DELAY)
                else:
                    print(f"❌ Не удалось загрузить {url}")
                    return None
        return None

    @staticmethod
    def fetch_zip_with_retry(url: str, target_extension: str = ".xml") -> bytes | None:
        """Скачивает ZIP-архив и извлекает файл с нужным расширением"""
        for attempt in range(Config.RETRY_ATTEMPTS):
            try:
                print(f"📥 Загрузка ZIP: {url} (попытка {attempt + 1})")
                response = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
                response.raise_for_status()

                with zipfile.ZipFile(BytesIO(response.content)) as zf:
                    target_files = [f for f in zf.namelist() if f.endswith(target_extension)]
                    if target_files:
                        return zf.read(target_files[0])
                    print(f"⚠️ Не найден файл {target_extension} в архиве")
                    return None

            except requests.RequestException as e:
                print(f"⚠️ Ошибка загрузки: {e}")
                if attempt < Config.RETRY_ATTEMPTS - 1:
                    time.sleep(Config.RETRY_DELAY)
                else:
                    print(f"❌ Не удалось загрузить {url}")
                    return None
            except zipfile.BadZipFile as e:
                print(f"❌ Ошибка распаковки ZIP: {e}")
                return None
        return None
    
    @staticmethod
    def fetch_cve_latest_release_url() -> str | None:
        """Получает прямую ссылку на ZIP-архив последнего релиза CVE"""
        try:
            response = requests.get(Config.SOURCES["cve_latest"], timeout=Config.REQUEST_TIMEOUT)
            response.raise_for_status()
            release = response.json()
            for asset in release.get("assets", []):
                if asset.get("name", "").endswith(".zip"):
                    return asset["browser_download_url"]
        except Exception as e:
            print(f"⚠️ Ошибка получения ссылки CVE: {e}")
        return None
    
    @staticmethod
    def fetch_gz_json(url: str) -> dict | None:
        """Скачивает и распаковывает сжатый JSON-фид (NVD)"""
        for attempt in range(Config.RETRY_ATTEMPTS):
            try:
                print(f"📥 Загрузка сжатого фида: {url} (попытка {attempt + 1})")
                response = requests.get(url, timeout=Config.REQUEST_TIMEOUT, stream=True)
                response.raise_for_status()
                
                # Декомпрессия в памяти
                with gzip.GzipFile(fileobj=BytesIO(response.content)) as gz:
                    return json.loads(gz.read())
                    
            except requests.RequestException as e:
                print(f"⚠️ Ошибка загрузки: {e}")
                if attempt < Config.RETRY_ATTEMPTS - 1:
                    time.sleep(Config.RETRY_DELAY)
            except Exception as e:
                print(f"❌ Ошибка распаковки JSON: {e}")
                return None
        return None
