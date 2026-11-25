import subprocess
import sys
from pathlib import Path

# Важно: перевод идёт ДО автозаполнения — автозаполнение работает по русским
# словарям/шаблонам и должно дописывать уже переведённую базу.
modules = ["mpdb.step1_parse", "mpdb.step2_link", "mpdb.translate_fields", "mpdb.step4_autofill"]

# Корень репозитория (mpdb/run_all.py -> mpdb -> root)
repo_root = Path(__file__).resolve().parent.parent

def main():
    for module in modules:
        print(f"\n🚀 Выполнение {module}...")
        result = subprocess.run([sys.executable, "-u", "-m", module], cwd=str(repo_root))
        if result.returncode != 0:
            print(f"❌ Ошибка в {module}")
            break


if __name__ == "__main__":
    main()
