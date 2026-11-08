@echo off
chcp 65001 >nul 2>&1
echo ============================================================
echo   Настройка виртуального окружения
echo   Security Assessment System
echo ============================================================
echo.

REM Проверяем наличие Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Python не найден!
    echo Скачайте Python 3.10+ с https://www.python.org/downloads/
    echo При установке отметьте "Add Python to PATH"
    pause
    exit /b 1
)

echo [1/4] Создание виртуального окружения...
if exist venv (
    echo       Окружение уже существует, пропускаем...
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ОШИБКА] Не удалось создать виртуальное окружение
        pause
        exit /b 1
    )
)

echo [2/4] Активация виртуального окружения...
call venv\Scripts\activate.bat

echo [3/4] Обновление pip...
python -m pip install --upgrade pip --quiet

echo [4/4] Установка зависимостей (PyQt6, cryptography, PyInstaller)...
pip install -r requirements.txt

echo.
echo ============================================================
echo   Виртуальное окружение готово!
echo ============================================================
echo.
echo   Активация окружения:
echo     venv\Scripts\activate.bat
echo.
echo   Запуск GUI:
echo     python gui_server.py           (серверный агент)
echo     python gui_attacker.py         (атакующий агент)
echo.
echo   Запуск без GUI:
echo     python run_server.py           (серверный агент)
echo     python run_attacker.py -t IP   (атакующий агент)
echo.
echo   Сборка EXE:
echo     python build_exe.py
echo ============================================================
pause
