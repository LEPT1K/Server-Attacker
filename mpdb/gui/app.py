#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MPDB (MITRE Parser Databases) GUI - Графический интерфейс для управления парсером
"""

import sys
import os
import json
import re
import threading
import time
import subprocess
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Добавляем путь к основному проекту

from ..config import Config
from ..updates_checker import UpdatesChecker
from ..link_graph import LinkGraph
from ..progress import parse_event
from .exporters import DB_TITLES, export_csv, export_pdf_report, export_xlsx

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mitre-parser-gui-secret-key'
CORS(app)
# Используем threading вместо eventlet для совместимости с Python 3.13
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Глобальные переменные для управления процессами
process_status = {
    'parsing': {'status': 'idle', 'progress': 0, 'log': []},
    'linking': {'status': 'idle', 'progress': 0, 'log': []},
    'autofilling': {'status': 'idle', 'progress': 0, 'log': []},
    'translating': {'status': 'idle', 'progress': 0, 'log': []}
}

process_threads = {}
process_handles = {}

# Инициализация проверочника обновлений
updates_checker = None

# Граф перекрёстных связей между базами (для визуализации связывания)
link_graph = None

def get_output_dir():
    """Получить путь к директории output"""
    return Config.OUTPUT_DIR

# Файл для сохранения статуса процессов между перезапусками приложения
STATUS_FILE = Config.OUTPUT_DIR / 'process_status.json'

def save_process_status():
    """Сохранить статус и прогресс процессов на диск (без объёмных логов)."""
    try:
        slim = {name: {'status': st['status'], 'progress': st['progress']}
                for name, st in process_status.items()}
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(STATUS_FILE, 'w', encoding='utf-8') as f:
            json.dump(slim, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Не удалось сохранить статус процессов: {e}")

def load_process_status():
    """Восстановить статус процессов при запуске.

    Процесс, помеченный 'running', после перезапуска приложения уже не выполняется
    (его подпроцесс умер вместе с прошлым сервером) — сбрасываем такой в 'idle'.
    """
    try:
        if not STATUS_FILE.exists():
            return
        with open(STATUS_FILE, 'r', encoding='utf-8') as f:
            saved = json.load(f)
        for name, value in (saved or {}).items():
            if name in process_status and isinstance(value, dict):
                st = value.get('status', 'idle')
                if st == 'running':
                    st = 'idle'
                    progress_val = 0
                else:
                    progress_val = value.get('progress', 0)
                process_status[name]['status'] = st
                process_status[name]['progress'] = progress_val
    except Exception as e:
        print(f"Не удалось загрузить статус процессов: {e}")

# Восстанавливаем сохранённый статус при импорте модуля (в т.ч. под launcher.py)
load_process_status()

def load_json_file(filename, as_dict=False):
    """Загрузить JSON файл.
    Если as_dict=True и файл не является словарём (или отсутствует), вернуть {}.
    Для обычных файлов (as_dict=False) возвращается [] при отсутствии.
    """
    filepath = get_output_dir() / filename
    if filepath.exists():
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if as_dict and not isinstance(data, dict):
                return {}
            return data
    return {} if as_dict else []

def save_json_file(filename, data):
    """Сохранить JSON файл в output директорию"""
    filepath = get_output_dir() / filename
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

CONFIG_PATH = Path(__file__).parent.parent / 'config.py'

def update_config_file(updates: dict):
    """Обновляет константы в src/config.py и в уже загруженном классе Config"""
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    for key, value in updates.items():
        replacement = f'"{value}"' if isinstance(value, str) else str(value)
        content, count = re.subn(
            rf'^(\s*{re.escape(key)}\s*=\s*).*$',
            lambda m, r=replacement: m.group(1) + r,
            content,
            count=1,
            flags=re.MULTILINE
        )
        if count:
            setattr(Config, key, value)

    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        f.write(content)

# Маппинг процессов к модулям пакета mpdb
PROCESS_MODULES = {
    'parsing': 'mpdb.step1_parse',
    'linking': 'mpdb.step2_link',
    'autofilling': 'mpdb.step4_autofill',
    'translating': 'mpdb.translate_fields'
}

def run_real_process(process_name):
    """Запуск реального процесса парсера"""
    status = process_status[process_name]
    status['status'] = 'running'
    status['progress'] = 0
    status['log'] = []
    save_process_status()

    # Отправляем уведомление о старте
    socketio.emit('process_started', {'process': process_name})

    module_name = PROCESS_MODULES.get(process_name)
    if not module_name:
        status['status'] = 'error'
        error_msg = f"❌ Неизвестный процесс: {process_name}"
        status['log'].append(error_msg)
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 0,
            'log': error_msg
        })
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 0
        })
        save_process_status()
        return
    
    # Корень репозитория Server-Attacker (mpdb/gui/app.py -> mpdb/gui -> mpdb -> root)
    repo_root = Path(__file__).resolve().parent.parent.parent

    try:
        # Запускаем процесс с правильным рабочим каталогом
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        # Просим шаги слать структурные события (уровень/прогресс) вместо
        # угадывания по эмодзи — см. src/progress.py
        env['MPDB_STRUCTURED'] = '1'

        process = subprocess.Popen(
            [sys.executable, '-u', '-m', module_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            env=env,
            cwd=str(repo_root)
        )
        process_handles[process_name] = process

        # Читаем вывод построчно
        total_lines = 0
        estimated_lines = 200  # Увеличенное количество строк для прогресса

        socketio.emit('process_update', {
            'process': process_name,
            'status': 'running',
            'progress': 5,
            'log': f"🚀 Запуск {module_name}..."
        })

        for line in process.stdout:
            if status['status'] == 'stopped':
                process.terminate()
                break

            line = line.strip()
            if line:
                total_lines += 1

                # Сначала пробуем разобрать структурное событие (уровень/прогресс)
                event = parse_event(line)
                explicit_progress = None
                if event is not None:
                    log_type = event['level'] if event['level'] in ('info', 'success', 'warning', 'error') else 'info'
                    line = event.get('msg', '')
                    explicit_progress = event.get('progress')
                else:
                    # Fallback для строк без события: эвристика по эмодзи/ключевым словам
                    log_type = 'info'
                    if '✅' in line or 'OK' in line or 'успешно' in line.lower():
                        log_type = 'success'
                    elif '❌' in line or 'ERROR' in line or 'ошибка' in line.lower():
                        log_type = 'error'
                    elif '⚠️' in line or 'WARNING' in line or 'предупреждение' in line.lower():
                        log_type = 'warning'

                if not line:
                    continue

                status['log'].append(line)

                # Явный прогресс из события имеет приоритет над оценкой по числу строк
                if explicit_progress is not None:
                    progress = max(5, min(int(explicit_progress), 95))
                else:
                    progress = min(int((total_lines / estimated_lines) * 95), 95)
                    if progress < 5:
                        progress = 5
                status['progress'] = progress

                socketio.emit('process_update', {
                    'process': process_name,
                    'status': 'running',
                    'progress': progress,
                    'log': line,
                    'log_type': log_type
                })

        # Ждем завершения процесса
        return_code = process.wait()
        process_handles.pop(process_name, None)

        if status['status'] == 'stopped':
            stop_msg = "⏹️ Процесс остановлен пользователем"
            status['log'].append(stop_msg)

            socketio.emit('process_update', {
                'process': process_name,
                'status': 'stopped',
                'progress': status['progress'],
                'log': stop_msg,
                'log_type': 'warning'
            })

            socketio.emit('process_complete', {
                'process': process_name,
                'status': 'stopped',
                'progress': status['progress']
            })
        elif return_code == 0:
            status['status'] = 'completed'
            status['progress'] = 100
            success_msg = "✅ Процесс завершен успешно!"
            status['log'].append(success_msg)
            
            socketio.emit('process_update', {
                'process': process_name,
                'status': 'completed',
                'progress': 100,
                'log': success_msg,
                'log_type': 'success'
            })
            
            socketio.emit('process_complete', {
                'process': process_name,
                'status': 'completed',
                'progress': 100
            })
        else:
            status['status'] = 'error'
            error_msg = f"❌ Ошибка: код возврата {return_code}"
            status['log'].append(error_msg)
            
            socketio.emit('process_update', {
                'process': process_name,
                'status': 'error',
                'progress': 100,
                'log': error_msg,
                'log_type': 'error'
            })
            
            socketio.emit('process_complete', {
                'process': process_name,
                'status': 'error',
                'progress': 100
            })
            
    except subprocess.CalledProcessError as e:
        error_msg = f"❌ Ошибка выполнения: {e}"
        status['status'] = 'error'
        status['log'].append(error_msg)
        
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 100,
            'log': error_msg,
            'log_type': 'error'
        })
        
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 100
        })
        
    except Exception as e:
        error_msg = f"❌ Исключение: {str(e)}"
        status['status'] = 'error'
        status['log'].append(error_msg)
        
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 100,
            'log': error_msg,
            'log_type': 'error'
        })
        
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 100
        })

    # Сохраняем итоговый статус (любая ветка: completed/stopped/error) на диск
    save_process_status()

# ==================== МАРШРУТЫ ====================

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Получить статус всех процессов"""
    return jsonify(process_status)

@app.route('/api/databases')
def get_databases():
    """Получить список баз данных"""
    databases = []
    output_dir = get_output_dir()
    total_links = 0
    
    db_files = {
        'capec_database.json': 'CAPEC',
        'cwe_database.json': 'CWE',
        'cve_database.json': 'CVE',
        'mitre_attack.json': 'MITRE ATT&CK'
    }
    
    for filename, name in db_files.items():
        filepath = output_dir / filename
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Подсчитываем связи в этой базе
                db_links = 0
                for record in data:
                    # Считаем все поля, которые могут содержать связи
                    for key in ['related_capec', 'related_cwe', 'related_mitre', 'related_cve']:
                        if key in record:
                            value = record[key]
                            if isinstance(value, list):
                                db_links += len([x for x in value if x])  # Считаем только непустые значения
                            elif isinstance(value, str) and value:
                                db_links += 1
                
                total_links += db_links
                
                databases.append({
                    'id': filename.replace('.json', ''),
                    'name': name,
                    'filename': filename,
                    'records': len(data),
                    'size': filepath.stat().st_size,
                    'links': db_links
                })
            except Exception as e:
                print(f"Error loading {filename}: {e}")
                pass
    
    # Добавляем общее количество связей в ответ
    return jsonify({
        'databases': databases,
        'total_links': total_links
    })

@app.route('/api/database/<db_name>')
def get_database(db_name):
    """Получить данные конкретной базы"""
    filename = f"{db_name}.json"
    data = load_json_file(filename)
    return jsonify(data)

@app.route('/api/database/<db_name>', methods=['PUT'])
def update_database(db_name):
    """Обновить данные базы"""
    filename = f"{db_name}.json"
    data = request.json
    save_json_file(filename, data)
    return jsonify({'status': 'success', 'message': f'База {db_name} обновлена'})

@app.route('/api/database/<db_name>/record/<record_id>', methods=['GET'])
def get_record(db_name, record_id):
    """Получить полные данные одной записи из базы"""
    filename = f"{db_name}.json"
    data = load_json_file(filename)

    for record in data:
        if record.get('id') == record_id:
            return jsonify(record)

    return jsonify({'status': 'error', 'message': 'Запись не найдена'}), 404

@app.route('/api/database/<db_name>/record/<record_id>', methods=['PUT'])
def update_record(db_name, record_id):
    """Обновить конкретную запись в базе"""
    filename = f"{db_name}.json"
    data = load_json_file(filename)
    
    # Найти и обновить запись
    for i, record in enumerate(data):
        if record.get('id') == record_id:
            data[i] = request.json
            save_json_file(filename, data)
            return jsonify({'status': 'success', 'message': f'Запись {record_id} обновлена'})
    
    return jsonify({'status': 'error', 'message': 'Запись не найдена'}), 404

@app.route('/api/export/<db_name>/csv')
def export_database_csv(db_name):
    """Экспортировать базу данных в CSV"""
    data = load_json_file(f"{db_name}.json")
    if not data:
        return jsonify({'status': 'error', 'message': 'База данных не найдена или пуста'}), 404

    buffer = export_csv(data)
    return send_file(
        buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"{db_name}.csv"
    )

@app.route('/api/export/<db_name>/xlsx')
def export_database_xlsx(db_name):
    """Экспортировать базу данных в XLSX (с листом сводки и диаграммой)"""
    data = load_json_file(f"{db_name}.json")
    if not data:
        return jsonify({'status': 'error', 'message': 'База данных не найдена или пуста'}), 404

    title = DB_TITLES.get(db_name, db_name)
    buffer = export_xlsx(data, title)
    return send_file(
        buffer,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f"{db_name}.xlsx"
    )

@app.route('/api/export/report/pdf')
def export_report_pdf():
    """Сформировать сводный PDF-отчёт по всем базам данных с графиками"""
    global link_graph
    databases = get_databases().get_json().get('databases', [])

    # Статистика связей — для расшифровки, из чего складывается их число
    try:
        if link_graph is None:
            link_graph = LinkGraph(get_output_dir())
        link_stats = link_graph.get_link_statistics()
    except Exception:
        link_stats = None

    buffer = export_pdf_report(databases, link_stats)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='mpdb_report.pdf'
    )

@app.route('/api/output-folder/open', methods=['POST'])
def open_output_folder():
    """Открыть локальную папку output (с JSON базами) в проводнике/файловом менеджере"""
    output_dir = get_output_dir()
    if not output_dir.exists():
        return jsonify({'status': 'error', 'message': f'Папка не найдена: {output_dir}'}), 404

    path = str(output_dir.resolve())
    try:
        if sys.platform.startswith('win'):
            os.startfile(path)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', path])
        else:
            subprocess.Popen(['xdg-open', path])
        return jsonify({'status': 'success', 'message': 'Папка открыта', 'path': path})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'path': path}), 500

@app.route('/api/translate-cache')
def get_translate_cache():
    cache = load_json_file('translate_cache.json', as_dict=True)
    return jsonify(cache)

@app.route('/api/translate-cache', methods=['PUT'])
def update_translate_cache():
    """Обновить кэш переводов"""
    data = request.json
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Кэш должен быть объектом'}), 400
    save_json_file('translate_cache.json', data)
    return jsonify({'status': 'success', 'message': 'Кэш переводов обновлен'})

@app.route('/api/translate-cache', methods=['DELETE'])
def clear_translate_cache():
    """Очистить кэш переводов (сохранение пустого словаря)"""
    save_json_file('translate_cache.json', {})
    return jsonify({'status': 'success', 'message': 'Кэш переводов очищен'})

@app.route('/api/config')
def get_config():
    """Получить текущие настройки"""
    config_data = {
        'translation': {
            'enabled': Config.ENABLE_TRANSLATION,
            'service': Config.TRANSLATION_SERVICE,
            'target_lang': Config.TRANSLATE_TO,
            'workers': Config.TRANSLATION_WORKERS,
            'delay': Config.TRANSLATION_DELAY,
            'max_retries': Config.TRANSLATION_MAX_RETRIES
        },
        'limits': {
            'max_capec': Config.MAX_CAPEC_RECORDS,
            'max_cwe': Config.MAX_CWE_RECORDS,
            'max_cve': Config.MAX_CVE_RECORDS,
            'max_attack': Config.MAX_ATTACK_RECORDS
        }
    }
    return jsonify(config_data)

@app.route('/api/config', methods=['PUT'])
def update_config():
    """Обновить настройки перевода и сохранить их в config.py"""
    try:
        data = request.json or {}
        updates = {}

        translation = data.get('translation', {})
        translation_map = {
            'service': 'TRANSLATION_SERVICE',
            'target_lang': 'TRANSLATE_TO',
            'workers': 'TRANSLATION_WORKERS',
            'delay': 'TRANSLATION_DELAY',
            'max_retries': 'TRANSLATION_MAX_RETRIES',
        }
        for json_key, config_key in translation_map.items():
            if json_key in translation:
                updates[config_key] = translation[json_key]

        if updates:
            update_config_file(updates)

        return jsonify({'status': 'success', 'message': 'Настройки сохранены в config.py'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/config/limits', methods=['PUT'])
def update_limits():
    """Обновить лимиты записей для парсинга и сохранить их в config.py"""
    try:
        data = request.json or {}
        limits = data.get('limits', {})

        limits_map = {
            'max_capec': 'MAX_CAPEC_RECORDS',
            'max_cwe': 'MAX_CWE_RECORDS',
            'max_cve': 'MAX_CVE_RECORDS',
            'max_attack': 'MAX_ATTACK_RECORDS',
        }
        updates = {}
        for json_key, config_key in limits_map.items():
            if json_key in limits:
                updates[config_key] = int(limits[json_key])

        update_config_file(updates)

        return jsonify({
            'status': 'success',
            'message': 'Лимиты обновлены и сохранены в config.py',
            'updated': limits
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process/<process_name>/stop', methods=['POST'])
def stop_process_api(process_name):
    """API для остановки процесса"""
    if process_name in process_status:
        process_status[process_name]['status'] = 'stopped'
        handle = process_handles.get(process_name)
        if handle and handle.poll() is None:
            handle.terminate()
        save_process_status()
        return jsonify({'status': 'success', 'message': f'Процесс {process_name} остановлен'})
    return jsonify({'status': 'error', 'message': 'Процесс не найден'}), 404

# ==================== API НОВОСТНОЙ ЛЕНТЫ ====================

@app.route('/api/updates', methods=['GET'])
def get_updates():
    """Получить информацию об обновлениях в MITRE базах"""
    global updates_checker

    try:
        if updates_checker is None:
            updates_checker = UpdatesChecker(get_output_dir())

        force_refresh = request.args.get('force', 'false').lower() == 'true'
        data = updates_checker.check_updates(force_refresh=force_refresh)

        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'updates': []}), 500

@app.route('/api/updates/changelog', methods=['GET'])
def get_changelog():
    """Журнал изменений состава баз (дельта-обновления между прогонами парсера)"""
    try:
        from ..db_history import DBHistory
        limit = request.args.get('limit', 20, type=int) or 20
        return jsonify(DBHistory(get_output_dir()).get_changelog(limit))
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'changelog': []}), 500

@app.route('/api/updates/<source_key>', methods=['GET'])
def get_source_comparison(source_key):
    """Получить детальное сравнение конкретного источника"""
    global updates_checker

    try:
        if updates_checker is None:
            updates_checker = UpdatesChecker(get_output_dir())

        data = updates_checker.get_db_comparison(source_key)

        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==================== ВИЗУАЛИЗАЦИЯ СВЯЗЫВАНИЯ ====================

@app.route('/api/linking/stats', methods=['GET'])
def get_linking_stats():
    """Статистика перекрёстных связей между базами (для обзорной диаграммы)"""
    global link_graph

    try:
        if link_graph is None:
            link_graph = LinkGraph(get_output_dir())

        return jsonify(link_graph.get_link_statistics())
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/linking/coverage', methods=['GET'])
def get_linking_coverage():
    """Отчёт о покрытии связей (gap-analysis): % записей, дотянутых до смежных баз"""
    global link_graph

    try:
        if link_graph is None:
            link_graph = LinkGraph(get_output_dir())

        return jsonify(link_graph.get_coverage_report())
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/linking/search', methods=['GET'])
def search_linking_nodes():
    """Поиск узлов (записей) по id или названию для графа связей"""
    global link_graph

    try:
        if link_graph is None:
            link_graph = LinkGraph(get_output_dir())

        query = request.args.get('q', '')
        return jsonify({'results': link_graph.search_nodes(query)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/linking/graph/<node_id>', methods=['GET'])
def get_linking_graph(node_id):
    """Локальный граф связей узла (depth=1..3 шагов)"""
    global link_graph

    try:
        if link_graph is None:
            link_graph = LinkGraph(get_output_dir())

        depth = request.args.get('depth', 1, type=int) or 1
        data = link_graph.get_network(node_id, depth)
        if 'error' in data:
            return jsonify(data), 404

        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/linking/path', methods=['GET'])
def get_linking_path():
    """Кратчайший путь между двумя записями в графе перекрёстных связей"""
    global link_graph

    try:
        if link_graph is None:
            link_graph = LinkGraph(get_output_dir())

        from_id = request.args.get('from', '').strip()
        to_id = request.args.get('to', '').strip()
        if not from_id or not to_id:
            return jsonify({'status': 'error', 'message': 'Параметры from и to обязательны'}), 400

        data = link_graph.find_path(from_id, to_id)
        if 'error' in data:
            return jsonify(data), 404

        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==================== WEBSOCKET СОБЫТИЯ ====================

@socketio.on('connect')
def handle_connect():
    """Клиент подключился"""
    print('Клиент подключился к WebSocket')

@socketio.on('start_process')
def handle_start_process(data):
    """Запуск процесса"""
    process_name = data.get('process')

    # Автозаполнение работает по русским словарям/шаблонам, поэтому должно идти
    # ПОСЛЕ перевода. Блокируем запуск, пока перевод не завершён в этой сессии.
    if process_name == 'autofilling' and process_status['translating']['status'] != 'completed':
        emit('process_update', {
            'process': process_name,
            'status': 'idle',
            'progress': 0,
            'log': '⚠️ Сначала выполните «Перевод» — автозаполнение работает на русском языке',
            'log_type': 'warning'
        })
        return

    if process_name in process_status:
        # Остановить предыдущий процесс если есть
        if process_threads.get(process_name):
            if process_threads[process_name].is_alive():
                process_status[process_name]['status'] = 'stopped'
                handle = process_handles.get(process_name)
                if handle and handle.poll() is None:
                    handle.terminate()
                process_threads[process_name].join(timeout=5)
        
        # Запустить новый процесс
        thread = threading.Thread(
            target=run_real_process,
            args=(process_name,)
        )
        process_threads[process_name] = thread
        thread.start()

@socketio.on('stop_process')
def handle_stop_process(data):
    """Остановка процесса"""
    process_name = data.get('process')
    if process_name in process_status:
        process_status[process_name]['status'] = 'stopped'
        handle = process_handles.get(process_name)
        if handle and handle.poll() is None:
            handle.terminate()
        save_process_status()
        emit('process_stopped', {'process': process_name})

@socketio.on('clear_log')
def handle_clear_log(data):
    """Очистка лога"""
    process_name = data.get('process')
    if process_name in process_status:
        process_status[process_name]['log'] = []
        emit('log_cleared', {'process': process_name})

# ==================== ЗАПУСК ПРИЛОЖЕНИЯ ====================

if __name__ == '__main__':
    print("🚀 Запуск MPDB GUI...")
    print(f"📂 Директория данных: {get_output_dir()}")
    print("🌐 Веб-интерфейс доступен по адресу: http://localhost:5000")
    
    # Убедимся, что output директория существует
    get_output_dir().mkdir(parents=True, exist_ok=True)
    
    # allow_unsafe_werkzeug: GUI — локальный инструмент, продакшен-сервер не требуется
    # host=127.0.0.1: не выставляем локальный инструмент в LAN
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
