/**
 * MPDB (MITRE Parser Databases) GUI - Клиентская часть
 */

// Глобальные переменные
let socket;
let currentDb = null;
let currentData = [];
let currentPage = 1;
let recordsPerPage = 25;
let translateCache = {};
let processStates = {
    parsing: 'idle',
    linking: 'idle',
    autofilling: 'idle',
    translating: 'idle'
};

// ==================== Экранирование текста ====================
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeJs(str) {
    if (!str) return '';
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}

// Инициализация при загрузке
$(document).ready(function() {
    initSocket();
    initNavigation();
    initForms();
    initTheme();
    initScrollEffects();
    loadDashboardData();
    restoreLastPage();
});

// Восстановить вкладку, открытую до обновления страницы
function restoreLastPage() {
    const savedPage = localStorage.getItem('mpdb-page') || 'home';

    if (savedPage === 'database') {
        const savedDb = localStorage.getItem('mpdb-db');
        if (savedDb) {
            showDatabase(savedDb);
            return;
        }
    }

    showPage(savedPage);
}

// ==================== Тема оформления ====================

function applyTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    $('#themeIcon')
        .toggleClass('bi-moon-stars-fill', theme === 'light')
        .toggleClass('bi-sun-fill', theme === 'dark');
}

function initTheme() {
    const savedTheme = localStorage.getItem('mpdb-theme') || 'light';
    applyTheme(savedTheme);

    $('#themeToggle').on('click', function() {
        const current = document.documentElement.getAttribute('data-bs-theme') || 'light';
        const next = current === 'dark' ? 'light' : 'dark';

        applyTheme(next);
        localStorage.setItem('mpdb-theme', next);

        $(this).addClass('spin');
        setTimeout(() => $(this).removeClass('spin'), 400);
    });
}

// ==================== Эффекты прокрутки ====================

function initScrollEffects() {
    $(window).on('scroll', function() {
        const scrollTop = $(window).scrollTop();
        $('#mainNavbar').toggleClass('scrolled', scrollTop > 10);
        $('#scrollTopBtn').toggleClass('visible', scrollTop > 300);
    });

    $('#scrollTopBtn').on('click', function() {
        $('html, body').animate({ scrollTop: 0 }, 400);
    });
}

// ==================== Анимация счётчиков ====================

function animateCounter(selector, target) {
    const $el = $(selector);
    const start = parseInt($el.text(), 10) || 0;

    if (start === target) {
        $el.text(target);
        return;
    }

    const duration = 600;
    const startTime = performance.now();

    function step(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(start + (target - start) * eased);
        $el.text(value);

        if (progress < 1) {
            requestAnimationFrame(step);
        }
    }

    requestAnimationFrame(step);
}

// ==================== WebSocket ====================

function initSocket() {
    socket = io.connect('http://' + document.domain + ':' + location.port);
    
    socket.on('connect', function() {
        $('#connectionStatus').html('<span class="badge bg-success connected">Подключено</span>');
        addLog('info', 'Подключено к серверу');
    });
    
    socket.on('disconnect', function() {
        $('#connectionStatus').html('<span class="badge bg-danger">Отключено</span>');
        addLog('error', 'Отключено от сервера');
    });
    
    socket.on('process_started', function(data) {
        addLog('info', `Процесс "${data.process}" запущen`);
        processStates[data.process] = 'running';
    });
    
    socket.on('process_update', function(data) {
        updateProgress(data.process, data.progress);
        const logType = data.log_type || 'info';
        addProcessLog(data.process, data.log, logType);
    });
    
    socket.on('process_complete', function(data) {
        updateProgress(data.process, 100);
        processStates[data.process] = 'completed';
        addLog('success', `Процесс "${data.process}" завершен`);

        // Автозаполнение становится доступным только после завершения перевода
        updateAutofillGate();

        // Обновляем статистику
        setTimeout(loadDashboardData, 1000);
    });
    
    socket.on('process_stopped', function(data) {
        processStates[data.process] = 'stopped';
        addLog('warning', `Процесс "${data.process}" остановлен`);
    });
    
    socket.on('log_cleared', function(data) {
        $('#processLogs').html('<div class="log-entry text-muted">Логи очищены</div>');
    });
}

// ==================== Навигация ====================

function initNavigation() {
    // Переключение страниц
    $('a[data-page]').click(function(e) {
        e.preventDefault();
        const page = $(this).data('page');
        showPage(page);
    });
    
    // Выбор базы данных
    $('a[data-db]').click(function(e) {
        e.preventDefault();
        const db = $(this).data('db');
        showDatabase(db);
    });
}

function showPage(pageName) {
    let pageId = pageName.replace(/-([a-z])/g, (m, c) => c.toUpperCase()) + 'Page';

    // Неизвестная страница (например, устаревшее значение в localStorage) — открываем главную
    if ($('#' + pageId).length === 0) {
        pageName = 'home';
        pageId = 'homePage';
    }

    // Запоминаем вкладку, чтобы вернуться на неё после обновления страницы
    localStorage.setItem('mpdb-page', pageName);

    $('.page').removeClass('active').hide();
    $('#' + pageId).addClass('active').show();

    $('.nav-link').removeClass('active');
    $(`a[data-page="${pageName}"]`).addClass('active');

    // Для редактора БД подсвечиваем выпадающее меню «Базы данных»
    if (pageName === 'database') {
        $('#databasesDropdown').addClass('active');
    }

    // Загрузка данных для каждой страницы
    if (pageName === 'home') {
        loadUpdates();
    } else if (pageId === 'translateCachePage' || pageName === 'translate-cache' || pageName === 'translateCache') {
        loadTranslateCache();
    } else if (pageName === 'settings') {
        loadSettings();
    } else if (pageName === 'linking') {
        loadLinkingOverview();
    }
}

// ==================== Панель управления ====================

function loadDashboardData() {
    // Загружаем статистику баз данных
    $.get('/api/databases', function(response) {
        const databases = response.databases || [];
        const totalLinks = response.total_links || 0;

        animateCounter('#totalDatabases', databases.length);

        let totalRecords = 0;
        databases.forEach(db => {
            totalRecords += db.records;
        });
        animateCounter('#totalRecords', totalRecords);

        // Обновляем количество связей
        animateCounter('#totalLinks', totalLinks);
    });

    // Загружаем кэш переводов
    $.get('/api/translate-cache', function(cache) {
        // Проверяем, что cache - это объект, а не массив
        if (typeof cache === 'object' && cache !== null) {
            animateCounter('#totalTranslations', Object.keys(cache).length);
        } else {
            animateCounter('#totalTranslations', 0);
        }
    }).fail(function() {
        // Если кэш не найден или ошибка
        animateCounter('#totalTranslations', 0);
    });
    
    // Загружаем статус процессов
    $.get('/api/status', function(status) {
        Object.keys(status).forEach(process => {
            const state = status[process];
            updateProgress(process, state.progress);
            processStates[process] = state.status;
        });
        updateAutofillGate();
    });
}

function openOutputFolder() {
    /**Открыть локальную папку output (с JSON базами) в проводнике на этом компьютере*/
    $.ajax({
        url: '/api/output-folder/open',
        method: 'POST',
        timeout: 10000,
        success: function(data) {
            showToast('success', data.message || 'Папка открыта');
        },
        error: function(error) {
            const message = (error.responseJSON && error.responseJSON.message) || 'Не удалось открыть папку';
            showToast('danger', message);
        }
    });
}

// Автозаполнение работает по русским словарям/шаблонам → должно идти после перевода.
// Кнопка доступна только когда перевод завершён в текущей сессии.
function updateAutofillGate() {
    const ready = processStates['translating'] === 'completed';
    const btn = $('#autofillStartBtn');
    btn.prop('disabled', !ready);
    btn.attr('title', ready ? 'Запустить автозаполнение' : 'Сначала выполните «Перевод»');
}

function startProcess(processName) {
    if (processStates[processName] === 'running') {
        showToast('warning', 'Процесс уже запущен');
        return;
    }

    // Автозаполнение разрешено только после перевода (работает на русском языке)
    if (processName === 'autofilling' && processStates['translating'] !== 'completed') {
        showToast('warning', 'Сначала выполните «Перевод» — автозаполнение работает на русском языке');
        return;
    }

    socket.emit('start_process', { process: processName });
    showToast('info', `Запуск процесса: ${processName}`);
}

function stopProcess(processName) {
    if (processStates[processName] !== 'running') {
        showToast('warning', 'Процесс не запущен');
        return;
    }
    
    // Отправляем запрос на остановку
    socket.emit('stop_process', { process: processName });
    
    // Также отправляем API запрос для принудительной остановки
    fetch(`/api/process/${processName}/stop`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('info', `Процесс ${processName} остановлен`);
            }
        })
        .catch(err => {
            console.error('Error stopping process:', err);
        });
    
    showToast('info', `Отправка команды остановки: ${processName}`);
}

function updateProgress(processName, progress) {
    const progressBar = $(`#${processName}Progress`);
    progressBar.css('width', progress + '%');
    progressBar.text(progress + '%');
    
    // Убираем анимацию если процесс завершен
    if (progress === 100) {
        progressBar.removeClass('progress-bar-animated');
    } else if (progress > 0 && progress < 100) {
        progressBar.addClass('progress-bar-animated');
    }
}

function clearLogs() {
    socket.emit('clear_log', {});
}

function toggleLogExpand() {
    const logContainer = document.getElementById('processLogs');
    const btn = document.getElementById('toggleLogExpandBtn');
    const expanded = logContainer.classList.toggle('expanded');
    btn.innerHTML = expanded
        ? '<i class="bi bi-arrows-angle-contract"></i>'
        : '<i class="bi bi-arrows-angle-expand"></i>';
    logContainer.scrollTop = logContainer.scrollHeight;
}

function addLog(type, message) {
    const timestamp = new Date().toLocaleTimeString();
    const logHtml = `<div class="log-entry ${type}">[${timestamp}] ${message}</div>`;
    
    const logContainer = $('#processLogs');
    logContainer.append(logHtml);
    
    // Прокручиваем вниз
    logContainer.scrollTop(logContainer[0].scrollHeight);
    
    // Ограничиваем количество записей
    if (logContainer.children().length > 200) {
        logContainer.children().first().remove();
    }
}

function addProcessLog(processName, message, logType = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = `[${processName}]`;
    const logHtml = `<div class="log-entry ${logType}">[${timestamp}] ${prefix} ${message}</div>`;
    
    const logContainer = $('#processLogs');
    logContainer.append(logHtml);
    
    // Прокручиваем вниз
    logContainer.scrollTop(logContainer[0].scrollHeight);
    
    // Ограничиваем количество записей
    if (logContainer.children().length > 200) {
        logContainer.children().first().remove();
    }
}

// ==================== Редактор баз данных ====================

function showDatabase(dbName) {
    currentDb = dbName;
    currentPage = 1;
    localStorage.setItem('mpdb-db', dbName);

    // Обновляем заголовок
    const dbNames = {
        'capec_database': 'CAPEC',
        'cwe_database': 'CWE',
        'cve_database': 'CVE',
        'mitre_attack': 'MITRE ATT&CK'
    };
    $('#databaseTitle').html(`<i class="bi bi-table"></i> Редактор базы: ${dbNames[dbName]}`);
    
    // Показываем страницу
    showPage('database');
    
    // Загружаем данные
    loadDatabaseData();
}

function loadDatabaseData() {
    if (!currentDb) return;

    $('#databaseTableBody').html('<tr><td colspan="4" class="text-center py-5"><div class="loading-spinner-inline"></div></td></tr>');

    $.get(`/api/database/${currentDb}`, function(data) {
        currentData = data;
        $('#recordCount').text(`Записей: ${data.length}`);
        renderTable();
    });
}

function renderTable() {
    const tbody = $('#databaseTableBody');
    tbody.empty();
    
    const searchTerm = $('#databaseSearch').val().toLowerCase();
    let filteredData = currentData;
    
    if (searchTerm) {
        filteredData = currentData.filter(record => {
            const id = (record.id || '').toLowerCase();
            const name = (record.name || '').toLowerCase();
            const description = (record.description || '').toLowerCase();
            return id.includes(searchTerm) || name.includes(searchTerm) || description.includes(searchTerm);
        });
    }
    
    // Пагинация
    const startIndex = (currentPage - 1) * recordsPerPage;
    const endIndex = Math.min(startIndex + recordsPerPage, filteredData.length);
    const pageData = filteredData.slice(startIndex, endIndex);
    
    const fragment = document.createDocumentFragment();
    pageData.forEach(record => {
        const row = document.createElement('tr');

        const tdId = document.createElement('td');
        const strong = document.createElement('strong');
        strong.textContent = record.id || 'N/A';
        tdId.appendChild(strong);
        row.appendChild(tdId);

        row.appendChild(createExpandableCell(record.name || ''));
        row.appendChild(createExpandableCell(record.description || ''));

        const tdActions = document.createElement('td');

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-sm btn-primary btn-action';
        editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
        editBtn.onclick = () => editRecord(record.id);
        tdActions.appendChild(editBtn);

        const viewBtn = document.createElement('button');
        viewBtn.className = 'btn btn-sm btn-info btn-action';
        viewBtn.innerHTML = '<i class="bi bi-eye"></i>';
        viewBtn.onclick = () => viewRecord(record.id);
        tdActions.appendChild(viewBtn);

        row.appendChild(tdActions);
        fragment.appendChild(row);
    });
    tbody[0].appendChild(fragment);

    renderPagination(filteredData.length);
}

// Длинные тексты сворачиваются (CSS line-clamp), клик разворачивает
function createExpandableCell(text) {
    const td = document.createElement('td');
    const div = document.createElement('div');
    div.className = 'expandable-text';
    div.textContent = text;
    div.title = 'Нажмите, чтобы развернуть/свернуть';
    div.onclick = () => div.classList.toggle('expanded');
    td.appendChild(div);
    return td;
}

function renderPagination(totalRecords) {
    const totalPages = Math.ceil(totalRecords / recordsPerPage);
    const pagination = $('#pagination');
    pagination.empty();
    
    if (totalPages <= 1) return;
    
    // Кнопка "Назад"
    if (currentPage > 1) {
        pagination.append(`
            <li class="page-item">
                <a class="page-link" href="#" onclick="goToPage(${currentPage - 1})">←</a>
            </li>
        `);
    }
    
    // Номера страниц
    for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
            pagination.append(`
                <li class="page-item ${i === currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="goToPage(${i})">${i}</a>
                </li>
            `);
        } else if (i === currentPage - 3 || i === currentPage + 3) {
            pagination.append('<li class="page-item disabled"><a class="page-link">...</a></li>');
        }
    }
    
    // Кнопка "Вперед"
    if (currentPage < totalPages) {
        pagination.append(`
            <li class="page-item">
                <a class="page-link" href="#" onclick="goToPage(${currentPage + 1})">→</a>
            </li>
        `);
    }
}

function goToPage(page) {
    currentPage = page;
    renderTable();
}

function editRecord(recordId) {
    const record = currentData.find(r => r.id === recordId);
    if (!record) return;
    
    $('#editRecordId').val(recordId);
    $('#editDbName').val(currentDb);
    
    const fieldsContainer = $('#editRecordFields');
    fieldsContainer.empty();
    
    // Создаем поля для редактирования
    Object.keys(record).forEach(key => {
        const value = record[key];
        const fieldId = `edit_field_${key}`;
        
        if (typeof value === 'string') {
            fieldsContainer.append(`
                <div class="mb-3">
                    <label class="form-label">${key}</label>
                    <textarea class="form-control" id="${fieldId}" rows="3">${value}</textarea>
                </div>
            `);
        } else if (Array.isArray(value)) {
            fieldsContainer.append(`
                <div class="mb-3">
                    <label class="form-label">${key}</label>
                    <textarea class="form-control" id="${fieldId}" rows="3">${value.join('\n')}</textarea>
                </div>
            `);
        } else {
            fieldsContainer.append(`
                <div class="mb-3">
                    <label class="form-label">${key}</label>
                    <input type="text" class="form-control" id="${fieldId}" value="${JSON.stringify(value)}">
                </div>
            `);
        }
    });
    
    const modal = new bootstrap.Modal(document.getElementById('editRecordModal'));
    modal.show();
}

function saveRecord() {
    const recordId = $('#editRecordId').val();
    const dbName = $('#editDbName').val();
    
    const updatedRecord = {};
    
    // Собираем данные из формы
    $('#editRecordFields .mb-3').each(function() {
        const label = $(this).find('label').text();
        const input = $(this).find('textarea, input');
        const value = input.val();
        
        // Определяем тип значения
        try {
            const parsed = JSON.parse(value);
            updatedRecord[label] = parsed;
        } catch {
            updatedRecord[label] = value;
        }
    });
    
    // Отправляем на сервер
    $.ajax({
        url: `/api/database/${dbName}/record/${recordId}`,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(updatedRecord),
        success: function(response) {
            showToast('success', response.message);
            loadDatabaseData();
            bootstrap.Modal.getInstance(document.getElementById('editRecordModal')).hide();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

function viewRecord(recordId) {
    const record = currentData.find(r => r.id === recordId);
    if (!record) return;
    
    // Показываем в модальном окне (можно доработать)
    alert(JSON.stringify(record, null, 2));
}

function refreshDatabase() {
    loadDatabaseData();
    showToast('info', 'Данные обновлены');
}

function exportDatabase(format) {
    if (!currentDb) return;
    window.location.href = `/api/export/${currentDb}/${format}`;
}

function saveDatabase() {
    if (!currentDb) return;
    
    $.ajax({
        url: `/api/database/${currentDb}`,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(currentData),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

// Поиск
$('#databaseSearch').on('input', function() {
    currentPage = 1;
    renderTable();
});

// Изменение количества записей на странице
$('#recordsPerPage').change(function() {
    recordsPerPage = parseInt($(this).val());
    currentPage = 1;
    renderTable();
});

// ==================== Кэш переводов ====================

let cachePage = 1;
let cachePerPage = 50;
let cacheFilteredKeys = [];   // отсортированные ключи, прошедшие фильтр поиска

function loadTranslateCache() {
    $('#cacheTableBody').html('<tr><td colspan="3" class="text-center py-5"><div class="loading-spinner-inline"></div></td></tr>');

    $.get('/api/translate-cache', function(cache) {
        translateCache = cache;
        cachePage = 1;
        filterCacheKeys();
        renderCacheTable();
    });
}

function filterCacheKeys() {
    const searchTerm = $('#cacheSearch').val().toLowerCase();
    let keys = Object.keys(translateCache).sort((a, b) => a.localeCompare(b));
    if (searchTerm) {
        keys = keys.filter(original =>
            original.toLowerCase().includes(searchTerm) ||
            String(translateCache[original]).toLowerCase().includes(searchTerm)
        );
    }
    cacheFilteredKeys = keys;
}

function renderCacheTable() {
    const tbody = $('#cacheTableBody');
    tbody.empty();

    const total = cacheFilteredKeys.length;
    const totalPages = Math.max(1, Math.ceil(total / cachePerPage));
    if (cachePage > totalPages) cachePage = totalPages;

    const startIndex = (cachePage - 1) * cachePerPage;
    const endIndex = Math.min(startIndex + cachePerPage, total);
    const pageKeys = cacheFilteredKeys.slice(startIndex, endIndex);

    const fragment = document.createDocumentFragment();
    pageKeys.forEach(original => {
        const translation = translateCache[original];
        const row = document.createElement('tr');

        // Длинные тексты сворачиваются (CSS line-clamp), клик разворачивает
        const tdOriginal = document.createElement('td');
        const divOriginal = document.createElement('div');
        divOriginal.className = 'expandable-text';
        divOriginal.textContent = original;  // безопасно, экранирует всё автоматически
        divOriginal.title = 'Нажмите, чтобы развернуть/свернуть';
        divOriginal.onclick = () => divOriginal.classList.toggle('expanded');
        tdOriginal.appendChild(divOriginal);
        row.appendChild(tdOriginal);

        const tdTranslation = document.createElement('td');
        const divTranslation = document.createElement('div');
        divTranslation.className = 'expandable-text';
        divTranslation.textContent = translation;
        divTranslation.title = 'Нажмите, чтобы развернуть/свернуть';
        divTranslation.onclick = () => divTranslation.classList.toggle('expanded');
        tdTranslation.appendChild(divTranslation);
        row.appendChild(tdTranslation);

        const tdActions = document.createElement('td');
        tdActions.className = 'text-center text-nowrap';

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-sm btn-primary btn-action me-1';
        editBtn.title = 'Редактировать';
        editBtn.innerHTML = '<i class="bi bi-pencil"></i>';
        editBtn.onclick = () => editTranslation(original);
        tdActions.appendChild(editBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-sm btn-danger btn-action';
        deleteBtn.title = 'Удалить';
        deleteBtn.innerHTML = '<i class="bi bi-trash"></i>';
        deleteBtn.onclick = () => deleteTranslation(original);
        tdActions.appendChild(deleteBtn);

        row.appendChild(tdActions);
        fragment.appendChild(row);
    });
    tbody[0].appendChild(fragment);

    const totalAll = Object.keys(translateCache).length;
    $('#cacheCount').text(total === totalAll
        ? `Записей: ${totalAll}`
        : `Найдено: ${total} из ${totalAll}`);
    $('#cachePageInfo').text(total > 0
        ? `Показаны ${startIndex + 1}–${endIndex} из ${total}`
        : 'Нет записей');

    renderCachePagination(totalPages);
}

function renderCachePagination(totalPages) {
    const pagination = $('#cachePagination');
    pagination.empty();

    if (totalPages <= 1) return;

    if (cachePage > 1) {
        pagination.append(`
            <li class="page-item">
                <a class="page-link" href="#" onclick="goToCachePage(${cachePage - 1}); return false;">←</a>
            </li>
        `);
    }

    for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= cachePage - 2 && i <= cachePage + 2)) {
            pagination.append(`
                <li class="page-item ${i === cachePage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="goToCachePage(${i}); return false;">${i}</a>
                </li>
            `);
        } else if (i === cachePage - 3 || i === cachePage + 3) {
            pagination.append('<li class="page-item disabled"><a class="page-link">...</a></li>');
        }
    }

    if (cachePage < totalPages) {
        pagination.append(`
            <li class="page-item">
                <a class="page-link" href="#" onclick="goToCachePage(${cachePage + 1}); return false;">→</a>
            </li>
        `);
    }
}

function goToCachePage(page) {
    cachePage = page;
    renderCacheTable();
}

function escapeForAttr(text) {
    return text.replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function editTranslation(original) {
    const translation = translateCache[original];
    if (translation === undefined) return;
    
    $('#editTranslationOriginal').val(original);
    $('#editTranslationText').val(translation);
    
    const modal = new bootstrap.Modal(document.getElementById('editTranslationModal'));
    modal.show();
}

function saveTranslation() {
    const original = $('#editTranslationOriginal').val();
    const newTranslation = $('#editTranslationText').val();
    
    translateCache[original] = newTranslation;
    
    $.ajax({
        url: '/api/translate-cache',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(translateCache),
        success: function(response) {
            showToast('success', response.message);
            filterCacheKeys();
            renderCacheTable();
            bootstrap.Modal.getInstance(document.getElementById('editTranslationModal')).hide();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

function deleteTranslation(original) {
    if (!confirm('Удалить эту запись перевода?')) return;
    
    delete translateCache[original];
    
    $.ajax({
        url: '/api/translate-cache',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(translateCache),
        success: function(response) {
            showToast('success', response.message);
            filterCacheKeys();
            renderCacheTable();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при удалении');
        }
    });
}

function clearTranslateCache() {
    if (!confirm('Вы уверены, что хотите очистить весь кэш переводов?')) return;
    
    $.ajax({
        url: '/api/translate-cache',
        method: 'DELETE',
        success: function(response) {
            showToast('success', response.message);
            translateCache = {};
            cachePage = 1;
            filterCacheKeys();
            renderCacheTable();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при очистке');
        }
    });
}

function saveTranslateCache() {
    $.ajax({
        url: '/api/translate-cache',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(translateCache),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

// Поиск по кэшу (с задержкой, чтобы не перерисовывать на каждый символ)
let cacheSearchTimer = null;
$('#cacheSearch').on('input', function() {
    clearTimeout(cacheSearchTimer);
    cacheSearchTimer = setTimeout(function() {
        cachePage = 1;
        filterCacheKeys();
        renderCacheTable();
    }, 300);
});

// Изменение количества записей на странице кэша
$('#cachePerPage').change(function() {
    cachePerPage = parseInt($(this).val());
    cachePage = 1;
    renderCacheTable();
});

// ==================== Настройки ====================

function loadSettings() {
    $.get('/api/config', function(config) {
        // Настройки лимитов
        $('input[name="max_capec"]').val(config.limits.max_capec || 330);
        $('input[name="max_cwe"]').val(config.limits.max_cwe || 500);
        $('input[name="max_cve"]').val(config.limits.max_cve || 2000);
        $('input[name="max_attack"]').val(config.limits.max_attack || 300);
        
        // Настройки перевода
        $('select[name="service"]').val(config.translation.service || 'google');
        $('select[name="target_lang"]').val(config.translation.target_lang || 'ru');
        $('input[name="workers"]').val(config.translation.workers || 5);
        $('input[name="delay"]').val(config.translation.delay || 0.4);
        $('input[name="max_retries"]').val(config.translation.max_retries || 5);
    });
}

function initForms() {
    // Форма лимитов парсинга
    $('#limitsSettings').submit(function(e) {
        e.preventDefault();
        
        const formData = {
            limits: {
                max_capec: parseInt($('input[name="max_capec"]').val()),
                max_cwe: parseInt($('input[name="max_cwe"]').val()),
                max_cve: parseInt($('input[name="max_cve"]').val()),
                max_attack: parseInt($('input[name="max_attack"]').val())
            }
        };
        
        saveLimits(formData);
    });
    
    // Форма настроек перевода
    $('#translationSettings').submit(function(e) {
        e.preventDefault();
        
        const formData = {
            translation: {
                service: $('select[name="service"]').val(),
                target_lang: $('select[name="target_lang"]').val(),
                workers: parseInt($('input[name="workers"]').val()),
                delay: parseFloat($('input[name="delay"]').val()),
                max_retries: parseInt($('input[name="max_retries"]').val())
            }
        };
        
        saveConfig(formData);
    });
}

function saveLimits(limits) {
    $.ajax({
        url: '/api/config/limits',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(limits),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении лимитов');
        }
    });
}

function saveConfig(config) {
    $.ajax({
        url: '/api/config',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(config),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении настроеk');
        }
    });
}

// ==================== Уведомления ====================

function showToast(type, message) {
    const toastContainer = $('#toastContainer');
    if (toastContainer.length === 0) {
        $('body').append('<div id="toastContainer" class="position-fixed top-0 end-0 p-3" style="z-index: 11"></div>');
    }
    
    const bgClass = {
        'success': 'bg-success',
        'error': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-primary';
    
    const icon = {
        'success': 'bi-check-circle',
        'error': 'bi-x-circle',
        'warning': 'bi-exclamation-triangle',
        'info': 'bi-info-circle'
    }[type] || 'bi-info-circle';
    
    const toast = `
        <div class="toast show" role="alert">
            <div class="toast-header ${bgClass} text-white">
                <i class="bi ${icon} me-2"></i>
                <strong class="me-auto">MPDB</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    $('#toastContainer').append(toast);

    // Автоматическое удаление через 3 секунды
    setTimeout(() => {
        $('#toastContainer .toast').first().remove();
    }, 3000);
}

// ==================== ФУНКЦИИ НОВОСТНОЙ ЛЕНТЫ ====================

function formatSourceDate(value) {
    /**Дата в локальном формате; 'Неизвестно' для пустых/некорректных значений*/
    if (!value || value === 'unknown') return 'Неизвестно';
    const date = new Date(value);
    return isNaN(date.getTime()) ? 'Неизвестно' : date.toLocaleString('ru-RU');
}

function formatBytes(bytes) {
    /**Размер файла в читаемом виде*/
    const size = parseInt(bytes, 10);
    if (!size || isNaN(size)) return 'Неизвестно';
    if (size >= 1024 * 1024) return (size / (1024 * 1024)).toFixed(1) + ' МБ';
    if (size >= 1024) return (size / 1024).toFixed(1) + ' КБ';
    return size + ' Б';
}

function loadUpdates() {
    /**Загрузить информацию об обновлениях из API*/
    $.ajax({
        url: '/api/updates',
        method: 'GET',
        timeout: 10000,
        success: function(data) {
            renderUpdates(data);
        },
        error: function(error) {
            showUpdatesError('Ошибка при загрузке обновлений. Проверьте интернет соединение.');
            console.error('Updates error:', error);
        }
    });
    loadChangelog();
}

const CHANGELOG_DB_COLORS = { capec: '#0d6efd', cwe: '#ffc107', attack: '#dc3545', cve: '#198754' };

function loadChangelog() {
    /**Загрузить журнал изменений баз (дельта-обновления)*/
    $.ajax({
        url: '/api/updates/changelog?limit=20',
        method: 'GET',
        timeout: 10000,
        success: function(data) {
            renderChangelog(data.changelog || []);
        },
        error: function(error) {
            $('#changelogList').html('<p class="text-muted small mb-0">Не удалось загрузить журнал изменений.</p>');
            console.error('Changelog error:', error);
        }
    });
}

function renderChangelog(entries) {
    /**Отрисовать записи журнала изменений*/
    const container = $('#changelogList');
    if (!entries.length) {
        container.html('<p class="text-muted small mb-0">Журнал пуст. Запустите парсинг, чтобы зафиксировать состав баз — последующие прогоны покажут, что изменилось.</p>');
        return;
    }

    let html = '<div class="list-group">';
    entries.forEach(entry => {
        const dt = new Date(entry.timestamp);
        const dateStr = isNaN(dt) ? entry.timestamp : dt.toLocaleString('ru-RU');
        const badge = entry.is_baseline
            ? '<span class="badge bg-secondary ms-2">базовый снимок</span>'
            : '';

        let chips = '';
        Object.keys(entry.changes || {}).forEach(dbKey => {
            const ch = entry.changes[dbKey];
            const color = CHANGELOG_DB_COLORS[dbKey] || '#6c757d';
            const addStr = ch.added ? `<span class="text-success">+${ch.added.toLocaleString('ru-RU')}</span>` : '';
            const remStr = ch.removed ? `<span class="text-danger">-${ch.removed.toLocaleString('ru-RU')}</span>` : '';
            const delta = [addStr, remStr].filter(Boolean).join(' / ') || '<span class="text-muted">без изменений</span>';
            chips += `
                <div class="me-3 mb-1 d-inline-block">
                    <span class="badge" style="background-color: ${color}">${escapeHtml(ch.label)}</span>
                    <span class="small ms-1">${delta}</span>
                    <span class="text-muted small">(всего ${ch.total.toLocaleString('ru-RU')})</span>
                </div>`;
        });

        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-center mb-1">
                    <strong class="small"><i class="bi bi-calendar3"></i> ${dateStr}</strong>
                    ${badge}
                </div>
                <div>${chips}</div>
            </div>`;
    });
    html += '</div>';
    container.html(html);
}

function refreshUpdates() {
    /**Принудительно обновить информацию об обновлениях*/
    const btn = $('#refreshUpdatesBtn');
    btn.prop('disabled', true);
    btn.html('<i class="bi bi-arrow-clockwise spin"></i> Проверка...');

    $.ajax({
        url: '/api/updates?force=true',
        method: 'GET',
        timeout: 15000,
        success: function(data) {
            renderUpdates(data);
            showToast('Информация об обновлениях обновлена', 'success');
        },
        error: function(error) {
            showUpdatesError('Ошибка при проверке обновлений. Попробуйте позже.');
            console.error('Refresh error:', error);
        },
        complete: function() {
            btn.prop('disabled', false);
            btn.html('<i class="bi bi-arrow-clockwise"></i> Проверить');
        }
    });
}

function renderUpdates(data) {
    /**Отобразить список обновлений*/
    const updatesList = $('#updatesList');
    const updatesLoading = $('#updatesLoading');
    const updatesError = $('#updatesError');

    updatesLoading.hide();
    updatesError.hide();

    if (!data.updates || data.updates.length === 0) {
        updatesList.html('<p class="text-muted">Нет доступной информации об обновлениях</p>');
        updatesList.show();
        return;
    }

    let html = '<div class="updates-list">';

    data.updates.forEach(update => {
        const statusBadge = getStatusBadge(update.status, update.status_text);
        const statsHtml = (update.local_stats && update.local_stats.count > 0) ?
            `<small class="text-muted">${update.local_stats.count} записей в локальной базе</small>` :
            '<small class="text-danger">База не распарсена</small>';
        const lastModified = update.metadata ? update.metadata.last_modified : null;
        const sourceDateHtml = lastModified ?
            `<small class="text-muted d-block">Источник обновлён: ${formatSourceDate(lastModified)}</small>` : '';

        html += `
            <div class="card mb-3 border-${update.status_color}">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <h6 class="card-title mb-1">
                                <i class="bi bi-database"></i> ${update.name}
                                ${statusBadge}
                            </h6>
                            <p class="card-text small text-muted mb-2">${update.description}</p>
                            <p class="card-text small mb-2">${statsHtml}</p>
                            ${sourceDateHtml}
                            <small class="text-muted">Проверено: ${new Date(update.timestamp).toLocaleString('ru-RU')}</small>
                        </div>
                        <div class="col-md-4 text-md-end mt-2 mt-md-0">
                            <button class="btn btn-sm btn-outline-primary me-2"
                                    onclick="showSourceDetails('${update.source}')">
                                <i class="bi bi-info-circle"></i> Детали
                            </button>
                            <a class="btn btn-sm btn-outline-secondary" href="${update.url}" target="_blank">
                                <i class="bi bi-box-arrow-up-right"></i> Источник
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });

    html += '</div>';
    updatesList.html(html);
    updatesList.show();
}

function getStatusBadge(status, text) {
    /**Получить Badge для статуса актуальности*/
    const colors = {
        'up_to_date': 'success',
        'outdated': 'warning',
        'missing': 'danger',
        'unavailable': 'secondary'
    };

    const color = colors[status] || 'secondary';
    const icons = {
        'up_to_date': 'check-circle',
        'outdated': 'exclamation-triangle',
        'missing': 'x-circle',
        'unavailable': 'wifi-off'
    };

    const icon = icons[status] || 'info-circle';

    return `<span class="badge bg-${color}"><i class="bi bi-${icon}"></i> ${text}</span>`;
}

function showSourceDetails(sourceKey) {
    /**Показать детали источника в модальном окне*/
    const modal = new bootstrap.Modal(document.getElementById('sourceDetailsModal'));
    const body = $('#sourceDetailsBody');
    const title = $('#sourceDetailsTitle');

    body.html('<div class="text-center"><div class="spinner-border" role="status"><span class="visually-hidden">Загрузка...</span></div></div>');

    // Пока данные не загружены, ведём на главный сайт источника
    const fallbackUrls = {
        'capec': 'https://capec.mitre.org/',
        'cwe': 'https://cwe.mitre.org/',
        'attack': 'https://attack.mitre.org/',
        'cve': 'https://nvd.nist.gov/'
    };
    $('#openSourceButton').attr('href', fallbackUrls[sourceKey] || '#');

    $.ajax({
        url: `/api/updates/${sourceKey}`,
        method: 'GET',
        timeout: 10000,
        success: function(data) {
            renderSourceDetails(data);
            if (data.source_url) {
                $('#openSourceButton').attr('href', data.source_url);
            }
        },
        error: function() {
            body.html('<div class="alert alert-danger">Ошибка при загрузке деталей источника</div>');
        }
    });

    modal.show();
}

function renderSourceDetails(data) {
    /**Отобразить детали источника*/
    const body = $('#sourceDetailsBody');

    const sourceMap = {
        'capec': 'CAPEC',
        'cwe': 'CWE',
        'attack': 'MITRE ATT&CK',
        'cve': 'CVE'
    };

    const source_name = sourceMap[data.source_key] || data.source_name;
    const metadata = data.metadata || {};
    const available = data.available !== false;

    let statusBadge;
    if (!available) {
        statusBadge = '<span class="badge bg-secondary">Источник недоступен</span>';
    } else if (data.is_outdated) {
        statusBadge = '<span class="badge bg-warning">Требует обновления</span>';
    } else {
        statusBadge = '<span class="badge bg-success">Актуальна</span>';
    }

    const alertClass = !available ? 'alert-danger' : (data.is_outdated ? 'alert-warning' : 'alert-success');
    const alertIcon = !available ? 'bi-x-circle' : (data.is_outdated ? 'bi-exclamation-triangle' : 'bi-check-circle');

    let html = `
        <div class="source-details">
            <h6 class="mb-3">
                <i class="bi bi-database"></i> ${source_name}
            </h6>

            <div class="row mb-3">
                <div class="col-md-6">
                    <strong>Статус:</strong>
                    <p>${statusBadge}</p>
                </div>
                <div class="col-md-6">
                    <strong>Записей в локальной БД:</strong>
                    <p>${(data.local_stats && data.local_stats.count > 0) ? data.local_stats.count : 'Не распарсена'}</p>
                </div>
            </div>

            <hr>

            <h6 class="mb-2">Информация об источнике:</h6>
            <ul class="list-unstyled small">
                <li><strong>URL:</strong> <a href="${data.source_url}" target="_blank" class="text-break">${data.source_url}</a></li>
                <li class="mt-2"><strong>Размер данных:</strong> ${formatBytes(metadata.content_length)}</li>
                <li class="mt-2"><strong>Последнее изменение:</strong> ${formatSourceDate(metadata.last_modified)}</li>
                <li class="mt-2"><strong>Проверено:</strong> ${formatSourceDate(data.last_checked)}</li>
            </ul>

            <hr>

            <div class="alert ${alertClass} mb-0">
                <i class="bi ${alertIcon}"></i>
                ${data.info}
            </div>
        </div>
    `;

    $('#sourceDetailsBody').html(html);
}

function showUpdatesError(message) {
    /**Показать ошибку при загрузке обновлений*/
    $('#updatesLoading').hide();
    $('#updatesList').hide();
    $('#updatesError').html(`<i class="bi bi-exclamation-circle"></i> ${message}`).show();
}

// ==================== Визуализация связывания ====================

const LINK_DB_LABELS = {
    capec: 'CAPEC',
    cwe: 'CWE',
    attack: 'MITRE ATT&CK',
    cve: 'CVE'
};

const LINK_DB_COLORS = {
    capec: '#0d6efd',
    cwe: '#ffc107',
    attack: '#dc3545',
    cve: '#198754'
};

// Соответствие базы узла графа имени файла/раздела в редакторе баз данных
const LINK_DB_TO_FILE = {
    capec: 'capec_database',
    cwe: 'cwe_database',
    attack: 'mitre_attack',
    cve: 'cve_database'
};

let linkGraphNetworkInstance = null;
let linkGraphNodesById = {};
let linkGraphSearchTimer = null;

function loadLinkingOverview() {
    /**Загрузить статистику связей и отрисовать обзорную диаграмму*/
    $('#linkingLoading').show();
    $('#linkingOverview').hide();
    $('#linkingCoverage').hide();
    $('#linkingDetails').hide();
    $('#linkingPathSection').hide();
    $('#linkingError').hide();

    $.ajax({
        url: '/api/linking/stats',
        method: 'GET',
        timeout: 15000,
        success: function(data) {
            renderLinkFlowDiagram(data);
            renderTopReferenced(data.top_referenced || []);
            $('#linkingLoading').hide();
            $('#linkingOverview').show();
            $('#linkingDetails').show();
            $('#linkingPathSection').show();
            loadLinkingCoverage();
        },
        error: function(error) {
            $('#linkingLoading').hide();
            $('#linkingErrorMessage').text('Ошибка при загрузке статистики связей.');
            $('#linkingError').show();
            console.error('Linking stats error:', error);
        }
    });
}

function loadLinkingCoverage() {
    /**Загрузить и отрисовать отчёт о покрытии связей (gap-analysis)*/
    $.ajax({
        url: '/api/linking/coverage',
        method: 'GET',
        timeout: 15000,
        success: function(data) {
            if (data && data.databases) {
                renderCoverage(data);
                $('#linkingCoverage').show();
            }
        },
        error: function(error) {
            console.error('Coverage error:', error);
        }
    });
}

function coverageBar(percent, color) {
    /**HTML-полоска прогресса для процента покрытия*/
    const p = Math.max(0, Math.min(100, percent));
    return `
        <div class="progress" style="height: 18px; min-width: 120px;">
            <div class="progress-bar" role="progressbar" style="width: ${p}%; background-color: ${color};">${percent}%</div>
        </div>`;
}

function coverageColor(percent) {
    if (percent >= 80) return '#198754';   // зелёный
    if (percent >= 50) return '#fd7e14';   // оранжевый
    return '#dc3545';                       // красный
}

function renderCoverage(data) {
    /**Отрисовать сквозную цепочку и таблицы покрытия по базам*/
    const chain = data.chain || {};
    const chainItems = [
        ['CVE → CWE', chain.cve_to_cwe],
        ['CVE → CAPEC', chain.cve_to_capec],
        ['CVE → ATT&CK', chain.cve_to_attack],
    ];
    let chainHtml = `<h6 class="text-muted">Сквозная цепочка по ${(data.cve_total || 0).toLocaleString('ru-RU')} CVE</h6><div class="row g-2 mb-2">`;
    chainItems.forEach(([label, info]) => {
        const pct = info ? info.percent : 0;
        chainHtml += `
            <div class="col-md-4">
                <div class="border rounded p-2">
                    <div class="d-flex justify-content-between small mb-1">
                        <span>${label}</span>
                        <span class="text-muted">${info ? info.count.toLocaleString('ru-RU') : 0} есть / ${info ? info.missing.toLocaleString('ru-RU') : 0} нет</span>
                    </div>
                    ${coverageBar(pct, coverageColor(pct))}
                </div>
            </div>`;
    });
    chainHtml += '</div>';
    $('#coverageChain').html(chainHtml);

    const dbs = data.databases || {};
    let rows = '';
    Object.keys(dbs).forEach(dbKey => {
        const db = dbs[dbKey];
        const fieldKeys = Object.keys(db.fields || {});
        const fieldsCells = fieldKeys.map(fk => {
            const f = db.fields[fk];
            return `<div class="mb-1"><div class="small text-muted">→ ${escapeHtml(f.label)} (${f.count.toLocaleString('ru-RU')})</div>${coverageBar(f.percent, coverageColor(f.percent))}</div>`;
        }).join('') || '<span class="text-muted small">—</span>';

        rows += `
            <tr>
                <td><strong style="color: ${LINK_DB_COLORS[dbKey] || '#6c757d'}">${escapeHtml(db.label)}</strong><div class="small text-muted">${db.total.toLocaleString('ru-RU')} записей</div></td>
                <td>${fieldsCells}</td>
                <td class="text-center">${db.linked_any.percent}%<div class="small text-muted">${db.linked_any.count.toLocaleString('ru-RU')}</div></td>
                <td class="text-center">${db.orphans.percent}%<div class="small text-muted">${db.orphans.count.toLocaleString('ru-RU')}</div></td>
            </tr>`;
    });

    const tableHtml = `
        <h6 class="text-muted">Покрытие по базам</h6>
        <div class="table-responsive">
            <table class="table table-sm table-bordered align-middle">
                <thead class="table-light">
                    <tr>
                        <th>База</th>
                        <th>Покрытие связей</th>
                        <th class="text-center">Со связями</th>
                        <th class="text-center">Без связей<br><small class="text-muted fw-normal">(orphans)</small></th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
    $('#coverageTables').html(tableHtml);
}

function renderLinkFlowDiagram(data) {
    /**Отрисовать карточки баз и список связей между ними*/
    const nodeCounts = data.nodes || {};

    let boxesHtml = '';
    Object.keys(LINK_DB_LABELS).forEach(dbKey => {
        boxesHtml += `
            <div class="link-flow-box" style="border-color: ${LINK_DB_COLORS[dbKey]}">
                <div class="link-flow-box-title" style="color: ${LINK_DB_COLORS[dbKey]}">${LINK_DB_LABELS[dbKey]}</div>
                <div class="link-flow-box-count">${(nodeCounts[dbKey] || 0).toLocaleString('ru-RU')}</div>
                <div class="link-flow-box-label">записей</div>
            </div>
        `;
    });
    $('#linkFlowBoxes').html(boxesHtml);

    const edges = (data.edges || []).slice().sort((a, b) => b.count - a.count);
    const maxCount = edges.length ? edges[0].count : 1;

    let edgesHtml = '';
    edges.forEach(edge => {
        const pct = Math.max(2, Math.round((edge.count / maxCount) * 100));
        edgesHtml += `
            <div class="link-edge-row mb-2">
                <div class="link-edge-label">
                    <span class="badge" style="background-color: ${LINK_DB_COLORS[edge.source]}">${LINK_DB_LABELS[edge.source]}</span>
                    <i class="bi bi-arrow-right mx-1"></i>
                    <span class="badge" style="background-color: ${LINK_DB_COLORS[edge.target]}">${LINK_DB_LABELS[edge.target]}</span>
                    <small class="text-muted ms-2">${edge.field}</small>
                </div>
                <div class="link-edge-bar-wrap">
                    <div class="link-edge-bar" style="width: ${pct}%; background-color: ${LINK_DB_COLORS[edge.source]}"></div>
                </div>
                <div class="link-edge-count">${edge.count.toLocaleString('ru-RU')}</div>
            </div>
        `;
    });
    $('#linkFlowEdges').html(edgesHtml || '<p class="text-muted">Связи не найдены</p>');
}

function renderTopReferenced(items) {
    /**Отрисовать список часто цитируемых записей*/
    let html = '';
    items.forEach(item => {
        html += `
            <a href="#" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center"
               onclick="loadEgoNetwork('${escapeJs(item.id)}'); return false;">
                <span>
                    <span class="badge me-2" style="background-color: ${LINK_DB_COLORS[item.db] || '#6c757d'}">${LINK_DB_LABELS[item.db] || item.db}</span>
                    ${escapeHtml(item.id)}
                    <small class="text-muted d-block">${escapeHtml(item.name || '')}</small>
                </span>
                <span class="badge bg-secondary rounded-pill">${item.count}</span>
            </a>
        `;
    });
    $('#topReferencedList').html(html || '<p class="text-muted">Нет данных</p>');
}

$(document).on('input', '#linkGraphSearchInput', function() {
    const query = $(this).val().trim();
    clearTimeout(linkGraphSearchTimer);

    if (query.length < 2) {
        $('#linkGraphSearchResults').hide().empty();
        return;
    }

    linkGraphSearchTimer = setTimeout(() => searchLinkNodes(query), 300);
});

function searchLinkNodes(query) {
    /**Поиск узлов по id/названию*/
    $.ajax({
        url: '/api/linking/search',
        method: 'GET',
        data: { q: query },
        timeout: 10000,
        success: function(data) {
            renderLinkSearchResults(data.results || []);
        },
        error: function(error) {
            console.error('Link search error:', error);
        }
    });
}

function renderLinkSearchResults(results) {
    const container = $('#linkGraphSearchResults');

    if (!results.length) {
        container.html('<div class="list-group-item text-muted">Ничего не найдено</div>').show();
        return;
    }

    let html = '';
    results.forEach(item => {
        html += `
            <a href="#" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center"
               onclick="loadEgoNetwork('${escapeJs(item.id)}'); return false;">
                <span>
                    <span class="badge me-2" style="background-color: ${LINK_DB_COLORS[item.db] || '#6c757d'}">${LINK_DB_LABELS[item.db] || item.db}</span>
                    ${escapeHtml(item.id)} — ${escapeHtml(item.name || '')}
                </span>
                <small class="text-muted">${item.links} связей</small>
            </a>
        `;
    });
    container.html(html).show();
}

let currentLinkGraphNodeId = null;

function loadEgoNetwork(nodeId) {
    /**Загрузить и отрисовать граф связей записи*/
    $('#linkGraphSearchResults').hide().empty();
    $('#linkGraphSearchInput').val(nodeId);
    currentLinkGraphNodeId = nodeId;

    const depth = parseInt($('#linkGraphDepthSelect').val(), 10) || 1;

    $.ajax({
        url: '/api/linking/graph/' + encodeURIComponent(nodeId),
        method: 'GET',
        data: { depth: depth },
        timeout: 15000,
        success: function(data) {
            renderLinkGraphNetwork(data);
        },
        error: function(error) {
            const message = (error.responseJSON && error.responseJSON.error) || 'Ошибка при загрузке графа связей';
            $('#linkGraphPlaceholder').show().find('p').text(message);
            $('#linkGraphContainer').hide();
            console.error('Ego network error:', error);
        }
    });
}

$(document).on('change', '#linkGraphDepthSelect', function() {
    if (currentLinkGraphNodeId) {
        loadEgoNetwork(currentLinkGraphNodeId);
    }
});

function renderLinkGraphNetwork(data) {
    /**Отрисовать граф связей записи через vis-network*/
    $('#linkGraphPlaceholder').hide();
    $('#linkGraphContainer').show();
    $('#linkGraphNodeDetails').hide();

    linkGraphNodesById = {};
    data.nodes.forEach(n => { linkGraphNodesById[n.id] = n; });

    $('#linkGraphTitle').html(
        `<span class="badge me-2" style="background-color: ${LINK_DB_COLORS[data.center.db] || '#6c757d'}">${LINK_DB_LABELS[data.center.db] || data.center.db}</span>` +
        `${escapeHtml(data.center.id)} — ${escapeHtml(data.center.name || '')}`
    );
    $('#linkGraphLegendInfo').text(`${data.nodes.length} узлов, ${data.edges.length} связей, глубина ${data.depth || 1}`);

    const visNodes = data.nodes.map(n => ({
        id: n.id,
        label: n.id,
        title: escapeHtml(n.name || n.id),
        shape: 'box',
        font: { color: '#fff' },
        color: {
            background: LINK_DB_COLORS[n.db] || '#6c757d',
            border: n.id === data.center.id ? '#000000' : (LINK_DB_COLORS[n.db] || '#6c757d')
        },
        borderWidth: n.id === data.center.id ? 3 : 1
    }));

    // При большом числе связей подписи рёбер превращаются в шум — скрываем их
    const showEdgeLabels = data.edges.length <= 60;
    const visEdges = data.edges.map(e => ({
        from: e.from,
        to: e.to,
        arrows: 'to',
        label: showEdgeLabels ? (e.field || '').replace('related_', '') : undefined,
        font: { size: 10, align: 'middle' },
        color: { color: '#999999' }
    }));

    const visData = {
        nodes: new vis.DataSet(visNodes),
        edges: new vis.DataSet(visEdges)
    };

    // Чем больше узлов, тем больше места им нужно — иначе граф превращается в плотный клубок
    const nodeCount = visNodes.length;
    const containerHeight = Math.min(750, Math.max(420, 320 + nodeCount * 4));
    document.getElementById('linkGraphNetwork').style.height = containerHeight + 'px';

    const options = {
        layout: { improvedLayout: nodeCount <= 100 },
        physics: {
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -60,
                springLength: nodeCount > 40 ? 150 : 130,
                springConstant: 0.05,
                avoidOverlap: 0.8,
                damping: 0.4
            },
            stabilization: { iterations: 300, fit: true }
        },
        interaction: { hover: true },
        nodes: { margin: 8, widthConstraint: { maximum: 140 } }
    };

    const container = document.getElementById('linkGraphNetwork');
    if (linkGraphNetworkInstance) {
        // Включаем физику заново, чтобы граф стабилизировался под новые данные
        linkGraphNetworkInstance.setOptions(options);
        linkGraphNetworkInstance.setData(visData);
    } else {
        linkGraphNetworkInstance = new vis.Network(container, visData, options);
        linkGraphNetworkInstance.on('doubleClick', function(params) {
            if (params.nodes && params.nodes.length) {
                loadEgoNetwork(params.nodes[0]);
            }
        });

        // Клик колесом мыши (средняя кнопка) — показать описание записи под графом
        container.addEventListener('mousedown', function(event) {
            if (event.button === 1) {
                event.preventDefault(); // отключаем авто-скролл браузера
            }
        });
        container.addEventListener('auxclick', function(event) {
            if (event.button !== 1) return;
            event.preventDefault();
            const nodeId = linkGraphNetworkInstance.getNodeAt({ x: event.offsetX, y: event.offsetY });
            if (nodeId) {
                showLinkGraphNodeDetails(nodeId);
            }
        });
    }
    // Останавливаем физику после стабилизации, чтобы узлы не "дрожали" бесконечно
    linkGraphNetworkInstance.once('stabilizationIterationsDone', function() {
        linkGraphNetworkInstance.setOptions({ physics: false });
    });

    const truncated = data.truncated || {};
    let note = '';
    if (truncated.incoming) {
        note += `Показаны не все входящие связи (скрыто ещё ${truncated.incoming}). `;
    }
    if (truncated.outgoing) {
        note += `Показаны не все исходящие связи (скрыто ещё ${truncated.outgoing}). `;
    }
    if (truncated.nodes) {
        note += `Граф обрезан по лимиту узлов. `;
    }
    note += 'Двойной клик по узлу — посмотреть его связи. Клик колесом мыши — показать описание записи.';
    $('#linkGraphTruncatedNote').text(note);
}

function showLinkGraphNodeDetails(nodeId) {
    /**Показать карточку с полным описанием записи под графом связей*/
    const node = linkGraphNodesById[nodeId];
    const dbKey = node ? node.db : _dbForNodeId(nodeId);
    const dbName = LINK_DB_TO_FILE[dbKey];

    $('#linkGraphNodeDetails').show();
    $('#linkGraphNodeDetailsTitle').html(
        `<span class="badge me-2" style="background-color: ${LINK_DB_COLORS[dbKey] || '#6c757d'}">${LINK_DB_LABELS[dbKey] || dbKey || '?'}</span>${escapeHtml(nodeId)}`
    );
    $('#linkGraphNodeDetailsBody').html('<div class="text-center py-3"><div class="loading-spinner-inline"></div></div>');

    const openBtn = $('#linkGraphNodeDetailsOpenBtn');
    if (!dbName) {
        openBtn.prop('disabled', true).off('click');
        $('#linkGraphNodeDetailsBody').html('<p class="text-muted mb-0">Не удалось определить базу записи.</p>');
        return;
    }
    openBtn.prop('disabled', false).off('click').on('click', function() {
        openRecordInDatabase(nodeId, dbName);
    });

    $.ajax({
        url: `/api/database/${dbName}/record/${encodeURIComponent(nodeId)}`,
        method: 'GET',
        timeout: 10000,
        success: function(record) {
            renderLinkGraphNodeDetails(record);
        },
        error: function() {
            $('#linkGraphNodeDetailsBody').html('<p class="text-danger mb-0">Не удалось загрузить запись (возможно, она ещё не скачана/распарсена).</p>');
        }
    });
}

function _dbForNodeId(nodeId) {
    /**Определить базу узла по формату его id (используется, если узла нет среди отрисованных)*/
    if (nodeId.startsWith('CAPEC-')) return 'capec';
    if (nodeId.startsWith('CWE-')) return 'cwe';
    if (nodeId.startsWith('CVE-')) return 'cve';
    if (nodeId.startsWith('T')) return 'attack';
    return null;
}

function renderLinkGraphNodeDetails(record) {
    let html = '';
    if (record.name) {
        html += `<p class="text-muted mb-2">${escapeHtml(record.name)}</p>`;
    }
    if (record.description) {
        html += `<p style="white-space: pre-wrap;">${escapeHtml(record.description)}</p>`;
    }

    const skip = new Set(['id', 'name', 'description']);
    const rows = [];
    Object.keys(record).forEach(key => {
        if (skip.has(key)) return;
        const value = record[key];
        if (value === null || value === undefined || value === '') return;

        if (Array.isArray(value)) {
            if (!value.length) return;
            const shown = value.slice(0, 15).map(v => escapeHtml(String(v))).join(', ');
            const more = value.length > 15 ? ` … (+${value.length - 15})` : '';
            rows.push(`<tr><th class="text-nowrap pe-3">${escapeHtml(key)}</th><td>${shown}${more}</td></tr>`);
        } else {
            rows.push(`<tr><th class="text-nowrap pe-3">${escapeHtml(key)}</th><td style="white-space: pre-wrap;">${escapeHtml(String(value))}</td></tr>`);
        }
    });

    if (rows.length) {
        html += `<table class="table table-sm table-borderless mb-0"><tbody>${rows.join('')}</tbody></table>`;
    }

    $('#linkGraphNodeDetailsBody').html(html || '<p class="text-muted mb-0">Нет дополнительных данных.</p>');
}

function openRecordInDatabase(nodeId, dbName) {
    /**Перейти на вкладку "Базы данных" и отфильтровать таблицу по этой записи*/
    $('#databaseSearch').val(nodeId);
    showDatabase(dbName);
}

// ==================== ПОИСК ПУТИ МЕЖДУ ЗАПИСЯМИ ====================

let pathFromSearchTimer = null;
let pathToSearchTimer = null;

$(document).on('input', '#pathFromInput', function() {
    const query = $(this).val().trim();
    clearTimeout(pathFromSearchTimer);
    if (query.length < 2) {
        $('#pathFromResults').hide().empty();
        return;
    }
    pathFromSearchTimer = setTimeout(() => searchPathNodes(query, '#pathFromResults', '#pathFromInput'), 300);
});

$(document).on('input', '#pathToInput', function() {
    const query = $(this).val().trim();
    clearTimeout(pathToSearchTimer);
    if (query.length < 2) {
        $('#pathToResults').hide().empty();
        return;
    }
    pathToSearchTimer = setTimeout(() => searchPathNodes(query, '#pathToResults', '#pathToInput'), 300);
});

function searchPathNodes(query, resultsSelector, inputSelector) {
    /**Поиск узлов по id/названию для полей "Откуда"/"Куда"*/
    $.ajax({
        url: '/api/linking/search',
        method: 'GET',
        data: { q: query },
        timeout: 10000,
        success: function(data) {
            renderPathSearchResults(data.results || [], resultsSelector, inputSelector);
        },
        error: function(error) {
            console.error('Path search error:', error);
        }
    });
}

function renderPathSearchResults(results, resultsSelector, inputSelector) {
    const container = $(resultsSelector);

    if (!results.length) {
        container.html('<div class="list-group-item text-muted">Ничего не найдено</div>').show();
        return;
    }

    let html = '';
    results.forEach(item => {
        html += `
            <a href="#" class="list-group-item list-group-item-action"
               onclick="selectPathNode('${escapeJs(item.id)}', '${inputSelector}', '${resultsSelector}'); return false;">
                <span class="badge me-2" style="background-color: ${LINK_DB_COLORS[item.db] || '#6c757d'}">${LINK_DB_LABELS[item.db] || item.db}</span>
                ${escapeHtml(item.id)} — ${escapeHtml(item.name || '')}
            </a>
        `;
    });
    container.html(html).show();
}

function selectPathNode(nodeId, inputSelector, resultsSelector) {
    $(inputSelector).val(nodeId);
    $(resultsSelector).hide().empty();
}

function findLinkPath() {
    /**Найти и отрисовать путь между записями из полей "Откуда"/"Куда"*/
    const fromId = $('#pathFromInput').val().trim();
    const toId = $('#pathToInput').val().trim();

    if (!fromId || !toId) {
        $('#pathResult').html('<div class="alert alert-warning mb-0">Укажите обе записи.</div>');
        return;
    }

    $('#pathFromResults, #pathToResults').hide().empty();
    $('#pathResult').html('<div class="text-center py-2"><div class="spinner-border spinner-border-sm text-primary" role="status"></div></div>');

    $.ajax({
        url: '/api/linking/path',
        method: 'GET',
        data: { from: fromId, to: toId },
        timeout: 15000,
        success: function(data) {
            renderPathResult(data);
        },
        error: function(error) {
            const message = (error.responseJSON && (error.responseJSON.message || error.responseJSON.error)) || 'Ошибка при поиске пути';
            $('#pathResult').html(`<div class="alert alert-danger mb-0">${escapeHtml(message)}</div>`);
            console.error('Find path error:', error);
        }
    });
}

function renderPathResult(data) {
    /**Отрисовать найденный путь как цепочку записей*/
    const container = $('#pathResult');

    if (!data.found) {
        container.html(`<div class="alert alert-warning mb-0">${escapeHtml(data.message || 'Путь не найден')}</div>`);
        return;
    }

    if (data.length === 0) {
        container.html('<div class="alert alert-info mb-0">Это одна и та же запись.</div>');
        return;
    }

    let html = '<div class="path-chain">';
    data.nodes.forEach((node, i) => {
        html += `
            <a href="#" class="path-chain-node" style="border-color: ${LINK_DB_COLORS[node.db] || '#6c757d'}"
               onclick="loadEgoNetwork('${escapeJs(node.id)}'); return false;" title="Посмотреть граф связей">
                <span class="badge mb-1" style="background-color: ${LINK_DB_COLORS[node.db] || '#6c757d'}">${LINK_DB_LABELS[node.db] || node.db}</span>
                <div class="path-chain-node-id">${escapeHtml(node.id)}</div>
                <small class="text-muted">${escapeHtml(node.name || '')}</small>
            </a>
        `;
        if (i < data.edges.length) {
            const field = (data.edges[i].field || '').replace('related_', '');
            html += `
                <div class="path-chain-edge">
                    <i class="bi bi-arrow-right"></i>
                    <small class="text-muted">${escapeHtml(field)}</small>
                </div>
            `;
        }
    });
    html += '</div>';
    html += `<p class="text-muted small mt-2">Длина пути: ${data.length} ${data.length === 1 ? 'шаг' : 'шага'}. Нажмите на запись, чтобы открыть граф её связей.</p>`;

    container.html(html);
}