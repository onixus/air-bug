# Интеграция aircrack-rs как модуля Shapoclyack (EASM/RBVM) и APEX

Документ описывает, как встроить существующий код `aircrack-rs` в платформу
Shapoclyack в роли **модуля беспроводного аудита и сканирования для EASM**
(External/Enterprise Attack Surface Management) и источника сигналов для RBVM
(Risk-Based Vulnerability Management). Исходный код не меняется; описанные
обёртки, контракты и агент — отдельный слой поверх текущих крейтов.

Опора: [ARCHITECTURE.md](../ARCHITECTURE.md), [README.md](../README.md),
[SECURITY.md](../SECURITY.md). Все ограничения из этих документов остаются в силе
и в интеграции не ослабляются.

## 1. Роль модуля в Shapoclyack

`aircrack-rs` закрывает «беспроводной» сегмент поверхности атаки, который обычный
сетевой/хостовый EASM не видит:

- **Discovery эфира** — инвентарь AP/клиентов (`survey`): BSSID, SSID (в т.ч.
  скрытые по hex), каналы 2.4/5 GHz, RSSI, метки защиты (`Open`, `Privacy`,
  `WPA`, `RSN`, `RSN/SAE`).
- **Signals для RBVM** — наблюдаемые факторы риска: открытые сети, `Privacy`
  (возможный WEP), отсутствие/наличие PMF, слабые AKM/шифры, Enterprise-метаданные
  802.1X/EAP, диагностика роуминга 802.11k/v/FT, индикатор перехваченного
  handshake/PMKID (признак пригодности к offline-подбору — **без** проверки MIC).
- **Подтверждение эксплуатируемости** — офлайн-верификация словаря против
  авторизованно полученного capture (`aircrack`/`airdecap`) как доказательство
  слабого пароля PSK для конкретного актива.

Модуль **пассивный и offline-ориентированный**. Он не выполняет инъекцию,
деаутентификацию, fake AP, WEP/SAE recovery — эти команды возвращают явную ошибку
unsupported. Это сознательное ограничение области для безопасного EASM.

## 2. Границы модуля и повторно используемые крейты

Повторно используется существующий workspace как есть; интеграция добавляет только
верхний слой адаптеров.

| Крейт | Что даёт интеграции |
| --- | --- |
| `air-core` | Крипто-примитивы PMK/PTK/MIC, PBKDF2, TKIP. Чистые, без I/O. |
| `air-frames` | Разбор 802.11-заголовков, SSID IE, bounded reassembly. |
| `air-capture` | pcap/pcapng нормализация, streaming `survey`, bounded инвентарь AP/STA, enterprise/roaming audit, security-audit метаданные. |
| `air-handshake` | Сборка WPA/WPA2/SAE descriptor v0–v3, FT, PMKID targets. |
| `air-crack` | Параллельная верификация кандидатов, streaming словари, PMK cache. |
| `air-platform` | Bounded tcpdump runner, фильтры, пассивное управление каналами, CoreWLAN scan/helper. |
| `air-cli` | Готовые подкоманды + JSON/CSV экспорт — основной машинный контракт. |
| `air-tui` | Дашборд `survey` на ratatui + APEX-палитра (см. §6). |
| `air-jni` | Bounded offline-адаптер для Android (run/control, progress/cancel). |

**Новый код интеграции (вне репозитория или в отдельном слое):**

1. `shapo-sensor` — агент-обёртка над `air-cli` (см. §5).
2. `shapo-ingest` — адаптер на backend Shapoclyack, принимающий survey-JSON.
3. UI-виджеты Shapoclyack (web/Android/macOS), потребляющие нормализованные
   данные EASM; TUI остаётся в `air-tui`.

Правило: Shapoclyack **никогда** не линкуется с крейтами напрямую для live-capture;
он общается с модулем через стабильные контракты §4 (JSON/PCAP/exit codes) или
через `air-jni` на Android. Это изолирует системные привилегии capture от backend.

## 3. Поток данных aircrack-rs → Shapoclyack

```text
[ эфир / авторизованный радиоинтерфейс ]
        │  (только с явной авторизацией владельца сети)
        ▼
  air-platform (tcpdump, bounded) ──► приватный PCAP 0600
        │
        ▼
  air-capture::survey ──► bounded AP/STA инвентарь + audit + evidence-флаги
        │
        ▼
  air-cli survey --export-json/--export-csv   (schema_version: 1)
        │                                       [машинный контракт §4]
        ▼
  shapo-sensor  ──(подписанный HTTPS push / очередь)──►  shapo-ingest (backend)
        │                                                      │
        │                                                      ▼
        │                                           нормализация в EASM-ассеты
        │                                           + RBVM risk-signals
        ▼                                                      ▼
  offline-ветвь (по требованию аналитика):               Shapoclyack UI
  air-cli aircrack / airdecap  ──► подтверждение          (web / Android / macOS)
  слабого PSK как «эксплуатируемость» актива              + APEX-токены
```

Два независимых канала:

- **Телеметрия (непрерывно):** survey-JSON снимки → backend → EASM/RBVM.
- **Верификация (по запросу, ручная авторизация):** сохранённый PCAP +
  словарь → `aircrack`/`airdecap` → доказательство/опровержение слабого пароля.
  Эта ветвь не запускается автоматически из backend без явной команды оператора.

## 4. Контракты (API) между модулем и платформой

Интеграция опирается на **уже существующие** выходные форматы, а не на новый RPC.

### 4.1 Survey JSON (основной контракт телеметрии)
`schema_version: 1`. Массивы `access_points` и `clients`, summary-счётчики,
elapsed processing time. Поля AP: `handshake_m1m2`, `handshake_m2m3`,
`handshake_m3m4`, `pmkid` (boolean-признаки, **не** проверка MIC/пароля),
`ssid_hex`/`probe_ssid_hex` (точные байты), метки защиты, RSN/WPA cipher/AKM
селекторы, RSN capabilities, PMF, group-management cipher, RSNXE/SAE флаги,
агрегаты 802.1X/EAP, журнал management-событий роуминга. Неизвестные числовые
метаданные — `null`; неизвестные селекторы сохраняют wire-идентификаторы.
Идентичности и EAP-payload не сохраняются.

Рекомендация для `shapo-ingest`: читать только по `schema_version`; при его росте
отклонять неизвестную мажорную версию, а не угадывать поля.

### 4.2 Survey CSV
Плоская таблица с колонкой `kind` (`ap`/`client`), защита ячеек от формул,
raw SSID hex отдельно. Для EASM предпочтителен JSON (CSV теряет диагностику
pending-cache/coverage).

### 4.3 PCAP-артефакт
`survey`/`live`/`wpaclean`/`airdecap` создают приватные файлы 0600, не
перезаписывают существующие. Для forensic-хранения в Shapoclyack передаётся
именно PCAP; survey-экспорт не содержит EAPOL payload/nonce/MIC/паролей.

### 4.4 CLI как процесс-контракт
Подкоманды (`survey`, `live`, `shadow`, `scan`, `interfaces`, `aircrack`,
`airdecap`, `wpaclean`, `benchmark`). `shapo-sensor` вызывает их как дочерние
процессы и разбирает stdout/stderr + файлы экспорта. Неподдерживаемые команды
(`aireplay`, `airbase`, `packetforge`, `ivstools`, `airmon`) дают явную ошибку —
backend не должен их вызывать.

> Пробел: стабильные машинные exit codes и единый JSON-диагностический поток ещё
> не стандартизированы (см. [ROADMAP](ROADMAP_INTEGRATION.ru.md), этап 1 и
> [CODE_REVIEW](CODE_REVIEW_INTEGRATION.ru.md)). До этого `shapo-ingest` опирается
> на JSON-файл как на источник истины, а не на парсинг текста.

### 4.5 Android JNI (`air-jni`)
`Java_..._NativeBridge_run` и `..._control` — bounded offline-адаптер с
progress/cancellation. JSON-результат содержит `sessions` (совместимость),
`handshakes`, `pmkids`. Используется мобильным сенсором/клиентом Shapoclyack на
Android без сетевых прав у самого APK.

## 5. Концепция сенсор-агента (`shapo-sensor`)

Лёгкий агент, разворачиваемый оператором на авторизованной точке наблюдения
(ноутбук аудитора, выделенный Linux-сенсор). Назначение — превратить пассивный
`survey` в источник непрерывной EASM-телеметрии.

**Свойства:**
- Тонкая обёртка над `air-cli`: не дублирует крипто/парсинг, а оркеструет процессы
  и доставку. Привилегии capture изолированы в дочернем процессе `air-cli`.
- **Explicit authorization gate:** запуск только с конфигом, где указан
  разрешённый интерфейс и (для `live`) точный BSSID; без него — отказ. Авторизация
  владельца сети фиксируется в конфиге/логе до старта.
- **Bounded by design:** наследует лимиты времени/пакетов/строк из CLI; добавляет
  троттлинг частоты снимков и ротацию локальных PCAP.
- **Доставка:** снимки survey-JSON отправляются на `shapo-ingest` по взаимно
  аутентифицированному TLS (клиентский сертификат сенсора), с идемпотентным
  `sensor_id`+timestamp. PCAP передаётся только по явному запросу верификации.
- **Offline-first:** при недоступности backend снимки буферизуются локально
  (0600, с ротацией), без потери bounded-гарантий.
- **Платформы:** Linux (основной сенсор, monitor через `iw`), macOS (с
  ограничениями CoreWLAN/дисассоциации, см. README — продакшн-survey отказывает
  на ассоциированном адаптере). Windows live не поддерживается — на Windows агент
  работает только в offline-режиме (разбор переданных PCAP) и как потребитель UI.

**Чего агент не делает:** не хранит секреты в backend, не запускает подбор пароля
автоматически, не меняет состояние интерфейсов сверх пассивного tuning, не
выполняет активные атаки.

## 6. APEX: использование только существующих токенов

Новые токены не вводятся. Источник — [Apex #117](https://github.com/onixus/unified-platform/issues/117),
уже вендорённый в [`air-tui/src/apex_tokens.rs`](../crates/air-tui/src/apex_tokens.rs)
и `android/.../ApexTokens.java`.

Доступная палитра (DARK/LIGHT), применяемая во всех поверхностях модуля:

| Токен | Назначение в модуле |
| --- | --- |
| `bg_canvas` | фон экрана/дашборда |
| `surface_1`, `surface_2` | карточки, строки таблицы, панели |
| `border_control` | разделители, границы контролов |
| `text_primary`, `text_secondary` | основной/вторичный текст |
| `accent` | единственный sky-акцент, активное выделение |
| `focus_ring` | кольцо фокуса/нажатия (2dp на Android) |
| `success`, `success_subtle` | статус-индикатор (иконка+слово+subtle-подложка) |

**Правила отображения риска только существующими токенами (без новых цветов):**
- Статус = иконка + слово + `success_subtle` подложка; степень риска кодируется
  **текстом/иконкой и порядком сортировки**, а не новым цветом. Там, где нет
  зелёного «успеха» (открытая сеть, слабый шифр), используется `text_primary`/
  `text_secondary` + явное слово-метка, а не вымышленный «danger»-токен.
- Акцент (`accent`) — ровно один на экран, для текущего выбора/фокусного действия.
- Контраст соблюдает порог Apex-проверки: текст ≥ 4.5:1, control/focus ≥ 3:1
  (проверяется `android/tests/check_apex.py`).

Если платформе Shapoclyack для RBVM нужна полноценная шкала severity (цвета
критичности), это решается **на стороне дизайн-системы APEX добавлением токенов в
upstream #117**, а не локальным изобретением в этом модуле. До этого модуль
отображает severity нецветовыми средствами.

## 7. Требования к UI

### 7.1 TUI (macOS/Linux/Windows) — `air-tui`
- Таблица AP/клиентов `survey`: BSSID, SSID (escape control/non-ASCII), канал,
  RSSI, метки защиты, колонка **Evidence** (`HS`/`FT`/`PMKID`/`HS+PMKID`/`-`),
  строка-статус со счётчиками типов evidence и `pending-evicted`.
- Темы Dark/Light/System (`Theme`), System учитывает `COLORFGBG`.
- Только токены §6; один `accent`; фокус — `focus_ring`.
- Кроссплатформенность: ratatui/crossterm работают на всех трёх ОС; на Windows —
  только как просмотр переданного capture/телеметрии (live недоступен).
- `tui` (legacy) остаётся демо; рабочий дашборд — `survey`.

### 7.2 Android и macOS UI
- **Android:** нативные Java Views (не web-wrapper), API 26+, arm64-v8a/x86_64,
  **без сетевого разрешения**. Импорт PCAP/словаря через SAF в app-private cache,
  bounded (capture 4 MiB, dict 16 MiB, 32768 пакетов, 128 EAPOL-записей). Темы
  `apex.theme` (dark/light/system), сетка 4dp, header 56dp, radius 12dp, touch
  48dp, шрифты Inter/JetBrains Mono, иконки Lucide. `FLAG_SECURE`, пароль скрыт до
  явного показа. Для EASM Android-клиент выступает **потребителем** телеметрии и
  локальным offline-верификатором; отправка на backend — функция сенсора, не APK.
- **macOS:** два режима — (а) TUI через терминал; (б) при потребности в нативном
  GUI — следовать той же APEX-карте токенов, что и Android (#117), повторно
  используя `air-cli scan`/`survey` как бэкенд через процесс-контракт §4.
  Нативный GUI для macOS в текущем коде отсутствует и является отдельной работой
  (см. ROADMAP, этап 3); он не должен вводить новые токены.

Общие требования ко всем UI: отображать явные ограничения (evidence ≠ проверка
пароля, `?` = не наблюдалось, security-метка = реклама AP, не доказательство
WEP), не показывать секреты в логах, различать processing-time и capture-time.

## 8. Безопасность интеграции (сводка)
Детали и риски — в [CODE_REVIEW_INTEGRATION.ru.md](CODE_REVIEW_INTEGRATION.ru.md).
Ключевое: привилегии capture изолированы в CLI-процессе/сенсоре; backend получает
только метаданные (не payload); verification-ветвь запускается вручную; все
bounded-лимиты сохраняются; авторизация владельца сети обязательна до любого
радио-действия.
