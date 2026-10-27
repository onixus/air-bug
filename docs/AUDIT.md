# Аудит и приведение прототипа в порядок

## Оценка

Полезное ядро уже существовало: offline WPA2 descriptor-v2 M1/M2, pcap/pcapng и независимые fixtures. Это не полноценная замена aircrack-ng. Первоначальная архитектура описывала в основном несуществующие модули, функции и сроки; число команд в CLI не соответствовало числу реализованных возможностей.

## Исправленные дефекты

| Проблема | Исправление |
| --- | --- |
| Фрагментированные management frames могли интерпретироваться как полные beacon/probe response | Общая проверка More Fragments и fragment number до парсинга payload |
| PMKID helper принимал произвольный malformed хвост RSN | Допускаются только отсутствие хвоста или 4 байта group management cipher selector |
| Одна строка словаря могла неограниченно выделять память | Bounded reader, максимум 64 KiB без LF, ошибка и завершение на length/UTF-8/I/O failure |
| ASCII-проверка пропускала управляющие байты в WPA passphrase | Только printable ASCII, 8–63 байта, пробелы не удаляются |
| Последний beacon молча перезаписывал SSID того же BSSID | Хранится множество SSID, конфликт требует явного `--essid` |
| TUI показывал фиктивный прогресс как реальный | Явный preview, проверка интерактивного терминала до escape sequences, выход Ctrl-C |
| CLI и архитектура преувеличивали delivered scope | Честная справка, актуальная архитектура и ограничения |
| Отсутствовали повторяемые quality gates | CI matrix: format, strict Clippy, workspace tests, release build |

Добавлены регрессии для исправленных ошибок, radiotap padding/FCS, wordlist boundaries и invalid sessions. Existing synthetic capture-to-CLI сценарии сохранены.

## Что намеренно не сделано

- Не добавлены live атаки, радиооперации, WPA3/WEP или новые режимы подбора.
- Не выполнены формальный crypto audit, fuzz campaign, GPU benchmarks или реальные радиотесты.
- Capture/session API пока не потоковый, объём capture и число handshake candidates не ограничены.
- Не удалены совместимые заглушки команд; они завершаются явной ошибкой.
- Не выбран лицензионный режим за владельца проекта и не создан первый Git commit. Исходное состояние: репозиторий без коммитов, всё содержимое untracked.

## Итог локальной проверки на этапе первоначального аудита

macOS, Rust/Cargo 1.98.1:

- `cargo fmt --all -- --check` — успешно.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — успешно.
- `cargo test --workspace --locked` — 35 тестов успешно, 0 ошибок.
- `cargo build --release --workspace --locked` — успешно.
- Release-бинарник на synthetic raw capture и fixture wordlist нашёл ожидаемый `correct horse battery`; справка показывает ограничения.

Конфигурация hosted CI не равнозначна успешному удалённому прогону. Linux/Windows и интерактивная отрисовка TUI локально не проверялись.

## Обновление состояния 2026-10-27

Этот аудит фиксирует предыдущий этап (35 тестов); последующие live/shadow и Android/JNI уже присутствуют в коде. Повторный текущий прогон: **56 Rust-тестов успешно**, rustfmt, strict Clippy и Apex checks — PASS. Текущий scope и сравнение с оригиналом — в [срезе проекта](PROJECT_STATUS_2026-10-27.ru.md). Новые release/Gradle/device проверки в этом срезе не выполнялись.

Последующее расширение PMKID/M2-M3: [реализация, 62 теста и сравнение с оригиналом](PMKID_M2M3_VALIDATION.ru.md). Предыдущие числа тестов выше сохранены как история этапов.
