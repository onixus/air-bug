# Состояние aircrack-rs и сравнение с aircrack-ng

> Исторический срез до реализации PMKID/M2-M3. Актуальное дополнение: [поддержка и сравнение с upstream](PMKID_M2M3_VALIDATION.ru.md).

Дата проверки: **27 октября 2026**, Europe/Istanbul.

## Вывод

`aircrack-rs` — экспериментальный инструмент с рабочим узким offline-путём WPA2-PSK,
пассивным desktop capture supervisor и отдельным Android UI. Полной совместимости
с набором aircrack-ng, его CLI и аппаратной поддержкой нет. Численный «процент
готовности» без перечня приёмочных сценариев был бы произвольным.

Со времени первой проверки добавлены live/shadow через системный tcpdump,
Android/JNI, дополнительные проверки входов и CI-конфигурация. Ранее указанные
21 тест и отсутствие live-backend больше не описывают текущий код.

## Основание сравнения

Для оригинала выбран стабильный **aircrack-ng 1.7**: официальный
[GitHub latest release](https://github.com/aircrack-ng/aircrack-ng/releases/latest)
на момент проверки указывает на [тег 1.7](https://github.com/aircrack-ng/aircrack-ng/releases/tag/1.7),
как и [страница загрузок](https://www.aircrack-ng.org/downloads.html).
Разработка upstream продолжается отдельно от этого релиза. Справочные страницы
wiki могут обновляться независимо от тега; спорные детали не считаются доказанными
одним отсутствием упоминания в документации.

Локально просмотрены README, manifests, Rust/Android исходники, workflow и тесты.
Пакеты Rust имеют версию 0.1.0, workspace содержит **9 крейтов** с `air-jni`.
Git-репозиторий ещё не имеет коммитов; исходники untracked, remote не настроен.
Следовательно, локальная проверка не привязана к опубликованному commit SHA.

## Сравнение возможностей

| Область | Оригинальный aircrack-ng | Текущий aircrack-rs |
| --- | --- | --- |
| WPA/WPA2-PSK | Проверка словарей WPA/WPA2, больше поддерживаемых вариантов | Только WPA2 descriptor v2 / HMAC-SHA1, пара M1/M2 |
| Handshake | Обработка M1–M4; исходники 1.7 используют также M3 | Только M1/M2, совпадающие BSSID/STA/replay; M2/M3-only и M3/M4-only отклоняются |
| WEP | PTW и FMS/KoreK | Нет |
| PMKID | Поддерживается | Есть RSN extraction helper, но проверки пароля по PMKID нет |
| Словари и сессии | Несколько словарей, stdin, сохранение/восстановление подбора | Один UTF-8 файл, 8–63 printable ASCII байта; нет stdin, resume и raw 64-hex PSK |
| Скорость | Специализированные SIMD engines, benchmark и airolib | Rayon, пакет по 256 кандидатов; сравнительных замеров нет |
| Пассивный захват | airodump-ng: AP/STA обзор, каналы, несколько интерфейсов и форматы отчётов | live/airodump: один заданный интерфейс и MAC, tcpdump, лимиты времени/пакетов; нет channel hopping и AP/STA dashboard |
| Monitor mode | airmon-ng управляет интерфейсами | airmon — заглушка; --monitor передаёт явный запрос tcpdump, зависит от ОС/драйвера |
| Инъекция / fake AP | aireplay-ng / airbase-ng | Не реализованы |
| Расшифровка / утилиты | airdecap-ng, packetforge-ng, ivstools и другие инструменты | Соответствующие команды возвращают unsupported-operation error |
| Интерфейс пользователя | Набор CLI с устоявшимися параметрами | Один CLI с подкомандами; TUI — preview; отдельное Android Apex-приложение |
| Платформы | Основная платформа Linux, также другие ОС; конкретные радиооперации зависят от драйверов | Offline portable Rust; live пути только Linux/macOS; Windows live отсутствует; Android только offline |

Основание строк о cracking: [справка aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
и [исходники стабильного 1.7](https://github.com/aircrack-ng/aircrack-ng/blob/1.7/src/aircrack-ng/aircrack-ng.c).
PMKID и общий scope: [официальное введение](https://www.aircrack-ng.org/doku.php).
Захват: [airodump-ng](https://www.aircrack-ng.org/doku.php?id=airodump-ng).
Утилиты: [каталог документации](https://www.aircrack-ng.org/documentation.html).

Это сравнение функций, а не результат запуска двух реализаций на одном наборе
данных. Upstream-бинарник не найден в PATH; side-by-side interoperability и
throughput benchmark не проводились. Нельзя заключить, что Rust быстрее,
медленнее или эквивалентен оригиналу по обнаружению handshake.

WPA3/SAE не включён в целевой паритет как «обычный пассивный offline WPA2-путь».
Официальное описание оригинала заявляет WEP/WPA/WPA2-PSK; это не подтверждение
универсального offline-подбора SAE и не основание обещать его в Rust-версии.

## Что подтверждено в текущем проекте

### Offline desktop

- pcap и pcapng EPB/SPB, несколько секций и интерфейсов.
- Raw 802.11, Radiotap с FCS/data padding, Ethernet EAPOL без VLAN.
- QoS headers, SSID из beacon/probe response; hidden SSID требует явного значения.
- Сессии разделяются по BSSID, station и replay counter; повторы убираются.
- PMK/PTK/MIC known-answer tests и synthetic captures, созданные Python независимо
  от Rust. Ошибки MIC, SSID, словаря и неполные пары проверяются через CLI.
- Захват и кадры загружаются целиком; desktop session extraction может создавать
  декартово произведение кандидатов. Общих лимитов памяти/CPU для враждебного
  capture пока нет. Rust сам по себе эту проблему не устраняет.

### Passive live/shadow

Код реализует bounded tcpdump runner, приватный новый pcap, явный background worker,
heartbeat и stop request. Default Ethernet endpoint filter не доказывает BSSID;
monitor-фильтр учитывает DS-биты. Автозагрузки, injection и принудительного
переподключения клиента нет. `shadow` относится к захвату, а не к resume подбора.

Тесты используют fake subprocess и реальный tcpdump только на synthetic offline
файлах. Ранее документированный доступ к `/dev/bpf0` на Mac был запрещён;
успешный радио/monitor тест не подтверждён и сегодня не повторялся.
Подробнее: [валидация live](LIVE_CAPTURE_VALIDATION.md).

### Android

Есть native Java UI с Apex темами, SAF import и Rust JNI. Manifest не запрашивает
Internet; обработка offline. Ограничения адаптера: capture 4 MiB, dictionary 16 MiB,
32 768 пакетов и 128 поддерживаемых EAPOL keys перед сборкой сессий. Эти лимиты не
распространяются автоматически на desktop CLI. Есть progress/cancellation.

Debug APK присутствует в build outputs, но в этой проверке он не пересобирался.
Ранее описанные host-JNI/APK проверки не заменяют ART/UI acceptance. Android
instrumentation execution на устройстве/эмуляторе здесь не подтверждён.
Подробнее: [Android README](../android/README.md).

## Повторённые проверки 2026-10-27

Локальная macOS, Rust/Cargo 1.98.1:

| Проверка | Результат текущего запуска |
| --- | --- |
| `cargo test --workspace --locked --offline` | **56 passed, 0 failed, 0 ignored**; включая inert subprocess helper |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | PASS |
| `python3 android/tests/check_apex.py` | PASS: tokens, typography, contrast |

Не повторялись: release build/tests, JNI JVM smoke, Gradle/APK/lint и Android
instrumentation. Hosted CI Linux/macOS/Windows и Android описан в workflow, но
его удалённое выполнение в этой проверке не проверялось. Отсутствие коммитов и
remote дополнительно ограничивает воспроизводимость опубликованного результата.

## Следующие приоритеты

1. Сформировать разрешённый к распространению набор независимых реальных captures
   и side-by-side проверку с фиксированным upstream 1.7: одинаковые SSID/пароли,
   обнаруженные/пропущенные сессии, повреждённые контейнеры. Текущая synthetic
   проверка подтверждает рабочий сценарий, но не полный паритет.
2. Ограничить desktop capture/session resources, добавить streaming и fuzz targets.
3. Провести Android ART/UI acceptance и авторизованный аппаратный passive-capture
   тест отдельно от unit/integration tests.
4. Измерять производительность только на одном CPU, одном capture, словаре и числе
   потоков с release builds обеих реализаций. До этого не обещать ускорение.
5. Выбрать продуктовый scope: узкий offline/mobile инструмент или расширение
   протокольной совместимости. Поддержку новых handshake/descriptor вариантов
   принимать через отдельные fixtures, а не через количество CLI-команд.

Текущие отличия полезны как продуктовые решения: offline Android UI и явный
ограниченный capture lifecycle. Они не доказывают превосходства по криптографии,
производительности или аппаратной совместимости над оригиналом.
