# Этап 6. Кроссплатформенная приёмка и зависимости

Документ задаёт границы поддержки и порядок приёмки текущей реализации.
Это критерии проверки, а не отчёт об успешном запуске на всех ОС. Результат
относят к конкретным SHA, сборке, ОС, архитектуре и, для радио, адаптеру/драйверу.

## Матрица покрытия

| Платформа | Допустимый сценарий | Граница приёмки |
| --- | --- | --- |
| Windows | Только офлайн: анализ PCAP/PCAPNG, проверка кандидатов, `survey --read`, поддержанные операции `wpaclean` и `airdecap` | Live/monitor capture, `interfaces`, управление каналами и CoreWLAN `scan` не поддерживаются. Установка Npcap не добавляет backend. |
| Linux | Офлайн и разрешённый пассивный захват через tcpdump; `survey` на заранее подготовленном monitor-интерфейсе | Нужны физический Wi-Fi адаптер, подходящий драйвер, разрешённые каналы и права. Программа не создаёт monitor-интерфейс и не вызывает sudo автоматически. |
| macOS | Офлайн; обычный обзор `scan`; ограниченный пассивный захват с ручной подготовкой и проверкой оборудования | `scan` использует отдельный CoreWLAN helper. Для live `survey` нужен выделенный неподключённый адаптер; associated/unknown mode отклоняется до открытия захвата. Универсальная поддержка Mac не заявляется. |
| Android | Локальный офлайн-верификатор импортированных PCAP/PCAPNG и словарей через общий Rust/JNI | API 26+, arm64-v8a или x86_64. Нет live/monitor capture, управления каналами и интерфейса `airdecap`; root не требуется, Internet permission отсутствует. |

Пассивный захват выполняют только в согласованной области: разрешённые BSSID,
адаптер, канал, время и объём данных. Injection, deauthentication, эмуляция AP
и пассивный словарный подбор SAE-пароля не реализованы. Обычный macOS `scan`
использует системное обнаружение сетей и не является пассивным monitor capture.

## Общие зависимости и офлайн-приёмка

Для сборки desktop CLI нужны Rust/Cargo stable, системный linker/инструменты
сборки для выбранного Rust target и зависимости из `Cargo.lock`. На Windows
для MSVC target нужен соответствующий C++ build toolchain. Доступ к реестрам
нужен при первоначальной загрузке; `--locked` фиксирует lockfile, но не запрещает
сеть. `--offline` применим только с заранее подготовленным кешем или vendor.
У готового CLI офлайн-парсер не требует tcpdump, libpcap/Npcap или Wi-Fi адаптера.

Проверки из корня репозитория:

```sh
rustc --version
cargo --version
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build -p air-cli --release --locked
```

Минимальная проверка готового бинарника на публичных синтетических fixtures:

```sh
./target/release/aircrack --version
./target/release/aircrack aircrack --capture tests/fixtures/wpa2-radiotap.pcap
./target/release/aircrack aircrack --capture tests/fixtures/wpa2-radiotap.pcap --wordlist tests/fixtures/words.txt
./target/release/aircrack survey --read tests/fixtures/wpa2-radiotap.pcap --plain
```

В Windows PowerShell путь к бинарнику — `.\target\release\aircrack.exe`;
остальные аргументы сохраняются. Для JSON используют новые пути в приватном
каталоге; Windows наследует ACL каталога, Unix mode 0600 не переносится на NTFS.
Ожидаемые exit codes, негативные сценарии и значения `verification` описаны в
[машинном контракте CLI](CLI_MACHINE_CONTRACT.md). Inspection без словаря
не подтверждает пароль. Совпадение тестового кандидата проверяет офлайн-путь,
но не подключение к сети. Приватные PCAP и реальные ключи в CI не загружают.

## Linux: зависимости перед разрешённым пассивным захватом

Backend использует фиксированный `/usr/bin/tcpdump`; одного наличия команды
в PATH недостаточно. Для `survey` нужен `iw` в одном из путей
`/usr/sbin/iw`, `/sbin/iw`, `/usr/bin/iw`. Системный tcpdump использует свою
libpcap; Rust CLI не требует libpcap development package для офлайн-сборки.

```sh
test -x /usr/bin/tcpdump
/usr/bin/tcpdump --version
command -v iw
iw dev
iw phy
./target/release/aircrack interfaces
# mon0 — пример уже подготовленного оператором интерфейса
iw dev mon0 info
./target/release/aircrack survey --iface mon0 --list-channels
```

Проверяют `type monitor`, соответствующий PHY, поддержку monitor mode и
допустимость канала по драйверу/regulatory domain. Права открытия устройства
и настройки частоты должны быть предоставлены администратором заранее.
Отсутствующая зависимость, Ethernet вместо Wi-Fi или отказ прав блокируют
радиоприёмку. Наличие интерфейса в `interfaces` не доказывает приём 802.11.

После preflight оператор отдельно запускает ограниченный захват разрешённого
BSSID по [руководству README](../README.md#passive-apclient-survey), сохраняет
диагностику, проверяет реальные 802.11 кадры, ограничения, штатную остановку
и состояние канала после завершения. Захват не принуждает клиента к reconnect;
отсутствие handshake не означает ошибку программы. В VM нужен физический
адаптер, доступный гостю: виртуальный Ethernet не подтверждает Wi-Fi capture.
Исторический [отчёт Fedora](FEDORA_ENTERPRISE_ROAMING_VALIDATION.ru.md)
подтверждает офлайн-проверки, но прямо исключает проверку радио.

## macOS: ограниченная и ручная приёмка

Захват использует фиксированный `/usr/sbin/tcpdump` и требует доступа к BPF.
Проверки наличия инструмента и перечисления интерфейсов:

```sh
test -x /usr/sbin/tcpdump
/usr/sbin/tcpdump --version
./target/release/aircrack interfaces
```

Для сборки helpers нужны `swiftc`/Xcode Command Line Tools и системные
frameworks. Helpers размещают рядом с используемым CLI; наличие исходника
не означает наличие исполняемого helper:

```sh
sh tools/build-wifi-scan-macos.sh
swiftc tools/air-channel-macos.swift -framework CoreWLAN -o target/release/air-channel-macos
test -x target/release/air-channel-macos
test -x "target/release/Air Wi-Fi Scan.app/Contents/MacOS/air-wifi-scan-macos"
```

Первый helper нужен для обычного `scan`; второй — для состояния адаптера
и каналов `survey`. macOS может скрывать SSID/BSSID без согласия Location
Services; неизвестный BSSID нельзя восстанавливать по SSID. Перед live `survey`
оператор вручную проверяет выделенный неподключённый адаптер и права BPF/каналов.
Программа не выполняет диссоциацию автоматически. Точная настройка через
`--frequency`/`--hop-frequencies` доступна только Linux; аппаратная приёмка
6 GHz отсутствует.

В [отчёте macOS](MACOS_SURVEY_VALIDATION.ru.md) зафиксирован приём после ручной
диссоциации через прямой tcpdump и helper, а также отказ CLI на подключённом
адаптере. Полный live pipeline обновлённого CLI после восстановления связи
там не перепроверялся. Это ограниченное свидетельство для указанного Mac.
Пустой PCAP не подтверждает работающее радио: live `survey` с нулём 802.11
пакетов возвращает ошибку; `live`/`shadow` могут завершиться с корректным пустым
PCAP, что также не доказывает захват handshake.

## Android: зависимости сборки и проверка APK

Сборочный скрипт поддерживает macOS/Linux. Нужны Java 17+, Rust targets
`aarch64-linux-android` и `x86_64-linux-android`, Android SDK platform 36,
build-tools 36.0.0, NDK 28.2.13676358 и включённый Gradle wrapper.
Проверяют `JAVA_HOME`, `ANDROID_HOME` (либо `ANDROID_SDK_ROOT`) и
`ANDROID_NDK_HOME`; сеть сборочной машины нужна для загрузки зависимостей.

```sh
java -version
rustup target list --installed
python3 android/tests/check_apex.py
bash android/test-host-jni.sh
bash android/build-android.sh assembleDebugAndroidTest
# Отдельно, при доступном устройстве/эмуляторе API 26+ нужной ABI:
adb devices
./android/gradlew -p android connectedDebugAndroidTest
```

Python 3 нужен для Apex-проверки, `adb` — для установки и device-проверок.
После изменений Rust APK пересобирают скриптом: Gradle сам JNI не обновляет.
Host JNI smoke, сборка APK и компиляция instrumentation не заменяют выполнение
на ART. На устройстве проверяют импорт, известный/неверный кандидат, отмену,
обе темы и скрытие секрета; сохраняют SHA-256 APK, модель, API/ABI и результаты.
APK из скрипта debug-signed, производственная подпись и выпуск отдельно.
Ограничения импорта: capture 4 MiB, словарь 16 MiB; desktop-бюджеты к Android
не применяют. Подробности и исторические результаты:
[Android README](../android/README.md), [проверка APK](ANDROID_APK_0.1.1_VALIDATION.ru.md).

## Что считается завершённой приёмкой

В отчёте для каждой ОС фиксируют SHA исходников/хеш артефакта, версии зависимостей,
команду, exit code, ожидаемый/фактический результат и ссылку на безопасные логи.
Раздельно отмечают сборку, офлайн-путь, radio/driver и Android device/UI:
«пройдено», «ошибка» или «не выполнено» с причиной. Неподдержанный сценарий
отмечают как границу покрытия, а не как успешно пройденный тест.

[CI](../.github/workflows/ci.yml) задаёт Rust-проверки Linux/macOS/Windows,
Linux differential tests и Android сборку/JNI/instrumentation на эмуляторе.
Конфигурация workflow не доказывает успешный запуск для текущего SHA;
результаты конкретного прогона проверяют отдельно. Hosted runner, синтетический
fixture и Android эмулятор не подтверждают физический Wi-Fi адаптер, все модели
телефонов или эксплуатационную приёмку интеграции Shapoclyack.
