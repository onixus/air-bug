# Архитектура реализованного проекта

Документ описывает существующий код, а не обещает совместимость со всем aircrack-ng.

## Поток данных

```text
локальный pcap/pcapng
  -> air-capture: контейнер и link type каждого пакета
  -> air-frames: поддерживаемые 802.11 заголовки / SSID
  -> air-handshake: сборка descriptor-v1/v2/v3 M1/M2, M2/M3 и PMKID targets
  -> air-cli: выбор сети и SSID
  -> air-crack: валидация сессии + ограниченные пакеты кандидатов
  -> air-core: PMK -> PTK -> HMAC-MD5/SHA1/AES-CMAC MIC
```

## Границы крейтов

- `air-core`: детерминированные криптографические примитивы без I/O; полный протокольный контекст проверяет вызывающий код; CCMP/WEP decryption — RustCrypto/ICV проверки.
- `air-frames`: management/data заголовки и SSID. Зашифрованные, фрагментированные, null-data и агрегированные payload отклоняются. Это не универсальный декодер 802.11.
- `air-capture`: pcap/pcapng; raw 802.11, radiotap и Ethernet EAPOL без VLAN. Radiotap учитывает выравнивание, объявленные FCS и data padding. Ethernet-нормализация использует EAPOL ACK для направления; это не общий Ethernet bridge.
- `air-handshake`: связывает AP, station и replay counter; убирает повторы, сохраняет разные nonce. В MIC входит объявленная длина EAPOL с обнулённым MIC-полем. PMKID targets берутся из M1 KDE или PSK-only RSN association/reassociation lists; PMKID проверяется отдельной HMAC-SHA1 веткой в air-crack. M2/M3 используют M2 MIC и M3 ANonce при replay +1.
- `air-crack`: проверяет структуру сессии перед подбором. UTF-8 словарь читается пакетами по 256 строк; Rayon проверяет кандидаты параллельно. Сравнение MIC — constant-time. Ошибки чтения не маскируются под отсутствие пароля.
- `air-cli`: явно выбирает сеть, отклоняет неоднозначные SSID без `--essid`. Некорректные отдельные кадры пропускаются со счётчиком; некорректный контейнер и неподдерживаемый link type — ошибки.
- `air-platform`: пассивный tcpdump backend с фиксированным путём программы, валидацией параметров, эксклюзивным pcap (0600), лимитами времени/пакетов и RAII-завершением дочернего процесса. Monitor-фильтр учитывает DS-биты для точного BSSID; обычный режим фильтрует только EAPOL Ethernet endpoints (не доказывает BSSID).
- `air-cli live` / `airodump`: foreground supervisor; `shadow start/status/stop`: явный фоновый worker с отдельной process group, приватной сессией, heartbeat, result и STOP-файлом. PID только информационный, остановка не сигналит произвольному PID. INT/TERM/HUP обрабатываются штатно; SIGKILL/краш supervisor может оставить дочерний процесс. Автозагрузки и скрытого режима нет.
- `air-tui`: рабочая таблица AP/client для `survey`; отдельная команда `tui` остаётся preview.
- `air-jni`: offline Android-адаптер поверх общего pipeline; лимиты файлов, пакетов и EAPOL keys, progress/cancellation. Эти лимиты не распространяются на desktop CLI.

## Ресурсы и безопасность

Словарь потоковый, строка ограничена 64 KiB без LF. Принимаются пароли длиной 8–63 printable ASCII байта, пробелы сохраняются. SSID из захвата хранится в байтах; CLI `--essid` принимает UTF-8.

**Offline CLI читает capture потоком.** Размер и число пакетов ограничивают работу,
а память ограничена фиксированным parser buffer, evidence store, ключами и
reassembly chains. Подробные бюджеты и двухпроходный airdecap описаны в конце
документа. Сборка handshake ограничивает 1024 relevant records и 1024 targets
до декартова произведения. Старые Vec collectors и unrestricted extraction API
сохраняются для совместимости. CLI/JNI используют streaming/bounded API.
Это не OS RSS/CPU sandbox; обнуление секретов и формальный криптографический аудит
не гарантированы.

Офлайн-анализ работает без повышенных привилегий. Live/shadow требуют системный tcpdump и права на capture device; на этом Mac доступ к `/dev/bpf0` текущему пользователю запрещён. Monitor mode включается только явно и может отключить Wi-Fi. Заглушки не изменяют интерфейсы. Найденный пароль печатается в stdout и должен считаться секретом.

## Проверки

Тесты включают PMK/PTK/MIC known-answer vectors, независимые Python fixtures, поддерживаемые link types, реальный CLI, некорректные входы, endpoint/replay mismatches, ошибки словаря и unsupported commands. Радио и реальные сети не используются.

CI определяет форматирование, строгий Clippy, workspace tests и release build для Linux/macOS/Windows. Наличие workflow не означает, что удалённые прогоны уже прошли. Команды — в [CONTRIBUTING.md](CONTRIBUTING.md).

## Следующие приоритеты

1. Независимые реальные captures, fuzzing и измерение производительности потокового pipeline.
2. Fuzz targets и независимо полученные реальные захваты с разрешением на распространение.
3. Стабильные машинные диагностики и exit codes для автоматизации.
4. Решение о судьбе preview/stub крейтов в следующем breaking release.

Реализованы WEP-дешифрование по известному ключу, WPA-дешифрование, FT personal и SAE по экспортированному PMK; точные ограничения описаны ниже и в README. Injection, WEP recovery и SAE PAKE не реализованы. Live/shadow capture реализованы через системный tcpdump, но аппаратная совместимость и захват реального радио на этом Mac не подтверждены. SAE нельзя описывать как обычную пассивную offline dictionary attack: первоначальный roadmap был технически неверен.

## Актуальная оценка

[Срез на 2026-10-27 и сравнение с aircrack-ng 1.7](docs/PROJECT_STATUS_2026-10-27.ru.md): историческая проверка 62 Rust-тестов, форматирования, строгого Clippy и Apex checks. После добавления survey локально прошли 76 Rust-тестов, rustfmt и строгий Clippy; release CLI и CoreWLAN helper собраны. Apex в этом изменении не перепроверялся. Полная совместимость с upstream и аппаратная/Android device приёмка не подтверждены.

Поддержка PMKID и M2/M3 проверена на synthetic captures и сравнена с оригинальным 1.7: [отчёт](docs/PMKID_M2M3_VALIDATION.ru.md). На этапе этого исторического расширения M3/M4-only, SHA256/FT/SAE и WPA descriptor v1/v3 ещё отсутствовали; последующие расширения описаны ниже.

## Пассивный обзор эфира (`survey`)

`air-capture::survey` отделён от строгого handshake-декодера: читает только
открытые заголовки management/data, включая protected/QoS/null data, извлекает
Radiotap signal/channel и хранит ограниченную таблицу AP/client. WDS/control и
management fragmentation не интерпретируются. BSSID клиента — последнее наблюдение.

`PcapStream` разбирает растущий classic PCAP порциями до 64 KiB, сохраняет
незавершённую запись до следующего чтения и проверяет длины до обработки. На tick
CLI читает максимум четыре порции; таблицы ограничены 4096 записями каждая, есть
expiry и eviction. Декодирование survey не меняет криптографический pipeline.

`air-platform::survey` переиспользует supervisor и RAII cleanup, но использует
явный broad management/data filter и snaplen 4096. Диагностика tcpdump направлена
в новый приватный `<output>.log`. `channels` использует только passive tuning:
Linux iw для существующего monitor interface; macOS — отдельный CoreWLAN helper,
собираемый рядом с CLI. Проверяются доступные каналы 2.4/5 GHz; команды ограничены
таймаутом, исходный primary channel восстанавливается при наличии информации.
Переключение начинается после получения заголовка PCAP от tcpdump, то есть после
инициализации monitor capture. Режим интерфейса, ассоциация и ширина исходного
канала автоматически не восстанавливаются. Реальное радио не прошло приёмку.

## Уточнение аппаратной приёмки macOS

[Аппаратная диагностика](docs/MACOS_SURVEY_VALIDATION.ru.md) подтвердила 1202
Radiotap-пакета и каналы 1/6 после временной диссоциации, но эта операция
прерывает текущую связь. Production `survey` теперь отказывает на подключённом
Mac-интерфейсе до открытия BPF. Программа не выполняет диссоциацию или power cycle.
Наследуемая маска сигналов исправлена в CLI и перед exec capture child;
channel set требует readback, а нулевой приём в survey возвращает ошибку.

## Обычный обзор macOS (`scan`)

Отдельный `air-wifi-scan-macos` (в bundle `Air Wi-Fi Scan.app`) вызывает только
CoreWLAN scan/cache, читает состояние интерфейса и возвращает JSON version 1.
Он не связан с monitor capture или helper управления каналами. `air-platform`
ограничивает время subprocess (20 секунд, 60 при явном запросе разрешения),
проверяет JSON и метаданные; `air-cli scan` печатает отсортированную таблицу,
экранирует управляющие символы, явно отмечает скрытые идентификаторы и возраст
кэша как неизвестный. Watch обновляет снимки до Ctrl-C и останавливается при
потере ассоциации. CLI не пытается восстанавливать/менять подключение.

Нативный запрос Location Services доступен только по `--request-location`.
Сканирование на подключённом en0 проверено: 18 AP, mode 1 до/после, канал 44,
HTTPS 200. Выдача consent и повторные вызовы затем проверены: scan 25 AP/BSSID и 20 SSID,
cache 37 AP/BSSID и 20 SSID; соединение сохранилось. Исправлена инициализация
CoreLocation: объект менеджера и контекст приложения создаются при каждом запуске,
но запрос разрешения вызывается только при явном `--request-location`. Это не
запускает получение координат и не запрашивает разрешение повторно при обычном scan.

## Общий проход словаря и desktop checkpoints

`TargetSet` валидирует все targets выбранной сети, вычисляет PMK ровно один раз
на кандидата и использует его для всех MIC/PMKID проверок. CLI читает один словарь
один раз, Rayon выбирает первое совпадение в порядке словаря; JNI использует тот
же набор targets с последовательной обработкой кандидатов и cancellation между
ними. CLI больше не перечитывает словарь для каждой сессии.

`air-cli::dictionary` принимает файл или stdin, печатает progress в stderr и
сохраняет checkpoint после завершённой пачки. Состояние не содержит кандидатов
или пароля; версия и отпечатки capture snapshot/словаря, SSID и BSSID проверяются
при resume. JSON ограничен 16 KiB, неизвестные поля отклоняются. Запись — через
0600 temp + sync + rename; эксклюзивный `.lock` не даёт использовать одну сессию
одновременно. После аварии stale lock удаляется вручную после проверки процесса.
SIGINT/SIGTERM на Unix завершают текущую пачку; stdin не перехватывает сигналы.
Подробные команды, пределы и ограничения — в разделе README о checkpoints.

## Survey: индикатор проверочных данных и экспорт

`air-capture::survey` дополняет header inventory флагами M1/M2, M2/M3 и PMKID.
Трекер использует общий EAPOL/PMKID parser и сохраняет только 256 ограниченных
endpoint/replay/message summaries на 120 секунд processing time. Сам MIC/PMKID
и пароль не проверяются. Дубликаты обновляют summary; AP/STA/replay/direction
не смешиваются. Счётчик вытесненных summaries показывает неполноту наблюдения.
Индикаторы живут вместе с AP row и исчезают при её expiry/eviction.

`air-cli::survey_export` резервирует новые JSON/CSV пути до radio backend,
не перезаписывает существующие файлы, пишет финальный снимок после штатного
завершения и успешного restore. Резервирование/запись — 0600 на Unix; на обычной
ошибке собственные файлы удаляются. JSON version 1 содержит AP/client arrays,
raw SSID hex и coverage counters. CSV — плоские AP/client rows с экранированием
и защитой текстовых ячеек от формул. Нонсы/MIC/пароли и packet payload не экспортируются.

## WPA1/hex PSK и airdecap

EAPOL parser принимает descriptor types 2/254 и key versions 1/2; тип/версия
входят в ключ группировки наряду с AP/STA/replay, чтобы разные протоколы не
смешивались. MIC выбирается из HMAC-MD5 или HMAC-SHA1 по проверенному key version.
64 hex-символа означают готовый PMK; обычный пароль проходит PBKDF2 один раз.
Совместимость распространяется на CLI/JNI и survey indicators через общие крейты.
Checkpoint version повышен до 2: сохранённые позиции старого движка могут
пропускать 64-hex кандидаты, теперь требующие проверки.

`air-cli::decap` читает bounded PCAP/pcapng records с timestamps, проверяет MIC
handshake заданным PMK, собирает до 64 уникальных TK на AP/STA и проверяет CCM tag
каждого unicast CCMP пакета. WEP RC4 проверяется ICV; plaintext не возвращается
при ошибке проверки целостности. Выход — эксклюзивный 0600 classic PCAP с Ethernet
или raw 802.11. Тип/разрешение timestamps pcapng учитываются отдельно от packet
payload. Последующие расширения GTK/TKIP, descriptor v3, FT/SHA256/SAE-PMK и
reassembly описаны ниже. WEP recovery не реализован; последующее расширение WDS описано ниже. Ограничения и команды
описаны в README.

## TKIP / GTK / descriptor v3

`air-core::tkip` реализует обе фазы key mixing и Michael: ICV и MIC обязательны
до возврата plaintext. S-box генерируется алгебраически; RustCrypto даёт RC4/AES.
`ptk_extended` сохраняет 64 legacy SHA1 байта для directional Michael keys;
для RSN PSK-SHA256 v3 выводится ровно KDF-384 и применяется AES-CMAC. AKM6 и
CCMP-128 должны быть явно выбраны в корректном M2 RSN IE, иначе v3 отвергается.

`decap_keys` хранит authenticated pairwise records и GTK по AP/Key ID. MIC M3/G1
проверяется до RFC3394 unwrap/RC4-drop256. M3 дополнительно связывается с ANonce и
replay M2; G1 может менять GTK вне четырёхстороннего handshake. KDE key IDs,
lengths, control bits и wrap padding валидируются; negotiated group cipher
сверяется с GTK length. Исторические keys используются offline, включая reuse
Key ID; это не live anti-replay implementation. Лимиты: 64 pairwise records на
AP/STA, 64 GTK на AP/key ID, всего 1024 GTK, 4096 байт encrypted Key Data.
Выбор group keys основан на multicast receiver From-DS, а не MSDU destination
в To-DS. Неверный Michael не маскируется валидным ICV.

CLI checkpoints теперь version 3: v1/v2 snapshots не могут безопасно продолжать
prefix, где старый движок мог пропустить новые targets/candidates. Общий verifier
и survey parser поддерживают v3; Android APK требует пересборки для новых JNI.

## FT / SAE-PMK / reassembly

FT targets — отдельный variant, а не legacy EAPOL с другим MIC. FT-R0/R1/PTK
выводятся из root PMK/SSID/MDID/key-holder IDs/STA/AP/nonces; PMKR1Name и FTIE CMAC
проверяются до установки PTK/response GTK. Scope — FT-PSK/FT-SAE CCMP-128 reassoc
transaction 5/6 с complete RSN/MDIE/FTIE и тремя подписанными IEs. SAE поддерживается
как imported-PMK AKM8/descriptor0 verifier/data decryptor; угадывание пароля через
PBKDF2 для SAE/FT-SAE запрещено на уровне Engine и общего TargetSet.

`air-frames::reassembly` держит не больше 256 chains / 4 MiB bytes / 16 fragments
на MSDU, timeout 2s; identity — receiver/transmitter/sequence/TID, а сохранённая
signature дополнительно связывает headers и actual key fingerprint/ID/Protected.
PN/TSC последовательны; конфликтующий duplicate отравляет chain. `FrameDecoder`
собирает cleartext до разбора EAPOL/FT; protected MPDU сначала проходит cipher
проверку в airdecap. TKIP ICV относится к fragment, Michael — к целому MSDU.
Timestamp результата берётся у fragment 0. Checkpoints v4 включают resolved times
и original lengths, поскольку timestamp expiry теперь влияет на extraction.
CLI/JNI — capture time, survey — processing time. Это bounded offline assembly,
а не live anti-replay receiver или SAE/FT radio authentication stack.

## Потоковый offline pipeline и wpaclean

`CaptureReader` — pull iterator PCAP/PCAPng: фиксированный parser buffer 8 MB,
не больше 256 интерфейсов на секцию, один принадлежащий вызывающему record.
После EOF или ошибки итератор завершён. Бюджеты размера/числа пакетов ограничивают
работу, а не требуют хранения capture. CLI defaults — 4096 MiB / 10M packets;
совместимые Vec collectors и JNI сохраняют прежние более строгие лимиты.

`evidence::Evidence` отбрасывает обычные data frames и дубликаты, хранит не более
1024 EAPOL/association/FT записей, 1024 уникальных SSID advertisements и 4 MiB
payload. Переполнение — ошибка, без эвикции пригодной цели. `aircrack` хеширует
все records инкрементально: формат fingerprint/checkpoint v4 сохранён.

`airdecap` выполняет два потоковых прохода: сбор evidence/ключей, затем запись
каждого расшифрованного MSDU. Fingerprint обоих проходов обязан совпасть.
`PrivatePcap` эксклюзивно создаёт 0600 файл, удаляет его при обычной ошибке,
проверяет диапазоны timestamp/packet length и синхронизирует успешный результат.

`wpaclean` сохраняет provenance только bounded evidence в нормализованном raw
802.11 виде; выбирает M2 и соответствующий M1/M3 по endpoints, descriptor,
replay и nonce, отдельные FT/PMKID records и SSID advertisements. Перед записью
повторно проверяет число структурно извлекаемых целей. Политика MIC validation
не меняется: без credentials очищенный capture не считается аутентифицированным.
Реассемблированные кадры и Ethernet EAPOL нормализуются; forensic fidelity,
полный GTK rekey history и исходные Radiotap headers не сохраняются.

## M3/M4 и WDS

M4 parser требует Pairwise/MIC/Secure, пустой Key Data; replay M3=M4.
Standalone v1/v2 требует ненулевой SNonce в M4. Нулевая M4 SNonce и v0/v3
нуждаются в M2 от предыдущего replay counter. `nonce_source` хранит этот M2;
Engine повторно проверяет descriptor/replay/nonce context и берёт AKM/cipher
из него. M4 MIC проверяется отдельно; плохой M2 MIC не уничтожает пригодный M4.
SAE passphrase provenance остаётся запрещён. Checkpoint version повышен до 5:
старый движок мог пропустить кандидата для теперь поддерживаемого M4/WDS target.

Dot11Frame сохраняет Address4; WDS EAPOL endpoints — RA/TA и ACK role.
Дешифрование ищет PTK только для обеих ориентаций этой пары радиопиров.
CCMP AAD включает Address4, QoS находится после 30-byte header, Michael и
Ethernet используют DA=Address3/SA=Address4. Reassembly связывает всю MAC-шапку,
включая Address4, с key context и PN sequence. BPF включает WDS только при
совпадении выбранного радиопира в addr1/addr2, не addr3/addr4.
`wpaclean` сохраняет M4/M3 и обязательный M2 context. Survey добавляет
handshake_m3m4 в JSON и в конец CSV; обычные WDS MSDU не приписываются
выдуманному BSSID. WPA1 M4 без Secure не классифицируется отдельно от M2.

## Dictionary performance и PMK cache

`air-core::pbkdf` специализирует WPA PBKDF2 на короткий HMAC key/salt и 20-byte U:
precompressed ipad/opad, fixed SHA-1 padding, interleaved T1/T2 chains. Компрессия
остаётся RustCrypto с его hardware dispatch; generic baseline сохранён для
дифференциальных тестов и benchmark. Verification выводит только KCK, тогда как
airdecap сохраняет полный PTK. Векторы/границы и generic equivalence обязательны.

`air-crack::cache` — opt-in trusted local PMK store с фиксированным file budget,
4-way buckets и без RAM index. Header/entries имеют SHA-256 checksums; cache key
включает algorithm/version/SSID/candidate. File locking исключает одновременно
работающие cache users; body corruption даёт miss, header/I/O/lock error — failure.
Новые записи fsync до checkpoint commit. В cache нет plaintext candidate, но PMK
и candidate hash являются чувствительными данными. Это не encrypted vault и не
airolib SQLite interchange. Unix owner/private-mode/no-follow checks обязательны.

`crack_batch_cached` хранит не больше 256 candidates, dedup passphrases до
lookup/parallel derivation и сохраняет исходную candidate provenance при проверке
SAE/mixed targets. Raw PMK обходят cache. Выбор первого совпадения и checkpoint v5
не меняются; `--threads` задаёт локальный Rayon pool. Benchmark использует synthetic
WPA2-EAPOL+PMKID targets, reference/optimized derivation и cold/reopened cache,
пишет отдельные samples/medians без CI timing assertions.

## Multi-input / multi-network offline campaign

`offline` выполняет два bounded streaming прохода по не более 64 capture:
SSID discovery, затем evidence от выбранных BSSID/SSID. Fingerprints каждого
файла сравниваются; input bytes/packets глобальные. SSID discovery ограничен
1024 advertisements (BSSID selection до этого лимита), evidence — прежними
record/byte/target budgets после selection. FragmentDecoder сбрасывается между
файлами; обычные handshake records объединяются между файлами.

`air-crack::networks` группирует до 256 BSSID по точным SSID octets. Bounded
candidate preparation общая с persistent cache: один PMK на candidate/SSID/batch,
raw-PMK и SAE provenance сохранены. Каждый BSSID выбирает собственный earliest
match; solved networks/groups не проверяются повторно. Network ID/SSID обязаны
совпадать с валидированными targets.

`multi` читает до 64 словарей последовательно через отдельный Wordlist на файл:
EOF без LF не склеивает candidates, empty files не меняют global line count.
Common checkpoint v6 содержит ordered input hashes, effective network IDs,
cursor/completed lines и match positions без credentials. Resume replays prefix
и повторно проверяет stored matches, затем продолжает unresolved networks.
Новые результаты публикуются только после batch/cache и atomic checkpoint commit.
Private JSON export явно содержит credentials и различает complete/paused/exhausted.
Legacy one-capture/one-dictionary/one-network path без JSON сохраняет v5 contract.
