# WPA2 PMKID и M2/M3: реализация и сравнение с aircrack-ng

Проверено 27 октября 2026, macOS ARM64, Rust/Cargo 1.98.1.

## Реализованный scope

Общий offline pipeline CLI/JNI принимает три типа проверочных данных:

- M1/M2: одинаковый replay counter, ANonce из M1, SNonce и MIC из M2.
- M2/M3: одинаковые AP/STA, `M3.replay = M2.replay + 1` без переполнения.
  ANonce берётся из M3, проверяется **MIC M2**, а не содержимое GTK из M3.
  Порядок пакетов не важен. Повторы и совпадающие ANonce M1/M3 не дублируют сессию.
- PMKID: M1 PMKID KDE (vendor IE 221, OUI/type `00:0f:ac:04`, 16 байт ID)
  либо список PMKID в RSN IE association/reassociation request.
  RSN-путь принимает только AKM `00:0f:ac:02` (обычный PSK), сохраняет все ID
  и проверяет полную структуру списков и необязательного хвоста. Beacon не
  определяет station и не создаёт PMKID target.

Поддерживаются только WPA2 descriptor v2 и SHA1-PSK derivation. M3 с обычными
pairwise/install/ACK/MIC флагами допускает secure/encrypted-key-data bits;
групповые ключи, request/error и descriptor v1/v3 не принимаются. Парсер проверяет
длины EAPOL и key data до срезов. Nonce и MIC должны быть ненулевыми там, где
это требуется. PMKID отвергается только если **все** 16 байт нулевые: нулевой
первый байт сам по себе допустим.

В `air-core` добавлено:

```text
PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || STA)[0:16]
```

Метки без NUL; MAC-адреса имеют порядок AP, затем station и не сортируются.
`VerificationTarget` разделяет handshake и PMKID, `Engine::from_target` валидирует
их перед проверкой кандидатов. Существующий `Engine::new(HandshakeSession, ssid)`
сохранён. Сравнение MIC/PMKID выполняется constant-time.

JNI использует тот же pipeline. JSON `sessions` сохраняет совместимость как общее
число verification targets; `handshakes` и `pmkids` дают раздельные числа. Android
UI подписывает их как проверочные записи. Лимит перед extraction — 128 суммарных
EAPOL/PMKID records; M1 с одним PMKID учитывается дважды. Добавлена проверка
границы 128/129 association records. Desktop CLI по-прежнему не имеет общих
лимитов памяти для capture/session extraction.

## Независимые fixtures и тесты

`tests/fixtures/generate.py` создаёт байты контейнеров и ожидаемые PMK/PTK/MIC/PMKID
через Python stdlib hashlib/hmac/struct, без использования Rust-реализации.
Пароль `correct horse battery` и локальные MAC-адреса публичные и синтетические.
M3 key data — синтетический непрозрачный блок; тест не проверяет AES key unwrap
или корректность GTK, которые не нужны для проверки MIC M2 и не реализованы.

Новые end-to-end сценарии прогоняют библиотеку и настоящий CLI:

- M2/M3 и M1 PMKID: raw 802.11, Radiotap, Ethernet EAPOL и pcapng.
- Association/reassociation PMKID: raw, Radiotap и pcapng.
- Положительный и отрицательный словари, повреждённый MIC/PMKID,
  явный неправильный SSID/BSSID, обратный порядок и дубликаты пакетов.
- Unit-регрессии: replay mismatch/overflow, чужие AP/STA, направление,
  неверные key flags и AKM, усечённые/повреждённые KDE/RSN, несколько PMKID,
  нулевой PMKID, ненулевой PMKID с первым нулевым байтом, порядок AP/STA в HMAC.

## Исполненное сравнение с оригиналом

Использован **aircrack-ng 1.7**, Homebrew bottle revision `1.7_2`, arm64_tahoe.
Метаданные: [Homebrew formula API](https://formulae.brew.sh/api/formula/aircrack-ng.json).
SHA256 скачанного bottle:

```text
79663b102bfc2f2c70886c84e262cb77814c6138b87e26fa722cfa3e460eeb14
```

Bottle распакован в `/tmp` без глобальной установки. `install_name_tool` исправил
только пути зависимостей в Mach-O; после этого применена ad-hoc подпись.
`DYLD_LIBRARY_PATH` указывает на временные crypto engines. Код алгоритмов не
изменялся. Точный SHA256 запускавшихся бинарников, входных файлов, команды,
exit codes и вывод сохранены в [JSON-отчёте](../tests/interop/results-macos-arm64-2026-10-27.json).
Это не benchmark: особенности загрузки engine и короткие словари не позволяют
сравнивать производительность.

| Capture / словарь | Rust | Оригинал 1.7 |
| --- | --- | --- |
| M1/M2 / правильный | found | found |
| M1/M2 / неверный | not_found | not_found |
| M2/M3 / правильный | found | found |
| M2/M3 / неверный | not_found | not_found |
| M1 PMKID / правильный | found | found |
| M1 PMKID / неверный | not_found | not_found |
| M2/M3, изменённый MIC / правильный | not_found | not_found |
| M1 PMKID, изменённый ID / правильный | not_found | not_found |
| Association RSN PMKID / правильный | found | no_target |
| Association RSN PMKID / неверный | not_found | no_target |
| Reassociation RSN PMKID / правильный | found | no_target |
| Reassociation RSN PMKID / неверный | not_found | no_target |

**12 сценариев выполнены, 8 общих результатов совпали.** Четыре различия
ожидаемы: на этих association-only файлах оригинал печатает
`Packets contained no EAPOL data; unable to process this AP.` Это отсутствие
поддержанного verifier, а не доказательство неверного пароля. Скрипт различает
`found`, `not_found`, `no_target` и process error/timeout; ошибка запуска никогда
не засчитывается как совпадение отрицательного результата.

Повторный запуск из корня репозитория:

```sh
cargo build -p air-cli --release --locked
python3 tests/interop/compare_aircrack_ng.py \
  --upstream /path/to/aircrack-ng --rust target/release/aircrack \
  --report target/interop.json
```

Для распакованного macOS bottle добавьте `--upstream-library-path /path/to/lib`.
Скрипт требует banner версии 1.7, не загружает/устанавливает программы и не
открывает радио. CI job `interop` запускает его с distro-пакетом 1.7 на Linux;
переход пакета на новую версию требует отдельного пересмотра baseline.
Hosted job в этой сессии не выполнялся.

Для сверки протокольных деталей использованы
[исходники aircrack-ng 1.7](https://github.com/aircrack-ng/aircrack-ng/blob/1.7/src/aircrack-ng/aircrack-ng.c),
в частности обработка M3 и M1 PMKID KDE. Соответствие ограничено тестовым набором,
а не всеми возможными захватами или всеми функциями upstream.

## Результаты локальных проверок

- Debug workspace tests: **62 passed**, 0 failed.
- Release workspace tests: **62 passed**, 0 failed.
- rustfmt и Clippy с `-D warnings`: PASS.
- Host JVM/JNI smoke с новыми PMKID/M2-M3 fixtures: PASS (OpenJDK 17).
- Apex token/contrast checks: PASS.
- Differential script: PASS, 12 cases с явными ожидаемыми различиями.

Android APK/Gradle и ART/device instrumentation здесь не пересобирались и не
запускались. Ранее созданный debug APK не содержит новых JNI-функций до запуска
обычного Android build script. Реальные радио/клиенты не использовались.
WPA1, WEP, descriptor v3, FT/SHA256/SAE, M3/M4-only и raw hexadecimal PSK
по-прежнему не поддерживаются.
