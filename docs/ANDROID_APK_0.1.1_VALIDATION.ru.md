# Android APK 0.1.1 — PMKID и M2/M3

Сборка: 27 октября 2026, macOS ARM64. Версия `0.1.1`, versionCode `2`, package `dev.onixus.aircrack`.

Готовый установочный файл: [aircrack-apex-0.1.1-pmkid-m2m3-debug.apk](../android/build/distributions/aircrack-apex-0.1.1-pmkid-m2m3-debug.apk).
Размер: 1976326 байт. Android 8.0+ (API 26), arm64-v8a и x86_64, target SDK 36.

SHA256:

```text
5baebf67e8ad3696787efe26aa892f9030857673fdb8beecef0c2d5862e3dd24
```

## Выполнено

- Rust JNI заново собран в release для обеих Android ABI из текущего кода PMKID/M2-M3.
- `assembleDebug`, `lintDebug` и `assembleDebugAndroidTest` — успешно.
- В APK проверены обе JNI-библиотеки: staged files совпадают с Rust output, упакованные — с Gradle stripped output. Проверены JNI exports, новые диагностики, ELF PT_LOAD alignment >=16 KiB.
- `apksigner verify` — успешно, APK Signature Scheme v2. Сертификат совпадает с предыдущим debug APK: `a6bed5eab8bbfc8aef162f4f85cd3024db7c617202314551081d4d21cba59f1c`.
- `zipalign -c -P 16 -v 4` — успешно.
- 62 workspace Rust-теста, строгий Clippy, rustfmt, Apex checks и host JVM/JNI smoke с новыми PMKID/M2-M3 fixtures — успешно.
- Lint: 0 ошибок, 6 предупреждений (DataExtractionRules, DrawAllocation, ObsoleteSdkInt, ViewConstructor, два SetTextI18n).
- Добавлен Android instrumentation test для упакованных M2/M3, M1 PMKID, association/reassociation PMKID. Test APK компилируется; это не подтверждает выполнение тестов.
- `testDebugUnitTest` завершился `NO-SOURCE`: Java unit tests отсутствуют, этот task не засчитывается как исполненные тесты.

## Ограничение runtime-проверки

Тестовый эмулятор `Aircrack_Apex_Test` запускался отдельно, в read-only/no-snapshot режиме на порту 5580. Несмотря на успешный accel-check, он сообщил `hvf is not enabled on this aarch64 host` и `qemu_mprotect__osdep: mprotect failed: Permission denied`; ADB показывал offline. Эмулятор остановлен через targeted `emu kill`.

ART/UI instrumentation не выполнялся. На подключённый физический телефон приложение не устанавливалось. Это debug-подписанный APK для локальной установки, не production/Play Store release.

Подробная машинная проверка: [verification JSON](../android/build/distributions/aircrack-apex-0.1.1-verification.json).

Установка вручную через Android package installer или:

```sh
adb -s YOUR_DEVICE_SERIAL install -r /absolute/path/to/aircrack-apex-0.1.1-pmkid-m2m3-debug.apk
```

Предыдущий APK с тем же package и debug-сертификатом можно обновить без удаления приложения. Для иной подписи совместимость обновления не подтверждена.

## Последующая проверка на реальном телефоне

27 октября 2026 APK установлен на **Xiaomi 2211133G (fuxi), Android 16 / API 36, arm64-v8a**. Установлены основное приложение 0.1.1 (versionCode 2) и test APK. Выполнена instrumentation-команда с классом `dev.onixus.aircrack.NativeSmokeTest`: **OK (3 tests)**, ошибок нет.

- `testPackagedM2M3AndPmkid`: четыре synthetic captures — M2/M3, M1 PMKID KDE, association RSN PMKID, reassociation RSN PMKID. Для каждого проверены inspection, число targets/PMKID, найденный известный пароль и отклонение неверного SSID.
- `testPackagedPipeline`: базовый M1/M2 pipeline, progress, неверный SSID/JSON, cancellation.
- `testNotFoundAndInvalidDictionary`: словарь без нужного пароля и malformed UTF-8 dictionary.

APK скопирован обратно с телефона; SHA256 совпал с выданным файлом: `5baebf67e8ad3696787efe26aa892f9030857673fdb8beecef0c2d5862e3dd24`. Подтверждены установленная версия и ABI. `am start -W` главного Activity вернул `Status: ok`; приложение оставлено установленным и открыто. Вспомогательный test package удалён после прогона.

Это подтверждает исполнение общего JNI/ART pipeline на настоящем ARM64 устройстве. Проверки использовали только публичные synthetic fixtures; аппаратный Wi-Fi capture, чужие сети и реальные credentials не использовались. Отдельный UI instrumentation suite в этом прогоне не запускался; успешный запуск Activity не равен полному UI acceptance.

[Полный instrumentation output](../android/build/distributions/device-native-tests-0.1.1.txt) · [Машинный device report](../android/build/distributions/device-validation-0.1.1.json).

## UI-проверка тем на телефоне

На том же Xiaomi выполнен класс `ApexUiTest`: итог **OK (2 tests)** — `testDarkThemePipeline` и `testLightThemePipeline`. В каждой теме загружен публичный synthetic пример, подтверждено разрешение, выполнена проверка словаря, получен found result; пароль скрыт по умолчанию. Сохранены начальный экран и полностью видимая карточка результата, 1080×2400.

В тестовом коде исправлен ненадёжный захват результата: подготовка окна и ожидание layout, повторный поиск текущего View, явная прокрутка ScrollView, проверка полной видимости карточки. Предыдущие попытки и их ошибки сохранены рядом с финальным логом. Изменений production APK в этом прогоне нет. FLAG_SECURE снимается только для synthetic screenshots в instrumentation и восстанавливается; keep-screen-on ограничен тестовым окном.

Визуально текст и элементы приложения в обеих темах читаемы, карточка результата полностью помещается в кадр, пароль замаскирован. **Найден дефект:** на скриншоте тёмной темы часы и часть системных status-bar icons тёмные на тёмном фоне; это снижает читаемость. Автоматическая проверка этого системного оформления пока отсутствует. В рамках проверки production-код не изменялся. Apex token/contrast check — PASS; этот check не покрывает системные значки Android.

- [Тёмная тема, начальный экран](../android/build/distributions/ui-0.1.1/apex-dark.png)
- [Светлая тема, начальный экран](../android/build/distributions/ui-0.1.1/apex-light.png)
- [Тёмная тема, результат](../android/build/distributions/ui-0.1.1/apex-dark-result.png)
- [Светлая тема, результат](../android/build/distributions/ui-0.1.1/apex-light-result.png)
- [Финальный instrumentation output](../android/build/distributions/ui-0.1.1/instrumentation.txt)
- [Машинный отчёт](../android/build/distributions/ui-0.1.1/verification.json)

После прогона вспомогательный test package удалён, обычное приложение открыто. Это проверка конкретного устройства и двух тем на штатном масштабе; другие разрешения, font scales и состояния клавиатуры не покрыты.
