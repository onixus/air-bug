# Enterprise-аудит и диагностика роуминга

`survey` автоматически анализирует доступные пассивные наблюдения при чтении
PCAP/PCAPng и при разрешённом live-захвате. Отдельный флаг не требуется.

```sh
cargo build -p air-cli --release --locked
./target/release/aircrack survey --read authorized.pcap \
  --export-json enterprise.json --export-csv enterprise.csv
```

Для live используйте уже настроенный monitor-интерфейс отдельного адаптера и
обычные параметры `survey`. Проверка macOS по-прежнему запрещает live survey на
ассоциированном интерфейсе. Обычный `scan` не получает EAP и кадры роуминга.

## Enterprise

Аудит beacon/probe response различает `enterprise_advertised` и
`mixed_enterprise_personal`, сохраняет точные AKM/cipher selectors и PMF.
Объявление 802.1X не доказывает корректность конфигурации: вывод рекомендует
проверить RADIUS, допустимые EAP-методы и проверку имени/CA сертификата сервера
в профиле клиента. WPA3 Enterprise/192-bit certification не выводится по одному AKM.

Незашифрованные EAPOL EAP-Packet разбираются с проверкой вложенных длин и
направления и игнорированием padding за EAP Length: Request от AP, Response от клиента, Success/Failure от AP.
Счётчики агрегируются **по BSSID, через разных клиентов и обмены**:

- Request, Response, Success и Failure;
- факт внешнего Identity Response без сохранения значения;
- номера внешних EAP types и имена известных TLS/TTLS/PEAP/FAST/TEAP/MD5 типов;
- `expanded_ietf_types`: типы IETF 1–255 внутри Expanded (254); vendor-specific
  типы не интерпретируются как IETF, vendor payloads не сохраняются;
- неправильные длины/направления и неподдерживаемые EAP codes (включая ERP).

Identity, внешние MD5-Challenge и Failure порождают отдельные наблюдения для
проверки политики/логов. Identity может быть анонимным: само наличие ответа не
доказывает утечку имени пользователя. EAP type в Request может быть лишь
предложением; это не утверждение о согласованном или внутреннем методе.
Числа типов сверены с [реестром IANA](https://www.iana.org/assignments/eap-numbers),
формат и направления — с [RFC 3748](https://www.rfc-editor.org/rfc/rfc3748.html).

Имена пользователей, challenges и TLS payloads не сохраняются в полях аудита
и экспортах. Исходный PCAP, если сохраняется при live-захвате, содержит исходные
кадры и требует обычной защиты. Сертификаты, inner EAP, настройки supplicant и
RADIUS не инспектируются. Success/Failure — наблюдение неподтверждённого кадра,
не доказательство авторизации, отказа RADIUS или доступности сети. Повторы
учитываются; нет восстановления EAP-сессий или дедупликации по Identifier.
Enterprise EAP не превращается в индикатор Personal PSK/password verification.

## Роуминг

Из последнего структурно корректного beacon/probe response доступны:

- Mobility Domain ID (wire hex), FT over DS и resource request из MDIE;
- Neighbor Report capability из RM Enabled Capabilities (802.11k);
- BSS Transition capability из Extended Capabilities (802.11v).

Отсутствующее или слишком короткое поле — `null`, а не предположение о
выключенной функции. Повреждённый новый advertisement инвалидирует текущие
capabilities. Эти объявления не аутентифицированы.

Кольцевой журнал сохраняет последние **512** незашифрованных unicast management
наблюдений: association/reassociation request/response, authentication,
disassociation и deauthentication. Для каждого — AP, station, предыдущий BSSID
из reassociation request, status/reason, authentication algorithm/sequence,
Retry bit, номер записи, capture timestamp (или `null`) и processing time.
Алгоритм authentication `2` обозначает FT; криптографическая проверка здесь не
выполняется. События сохраняются при истечении AP-строк; переполнение явно
учитывается в `roaming_diagnostics.evicted`. Ошибки структурных management
полей — в `malformed_management`. Защищённые и фрагментированные management
кадры пропускаются; broadcast deauthentication в этот журнал не входит.

Запрос перехода и успешный response не приравниваются к завершённому роумингу.
Изменение BSSID в data headers не создаёт событие роуминга. Не выполняется
сопоставление ESS по одинаковому SSID, не рассчитывается время простоя или
задержка перехода. Одноканальный capture/channel hopping может пропустить
переход; timestamps могут отсутствовать или идти назад. Причину отказа нужно
сопоставлять с логами AP/контроллера/клиента. Action frames 802.11k/v и FT over
DS не декодируются; capability не доказывает использование функции.

## Вывод и экспорт

Plain-вывод содержит сводку EAP, capabilities и журнал. TUI показывает EAP и
capabilities выбранной AP-строки и последнее событие всего журнала.
JSON дополняет schema version 1 полями `enterprise`, `roaming_capabilities` у AP,
а также `roaming_events`, `roaming_diagnostics` и явными границами интерпретации.
CSV сохраняет прежние 43 столбца и добавляет `enterprise`, `roaming_capabilities`,
`roaming_event` (JSON внутри корректно экранированной ячейки). События идут как
строки `kind=roaming_event`; `mac` содержит station, `last_bssid` — BSSID наблюдаемого события. Потребителям следует разбирать строку по `kind`.

Синтетические тесты проверяют форматы, фильтр BSSID, opaque protected input,
границы размеров, отсутствие identity в экспортах, отказ reassociation, FT auth,
времена/номера записей, bounded journal и прямоугольный CSV. Они не подтверждают
совместимость с реальным Enterprise/RADIUS или успешный переход между AP.

## Проверка реализации — 2026-10-27

Полный `cargo test --workspace --locked`: **214 passed**, без ошибок.
`cargo fmt --all -- --check`, строгий Clippy для всех targets и release build
`air-cli` прошли. Release CLI также прочитал существующий offline fixture и
сформировал новый JSON. Проверки не запускали radio capture и не меняли Wi-Fi.

## Ревью реализации — 2026-10-27

Исправлены следующие проблемы:

- **P2:** EAP Length ошибочно требовалось равным EAPOL body length. Допустимое
  дополнение теперь игнорируется; превышение доступной длины по-прежнему
  отклоняется (RFC 3748 §4).
- **P2:** усечённый Expanded EAP принимался как валидное наблюдение, а
  Identity/MD5 в Expanded IETF оставались нераспознанными. Обязательный заголовок
  теперь проверяется; IETF namespace распознаётся отдельно от vendor-specific.
  Nak разрешён только в Response с непустым корректно размеренным списком.
- **P2:** короткие fixed fields beacon/probe response оставляли прежние текущие
  capabilities. Теперь такой кадр и malformed security IE инвалидируют текущее
  состояние; прошлый `security_audit.last_valid` остаётся только контекстом.
- **P2:** последнее событие TUI теряло status/reason из-за обрезания длинной
  строки. Событие вынесено на отдельную строку, числовые коды стоят в начале.

Добавлены регрессионные проверки padding, усечения Expanded, IETF/vendor
разделения, Nak, инвалидирования и видимости status/reason на терминале 120×32.

Итог ревью: **217 passed** в `cargo test --workspace --locked`; fmt,
`cargo clippy --workspace --all-targets --locked -- -D warnings` и release build
`air-cli` прошли. Реальные AP/RADIUS и переход клиента между AP не тестировались.
