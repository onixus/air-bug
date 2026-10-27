# Скорость словарного движка — 2026-10-27

Локальный release benchmark на macOS/aarch64. Синтетический SSID и 1024 уникальных кандидата; два проверяемых target: WPA2 EAPOL и PMKID. Ни один кандидат не совпадает, поэтому измерен полный проход. Один worker: 7 samples; четыре worker: 5 samples. В таблице медианы независимых измерений.

| Режим | 1 worker, кандидатов/с | 4 worker, кандидатов/с |
|---|---:|---:|
| Generic RustCrypto PBKDF2 | 2437.2 | 9265.4 |
| Специализированный WPA PBKDF2 | 3452.1 | 12989.7 |
| Словарь без cache | 3464.3 | 12962.1 |
| Холодный cache, включая запись/sync | 2338.1 | 4829.6 |
| Повторно открытый прогретый cache | 463864.3 | 523216.5 |

PBKDF2 ускорен в 1.416× / 1.402× относительно generic baseline в том же бинарнике. Холодный cache медленнее прохода без cache; он выключен по умолчанию. Прогретый cache избегает PBKDF2 и не является измерением скорости деривации. Во всех warm samples: 1024 hits, 0 misses, 0 derivations. OS page cache не сбрасывался; это не cold-boot disk benchmark и не сравнение скорости с upstream aircrack-ng.

## Воспроизведение

```sh
cargo build --release --workspace --locked
./target/release/aircrack benchmark --candidates 1024 --samples 7 --threads 1 --json benchmark-1t.json
./target/release/aircrack benchmark --candidates 1024 --samples 5 --threads 4 --json benchmark-4t.json
```

Baseline/optimized порядок чередуется, workers и SHA-1 dispatch одинаковы. До замеров прогреваются SHA-1 и worker pool. Cache для каждого sample новый, после cold прохода закрывается и открывается заново; после warm прохода удаляется. Все данные публичные synthetic. Время включает создание/открытие cache и sync новых batch; генерация кандидатов и построение targets вне замеров. Результаты зависят от CPU, нагрузки, файловой системы и числа workers. CI не вводит timing thresholds.

## Проверки

177 Rust-тестов прошли. Включены PBKDF2 differential с generic на границах длины и разных SSID, known answers, KCK/full-PTK equivalence, persistence между процессами, collisions/eviction, повреждения/header bounds, lock contention, Unix permissions/symlinks, first-match/resume/stdin и SAE/mixed-target provenance. Строгий Clippy, rustfmt, release build и JNI smoke прошли. 24 cracking и 23 airdecap сравнительных сценария с upstream, 16 FT/SAE/fragment scenarios и 2 streaming scenarios прошли с ожидаемыми результатами. Android APK/device и hosted CI в этом изменении не проверялись.

## Артефакты

- [1 worker: все samples и cache counters](benchmarks/dictionary-2026-10-27-1t.json)
- [4 workers: все samples и cache counters](benchmarks/dictionary-2026-10-27-4t.json)
- Rust compiler: `rustc 1.98.1 (48a229cea 2026-09-01)`
- SHA-256 release-бинарника: `88b54fe99ba21e7273877b95dd96d42e385d4eae167a499ea214eaa614b103c2`

PMK cache хранит чувствительные ключи и SHA-256 идентификаторы кандидатов; это trusted local store, а не encrypted vault. Команды, формат, лимиты и ограничения — в [README](../README.md#dictionary-speed-benchmark-and-persistent-pmk-cache).
