# Проверка Enterprise-аудита и роуминга на Fedora — 2026-10-27

Проверенный коммит реализации: `60c0c6414a72cad1c18859549b91bceefe8bdaec`
(`main`, опубликован в `origin/main`). Следующий коммит с этим отчётом изменяет
только документацию.

Среда: Fedora 43, x86_64, ядро `6.17.1-300.fc43.x86_64`, Rust/Cargo 1.98.1.
Тесты и release CLI выполнялись **нативно в гостевой Fedora**, вне контейнера.
Rust toolchain извлечён из уже имевшегося образа `rust:1.98.1-bookworm`;
`rustfmt` и Clippy добавлены из официального Rust-канала в изолированный каталог.
Первый запуск этих двух проверок завершился ошибкой отсутствующего компонента;
после установки оба повторных запуска прошли. Системные пакеты не менялись.

Исходники переданы через `git archive` точного коммита, зависимости — через
`cargo vendor --locked --offline`. Контрольные суммы архивов проверены в Fedora:

| Архив | SHA-256 |
| --- | --- |
| source.tar | `60ab8d9cbe00deed8c7856002324946a0b9e2882513a884c075e40b7dcd75d20` |
| vendor.tar.gz | `7fe8c2f56d08128b688d486efbf7416093e94c441846d350570fd6dec4c30963` |

## Результаты

| Проверка | Итог |
| --- | --- |
| `cargo test --workspace --locked --offline` | 218 passed, 0 failed |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | PASS |
| `cargo build -p air-cli --release --locked --offline` | PASS |
| `validate_roaming_fragments.py` с release CLI | 16 cases PASS |
| `aircrack interfaces` | PASS; только виртуальные Ethernet-интерфейсы и bridge/veth |
| `survey --iface enp0s9 --list-channels` | Ожидаемый отказ до захвата, exit 1 |

Число Rust-тестов отличается от macOS (217) из-за платформенных cfg.
Полный workspace-прогон включает новые Enterprise/roaming regression tests,
сквозной CLI JSON/CSV/plain тест и проверку отрисовки TUI. Python-прогон
проверяет синтетические FT Personal/SAE-PMK/fragment fixtures; он не заменяет
проверку реального Enterprise-роуминга.

## Адаптер и предел аппаратной проверки

`iw dev` и `iw phy` не вернули устройств; `/sys/class/ieee80211` пуст.
`enp0s9` имеет драйвер **virtio_net**; PCI ID — `1af4:1000` (Virtio network
device). Другие сетевые PCI-устройства — эмулированные Intel Ethernet.
USB-инвентарь содержит только root hubs и VirtualBox USB Tablet, Wi-Fi адаптера
в нём нет. Это наблюдение состояния гостя на момент проверки.

Read-only вызов `survey --iface enp0s9 --list-channels` завершился:

```text
Error: Wi-Fi helper failed (exit status: 237): command failed: No such device (-19)
```

Гостю доступен виртуальный Ethernet, даже если сеть хоста использует Wi-Fi.
VirtualBox описывает такую виртуальную сеть и wireless bridging в
[Virtual Networking](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html).
Для проверки radio/monitor capture гостю необходимо предоставить физический
Wi-Fi адаптер, например USB passthrough, с поддерживаемым Linux-драйвером.
Критерий готовности — устройство отображается в `iw phy` и `iw dev`, а PHY
поддерживает monitor mode.

Живой радиозахват, настройка каналов, проверка EAP/RADIUS и реальный переход
клиента между AP **не выполнялись**. Ассоциации, режимы интерфейсов и настройки
сети не менялись; deauthentication/injection не запускались.

## Артефакты

В Fedora сохранён изолированный каталог:
`/home/onixus/air-bug-validation/60c0c64/`.
Release CLI: `target/release/aircrack`; логи: `logs/`, включая `tests.log`,
`fmt-final.log`, `clippy-final.log`, `release.log`, `adapter.log`,
`ethernet_guard.log`, `roaming-fragments.json` и `summary.tsv`.
Локальная копия логов: `/private/tmp/air-fedora-60c0c64-results/`.
