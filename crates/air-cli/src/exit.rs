//! Стабильный машинный контракт кодов выхода (этап 1 интеграции).
//!
//! Backend (shapo-ingest и др.) различает исходы по коду возврата процесса и по
//! диагностическому JSON, а не по тексту stdout/stderr. Значения зафиксированы и
//! не должны меняться между релизами: совместимость — часть контракта.
//!
//! Нумерация следует соглашениям `sysexits.h` там, где они применимы
//! (`USAGE` = 64, `INTERNAL` = 70), остальные коды выбраны в непересекающемся с
//! ними диапазоне, чтобы оставить место под будущие категории.

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Успех: запрошенная операция выполнена, контракт соблюдён.
pub const SUCCESS: i32 = 0;
/// Пароль/ключ не найден после исчерпания словаря. Это штатный исход
/// верификации, а не сбой выполнения.
pub const PASSWORD_NOT_FOUND: i32 = 2;
/// Во входных данных нет поддержанной цели: нет сети, рукопожатия или PMKID,
/// которые инструмент умеет обрабатывать.
pub const NO_SUPPORTED_TARGET: i32 = 3;
/// Повреждённый, усечённый или неподдержанный контейнер/формат захвата.
pub const BAD_CONTAINER: i32 = 4;
/// Ошибка привилегий или устройства: монитор-режим, доступ к радио, интерфейсу
/// или к файлу вывода.
pub const PRIVILEGE_OR_DEVICE: i32 = 5;
/// Verification stopped before dictionary exhaustion.
pub const PARTIAL: i32 = 6;
/// Ошибка использования: некорректные аргументы или словарь.
pub const USAGE: i32 = 64;
/// Внутренняя ошибка: непредвиденный сбой, не относящийся к остальным категориям.
pub const INTERNAL: i32 = 70;

/// Категория исхода. Каждая категория отображается на стабильный код выхода и на
/// стабильную строковую метку в диагностическом JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Success,
    /// Верификация (`aircrack`): словарь исчерпан, пароль/ключ не найден.
    PasswordNotFound,
    Partial,
    NoSupportedTarget,
    BadContainer,
    PrivilegeOrDevice,
    Usage,
    Internal,
}

impl Category {
    /// Код выхода процесса для этой категории.
    pub const fn code(self) -> i32 {
        match self {
            Category::Success => SUCCESS,
            Category::Partial => PARTIAL,
            Category::PasswordNotFound => PASSWORD_NOT_FOUND,
            Category::NoSupportedTarget => NO_SUPPORTED_TARGET,
            Category::BadContainer => BAD_CONTAINER,
            Category::PrivilegeOrDevice => PRIVILEGE_OR_DEVICE,
            Category::Usage => USAGE,
            Category::Internal => INTERNAL,
        }
    }

    /// Стабильная строковая метка для поля `exit_category` в JSON.
    pub const fn label(self) -> &'static str {
        match self {
            Category::Success => "success",
            Category::Partial => "partial",
            Category::PasswordNotFound => "password_not_found",
            Category::NoSupportedTarget => "no_supported_target",
            Category::BadContainer => "bad_container",
            Category::PrivilegeOrDevice => "privilege_or_device",
            Category::Usage => "usage",
            Category::Internal => "internal",
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}
impl std::error::Error for Category {}

pub struct Summary {
    pub counts: serde_json::Value,
    pub verification: Option<&'static str>,
}
impl From<serde_json::Value> for Summary {
    fn from(counts: serde_json::Value) -> Self {
        Self {
            counts,
            verification: None,
        }
    }
}

/// Диагностический файл, зарезервированный до начала работы команды. В отличие
/// от обычных экспортов он пишется и при неуспехе — чтобы backend мог прочитать
/// категорию исхода из стабильного JSON, а не парсить текст stdout/stderr.
pub struct Diagnostic(Option<(PathBuf, File)>);

impl Diagnostic {
    /// Резервирует новый приватный путь (0600, без перезаписи существующего).
    /// `None` отключает диагностику: команда ведёт себя как раньше.
    pub fn reserve(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self(None));
        };
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).with_context(|| {
            format!(
                "cannot create diagnostic {}; existing files are never overwritten",
                path.display()
            )
        })?;
        Ok(Self(Some((path.to_owned(), file))))
    }

    /// Записывает финальную сводку исхода. Схема (`schema_version`) стабильна
    /// между запусками; `counts` — небольшой объект без секретов (ни пароля, ни
    /// PMK/ключа), `error` — сообщение об ошибке или `null`.
    pub fn write(
        &mut self,
        kind: &str,
        category: Category,
        summary: Summary,
        error: Option<&str>,
    ) -> Result<()> {
        let Some((path, file)) = &mut self.0 else {
            return Ok(());
        };
        let mut value = serde_json::json!({
            "schema_version": 1,
            "kind": kind,
            "command": kind.strip_suffix("_diagnostic").unwrap_or(kind),
            "exit_category": category.label(),
            "exit_code": category.code(),
            "counts": summary.counts,
            "error": error,
        });
        if let Some(verification) = summary.verification {
            value["verification"] = verification.into();
        }
        serde_json::to_writer_pretty(&mut *file, &value)?;
        file.write_all(b"\n")?;
        file.sync_all()
            .with_context(|| format!("cannot sync diagnostic {}", path.display()))?;
        Ok(())
    }
}

/// Общая обёртка машинного контракта: резервирует диагностику, запускает работу,
/// относит исход к стабильной категории, пишет JSON и выставляет код выхода.
///
/// `execute` возвращает счётчики успешного исхода; при неуспехе в JSON попадают
/// счётчики по умолчанию (нули), а категория берётся из `classify`. Поведение
/// команды без `--diagnostic-json` не меняется: файл не создаётся, а процесс
/// завершается тем же кодом категории.
pub fn run_with_diagnostic<T: Copy + Default>(
    diagnostic: Option<&Path>,
    kind: &'static str,
    classify: fn(&anyhow::Error) -> Category,
    to_counts: impl FnOnce(T, Category) -> Summary,
    execute: impl FnOnce() -> Result<T>,
) -> Result<()> {
    run_with_diagnostic_counts(diagnostic, kind, classify, to_counts, |counts| {
        *counts = execute()?;
        Ok(())
    })
}

/// Like `run_with_diagnostic`, retaining observed counts on failure as well.
pub fn run_with_diagnostic_counts<T: Copy + Default>(
    diagnostic: Option<&Path>,
    kind: &'static str,
    classify: fn(&anyhow::Error) -> Category,
    to_counts: impl FnOnce(T, Category) -> Summary,
    execute: impl FnOnce(&mut T) -> Result<()>,
) -> Result<()> {
    let mut diagnostic = match Diagnostic::reserve(diagnostic) {
        Ok(diagnostic) => diagnostic,
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::exit(USAGE);
        }
    };
    let mut counts = T::default();
    let outcome = execute(&mut counts);
    let category = match &outcome {
        Ok(_) => Category::Success,
        Err(error) => classify(error),
    };
    let counts = to_counts(counts, category);
    // Safe by default for every command: detailed errors remain on stderr.
    let error = outcome.as_ref().err().map(|_| safe_error(category));
    if let Err(error) = diagnostic.write(kind, category, counts, error) {
        eprintln!("Error: {error:#}");
        std::process::exit(INTERNAL);
    }
    match outcome {
        Ok(_) => Ok(()),
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::exit(category.code());
        }
    }
}

/// Inspect typed causes before matching legacy human-facing error contexts.
pub fn classify_cause(error: &anyhow::Error) -> Option<Category> {
    if let Some(category) = error.downcast_ref::<Category>() {
        return Some(*category);
    }
    for cause in error.chain() {
        if let Some(category) = cause.downcast_ref::<Category>() {
            return Some(*category);
        }
        let io = cause
            .downcast_ref::<std::io::Error>()
            .or_else(|| match cause.downcast_ref::<air_capture::CaptureError>() {
                Some(air_capture::CaptureError::Io(io)) => Some(io),
                _ => None,
            });
        if let Some(io) = io {
            return Some(match io.kind() {
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData => {
                    Category::BadContainer
                }
                _ => Category::PrivilegeOrDevice,
            });
        }
        if matches!(
            cause.downcast_ref::<air_capture::CaptureError>(),
            Some(air_capture::CaptureError::Pcap(_) | air_capture::CaptureError::UnsupportedDlt(_))
        ) {
            return Some(Category::BadContainer);
        }
    }
    None
}

fn safe_error(category: Category) -> &'static str {
    match category {
        Category::Success => "success",
        Category::PasswordNotFound => "password not found in supplied dictionaries",
        Category::NoSupportedTarget => "no supported target or decodable data frames",
        Category::Partial => "verification paused before dictionary exhaustion",
        Category::BadContainer => {
            "cannot read capture: malformed or unsupported container; supported Wi-Fi input requires raw 802.11 or Radiotap"
        }
        Category::PrivilegeOrDevice => "cannot access input, output or device",
        Category::Usage => "invalid command arguments or configuration",
        Category::Internal => "internal operation failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_categories_override_io_and_sensitive_context() {
        for (kind, category) in [
            (std::io::ErrorKind::InvalidData, Category::Usage),
            (std::io::ErrorKind::NotFound, Category::Usage),
            (std::io::ErrorKind::PermissionDenied, Category::Internal),
        ] {
            let error = anyhow::Error::new(std::io::Error::new(kind, "secret-sentinel"))
                .context("PMK cache batch failed; checkpoint not advanced")
                .context(category)
                .context("outer context");
            assert_eq!(classify_cause(&error), Some(category));
            assert!(!safe_error(category).contains("secret-sentinel"));
        }
        assert_eq!(
            classify_cause(&anyhow::anyhow!("paused").context(Category::Partial)),
            Some(Category::Partial)
        );
    }

    #[test]
    fn codes_and_labels_are_stable_and_distinct() {
        let all = [
            Category::Success,
            Category::PasswordNotFound,
            Category::Partial,
            Category::NoSupportedTarget,
            Category::BadContainer,
            Category::PrivilegeOrDevice,
            Category::Usage,
            Category::Internal,
        ];
        // Явно фиксируем контракт, чтобы случайная правка ломала тест.
        assert_eq!(Category::Success.code(), 0);
        assert_eq!(Category::PasswordNotFound.code(), 2);
        assert_eq!(Category::NoSupportedTarget.code(), 3);
        assert_eq!(Category::BadContainer.code(), 4);
        assert_eq!(Category::PrivilegeOrDevice.code(), 5);
        assert_eq!(Category::Usage.code(), 64);
        assert_eq!(Category::Partial.code(), 6);
        assert_eq!(Category::Internal.code(), 70);
        // Коды и метки не пересекаются между категориями.
        let mut codes: Vec<_> = all.iter().map(|c| c.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        let mut labels: Vec<_> = all.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len());
    }
}
