//! Private, exclusive PCAP output. Failed operations remove their output.
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct PrivatePcap {
    writer: Option<BufWriter<File>>,
    path: PathBuf,
    complete: bool,
    pub count: u64,
}
impl PrivatePcap {
    pub fn create(path: &Path, dlt: u32) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .context("cannot create output; existing paths are never overwritten")?;
        let mut out = Self {
            writer: Some(BufWriter::new(file)),
            path: path.into(),
            complete: false,
            count: 0,
        };
        let writer = out.writer.as_mut().unwrap();
        writer.write_all(&[0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0])?;
        for value in [0u32, 0, 65535, dlt] {
            writer.write_all(&value.to_le_bytes())?;
        }
        Ok(out)
    }
    pub fn write(&mut self, time: Duration, bytes: &[u8]) -> Result<()> {
        if time.as_secs() > u32::MAX as u64 || bytes.len() > 65535 {
            bail!("timestamp or packet length cannot be represented in output PCAP");
        }
        let writer = self.writer.as_mut().unwrap();
        for value in [
            time.as_secs() as u32,
            time.subsec_nanos(),
            bytes.len() as u32,
            bytes.len() as u32,
        ] {
            writer.write_all(&value.to_le_bytes())?;
        }
        writer.write_all(bytes)?;
        self.count += 1;
        Ok(())
    }
    pub fn finish(mut self) -> Result<u64> {
        let mut writer = self.writer.take().unwrap();
        writer.flush()?;
        writer.get_ref().sync_all()?;
        self.complete = true;
        Ok(self.count)
    }
}
impl Drop for PrivatePcap {
    fn drop(&mut self) {
        drop(self.writer.take());
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
