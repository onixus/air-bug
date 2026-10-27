use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

// A dictionary line is untrusted input. Batching candidates does not bound
// memory if reading a single line can allocate an arbitrary amount of memory.
const MAX_LINE_BYTES: usize = 64 * 1024;

pub struct Wordlist {
    reader: Box<dyn BufRead + Send>,
    finished: bool,
}

impl Wordlist {
    pub fn from_reader(reader: impl BufRead + Send + 'static) -> Self {
        Self {
            reader: Box::new(reader),
            finished: false,
        }
    }
    /// Read UTF-8 candidates, rejecting lines over 64 KiB (excluding LF).
    /// An I/O, encoding, or length error terminates iteration after that error.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            reader: Box::new(BufReader::new(File::open(path)?)),
            finished: false,
        })
    }
}

fn read_line(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let end = available.iter().position(|&byte| byte == b'\n');
        let take = end.unwrap_or(available.len());
        if take > MAX_LINE_BYTES - line.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "wordlist line exceeds 64 KiB",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(end.is_some()));
        if end.is_some() {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            break;
        }
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

impl Iterator for Wordlist {
    type Item = io::Result<String>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match read_line(&mut self.reader) {
            Ok(Some(line)) => Some(Ok(line)),
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn preserves_line_semantics_across_small_buffers() {
        let mut reader = BufReader::with_capacity(2, Cursor::new(b"first\r\n\nlast\r"));
        assert_eq!(read_line(&mut reader).unwrap().as_deref(), Some("first"));
        assert_eq!(read_line(&mut reader).unwrap().as_deref(), Some(""));
        assert_eq!(read_line(&mut reader).unwrap().as_deref(), Some("last\r"));
        assert!(read_line(&mut reader).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_lines_without_reading_the_entire_line() {
        let input = vec![b'a'; MAX_LINE_BYTES * 2];
        let mut reader = BufReader::with_capacity(1024, Cursor::new(input));
        assert_eq!(
            read_line(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(reader.get_ref().position() <= (MAX_LINE_BYTES + 1024) as u64);
    }

    #[test]
    fn accepts_exact_limit_with_or_without_newline() {
        for newline in [false, true] {
            let mut input = vec![b'a'; MAX_LINE_BYTES];
            if newline {
                input.push(b'\n');
            }
            let mut reader = BufReader::with_capacity(17, Cursor::new(input));
            assert_eq!(
                read_line(&mut reader).unwrap().unwrap().len(),
                MAX_LINE_BYTES
            );
            assert!(read_line(&mut reader).unwrap().is_none());
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        let mut reader = Cursor::new(b"valid\n\xff\n");
        assert_eq!(read_line(&mut reader).unwrap().as_deref(), Some("valid"));
        assert_eq!(
            read_line(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
