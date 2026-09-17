//! Streaming ingestion of a wordlist file.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

pub fn read_words<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let path = path.as_ref();
    let file = File::open(path)
        .with_context(|| format!("opening wordlist {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.split(b'\n') {
        let bytes = line.context("reading wordlist line")?;
        let s = String::from_utf8_lossy(&bytes);
        let trimmed = s.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_nonempty_trimmed_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "verano\r\n\nEmpresa\npassword\n").unwrap();
        let words = read_words(f.path()).unwrap();
        assert_eq!(words, vec!["verano", "Empresa", "password"]);
    }
}
