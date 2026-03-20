// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence helpers for the replay cache.
//!
//! The cache file format is one entry per line:
//!
//! ```text
//! <hex-encoded-32-char nonce> <unix-epoch-seconds>
//! ```
//!
//! Lines starting with `#` are treated as comments and ignored.

use std::{collections::HashMap, fs, io::Write, path::Path};

use crate::{cache::Nonce, error::ReplayError};

/// Read a cache file from disk and return its `(nonce, timestamp)` entries.
pub(crate) fn read_cache_file(path: &Path) -> Result<HashMap<Nonce, u64>, ReplayError> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => {
            return Err(ReplayError::Read {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };
    let mut out = HashMap::new();
    for (line_num, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let nonce_hex = parts.next().ok_or_else(|| ReplayError::InvalidFormat {
            path: path.to_path_buf(),
            reason: format!("line {}: missing nonce field", line_num + 1),
        })?;
        let ts_str = parts.next().ok_or_else(|| ReplayError::InvalidFormat {
            path: path.to_path_buf(),
            reason: format!("line {}: missing timestamp field", line_num + 1),
        })?;
        let nonce = parse_nonce_hex(nonce_hex).ok_or_else(|| ReplayError::InvalidFormat {
            path: path.to_path_buf(),
            reason: format!("line {}: nonce is not 32 hex chars", line_num + 1),
        })?;
        let ts: u64 = ts_str.parse().map_err(|_| ReplayError::InvalidFormat {
            path: path.to_path_buf(),
            reason: format!("line {}: timestamp is not a u64", line_num + 1),
        })?;
        out.insert(nonce, ts);
    }
    Ok(out)
}

/// Atomically write `entries` to `path` by writing to a temp file in the
/// same directory and renaming over the target.
pub(crate) fn write_cache_file(
    path: &Path,
    entries: &HashMap<Nonce, u64>,
) -> Result<(), ReplayError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| ReplayError::Write {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| ReplayError::Write {
        path: path.to_path_buf(),
        source: e,
    })?;
    {
        let file = tmp.as_file_mut();
        writeln!(file, "# fwknox replay cache").map_err(|e| ReplayError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;
        for (nonce, ts) in entries {
            writeln!(file, "{} {}", encode_nonce_hex(nonce), ts).map_err(|e| {
                ReplayError::Write {
                    path: path.to_path_buf(),
                    source: e,
                }
            })?;
        }
    }
    tmp.persist(path).map_err(|e| ReplayError::Write {
        path: path.to_path_buf(),
        source: e.error,
    })?;
    Ok(())
}

fn encode_nonce_hex(nonce: &Nonce) -> String {
    let mut s = String::with_capacity(32);
    for b in nonce {
        s.push(nibble_to_hex(b >> 4));
        s.push(nibble_to_hex(b & 0xF));
    }
    s
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

fn parse_nonce_hex(s: &str) -> Option<Nonce> {
    if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_to_nibble(bytes[i * 2])?;
        let lo = hex_to_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_hex_roundtrip() {
        let n = [0xAB; 16];
        let s = encode_nonce_hex(&n);
        assert_eq!(s.len(), 32);
        assert_eq!(parse_nonce_hex(&s), Some(n));
    }

    #[test]
    fn parse_rejects_short_hex() {
        assert!(parse_nonce_hex("abcd").is_none());
    }

    #[test]
    fn parse_rejects_non_hex() {
        let bad: String = "zz".repeat(16);
        assert!(parse_nonce_hex(&bad).is_none());
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.cache");
        let mut entries = HashMap::new();
        entries.insert([0xAA; 16], 1_700_000_000u64);
        entries.insert([0xBB; 16], 1_700_000_010u64);
        write_cache_file(&path, &entries).unwrap();
        let loaded = read_cache_file(&path).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn read_missing_file_returns_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.cache");
        let loaded = read_cache_file(&path).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn read_rejects_malformed_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.cache");
        fs::write(&path, "not enough fields\n").unwrap();
        let err = read_cache_file(&path).unwrap_err();
        assert!(matches!(err, ReplayError::InvalidFormat { .. }));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.cache");
        let body = "# header\n\n\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1234\n\
            # mid comment\n\
            bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 5678\n";
        fs::write(&path, body).unwrap();
        let loaded = read_cache_file(&path).unwrap();
        assert_eq!(loaded.len(), 2);
    }
}
