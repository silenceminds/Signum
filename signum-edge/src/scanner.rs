/// 64-byte sliding-window streaming outbound secret scanner.
/// Catches PEM private keys, .env credentials, and DB connection strings even when split across TCP chunks.
pub struct SlidingSecretScanner {
    tail: Vec<u8>,
}

const TAIL_WINDOW: usize = 64;

const SECRET_MARKERS: &[&[u8]] = &[
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    b"AWS_SECRET_ACCESS_KEY=",
    b"DATABASE_URL=",
    b"SIGNUM_SECRET=",
    b"PRIVATE_KEY=",
    b"postgres://",
    b"postgresql://",
    b"mysql://",
    b"mongodb+srv://",
    b"redis://",
];

impl SlidingSecretScanner {
    pub fn new() -> Self {
        Self {
            tail: Vec::with_capacity(TAIL_WINDOW),
        }
    }

    /// Returns `Some(matched_marker)` if a secret pattern is detected in `tail + chunk`.
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> Option<&'static str> {
        let mut window = Vec::with_capacity(self.tail.len() + chunk.len());
        window.extend_from_slice(&self.tail);
        window.extend_from_slice(chunk);

        for marker in SECRET_MARKERS {
            if let Some(pos) = find_subslice(&window, marker) {
                // For DB URLs, require userinfo ':' and '@' to avoid false positives on docs
                if marker.ends_with(b"://") {
                    let rest = &window[pos + marker.len()..];
                    if has_userinfo(rest) {
                        return Some(std::str::from_utf8(marker).unwrap_or("db_conn_str"));
                    }
                } else {
                    return Some(std::str::from_utf8(marker).unwrap_or("secret_marker"));
                }
            }
        }

        let keep = window.len().min(TAIL_WINDOW);
        self.tail.clear();
        self.tail
            .extend_from_slice(&window[window.len() - keep..]);
        None
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn has_userinfo(rest: &[u8]) -> bool {
    let mut saw_colon = false;
    for &b in rest.iter().take(64) {
        if b == b'\r' || b == b'\n' || b == b' ' || b == b'/' {
            return false;
        }
        if b == b':' {
            saw_colon = true;
        } else if b == b'@' && saw_colon {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_split_pem_across_chunks() {
        let mut scanner = SlidingSecretScanner::new();
        assert!(scanner.scan_chunk(b"HTTP/1.1 200 OK\r\n\r\n-----BEGIN RSA ").is_none());
        assert!(scanner.scan_chunk(b"PRIVATE KEY-----\nMIIE...").is_some());
    }

    #[test]
    fn catches_db_connection_string_with_credentials() {
        let mut scanner = SlidingSecretScanner::new();
        assert!(scanner.scan_chunk(b"url=postgres://admin:").is_none());
        assert!(scanner.scan_chunk(b"s3cr3t@db.internal:5432/prod").is_some());
    }
}
