use crate::config::SubdomainRule;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use sha2::{Sha256, Sha512};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Http1,
    Http2,
    WebSocket,
    Grpc,
    RawTcp,
}

pub struct ParsedHttpHead {
    pub host: Option<String>,
    pub protocol: ProtocolKind,
    pub authorization: Option<String>,
    pub hub_sig_256: Option<String>,
    pub signum_key_512: Option<String>,
    pub header_end: usize,
    pub content_length: usize,
}

pub struct TokenBucketLimiter {
    buckets: DashMap<IpAddr, (f64, Instant)>,
    rps: f64,
    burst: f64,
}

impl TokenBucketLimiter {
    pub fn new(rps: u32, burst: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            rps: rps.max(1) as f64,
            burst: burst.max(1) as f64,
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entry = self.buckets.entry(ip).or_insert((self.burst, now));
        let (tokens, last) = entry.value_mut();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.rps).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub fn detect_protocol_prefix(peek: &[u8]) -> ProtocolKind {
    if peek.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return ProtocolKind::Http2;
    }
    let methods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "];
    if methods.iter().any(|m| peek.starts_with(m.as_bytes())) {
        return ProtocolKind::Http1;
    }
    ProtocolKind::RawTcp
}

/// Strictly validates HTTP/1.1 headers to prevent CL.TE / TE.CL request smuggling and malformed headers.
pub fn parse_and_validate_http1(buf: &[u8]) -> Result<ParsedHttpHead, &'static str> {
    let header_end = find_crlfcrlf(buf).ok_or("incomplete headers")?;
    let head_bytes = &buf[..header_end];
    let head_str = std::str::from_utf8(head_bytes).map_err(|_| "non-utf8 headers")?;

    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().ok_or("missing request line")?;
    let mut parts = req_line.split(' ');
    let _method = parts.next().ok_or("missing method")?;
    let _target = parts.next().ok_or("missing target")?;
    let version = parts.next().ok_or("missing version")?;
    if parts.next().is_some() || (!version.starts_with("HTTP/1.1") && !version.starts_with("HTTP/1.0")) {
        return Err("invalid HTTP version");
    }

    let mut host: Option<String> = None;
    let mut content_length: Option<usize> = None;
    let mut has_transfer_encoding = false;
    let mut is_websocket = false;
    let mut is_grpc = false;
    let mut authorization: Option<String> = None;
    let mut hub_sig_256: Option<String> = None;
    let mut signum_key_512: Option<String> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') || line.contains('\n') || line.contains('\r') {
            return Err("obsolete line folding or bare CR/LF");
        }
        let (name, val) = line.split_once(':').ok_or("malformed header without colon")?;
        if name.is_empty() || name.bytes().any(|b| !is_tchar(b)) {
            return Err("invalid header name");
        }
        let val = val.trim();
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => {
                if host.is_some() {
                    return Err("duplicate Host header");
                }
                let h = val.split(':').next().unwrap_or(val).to_ascii_lowercase();
                host = Some(h);
            }
            "content-length" => {
                if content_length.is_some() {
                    return Err("duplicate Content-Length header");
                }
                let parsed = val.parse::<usize>().map_err(|_| "invalid Content-Length")?;
                content_length = Some(parsed);
            }
            "transfer-encoding" => {
                has_transfer_encoding = true;
            }
            "upgrade" => {
                if val.eq_ignore_ascii_case("websocket") {
                    is_websocket = true;
                }
            }
            "content-type" => {
                if val.to_ascii_lowercase().starts_with("application/grpc") {
                    is_grpc = true;
                }
            }
            "authorization" => authorization = Some(val.to_string()),
            "x-hub-signature-256" => hub_sig_256 = Some(val.to_string()),
            "x-signum-key-512" => signum_key_512 = Some(val.to_string()),
            _ => {}
        }
    }

    if has_transfer_encoding && content_length.is_some() {
        return Err("conflicting Transfer-Encoding and Content-Length");
    }

    let protocol = if is_websocket {
        ProtocolKind::WebSocket
    } else if is_grpc {
        ProtocolKind::Grpc
    } else {
        ProtocolKind::Http1
    };

    Ok(ParsedHttpHead {
        host,
        protocol,
        authorization,
        hub_sig_256,
        signum_key_512,
        header_end: header_end + 4,
        content_length: content_length.unwrap_or(0),
    })
}

pub fn check_ip_allowlist(peer_ip: IpAddr, rule: &SubdomainRule) -> bool {
    if rule.cidr_allowlist.is_empty() {
        return true;
    }
    rule.cidr_allowlist.iter().any(|cidr| {
        IpNet::from_str(cidr)
            .map(|net| net.contains(&peer_ip))
            .unwrap_or(false)
    })
}

pub fn verify_jwt_hs256(auth_header: Option<&str>, secret: &str) -> bool {
    let Some(header) = auth_header else { return false };
    let Some(token) = header.strip_prefix("Bearer ").or_else(|| header.strip_prefix("bearer ")) else {
        return false;
    };
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(sig), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(h.as_bytes());
    mac.update(b".");
    mac.update(p.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

pub fn verify_webhook_hmac(sig_header: Option<&str>, body: &[u8], secret: &str) -> bool {
    let Some(header) = sig_header else { return false };
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Layer 21: Constant-time verification of a 512-bit (64-byte / 128-hex) Signum access key.
pub fn verify_signum_key_512(provided: Option<&str>, allowed_keys: &[String]) -> bool {
    let Some(raw) = provided else { return false };
    let Ok(provided_bytes) = hex::decode(raw.trim()) else {
        return false;
    };
    if provided_bytes.len() != 64 {
        return false;
    }
    allowed_keys.iter().any(|k| {
        if let Ok(kb) = hex::decode(k.trim()) {
            kb.len() == 64
                && kb
                    .iter()
                    .zip(provided_bytes.iter())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        } else {
            false
        }
    })
}

/// Signs an authenticated/verified request with an HMAC-SHA512 512-bit (128-hex) tag.
pub fn sign_request_hmac_sha512(secret: &str, host: &str, head_bytes: &[u8]) -> String {
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(host.as_bytes());
    mac.update(b"|");
    mac.update(head_bytes);
    hex::encode(mac.finalize().into_bytes())
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_smuggling_headers() {
        let req = b"POST / HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
        assert!(parse_and_validate_http1(req).is_err());

        let dup = b"POST / HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n";
        assert!(parse_and_validate_http1(dup).is_err());
    }

    #[test]
    fn verifies_and_signs_512_bit_keys() {
        let valid_key = "ab".repeat(64);
        assert!(verify_signum_key_512(Some(&valid_key), &[valid_key.clone()]));
        assert!(!verify_signum_key_512(Some(&"cd".repeat(64)), &[valid_key.clone()]));
        assert!(!verify_signum_key_512(Some("short"), &[valid_key]));

        let sig = sign_request_hmac_sha512("master-secret", "app.signum.local", b"GET / HTTP/1.1\r\nHost: app.signum.local");
        assert_eq!(sig.len(), 128);
    }
}
