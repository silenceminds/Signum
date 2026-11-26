use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

pub fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    rustls_pemfile::certs(&mut reader).collect()
}

pub fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))
}

/// TLS 1.3-only public HTTPS server configuration.
pub fn build_public_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// TLS 1.3-only mTLS control listener (:4443) enforcing client X.509 certificate verification.
pub fn build_control_tls_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let ca_certs = load_certs(ca_path)?;

    let mut roots = RootCertStore::empty();
    for c in ca_certs {
        roots.add(c)?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    Ok(Arc::new(cfg))
}

/// Extracts CN and DNS SubjectAlternativeNames from a DER-encoded X.509 client certificate.
pub fn extract_client_identities(cert_der: &[u8]) -> Vec<String> {
    let mut ids = Vec::new();
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return ids;
    };

    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            ids.push(s.to_ascii_lowercase());
        }
    }

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                ids.push(dns.to_ascii_lowercase());
            }
        }
    }

    ids
}
