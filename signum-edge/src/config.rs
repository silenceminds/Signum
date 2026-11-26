use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    #[serde(default = "default_public_http")]
    pub public_http_addr: String,
    #[serde(default = "default_public_https")]
    pub public_https_addr: String,
    #[serde(default = "default_control_addr")]
    pub control_addr: String,

    pub public_cert_path: PathBuf,
    pub public_key_path: PathBuf,
    pub control_cert_path: PathBuf,
    pub control_key_path: PathBuf,
    pub control_ca_path: PathBuf,

    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default = "default_rps")]
    pub rate_limit_rps: u32,
    #[serde(default = "default_burst")]
    pub rate_limit_burst: u32,
    #[serde(default = "default_header_timeout")]
    pub header_timeout_secs: u64,
    #[serde(default = "default_channel_cap")]
    pub channel_capacity: usize,
    #[serde(default)]
    pub default_deny_unauthenticated: bool,
    #[serde(default)]
    pub require_key_512: bool,
    #[serde(default)]
    pub signum_keys_512: Vec<String>,
    pub key_512_master_secret: Option<String>,

    #[serde(default)]
    pub subdomains: HashMap<String, SubdomainRule>,
    #[serde(default)]
    pub raw_tcp: Vec<RawTcpRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubdomainRule {
    #[serde(default)]
    pub cidr_allowlist: Vec<String>,
    #[serde(default)]
    pub asn_blocklist: Vec<u32>,
    pub jwt_hs256_secret: Option<String>,
    pub webhook_hmac_secret: Option<String>,
    pub fallback_status: Option<u16>,
    pub fallback_body: Option<String>,
    pub allowed_cn: Option<String>,
    #[serde(default)]
    pub require_key_512: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawTcpRule {
    pub listen_addr: String,
    pub subdomain: String,
    pub target_port: u16,
}

fn default_public_http() -> String {
    "0.0.0.0:80".to_string()
}
fn default_public_https() -> String {
    "0.0.0.0:443".to_string()
}
fn default_control_addr() -> String {
    "0.0.0.0:4443".to_string()
}
fn default_domain() -> String {
    "signum.local".to_string()
}
fn default_rps() -> u32 {
    100
}
fn default_burst() -> u32 {
    200
}
fn default_header_timeout() -> u64 {
    5
}
fn default_channel_cap() -> usize {
    64
}

impl EdgeConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&content)?;
        Ok(cfg)
    }
}
