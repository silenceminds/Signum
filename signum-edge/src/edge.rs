use crate::config::{EdgeConfig, RawTcpRule, SubdomainRule};
use crate::http_filter::{
    check_ip_allowlist, detect_protocol_prefix, parse_and_validate_http1, sign_request_hmac_sha512,
    verify_jwt_hs256, verify_signum_key_512, verify_webhook_hmac, ProtocolKind, TokenBucketLimiter,
};
use crate::scanner::SlidingSecretScanner;
use crate::smpv2::{
    read_frame, write_frame, Opcode, SmpCipher, KEY_ROTATE_INTERVAL_SECS,
};
use crate::tls::{build_control_tls_config, build_public_tls_config, extract_client_identities};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha3::Sha3_256;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

type HmacSha3_256 = Hmac<Sha3_256>;

pub enum AgentCmd {
    OpenStream { stream_id: u32, target_port: u16 },
    Data { stream_id: u32, bytes: Vec<u8> },
    CloseStream { stream_id: u32 },
    WindowUpdate { stream_id: u32, increment: u32 },
    KillSwitch,
}

pub enum StreamEvent {
    Data(Vec<u8>),
    Closed,
}

pub struct AgentSession {
    pub id: u64,
    pub subdomain: String,
    pub weight: u16,
    pub tx: mpsc::Sender<AgentCmd>,
    pub streams: DashMap<u32, mpsc::Sender<StreamEvent>>,
    pub next_stream_id: AtomicU32,
    pub alive: AtomicBool,
}

impl AgentSession {
    pub fn alloc_stream_id(&self) -> u32 {
        loop {
            let id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

pub struct TelemetrySink {
    tx: mpsc::Sender<String>,
    pub dropped_events: AtomicU64,
    pub stream_errors: AtomicU64,
}

impl TelemetrySink {
    pub fn new(cap: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<String>(cap);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                warn!(target: "signum_telemetry", "{msg}");
            }
        });
        Self {
            tx,
            dropped_events: AtomicU64::new(0),
            stream_errors: AtomicU64::new(0),
        }
    }

    /// Non-blocking failure recording: never awaits or stalls the tunnel data path.
    pub fn record_nonblocking(&self, msg: String) {
        self.stream_errors.fetch_add(1, Ordering::Relaxed);
        if self.tx.try_send(msg).is_err() {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct EdgeState {
    pub config: EdgeConfig,
    pub agents: DashMap<String, Vec<Arc<AgentSession>>>,
    pub limiter: TokenBucketLimiter,
    pub next_session_id: AtomicU64,
    pub telemetry: TelemetrySink,
}

impl EdgeState {
    pub fn new(config: EdgeConfig) -> Self {
        let limiter = TokenBucketLimiter::new(config.rate_limit_rps, config.rate_limit_burst);
        Self {
            config,
            agents: DashMap::new(),
            limiter,
            next_session_id: AtomicU64::new(1),
            telemetry: TelemetrySink::new(1024),
        }
    }

    pub fn select_agent(&self, host: &str) -> Option<Arc<AgentSession>> {
        let list = self.agents.get(host)?;
        let active: Vec<&Arc<AgentSession>> = list
            .iter()
            .filter(|a| a.alive.load(Ordering::Relaxed))
            .collect();
        if active.is_empty() {
            return None;
        }
        let total_weight: u32 = active.iter().map(|a| a.weight.max(1) as u32).sum();
        let mut pick = (rand::thread_rng().next_u32()) % total_weight;
        for a in active {
            let w = a.weight.max(1) as u32;
            if pick < w {
                return Some((*a).clone());
            }
            pick -= w;
        }
        None
    }

    fn register_agent(&self, session: Arc<AgentSession>) {
        let mut entry = self.agents.entry(session.subdomain.clone()).or_default();
        entry.retain(|s| s.alive.load(Ordering::Relaxed));
        entry.push(session);
    }

    fn unregister_agent(&self, subdomain: &str, session_id: u64) {
        if let Some(mut entry) = self.agents.get_mut(subdomain) {
            entry.retain(|s| s.id != session_id && s.alive.load(Ordering::Relaxed));
        }
    }
}

pub async fn run_edge(config: EdgeConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let public_tls = build_public_tls_config(&config.public_cert_path, &config.public_key_path)?;
    let control_tls = build_control_tls_config(
        &config.control_cert_path,
        &config.control_key_path,
        &config.control_ca_path,
    )?;

    let state = Arc::new(EdgeState::new(config.clone()));

    let control_listener = TcpListener::bind(&config.control_addr).await?;
    info!("signum-edge control listener (mTLS) bound on {}", config.control_addr);

    let https_listener = TcpListener::bind(&config.public_https_addr).await?;
    info!("signum-edge public HTTPS listener bound on {}", config.public_https_addr);

    let http_listener = TcpListener::bind(&config.public_http_addr).await?;
    info!("signum-edge public HTTP listener bound on {}", config.public_http_addr);

    for raw in config.raw_tcp.clone() {
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_raw_tcp_listener(st, raw).await {
                error!("raw TCP listener error: {e}");
            }
        });
    }

    let control_acceptor = TlsAcceptor::from(control_tls);
    let public_acceptor = TlsAcceptor::from(public_tls);

    let st_ctrl = state.clone();
    let ctrl_task = tokio::spawn(async move {
        loop {
            match control_listener.accept().await {
                Ok((sock, peer)) => {
                    let acc = control_acceptor.clone();
                    let st = st_ctrl.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_agent_conn(st.clone(), acc, sock, peer).await {
                            st.telemetry.record_nonblocking(format!("agent {peer} disconnected: {e}"));
                        }
                    });
                }
                Err(e) => st_ctrl.telemetry.record_nonblocking(format!("control accept error: {e}")),
            }
        }
    });

    let st_https = state.clone();
    let https_task = tokio::spawn(async move {
        loop {
            match https_listener.accept().await {
                Ok((sock, peer)) => {
                    if !st_https.limiter.allow(peer.ip()) {
                        drop(sock);
                        continue;
                    }
                    let acc = public_acceptor.clone();
                    let st = st_https.clone();
                    tokio::spawn(async move {
                        let sni_host;
                        let tls_stream = match acc.accept(sock).await {
                            Ok(s) => {
                                sni_host = s.get_ref().1.server_name().map(|n| n.to_ascii_lowercase());
                                s
                            }
                            Err(_) => return,
                        };
                        if let Err(e) = handle_public_stream(st, tls_stream, peer, sni_host).await {
                            warn!("https {peer} closed: {e}");
                        }
                    });
                }
                Err(e) => error!("https accept error: {e}"),
            }
        }
    });

    let st_http = state.clone();
    let http_task = tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((sock, peer)) => {
                    if !st_http.limiter.allow(peer.ip()) {
                        drop(sock);
                        continue;
                    }
                    let st = st_http.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_public_stream(st, sock, peer, None).await {
                            warn!("http {peer} closed: {e}");
                        }
                    });
                }
                Err(e) => error!("http accept error: {e}"),
            }
        }
    });

    tokio::try_join!(ctrl_task, https_task, http_task)?;
    Ok(())
}

async fn handle_agent_conn(
    state: Arc<EdgeState>,
    acceptor: TlsAcceptor,
    sock: TcpStream,
    peer: SocketAddr,
) -> io::Result<()> {
    let _ = sock.set_nodelay(true);
    let mut tls_stream = acceptor.accept(sock).await?;

    let (client_ids, init_key) = {
        let (_, conn) = tls_stream.get_ref();
        let certs = conn
            .peer_certificates()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "missing client cert"))?;
        let mut ids = Vec::new();
        for c in certs {
            ids.extend(extract_client_identities(c.as_ref()));
        }
        let mut key = [0u8; 32];
        conn.export_keying_material(&mut key, b"EXPORTER-signum-smpv2", None)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("exporter failed: {e}")))?;
        (ids, key)
    };

    let mut rx_cipher = SmpCipher::new(init_key, 0x02);
    let mut tx_cipher = SmpCipher::new(init_key, 0x01);

    // 1. Send CHALLENGE (32 random bytes)
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    write_frame(&mut tls_stream, &mut tx_cipher, Opcode::Challenge, 0, &challenge).await?;

    // 2. Receive AUTH_PROOF: [32B HMAC-SHA3-256] [2B weight BE] [subdomain UTF-8]
    let auth_frame = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame(&mut tls_stream, &mut rx_cipher),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "auth timeout"))??;

    if auth_frame.opcode != Opcode::AuthProof || auth_frame.payload.len() < 35 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "invalid AUTH_PROOF"));
    }

    let proof_mac = &auth_frame.payload[0..32];
    let weight = u16::from_be_bytes([auth_frame.payload[32], auth_frame.payload[33]]);
    let subdomain = std::str::from_utf8(&auth_frame.payload[34..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid subdomain utf8"))?
        .to_ascii_lowercase();

    let mut mac = HmacSha3_256::new_from_slice(&init_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "hmac init"))?;
    mac.update(&challenge);
    mac.update(subdomain.as_bytes());
    mac.verify_slice(proof_mac)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "AUTH_PROOF HMAC mismatch"))?;

    // Layer 10: Verify subdomain is bound to client certificate CN/SAN
    let explicit_cn = state
        .config
        .subdomains
        .get(&subdomain)
        .and_then(|r| r.allowed_cn.as_ref())
        .map(|s| s.to_ascii_lowercase());

    let cert_authorized = client_ids.iter().any(|id| {
        if id == &subdomain {
            return true;
        }
        if let Some(rest) = id.strip_prefix("*.") {
            return subdomain.ends_with(rest) && subdomain.len() > rest.len();
        }
        false
    }) || explicit_cn.map(|cn| client_ids.contains(&cn)).unwrap_or(false);

    if !cert_authorized {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("subdomain '{subdomain}' not bound to client cert CN/SAN {client_ids:?}"),
        ));
    }

    // 3. Send SESSION_GRANT
    write_frame(&mut tls_stream, &mut tx_cipher, Opcode::SessionGrant, 0, subdomain.as_bytes()).await?;
    info!("agent {peer} authenticated for subdomain '{subdomain}' (weight={weight})");

    let (tx, mut rx) = mpsc::channel::<AgentCmd>(state.config.channel_capacity);
    let session = Arc::new(AgentSession {
        id: state.next_session_id.fetch_add(1, Ordering::Relaxed),
        subdomain: subdomain.clone(),
        weight,
        tx,
        streams: DashMap::new(),
        next_stream_id: AtomicU32::new(1),
        alive: AtomicBool::new(true),
    });
    state.register_agent(session.clone());

    let (mut reader, mut writer) = tokio::io::split(tls_stream);
    let last_activity = Arc::new(AtomicU64::new(0));
    let start_instant = Instant::now();
    let pong_notify = Arc::new(Notify::new());

    let sess_read = session.clone();
    let act_read = last_activity.clone();
    let pong_tx = pong_notify.clone();

    let mut read_task = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut reader, &mut rx_cipher).await?;
            act_read.store(start_instant.elapsed().as_secs(), Ordering::Relaxed);
            match frame.opcode {
                Opcode::Data => {
                    if let Some(stream_tx) = sess_read.streams.get(&frame.stream_id) {
                        let _ = stream_tx.send(StreamEvent::Data(frame.payload)).await;
                    }
                }
                Opcode::CloseStream => {
                    if let Some((_, stream_tx)) = sess_read.streams.remove(&frame.stream_id) {
                        let _ = stream_tx.send(StreamEvent::Closed).await;
                    }
                }
                Opcode::KeyRotate => {
                    rx_cipher.ratchet(frame.sequence);
                    info!("agent {} inbound key ratcheted at seq {}", sess_read.id, frame.sequence);
                }
                Opcode::PingPong => {
                    if frame.payload.first() == Some(&0x00) {
                        pong_tx.notify_one();
                    }
                }
                Opcode::KillSwitch => {
                    warn!("agent {} sent KILL_SWITCH", sess_read.id);
                    sess_read.alive.store(false, Ordering::Relaxed);
                    break;
                }
                _ => {}
            }
        }
        Ok::<(), io::Error>(())
    });

    let sess_write = session.clone();
    let act_write = last_activity.clone();
    let mut write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(10));
        let mut last_rotate = Instant::now();
        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    let elapsed = start_instant.elapsed().as_secs();
                    let last = act_write.load(Ordering::Relaxed);
                    if elapsed.saturating_sub(last) > 25 {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "heartbeat dead-man switch triggered"));
                    }
                    write_frame(&mut writer, &mut tx_cipher, Opcode::PingPong, 0, &[0x00]).await?;

                    if last_rotate.elapsed().as_secs() >= KEY_ROTATE_INTERVAL_SECS || tx_cipher.should_rotate() {
                        let seq = tx_cipher.next_sequence();
                        write_frame(&mut writer, &mut tx_cipher, Opcode::KeyRotate, 0, &[]).await?;
                        tx_cipher.ratchet(seq);
                        last_rotate = Instant::now();
                    }
                }
                _ = pong_notify.notified() => {
                    write_frame(&mut writer, &mut tx_cipher, Opcode::PingPong, 0, &[0x01]).await?;
                }
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    match cmd {
                        AgentCmd::OpenStream { stream_id, target_port } => {
                            let port_bytes = target_port.to_be_bytes();
                            write_frame(&mut writer, &mut tx_cipher, Opcode::OpenStream, stream_id, &port_bytes).await?;
                        }
                        AgentCmd::Data { stream_id, bytes } => {
                            for chunk in bytes.chunks(32768) {
                                write_frame(&mut writer, &mut tx_cipher, Opcode::Data, stream_id, chunk).await?;
                            }
                        }
                        AgentCmd::CloseStream { stream_id } => {
                            write_frame(&mut writer, &mut tx_cipher, Opcode::CloseStream, stream_id, &[]).await?;
                        }
                        AgentCmd::WindowUpdate { stream_id, increment } => {
                            write_frame(&mut writer, &mut tx_cipher, Opcode::WindowUpdate, stream_id, &increment.to_be_bytes()).await?;
                        }
                        AgentCmd::KillSwitch => {
                            let _ = write_frame(&mut writer, &mut tx_cipher, Opcode::KillSwitch, 0, &[]).await;
                            sess_write.alive.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        }
        Ok::<(), io::Error>(())
    });

    tokio::select! {
        _ = &mut read_task => { write_task.abort(); }
        _ = &mut write_task => { read_task.abort(); }
    }

    session.alive.store(false, Ordering::Relaxed);
    for entry in session.streams.iter() {
        let _ = entry.value().try_send(StreamEvent::Closed);
    }
    session.streams.clear();
    state.unregister_agent(&subdomain, session.id);
    Ok(())
}

async fn handle_public_stream<S>(
    state: Arc<EdgeState>,
    mut client: S,
    peer: SocketAddr,
    sni_host: Option<String>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut init_buf = vec![0u8; 16384];
    let n = tokio::time::timeout(
        Duration::from_secs(state.config.header_timeout_secs),
        client.read(&mut init_buf),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "header timeout"))??;

    if n == 0 {
        return Ok(());
    }
    init_buf.truncate(n);

    let proto = detect_protocol_prefix(&init_buf);
    let mut target_host = sni_host;
    let mut header_end_for_sig: Option<usize> = None;

    if proto == ProtocolKind::Http1 {
        let parsed = match parse_and_validate_http1(&init_buf) {
            Ok(p) => p,
            Err(reason) => {
                let resp = format!("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{reason}", reason.len());
                let _ = client.write_all(resp.as_bytes()).await;
                return Ok(());
            }
        };

        if let Some(ref h) = parsed.host {
            target_host = Some(h.clone());
        }

        let host_key = target_host.clone().unwrap_or_default();
        let mut need_512 = state.config.require_key_512;
        if let Some(rule) = state.config.subdomains.get(&host_key) {
            if !enforce_http_rule(peer.ip(), rule, &parsed, &mut client, &mut init_buf).await? {
                return Ok(());
            }
            if rule.require_key_512 {
                need_512 = true;
            }
        } else if state.config.default_deny_unauthenticated {
            let _ = client
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 23\r\nConnection: close\r\n\r\nUnauthenticated Blocked")
                .await;
            return Ok(());
        }

        if need_512 && !verify_signum_key_512(parsed.signum_key_512.as_deref(), &state.config.signum_keys_512) {
            let _ = client
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 23\r\nConnection: close\r\n\r\nInvalid 512-Bit Key\r\n")
                .await;
            return Ok(());
        }

        if parsed.header_end >= 4 && init_buf.len() >= parsed.header_end {
            header_end_for_sig = Some(parsed.header_end);
        }
    } else if state.config.default_deny_unauthenticated || state.config.require_key_512 {
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 23\r\nConnection: close\r\n\r\nUnauthenticated Blocked")
            .await;
        return Ok(());
    }

    let host_key = target_host.unwrap_or_default();
    let Some(agent) = state.select_agent(&host_key) else {
        if let Some(rule) = state.config.subdomains.get(&host_key) {
            if let Some(status) = rule.fallback_status {
                let body = rule.fallback_body.as_deref().unwrap_or("Service Offline");
                let resp = format!(
                    "HTTP/1.1 {status} Fallback\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = client.write_all(resp.as_bytes()).await;
                return Ok(());
            }
        }
        let resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\nTunnel Offline\n";
        let _ = client.write_all(resp).await;
        return Ok(());
    };

    // Assign 512-bit HMAC-SHA512 signature only AFTER all edge security layers and agent selection pass
    if let (Some(ref master), Some(hdr_end)) = (&state.config.key_512_master_secret, header_end_for_sig) {
        let tag = sign_request_hmac_sha512(master, &host_key, &init_buf[..hdr_end - 4]);
        let hdr_inject = format!("X-Signum-Auth-512: {tag}\r\n\r\n");
        let mut updated = Vec::with_capacity(init_buf.len() + hdr_inject.len());
        updated.extend_from_slice(&init_buf[..hdr_end - 4]);
        updated.extend_from_slice(b"\r\n");
        updated.extend_from_slice(hdr_inject.as_bytes());
        updated.extend_from_slice(&init_buf[hdr_end..]);
        init_buf = updated;
    }

    bridge_stream_to_agent(client, agent, 0, init_buf, state.config.channel_capacity).await
}

async fn enforce_http_rule<S: AsyncWrite + AsyncRead + Unpin>(
    peer_ip: IpAddr,
    rule: &SubdomainRule,
    parsed: &crate::http_filter::ParsedHttpHead,
    client: &mut S,
    init_buf: &mut Vec<u8>,
) -> io::Result<bool> {
    if !check_ip_allowlist(peer_ip, rule) {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nConnection: close\r\n\r\nForbidden\n").await;
        return Ok(false);
    }

    if let Some(ref jwt_secret) = rule.jwt_hs256_secret {
        if !verify_jwt_hs256(parsed.authorization.as_deref(), jwt_secret) {
            let _ = client.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\nConnection: close\r\n\r\nUnauthorized\n").await;
            return Ok(false);
        }
    }

    if let Some(ref hmac_secret) = rule.webhook_hmac_secret {
        let total_needed = parsed.header_end + parsed.content_length;
        while init_buf.len() < total_needed && init_buf.len() < 1024 * 1024 {
            let mut tmp = [0u8; 4096];
            let r = client.read(&mut tmp).await?;
            if r == 0 {
                break;
            }
            init_buf.extend_from_slice(&tmp[..r]);
        }
        let body = if init_buf.len() >= parsed.header_end {
            &init_buf[parsed.header_end..init_buf.len().min(total_needed)]
        } else {
            &[]
        };
        if !verify_webhook_hmac(parsed.hub_sig_256.as_deref(), body, hmac_secret) {
            let _ = client.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 18\r\nConnection: close\r\n\r\nInvalid Signature\n").await;
            return Ok(false);
        }
    }

    Ok(true)
}

async fn run_raw_tcp_listener(state: Arc<EdgeState>, rule: RawTcpRule) -> io::Result<()> {
    let listener = TcpListener::bind(&rule.listen_addr).await?;
    info!("raw TCP listener {} -> {}:{}", rule.listen_addr, rule.subdomain, rule.target_port);
    loop {
        let (sock, _peer) = listener.accept().await?;
        let st = state.clone();
        let sub = rule.subdomain.clone();
        let port = rule.target_port;
        tokio::spawn(async move {
            let Some(agent) = st.select_agent(&sub) else {
                return;
            };
            let _ = bridge_stream_to_agent(sock, agent, port, Vec::new(), st.config.channel_capacity).await;
        });
    }
}

async fn bridge_stream_to_agent<S>(
    client: S,
    agent: Arc<AgentSession>,
    target_port: u16,
    initial_bytes: Vec<u8>,
    chan_cap: usize,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream_id = agent.alloc_stream_id();
    let (stream_tx, mut stream_rx) = mpsc::channel::<StreamEvent>(chan_cap);
    agent.streams.insert(stream_id, stream_tx);

    if agent
        .tx
        .send(AgentCmd::OpenStream { stream_id, target_port })
        .await
        .is_err()
    {
        agent.streams.remove(&stream_id);
        return Ok(());
    }

    if !initial_bytes.is_empty()
        && agent
            .tx
            .send(AgentCmd::Data {
                stream_id,
                bytes: initial_bytes,
            })
            .await
            .is_err()
    {
        agent.streams.remove(&stream_id);
        return Ok(());
    }

    let (mut c_read, mut c_write) = tokio::io::split(client);
    let ag_in = agent.clone();
    let in_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = c_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if ag_in
                .tx
                .send(AgentCmd::Data {
                    stream_id,
                    bytes: buf[..n].to_vec(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = ag_in.tx.send(AgentCmd::CloseStream { stream_id }).await;
        Ok::<(), io::Error>(())
    });

    let ag_out = agent.clone();
    let out_task = tokio::spawn(async move {
        let mut scanner = SlidingSecretScanner::new();
        while let Some(ev) = stream_rx.recv().await {
            match ev {
                StreamEvent::Data(bytes) => {
                    if let Some(marker) = scanner.scan_chunk(&bytes) {
                        warn!("outbound secret leak blocked on stream {stream_id}: {marker}");
                        let _ = ag_out.tx.send(AgentCmd::CloseStream { stream_id }).await;
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "outbound secret detected",
                        ));
                    }
                    c_write.write_all(&bytes).await?;
                    let _ = ag_out
                        .tx
                        .try_send(AgentCmd::WindowUpdate {
                            stream_id,
                            increment: bytes.len() as u32,
                        });
                }
                StreamEvent::Closed => break,
            }
        }
        let _ = c_write.shutdown().await;
        Ok::<(), io::Error>(())
    });

    let _ = tokio::join!(in_task, out_task);

    agent.streams.remove(&stream_id);
    Ok(())
}
