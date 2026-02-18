use anyhow::{Context, Result, anyhow, bail};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::extract::{Form, Path as AxumPath, Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Request, Uri};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use bcrypt::{DEFAULT_COST, hash as hash_bcrypt, verify as verify_bcrypt};
use clap::{Parser, Subcommand};
use fxhash::FxHashMap as HashMap;
use hmac::Hmac;
use hmac::Mac as _;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, IoSlice, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    atomic::{AtomicU64, Ordering as AtomicOrdering},
    mpsc,
    Mutex,
};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

const ETH_MAX_FRAME: usize = 2000;
const MAX_IN_BUF_BYTES_PER_CLIENT: usize = 256 * 1024;
const MAX_OUT_BUF_BYTES_PER_CLIENT: usize = 256 * 1024;
const CTRL_REGISTER: u8 = 1;
const CTRL_DATA: u8 = 2;
const CTRL_ACK: u8 = 3;
const CTRL_ERROR: u8 = 255;
const ERR_UNKNOWN_SWITCH: u8 = 1;
const ERR_INVALID_TOKEN: u8 = 2;
const NONCE_DIR_CLIENT_TO_SERVER: u8 = 1;
const NONCE_DIR_SERVER_TO_CLIENT: u8 = 2;
const IFNAMSIZ: usize = libc::IFNAMSIZ;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const RPC_NONCE_TTL_MS: u64 = 5 * 60 * 1000;
const RPC_MAX_PAST_SKEW_MS: u64 = 2 * 60 * 1000;
const ADMIN_SESSION_TTL_MS: u64 = 8 * 60 * 60 * 1000;
const DROP_LOG_INTERVAL_MS: u64 = 5_000;

type Mac = [u8; 6];
type HmacSha256 = Hmac<Sha256>;

#[repr(C)]
struct IfReqFlags {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 24 - std::mem::size_of::<libc::c_short>()],
}

#[repr(C)]
struct IfReqHwaddr {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_hwaddr: libc::sockaddr,
    _pad: [u8; 24 - std::mem::size_of::<libc::sockaddr>()],
}

#[repr(C)]
struct IfReqAddr {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_addr: libc::sockaddr,
    _pad: [u8; 24 - std::mem::size_of::<libc::sockaddr>()],
}

struct TapDevice {
    file: File,
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    LocalTap,
    Client(RawFd),
}

#[derive(Deserialize)]
struct ServerConfig {
    listener: String,
    advertised_listener: String,
    rpc: Option<String>,
    principals: Option<Vec<PrincipalConfig>>,
    groups: Option<Vec<GroupConfig>>,
    acl: Option<Vec<JoinAclConfig>>,
    admin_groups: Option<Vec<String>>,
    rpc_hmac_secret: Option<String>,
    crypto_method: Option<String>,
    switches: Vec<ServerSwitchConfig>,
    bridges: Option<Vec<BridgeConfig>>,
}

#[derive(Deserialize)]
struct ServerSwitchConfig {
    name: String,
    tap: String,
    #[serde(default = "default_true")]
    disable_unknown_mac: bool,
    mac: Option<String>,
    ipv4: Option<String>,
    client_ip_pool: Option<String>,
    address_reservation: Option<Vec<AddressReservationConfig>>,
    server_routes: Option<Vec<RouteSpec>>,
    client_routes: Option<Vec<RouteSpec>>,
}

#[derive(Deserialize)]
struct AddressReservationConfig {
    mac: String,
    ipv4: String,
}

#[derive(Deserialize)]
struct BridgeConfig {
    name: String,
    members: Vec<String>,
}

#[derive(Deserialize)]
struct PrincipalConfig {
    name: String,
    credentials: PrincipalCredentialConfig,
    groups: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
struct PrincipalCredentialConfig {
    #[serde(default)]
    api_keys: Vec<String>,
    #[serde(default)]
    web_logins: Vec<String>,
}

#[derive(Deserialize)]
struct GroupConfig {
    name: String,
}

#[derive(Deserialize)]
struct JoinAclConfig {
    switch: String,
    principals: Option<Vec<String>>,
    groups: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ClientConfig {
    rpc: Option<String>,
    api_key: Option<String>,
    api_secret: Option<String>,
    #[serde(default = "default_true")]
    use_server_routes: bool,
    #[serde(default)]
    ignore_server_routes: Vec<String>,
    routes: Option<Vec<RouteSpec>>,
    ipv4: Option<String>,
    switch: Option<String>,
    tap: Option<String>,
    mac: Option<String>,
}

struct ServerSwitchState {
    name: String,
    tap: TapDevice,
    tap_has_ipv6: bool,
    disable_unknown_mac: bool,
    mac_table: HashMap<Mac, Endpoint>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct BridgeEndpoint {
    switch_id: u16,
    endpoint: Endpoint,
}

struct BridgeState {
    name: String,
    members: Vec<u16>,
    mac_table: HashMap<Mac, BridgeEndpoint>,
}

#[derive(Clone)]
struct ClientBinding {
    server_switch_id: u16,
    mac: Mac,
    assigned_ipv4: Option<String>,
    crypto: Option<BindingCrypto>,
}

#[derive(Clone, Copy)]
struct BindingCrypto {
    key: [u8; 32],
    tx_counter: u64,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteSpec {
    to: String,
    via: Option<String>,
}

struct ClientMuxState {
    stream: TcpStream,
    in_buf: RingBuffer,
    out_buf: RingBuffer,
    binding: Option<ClientBinding>,
    peer_addr: Option<String>,
    last_from_client_ms: Option<u64>,
    last_to_client_ms: Option<u64>,
}

struct RingBuffer {
    buf: Vec<u8>,
    start: usize,
    len: usize,
}

impl RingBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            start: 0,
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.len)
    }

    fn push_u8(&mut self, value: u8) -> Result<()> {
        self.push_slice(&[value])
    }

    fn push_slice(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > self.remaining() {
            bail!(
                "ring buffer overflow: src={} remaining={}",
                src.len(),
                self.remaining()
            );
        }
        let cap = self.buf.len();
        let write_pos = (self.start + self.len) % cap;
        let first = (cap - write_pos).min(src.len());
        self.buf[write_pos..write_pos + first].copy_from_slice(&src[..first]);
        let second = src.len() - first;
        if second > 0 {
            self.buf[..second].copy_from_slice(&src[first..]);
        }
        self.len += src.len();
        Ok(())
    }

    fn peek_u8(&self, offset: usize) -> Option<u8> {
        if offset >= self.len {
            return None;
        }
        let idx = (self.start + offset) % self.buf.len();
        Some(self.buf[idx])
    }

    fn copy_out(&self, offset: usize, out: &mut [u8]) -> Result<()> {
        if offset.saturating_add(out.len()) > self.len {
            bail!(
                "ring buffer copy out of bounds: offset={} len={} buffered={}",
                offset,
                out.len(),
                self.len
            );
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = self
                .peek_u8(offset + i)
                .ok_or_else(|| anyhow!("ring buffer read out of bounds"))?;
        }
        Ok(())
    }

    fn copy_vec(&self, offset: usize, len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.copy_out(offset, &mut out)?;
        Ok(out)
    }

    fn range_slices(&self, offset: usize, len: usize) -> Result<(&[u8], &[u8])> {
        if offset.saturating_add(len) > self.len {
            bail!(
                "ring buffer range out of bounds: offset={} len={} buffered={}",
                offset,
                len,
                self.len
            );
        }
        let cap = self.buf.len();
        let begin = (self.start + offset) % cap;
        let first_len = (cap - begin).min(len);
        let second_len = len - first_len;
        Ok((
            &self.buf[begin..begin + first_len],
            &self.buf[..second_len],
        ))
    }

    fn consume(&mut self, n: usize) -> Result<()> {
        if n > self.len {
            bail!("ring buffer consume out of bounds: consume={} buffered={}", n, self.len);
        }
        self.start = (self.start + n) % self.buf.len();
        self.len -= n;
        Ok(())
    }

    fn head_slices(&self) -> (&[u8], &[u8]) {
        if self.len == 0 {
            return (&[], &[]);
        }
        let cap = self.buf.len();
        let first_len = (cap - self.start).min(self.len);
        let second_len = self.len - first_len;
        (
            &self.buf[self.start..self.start + first_len],
            &self.buf[..second_len],
        )
    }

    #[allow(dead_code)]
    fn resize(&mut self, new_capacity: usize) -> Result<()> {
        if new_capacity == 0 {
            bail!("ring buffer resize capacity must be > 0");
        }
        let old_capacity = self.buf.len();
        if new_capacity == old_capacity {
            return Ok(());
        }
        if new_capacity < self.len {
            bail!(
                "ring buffer resize too small: new_capacity={} buffered={}",
                new_capacity,
                self.len
            );
        }

        let mut new_buf = vec![0u8; new_capacity];
        if self.len > 0 {
            self.copy_out(0, &mut new_buf[..self.len])?;
        }
        self.buf = new_buf;
        self.start = 0;
        Ok(())
    }
}

#[derive(Clone)]
struct RpcState {
    cmd_tx: mpsc::Sender<ControlPlaneCmd>,
    event_fd: RawFd,
    authz: Option<RpcAuthzState>,
    seen_nonces: Arc<Mutex<HashMap<String, u64>>>,
    admin_sessions: Arc<Mutex<HashMap<String, AdminSession>>>,
}

#[derive(Clone)]
struct RpcAuthzState {
    api_credentials: HashMap<String, ApiAuthCredential>,
    web_logins: HashMap<String, WebLoginCredential>,
    principal_groups: HashMap<String, HashSet<String>>,
    switch_acl: HashMap<String, SwitchJoinAcl>,
    admin_groups: HashSet<String>,
    has_acl_rules: bool,
}

#[derive(Clone)]
struct AdminSession {
    principal: String,
    expires_at_ms: u64,
}

#[derive(Clone)]
struct ApiAuthCredential {
    principal: String,
    api_secret: String,
}

#[derive(Clone)]
struct WebLoginCredential {
    principal: String,
    password_hash: String,
}

#[derive(Clone)]
struct SwitchJoinAcl {
    principals: HashSet<String>,
    groups: HashSet<String>,
}

struct ControlPlaneState {
    switches: HashMap<String, RpcSwitchView>,
    grants: HashMap<String, JoinGrantState>,
    peers: HashMap<String, Vec<RpcPeer>>,
    jwt_secret: Option<String>,
    advertised_listener: String,
    crypto_method: String,
}

enum ControlPlaneCmd {
    ListSwitches {
        resp: tokio::sync::oneshot::Sender<Vec<RpcSwitchView>>,
    },
    Join {
        switch_name: String,
        mac: String,
        principal: String,
        requested_ip: Option<String>,
        resp: tokio::sync::oneshot::Sender<std::result::Result<JoinResponse, u16>>,
    },
    ListPeers {
        switch_name: String,
        resp: tokio::sync::oneshot::Sender<std::result::Result<Vec<RpcPeer>, u16>>,
    },
    AdminSnapshot {
        resp: tokio::sync::oneshot::Sender<AdminSnapshot>,
    },
}

#[derive(Clone, Serialize)]
struct RpcSwitchView {
    name: String,
    host_ip: Option<String>,
    cidr: Option<String>,
    host_mac: String,
    tap: String,
    server_routes: Vec<RouteSpec>,
    client_routes: Vec<RouteSpec>,
    #[serde(skip_serializing)]
    client_ip_pool: Option<ClientIpPool>,
    #[serde(skip_serializing)]
    address_reservations: HashMap<String, ReservedAddress>,
}

#[derive(Clone)]
struct ClientIpPool {
    start: u32,
    end: u32,
    cidr: String,
}

#[derive(Clone)]
struct ReservedAddress {
    ip: Ipv4Addr,
    cidr: String,
}

#[derive(Clone, Serialize)]
struct RpcPeer {
    mac: String,
    ip: Option<String>,
}

#[derive(Clone)]
struct JoinGrantState {
    claims: JoinClaims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JoinClaims {
    iat: u64,
    exp: u64,
    principal: String,
    switch: String,
    mac: String,
    ipv4: String,
    crypt_method: String,
    crypt_key: String,
    gateway: Option<String>,
    routes: Vec<RouteSpec>,
    dns: Option<String>,
    jti: String,
}

#[derive(Deserialize)]
struct JoinQuery {
    switch: Option<String>,
    mac: Option<String>,
    requested_ip: Option<String>,
}

struct JoinGrantInfo {
    assigned_ip: Option<Ipv4Addr>,
    assigned_ipv4: Option<String>,
    crypto: Option<BindingCrypto>,
}

#[derive(Clone, Serialize)]
struct AdminSnapshot {
    generated_at_ms: u64,
    switches: Vec<AdminSwitchSnapshot>,
    bridges: Vec<AdminBridgeSnapshot>,
}

#[derive(Clone, Serialize)]
struct AdminSwitchSnapshot {
    name: String,
    tap: String,
    host_ip: Option<String>,
    cidr: Option<String>,
    host_mac: String,
    server_routes: Vec<RouteSpec>,
    client_routes: Vec<RouteSpec>,
    address_reservations: Vec<AdminReservationSnapshot>,
    clients: Vec<AdminClientSnapshot>,
}

#[derive(Clone, Serialize)]
struct AdminReservationSnapshot {
    mac: String,
    ipv4: String,
}

#[derive(Clone, Serialize)]
struct AdminClientSnapshot {
    mac: String,
    source_addr: Option<String>,
    assigned_ip: Option<String>,
    assigned_network: Option<String>,
    last_packet_from_client_ms: Option<u64>,
    last_packet_to_client_ms: Option<u64>,
}

#[derive(Clone, Serialize)]
struct AdminBridgeSnapshot {
    name: String,
    members: Vec<String>,
}

#[derive(Deserialize)]
struct AdminLoginForm {
    username: String,
    password: String,
}

#[derive(Parser, Debug)]
#[command(name = "vswitch", version, about = "Virtual switch dataplane and control-plane daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run server dataplane and RPC API.
    Server {
        /// Server config path (auto-detected when omitted).
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
    /// Run client TAP session.
    Client {
        /// Client config path (auto-detected when omitted).
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
    /// Generate username:bcrypt-hash entry for web_logins.
    Password {
        /// Username for the generated web_login entry. Prompts when omitted.
        #[arg(long = "username")]
        username: Option<String>,
        /// Password literal (not recommended; visible in shell history/process list).
        #[arg(long = "password", conflicts_with = "password_stdin")]
        password: Option<String>,
        /// Read password from stdin (single line, trims trailing newline).
        #[arg(long = "password-stdin")]
        password_stdin: bool,
    },
}

fn main() -> Result<()> {
    init_tracing();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Client { config } => run_client_mode(config),
        Commands::Server { config } => run_server_mode(config),
        Commands::Password {
            username,
            password,
            password_stdin,
        } => run_password_mode(username, password, password_stdin),
    }
}

fn run_client_mode(config: Option<String>) -> Result<()> {
    let path = resolve_config_path("client", config)?;
    run_client_config_mode(&path)
}

fn run_server_mode(config: Option<String>) -> Result<()> {
    let path = resolve_config_path("server", config)?;
    run_server_config_mode(&path)
}

fn prompt_line(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush().context("failed to flush stdout")?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .context("failed to read input")?;
    Ok(value.trim().to_string())
}

fn run_password_mode(
    username_arg: Option<String>,
    password_arg: Option<String>,
    password_stdin: bool,
) -> Result<()> {
    let username = username_arg
        .unwrap_or(prompt_line("Enter your username: ")?)
        .trim()
        .to_string();
    if username.is_empty() {
        bail!("username must not be empty");
    }

    let password = if let Some(pw) = password_arg {
        pw
    } else if password_stdin {
        let mut pw = String::new();
        io::stdin()
            .read_line(&mut pw)
            .context("failed to read password from stdin")?;
        pw.trim_end_matches(['\r', '\n']).to_string()
    } else {
        print!("Enter your password: ");
        io::stdout().flush().context("failed to flush stdout")?;
        rpassword::read_password().context("failed to read password")?
    };
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let hashed = hash_bcrypt(password, DEFAULT_COST).context("failed to hash password")?;
    println!("Your password:");
    println!("{username}:{hashed}");
    Ok(())
}

fn run_server_config_mode(path: &str) -> Result<()> {
    let cfg_text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read server config {path}"))?;
    let cfg: ServerConfig =
        serde_yaml::from_str(&cfg_text).with_context(|| format!("invalid YAML in {path}"))?;
    if cfg.switches.is_empty() {
        bail!("server config has no switches");
    }

    let listener = TcpListener::bind(&cfg.listener)
        .with_context(|| format!("bind {} failed", cfg.listener))?;
    listener
        .set_nonblocking(true)
        .context("failed to set listener nonblocking")?;

    let epfd = epoll_create()?;
    epoll_add(epfd, listener.as_raw_fd(), libc::EPOLLIN as u32)?;

    let mut switches: HashMap<u16, ServerSwitchState> = HashMap::default();
    let mut switch_name_to_id: HashMap<String, u16> = HashMap::default();
    let mut tap_fd_to_switch: HashMap<RawFd, u16> = HashMap::default();
    let mut switch_views: HashMap<String, RpcSwitchView> = HashMap::default();
    let mut switch_to_bridge: HashMap<u16, usize> = HashMap::default();
    let mut bridges: Vec<BridgeState> = Vec::new();

    for (idx, sw) in cfg.switches.iter().enumerate() {
        let switch_id = u16::try_from(idx).map_err(|_| anyhow!("too many switches"))?;
        let tap = create_tap(&sw.tap, true)?;
        if let Some(mac_str) = sw.mac.as_deref() {
            let mac = parse_mac(mac_str)?;
            set_iface_mac(&tap.name, mac)?;
        }

        let mut host_ip: Option<String> = None;
        let mut network_cidr: Option<String> = None;
        if let Some(ipv4) = sw.ipv4.as_deref() {
            let (ip, prefix) = parse_ipv4_with_prefix(ipv4)
                .with_context(|| format!("invalid ipv4 for switch {}: {ipv4}", sw.name))?;
            configure_iface_ipv4(&tap.name, ip, prefix)?;
            let network = Ipv4Addr::from(u32::from(ip) & prefix_to_mask(prefix));
            let cidr = format!("{network}/{prefix}");
            info!(
                "configured switch={} TAP={} ip={} network={}",
                sw.name, tap.name, ip, cidr
            );
            host_ip = Some(ip.to_string());
            network_cidr = Some(cidr);
        }
        let client_ip_pool = sw
            .client_ip_pool
            .as_deref()
            .map(parse_client_ip_pool)
            .transpose()
            .with_context(|| format!("invalid client_ip_pool for switch {}", sw.name))?;
        let mut address_reservations: HashMap<String, ReservedAddress> = HashMap::default();
        if let Some(resv) = sw.address_reservation.as_ref() {
            for item in resv {
                let mac = parse_mac(&item.mac).with_context(|| {
                    format!("invalid reservation mac for switch {}: {}", sw.name, item.mac)
                })?;
                let (ip, prefix) = parse_ipv4_with_prefix(&item.ipv4).with_context(|| {
                    format!(
                        "invalid reservation ipv4 for switch {} mac {}: {}",
                        sw.name,
                        format_mac(&mac),
                        item.ipv4
                    )
                })?;
                let mask = prefix_to_mask(prefix);
                let ip_u = u32::from(ip);
                let network_u = ip_u & mask;
                let broadcast_u = network_u | !mask;
                if ip_u == network_u || ip_u == broadcast_u {
                    bail!(
                        "reservation for switch {} mac {} uses network/broadcast address {}",
                        sw.name,
                        format_mac(&mac),
                        item.ipv4
                    );
                }
                if host_ip
                    .as_deref()
                    .and_then(|v| v.parse::<Ipv4Addr>().ok())
                    .is_some_and(|host| host == ip)
                {
                    bail!(
                        "reservation for switch {} mac {} conflicts with switch host ip {}",
                        sw.name,
                        format_mac(&mac),
                        ip
                    );
                }
                let key = format_mac(&mac);
                if address_reservations.contains_key(&key) {
                    bail!(
                        "duplicate reservation mac in switch {}: {}",
                        sw.name,
                        key
                    );
                }
                let normalized_network = Ipv4Addr::from(network_u);
                let cidr = format!("{normalized_network}/{prefix}");
                address_reservations.insert(key, ReservedAddress { ip, cidr });
            }
        }
        if let Some(routes) = sw.server_routes.as_ref() {
            for route in routes {
                info!(
                    "Adding server routes to {} via {}",
                    route.to,
                    route.via.as_deref().unwrap_or("on-link")
                );
                add_route_via_iface(route, &tap.name)?;
            }
            info!(
                "configured server routes for switch={} tap={} route_count={}",
                sw.name,
                tap.name,
                routes.len()
            );
        }

        let tap_has_ipv6 = iface_has_ipv6(&tap.name)?;
        let tap_mac = get_iface_mac(&tap.name)?;
        info!(
            "server switch={} id={} TAP={} MAC={} ipv6_enabled={}",
            sw.name,
            switch_id,
            tap.name,
            format_mac(&tap_mac),
            tap_has_ipv6
        );

        epoll_add(epfd, tap.file.as_raw_fd(), libc::EPOLLIN as u32)?;
        tap_fd_to_switch.insert(tap.file.as_raw_fd(), switch_id);
        switch_name_to_id.insert(sw.name.clone(), switch_id);

        let mut mac_table = HashMap::default();
        mac_table.insert(tap_mac, Endpoint::LocalTap);
        let normalized_client_routes = normalize_routes(
            sw.client_routes.clone().unwrap_or_default(),
            "server client_routes",
        )
        .with_context(|| format!("invalid client_routes for switch {}", sw.name))?;
        switch_views.insert(
            sw.name.clone(),
            RpcSwitchView {
                name: sw.name.clone(),
                host_ip,
                cidr: network_cidr,
                host_mac: format_mac(&tap_mac),
                tap: tap.name.clone(),
                server_routes: sw.server_routes.clone().unwrap_or_default(),
                client_routes: normalized_client_routes,
                client_ip_pool,
                address_reservations,
            },
        );

        switches.insert(
            switch_id,
            ServerSwitchState {
                name: sw.name.clone(),
                tap,
                tap_has_ipv6,
                disable_unknown_mac: sw.disable_unknown_mac,
                mac_table,
            },
        );
    }

    if let Some(bridge_cfgs) = cfg.bridges.as_ref() {
        for b in bridge_cfgs {
            if b.members.is_empty() {
                bail!("bridge {} has no members", b.name);
            }
            for i in 0..b.members.len() {
                for j in (i + 1)..b.members.len() {
                    let left = &b.members[i];
                    let right = &b.members[j];
                    let left_pool = switch_views
                        .get(left)
                        .and_then(|sw| sw.client_ip_pool.as_ref());
                    let right_pool = switch_views
                        .get(right)
                        .and_then(|sw| sw.client_ip_pool.as_ref());
                    if let (Some(lp), Some(rp)) = (left_pool, right_pool)
                        && lp.start <= rp.end
                        && rp.start <= lp.end
                    {
                        bail!(
                            "bridge {} has overlapping client_ip_pool ranges between switches {} ({}) and {} ({})",
                            b.name,
                            left,
                            format!("{}-{}", Ipv4Addr::from(lp.start), Ipv4Addr::from(lp.end)),
                            right,
                            format!("{}-{}", Ipv4Addr::from(rp.start), Ipv4Addr::from(rp.end))
                        );
                    }
                }
            }
            let mut members: Vec<u16> = Vec::with_capacity(b.members.len());
            for member_name in &b.members {
                let sid = switch_name_to_id
                    .get(member_name)
                    .copied()
                    .ok_or_else(|| anyhow!("bridge {} references unknown switch {}", b.name, member_name))?;
                if members.contains(&sid) {
                    bail!("bridge {} has duplicate member {}", b.name, member_name);
                }
                if switch_to_bridge.contains_key(&sid) {
                    bail!(
                        "switch {} is already part of another bridge; only one bridge membership is supported",
                        member_name
                    );
                }
                members.push(sid);
            }
            let bridge_id = bridges.len();
            for sid in &members {
                switch_to_bridge.insert(*sid, bridge_id);
            }
            info!("configured bridge name={} members={}", b.name, b.members.join(","));
            bridges.push(BridgeState {
                name: b.name.clone(),
                members,
                mac_table: HashMap::default(),
            });
        }
    }

    let mut control = ControlPlaneState {
        switches: switch_views,
        grants: HashMap::default(),
        peers: HashMap::default(),
        jwt_secret: cfg.rpc_hmac_secret.clone(),
        advertised_listener: cfg.advertised_listener.clone(),
        crypto_method: cfg
            .crypto_method
            .clone()
            .unwrap_or_else(|| "AES-GCM-256".to_string()),
    };
    let authz = build_rpc_authz_state(&cfg, &control.switches)?;
    let (cmd_tx, cmd_rx) = mpsc::channel::<ControlPlaneCmd>();
    let event_fd = create_eventfd()?;
    epoll_add(epfd, event_fd, libc::EPOLLIN as u32)?;

    if let Some(rpc_bind) = cfg.rpc.clone() {
        if authz.is_none() {
            bail!(
                "rpc is configured but authentication is not configured; set `principals`"
            );
        }
        let rpc_state = RpcState {
            cmd_tx,
            event_fd,
            authz,
            seen_nonces: Arc::new(Mutex::new(HashMap::default())),
            admin_sessions: Arc::new(Mutex::new(HashMap::default())),
        };
        thread::spawn(move || {
            if let Err(err) = run_rpc_server(rpc_bind, rpc_state) {
                error!("rpc server failed: {err:#}");
            }
        });
    }

    let mut clients: HashMap<RawFd, ClientMuxState> = HashMap::default();
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 256];
    let mut tap_buf = [0u8; ETH_MAX_FRAME];

    loop {
        let n = epoll_wait(epfd, &mut events, -1)?;
        for ev in events.iter().take(n) {
            let fd = ev.u64 as RawFd;
            let evflags = ev.events;

            if fd == event_fd {
                drain_eventfd(event_fd)?;
                process_control_plane_cmds(&mut control, &cmd_rx, &switches, &clients, &bridges)?;
                continue;
            }

            if fd == listener.as_raw_fd() {
                accept_mux_clients(epfd, &listener, &mut clients)?;
                continue;
            }

            if let Some(&switch_id) = tap_fd_to_switch.get(&fd) {
                loop {
                    let tap_file = {
                        let sw = switches
                            .get(&switch_id)
                            .ok_or_else(|| anyhow!("missing switch id {switch_id}"))?;
                        sw.tap.file.try_clone().context("failed to clone TAP fd")?
                    };
                    match read_frame_from_tap(&tap_file, &mut tap_buf) {
                        Ok(Some(frame)) => {
                            route_frame_mux(
                                epfd,
                                switch_id,
                                &frame,
                                Endpoint::LocalTap,
                                &mut switches,
                                &mut clients,
                                &switch_to_bridge,
                                &mut bridges,
                            )?;
                        }
                        Ok(None) => break,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => return Err(err.into()),
                    }
                }
                continue;
            }

            let mut disconnect = false;
            if evflags & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32) != 0 {
                disconnect = true;
            } else {
                if evflags & libc::EPOLLIN as u32 != 0 {
                    if let Err(err) = process_mux_client_read(
                        epfd,
                        fd,
                        &switch_name_to_id,
                        &mut switches,
                        &mut clients,
                        &mut control,
                        &switch_to_bridge,
                        &mut bridges,
                    )
                    {
                        warn!("mux client {fd} read/protocol failed: {err:#}");
                        remove_mux_client(
                            epfd,
                            fd,
                            &mut clients,
                            &mut switches,
                            &mut control,
                            &mut bridges,
                        )?;
                        continue;
                    }
                }
                if !disconnect && evflags & libc::EPOLLOUT as u32 != 0 {
                    if let Some(client) = clients.get_mut(&fd) {
                        if let Err(err) = flush_mux_client(client) {
                            warn!("mux client {fd} write failed: {err:#}");
                            disconnect = true;
                        } else {
                            epoll_mod(epfd, fd, mux_client_interest(client))?;
                        }
                    }
                }
            }

            if disconnect {
                remove_mux_client(
                    epfd,
                    fd,
                    &mut clients,
                    &mut switches,
                    &mut control,
                    &mut bridges,
                )?;
            }
        }
    }
}

fn run_client_config_mode(path: &str) -> Result<()> {
    let cfg_text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read client config {path}"))?;
    let cfg: ClientConfig =
        serde_yaml::from_str(&cfg_text).with_context(|| format!("invalid YAML in {path}"))?;
    let sw = single_client_switch_from_config(&cfg)?;
    if cfg.rpc.is_none() {
        bail!("client config requires `rpc` (static join_token is no longer supported)");
    }

    loop {
        info!("joining switch {} via rpc", sw.switch);
        match run_client_config_session(&cfg, &sw) {
            Ok(()) => {}
            Err(err) => warn!("client config session ended: {err:#}"),
        }
        info!("reconnecting in 1s");
        thread::sleep(Duration::from_secs(1));
    }
}

fn run_client_config_session(cfg: &ClientConfig, sw: &ClientSwitchConfigTop) -> Result<()> {
    let tap = create_tap(&sw.tap, true)?;
    if let Some(mac_str) = sw.mac.as_deref() {
        let mac = parse_mac(mac_str)?;
        set_iface_mac(&tap.name, mac)?;
    }
    let mac = get_iface_mac(&tap.name)?;
    let requested_ip = cfg
        .ipv4
        .as_ref()
        .map(|v| parse_ipv4_with_prefix(v).map(|x| x.0))
        .transpose()
        .with_context(|| "invalid client ipv4")?;
    let rpc = cfg
        .rpc
        .as_deref()
        .ok_or_else(|| anyhow!("client config requires `rpc`"))?;
    if cfg.api_key.is_some() && cfg.api_secret.is_none() {
        bail!("client config has api_key but missing api_secret");
    }
    let join = fetch_join_from_rpc(
        rpc,
        cfg.api_key.as_deref(),
        cfg.api_secret.as_deref(),
        &sw.switch,
        &mac,
        requested_ip,
    )?;
    if join.crypt_method != "AES-GCM-256" {
        bail!("unsupported crypt_method from join: {}", join.crypt_method);
    }
    let session_key = parse_hex_key_32(&join.crypt_key)?;
    debug!(
        "acquired join token switch={} token={} listener={} ipv4={} crypt_method={} crypt_key={}",
        sw.switch,
        join.token,
        join.listener,
        join.ipv4,
        join.crypt_method,
        join.crypt_key
    );
    let mut tx_stream = TcpStream::connect(&join.listener)
        .with_context(|| format!("failed to connect to advertised listener {}", join.listener))?;
    tx_stream
        .set_nodelay(true)
        .context("failed to set TCP_NODELAY")?;
    configure_tcp_keepalive(&tx_stream, 15, 5, 3)?;
    let mut rx_stream = tx_stream.try_clone().context("failed to clone stream")?;
    let client_ip: Ipv4Addr;
    if let Some(ip_cfg) = cfg.ipv4.as_ref() {
        let (ip, prefix) = parse_ipv4_with_prefix(ip_cfg)
            .with_context(|| format!("invalid client ipv4: {ip_cfg}"))?;
        let network = Ipv4Addr::from(u32::from(ip) & prefix_to_mask(prefix));
        let cidr = format!("{network}/{prefix}");
        configure_iface_ipv4(&tap.name, ip, prefix)?;
        client_ip = ip;
        info!(
            "configured client switch={} TAP={} ip={} network={} (static config)",
            sw.switch, tap.name, ip, cidr
        );
    } else {
        let (ip, prefix) = parse_ipv4_with_prefix(&join.ipv4)
            .with_context(|| format!("invalid ipv4 from RPC: {}", join.ipv4))?;
        let network = Ipv4Addr::from(u32::from(ip) & prefix_to_mask(prefix));
        let cidr = format!("{network}/{prefix}");
        configure_iface_ipv4(&tap.name, ip, prefix)?;
        client_ip = ip;
        info!(
            "configured client switch={} TAP={} ip={} network={} (from rpc join)",
            sw.switch, tap.name, ip, cidr
        );
    }
    let ignored_route_ranges = parse_ignore_server_routes(&cfg.ignore_server_routes)
        .context("invalid ignore_server_routes in client config")?;
    let normalized_server_routes = normalize_routes(join.routes.clone(), "server routes")
        .context("invalid routes from server")?;
    if cfg.use_server_routes {
        for route in &normalized_server_routes {
            if route_via_is_self(route, client_ip)? {
                warn!(
                    "Ignoring route to {} from server because via={} equals local client IP",
                    route.to,
                    route.via.as_deref().unwrap_or("")
                );
                continue;
            }
            if is_server_route_ignored(route, &ignored_route_ranges)? {
                info!(
                    "Ignoring route to {} via {} from server due to ignore_server_routes",
                    route.to,
                    route.via.as_deref().unwrap_or("on-link")
                );
                continue;
            }
            info!(
                "Adding route to {} via {} from server",
                route.to,
                route.via.as_deref().unwrap_or("on-link")
            );
            add_route_via_iface(route, &tap.name)?;
        }
    } else {
        for route in &normalized_server_routes {
            info!(
                "Ignoring route to {} via {} from server",
                route.to,
                route.via.as_deref().unwrap_or("on-link")
            );
        }
    }
    if let Some(routes) = cfg.routes.as_ref() {
        for route in routes {
            info!(
                "Adding route to {} via {} from local",
                route.to,
                route.via.as_deref().unwrap_or("on-link")
            );
            add_route_via_iface(route, &tap.name)?;
        }
    }
    let tap_has_ipv6 = iface_has_ipv6(&tap.name)?;
    write_register_msg(
        &mut tx_stream,
        &sw.switch,
        Some(join.token.as_str()),
        mac,
    )?;
    info!(
        "sent registration switch={} mac={} tap={} ipv6_enabled={}",
        sw.switch,
        format_mac(&mac),
        tap.name,
        tap_has_ipv6
    );

    wait_for_registration_acks(&mut rx_stream, 1)?;
    rx_stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .context("failed to set dataplane read timeout")?;
    info!(
        "client handshake completed with listener {}, accepted switch={}",
        join.listener,
        sw.switch
    );
    let mut tap_reader = tap.file.try_clone().context("failed to clone TAP reader")?;
    let mut tap_writer = tap.file.try_clone().context("failed to clone TAP writer")?;
    let switch_name = sw.switch.clone();
    let switch_name_rx = switch_name.clone();
    let switch_name_mac = switch_name.clone();
    let tap_name_mac = tap.name.clone();
    let registered_mac = mac;
    let mac_watch_stream = tx_stream
        .try_clone()
        .context("failed to clone stream for MAC watcher")?;
    let tx_session_key = session_key;
    let rx_session_key = session_key;

    let stop = Arc::new(AtomicBool::new(false));
    let mut tx_counter: u64 = 0;

    let stop_tx = Arc::clone(&stop);
    let tx_thread = thread::spawn(move || -> Result<()> {
        let res = (|| -> Result<()> {
            let mut tap_pollfd = libc::pollfd {
                fd: tap_reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let mut frame = [0u8; ETH_MAX_FRAME];

            while !stop_tx.load(Ordering::Relaxed) {
                let rc = unsafe { libc::poll(&mut tap_pollfd, 1, 100) };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    return Err(err.into());
                }
                if rc == 0 {
                    continue;
                }

                if tap_pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    bail!(
                        "tap poll error for switch={} events={:#x}",
                        switch_name,
                        tap_pollfd.revents
                    );
                }
                if tap_pollfd.revents & libc::POLLIN == 0 {
                    continue;
                }

                let n = tap_reader.read(&mut frame)?;
                if n == 0 {
                    continue;
                }
                let payload = encrypt_payload_aes_gcm(
                    &tx_session_key,
                    NONCE_DIR_CLIENT_TO_SERVER,
                    tx_counter,
                    &frame[..n],
                )?;
                tx_counter = tx_counter
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("tx nonce counter overflow"))?;
                debug!("client switch={} tap->server frame_len={}", switch_name, n);
                write_data_msg(&mut tx_stream, &payload)?;
            }
            Ok(())
        })();

        if res.is_err() {
            stop_tx.store(true, Ordering::Relaxed);
        }
        let _ = tx_stream.shutdown(Shutdown::Both);
        res
    });

    let stop_rx = Arc::clone(&stop);
    let rx_thread = thread::spawn(move || -> Result<()> {
        let res = (|| -> Result<()> {
            while !stop_rx.load(Ordering::Relaxed) {
                let mut kind = [0u8; 1];
                read_exact_until_deadline_or_stop(&mut rx_stream, &mut kind, &stop_rx)?;
                if kind[0] == CTRL_ERROR {
                    let mut err = [0u8; 1];
                    read_exact_until_deadline_or_stop(&mut rx_stream, &mut err, &stop_rx)?;
                    let code = err[0];
                    let reason = match code {
                        ERR_UNKNOWN_SWITCH => "unknown switch",
                        ERR_INVALID_TOKEN => "invalid join token",
                        _ => "unknown error",
                    };
                    bail!("server rejected switch registration: code={} reason={}", code, reason);
                }
                if kind[0] != CTRL_DATA {
                    bail!("unexpected message type from server: {}", kind[0]);
                }

                let mut len_buf = [0u8; 2];
                read_exact_until_deadline_or_stop(&mut rx_stream, &mut len_buf, &stop_rx)?;
                let len = u16::from_be_bytes(len_buf) as usize;
                if len == 0 || len > ETH_MAX_FRAME {
                    bail!("invalid frame size from server: {len}");
                }

                let mut frame = vec![0u8; len];
                read_exact_until_deadline_or_stop(&mut rx_stream, &mut frame, &stop_rx)?;
                let plain = decrypt_payload_aes_gcm(
                    &rx_session_key,
                    NONCE_DIR_SERVER_TO_CLIENT,
                    &frame,
                )?;
                if is_ipv6_frame(&plain) && !tap_has_ipv6 {
                    debug!(
                        "drop server->tap ipv6 frame switch={} len={}, TAP has no IPv6",
                        switch_name_rx, len
                    );
                    continue;
                }
                write_all_tap_retry(&mut tap_writer, &plain)?;
            }
            Ok(())
        })();

        if res.is_err() {
            stop_rx.store(true, Ordering::Relaxed);
        }
        let _ = rx_stream.shutdown(Shutdown::Both);
        res
    });

    let stop_mac = Arc::clone(&stop);
    let mac_watch_thread = thread::spawn(move || -> Result<()> {
        let res = (|| -> Result<()> {
            while !stop_mac.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(2));
                if stop_mac.load(Ordering::Relaxed) {
                    break;
                }
                let current_mac = match get_iface_mac(&tap_name_mac) {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(
                            "client switch={} tap={} failed to read TAP MAC while monitoring: {err:#}",
                            switch_name_mac,
                            tap_name_mac
                        );
                        continue;
                    }
                };
                if current_mac != registered_mac {
                    warn!(
                        "client switch={} tap={} detected MAC change {} -> {}; restarting session to rejoin with updated MAC",
                        switch_name_mac,
                        tap_name_mac,
                        format_mac(&registered_mac),
                        format_mac(&current_mac)
                    );
                    bail!(
                        "tap MAC changed from {} to {}",
                        format_mac(&registered_mac),
                        format_mac(&current_mac)
                    );
                }
            }
            Ok(())
        })();

        if res.is_err() {
            stop_mac.store(true, Ordering::Relaxed);
        }
        let _ = mac_watch_stream.shutdown(Shutdown::Both);
        res
    });

    let tx_res = tx_thread
        .join()
        .map_err(|_| anyhow!("tap->server config thread panicked"))?;
    stop.store(true, Ordering::Relaxed);
    let rx_res = rx_thread
        .join()
        .map_err(|_| anyhow!("server->tap config thread panicked"))?;
    let mac_watch_res = mac_watch_thread
        .join()
        .map_err(|_| anyhow!("mac-watch config thread panicked"))?;
    tx_res?;
    rx_res?;
    mac_watch_res?;
    Ok(())
}

fn accept_mux_clients(
    epfd: RawFd,
    listener: &TcpListener,
    clients: &mut HashMap<RawFd, ClientMuxState>,
) -> Result<()> {
    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                stream
                    .set_nonblocking(true)
                    .context("failed to set accepted socket nonblocking")?;
                let fd = stream.as_raw_fd();
                epoll_add(epfd, fd, libc::EPOLLIN as u32)?;
                clients.insert(
                    fd,
                    ClientMuxState {
                        stream,
                        in_buf: RingBuffer::with_capacity(MAX_IN_BUF_BYTES_PER_CLIENT),
                        out_buf: RingBuffer::with_capacity(MAX_OUT_BUF_BYTES_PER_CLIENT),
                        binding: None,
                        peer_addr: Some(addr.to_string()),
                        last_from_client_ms: None,
                        last_to_client_ms: None,
                    },
                );
                info!("accepted mux client fd={fd} from {addr}");
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn process_mux_client_read(
    epfd: RawFd,
    fd: RawFd,
    switch_name_to_id: &HashMap<String, u16>,
    switches: &mut HashMap<u16, ServerSwitchState>,
    clients: &mut HashMap<RawFd, ClientMuxState>,
    control: &mut ControlPlaneState,
    switch_to_bridge: &HashMap<u16, usize>,
    bridges: &mut [BridgeState],
) -> Result<()> {
    let mut client = clients
        .remove(&fd)
        .ok_or_else(|| anyhow!("mux client disappeared"))?;
    let res = (|| -> Result<()> {
        let mut tmp = [0u8; 4096];
        loop {
            if client.in_buf.len() >= MAX_IN_BUF_BYTES_PER_CLIENT {
                debug!(
                    "mux client fd={fd} input buffer reached cap={}, pause reading this cycle",
                    MAX_IN_BUF_BYTES_PER_CLIENT
                );
                break;
            }
            let room = MAX_IN_BUF_BYTES_PER_CLIENT - client.in_buf.len();
            let read_len = room.min(tmp.len());
            match client.stream.read(&mut tmp[..read_len]) {
                Ok(0) => bail!("peer closed"),
                Ok(n) => client.in_buf.push_slice(&tmp[..n])?,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => return Err(err.into()),
            }
        }

        let mut consumed = 0usize;
        while consumed < client.in_buf.len() {
            let kind = client
                .in_buf
                .peek_u8(consumed)
                .ok_or_else(|| anyhow!("ring buffer peek failed"))?;
            match kind {
                CTRL_REGISTER => {
                    if client.in_buf.len() < consumed + 4 {
                        break;
                    }
                    let name_len = client
                        .in_buf
                        .peek_u8(consumed + 1)
                        .ok_or_else(|| anyhow!("ring buffer peek failed"))?
                        as usize;
                    let token_len = u16::from_be_bytes([
                        client
                            .in_buf
                            .peek_u8(consumed + 2)
                            .ok_or_else(|| anyhow!("ring buffer peek failed"))?,
                        client
                            .in_buf
                            .peek_u8(consumed + 3)
                            .ok_or_else(|| anyhow!("ring buffer peek failed"))?,
                    ]) as usize;
                    let msg_len = 1 + 1 + 2 + name_len + token_len + 6;
                    if client.in_buf.len() < consumed + msg_len {
                        break;
                    }
                    let name_start = consumed + 4;
                    let name_end = name_start + name_len;
                    let token_end = name_end + token_len;
                    let switch_name =
                        String::from_utf8_lossy(&client.in_buf.copy_vec(name_start, name_len)?)
                            .to_string();
                    let token =
                        String::from_utf8_lossy(&client.in_buf.copy_vec(name_end, token_len)?)
                            .to_string();
                    let mut mac = [0u8; 6];
                    client.in_buf.copy_out(token_end, &mut mac)?;

                    let server_switch_id = match switch_name_to_id.get(&switch_name).copied() {
                        Some(id) => id,
                        None => {
                            let _ =
                                write_error_msg_best_effort(&mut client.stream, ERR_UNKNOWN_SWITCH);
                            return Err(anyhow!(
                                "client fd={fd} tried to register unknown switch={switch_name}, disconnecting"
                            ));
                        }
                    };

                    let grant = match validate_join_token(control, &switch_name, &token, &mac) {
                        Ok(ip) => ip,
                        Err(err) => {
                            let _ =
                                write_error_msg_best_effort(&mut client.stream, ERR_INVALID_TOKEN);
                            return Err(anyhow!(
                                "client fd={fd} token validation failed for switch={switch_name}: {err:#}"
                            ));
                        }
                    };

                    let old = client.binding.replace(ClientBinding {
                        server_switch_id,
                        mac,
                        assigned_ipv4: grant.assigned_ipv4.clone(),
                        crypto: grant.crypto,
                    });

                    if let Some(old_binding) = old
                        && let Some(sw) = switches.get_mut(&old_binding.server_switch_id)
                        && matches!(
                            sw.mac_table.get(&old_binding.mac),
                            Some(Endpoint::Client(existing_fd)) if *existing_fd == fd
                        )
                    {
                        sw.mac_table.remove(&old_binding.mac);
                    }

                    if let Some(sw) = switches.get_mut(&server_switch_id) {
                        sw.mac_table.insert(mac, Endpoint::Client(fd));
                        info!(
                            "client fd={fd} registered switch={} mac={}",
                            sw.name,
                            format_mac(&mac)
                        );
                    }
                    update_peer_register(control, &switch_name, mac, grant.assigned_ip);
                    client.out_buf.push_u8(CTRL_ACK)?;
                    consumed += msg_len;
                }
                CTRL_DATA => {
                    if client.in_buf.len() < consumed + 3 {
                        break;
                    }
                    let len = u16::from_be_bytes([
                        client
                            .in_buf
                            .peek_u8(consumed + 1)
                            .ok_or_else(|| anyhow!("ring buffer peek failed"))?,
                        client
                            .in_buf
                            .peek_u8(consumed + 2)
                            .ok_or_else(|| anyhow!("ring buffer peek failed"))?,
                    ]) as usize;
                    if len == 0 || len > ETH_MAX_FRAME {
                        bail!("invalid mux frame length {len}");
                    }
                    let msg_len = 1 + 2 + len;
                    if client.in_buf.len() < consumed + msg_len {
                        break;
                    }

                    let Some((server_switch_id, crypto_key, registered_mac)) = client
                        .binding
                        .as_ref()
                        .map(|b| (b.server_switch_id, b.crypto.map(|x| x.key), b.mac))
                    else {
                        warn!("client fd={fd} sent frame before registration");
                        consumed += msg_len;
                        continue;
                    };

                    let frame_start = consumed + 3;
                    let (f1, f2) = client.in_buf.range_slices(frame_start, len)?;
                    let encrypted_frame: Cow<[u8]> = if f2.is_empty() {
                        Cow::Borrowed(f1)
                    } else {
                        let mut v = Vec::with_capacity(len);
                        v.extend_from_slice(f1);
                        v.extend_from_slice(f2);
                        Cow::Owned(v)
                    };

                    let plain: Cow<[u8]> = if let Some(key) = crypto_key {
                        Cow::Owned(decrypt_payload_aes_gcm(
                            &key,
                            NONCE_DIR_CLIENT_TO_SERVER,
                            &encrypted_frame,
                        )?)
                    } else {
                        encrypted_frame
                    };
                    let plain = plain.as_ref();

                    if plain.len() >= 12
                        && let Some(sw) = switches.get(&server_switch_id)
                        && sw.disable_unknown_mac
                    {
                        let mut src_mac = [0u8; 6];
                        src_mac.copy_from_slice(&plain[6..12]);
                        if src_mac != registered_mac {
                            warn!(
                                "dropped frame from client fd={} switch={} due to unknown source mac={}, expected registered mac={}",
                                fd,
                                sw.name,
                                format_mac(&src_mac),
                                format_mac(&registered_mac)
                            );
                            consumed += msg_len;
                            continue;
                        }
                    }

                    client.last_from_client_ms = Some(unix_now_ms());
                    route_frame_mux(
                        epfd,
                        server_switch_id,
                        plain,
                        Endpoint::Client(fd),
                        switches,
                        clients,
                        switch_to_bridge,
                        bridges,
                    )?;
                    consumed += msg_len;
                }
                _ => bail!("unknown message type {kind} from client {fd}"),
            }
        }
        if consumed > 0 {
            client.in_buf.consume(consumed)?;
        }
        epoll_mod(epfd, fd, mux_client_interest(&client))?;
        Ok(())
    })();
    clients.insert(fd, client);
    res
}

fn route_frame_mux(
    epfd: RawFd,
    switch_id: u16,
    frame: &[u8],
    source: Endpoint,
    switches: &mut HashMap<u16, ServerSwitchState>,
    clients: &mut HashMap<RawFd, ClientMuxState>,
    switch_to_bridge: &HashMap<u16, usize>,
    bridges: &mut [BridgeState],
) -> Result<()> {
    if frame.len() < 12 {
        return Ok(());
    }
    let mut dst = [0u8; 6];
    dst.copy_from_slice(&frame[..6]);
    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    if let Some(&bridge_idx) = switch_to_bridge.get(&switch_id) {
        let ingress = BridgeEndpoint {
            switch_id,
            endpoint: source,
        };
        let bridge = bridges
            .get_mut(bridge_idx)
            .ok_or_else(|| anyhow!("missing bridge id {bridge_idx}"))?;
        bridge.mac_table.insert(src, ingress);

        if is_broadcast(&dst) || is_multicast(&dst) {
            let targets = collect_bridge_flood_targets(bridge, clients);
            for target in targets {
                emit_bridge_frame(epfd, ingress, target, frame, switches, clients)?;
            }
            return Ok(());
        }

        if let Some(target) = bridge.mac_table.get(&dst).copied() {
            emit_bridge_frame(epfd, ingress, target, frame, switches, clients)?;
        } else {
            let targets = collect_bridge_flood_targets(bridge, clients);
            for target in targets {
                emit_bridge_frame(epfd, ingress, target, frame, switches, clients)?;
            }
        }
        return Ok(());
    }

    let switch = switches
        .get_mut(&switch_id)
        .ok_or_else(|| anyhow!("missing switch id {switch_id}"))?;
    switch.mac_table.insert(src, source);

    if is_broadcast(&dst) || is_multicast(&dst) {
        for fd in clients.keys().copied().collect::<Vec<_>>() {
            if source == Endpoint::Client(fd) {
                continue;
            }
            enqueue_frame_mux(epfd, fd, switch_id, frame, clients)?;
        }
        if source != Endpoint::LocalTap && should_write_frame_to_tap(frame, switch.tap_has_ipv6) {
            write_frame_to_tap(&switch.tap.file, frame)?;
        }
        return Ok(());
    }

    match switch.mac_table.get(&dst).copied() {
        Some(Endpoint::LocalTap) => {
            if should_write_frame_to_tap(frame, switch.tap_has_ipv6) {
                write_frame_to_tap(&switch.tap.file, frame)?;
            }
        }
        Some(Endpoint::Client(fd)) => {
            if source != Endpoint::Client(fd) {
                enqueue_frame_mux(epfd, fd, switch_id, frame, clients)?;
            }
        }
        None => {
            warn!(
                "dropped frame on switch={} due to unknown destination mac={}",
                switch.name,
                format_mac(&dst)
            );
        }
    }
    Ok(())
}

fn collect_bridge_flood_targets(
    bridge: &BridgeState,
    clients: &HashMap<RawFd, ClientMuxState>,
) -> Vec<BridgeEndpoint> {
    let mut targets: Vec<BridgeEndpoint> = Vec::new();
    for switch_id in &bridge.members {
        targets.push(BridgeEndpoint {
            switch_id: *switch_id,
            endpoint: Endpoint::LocalTap,
        });
    }
    for (&fd, client) in clients {
        if let Some(binding) = client.binding.as_ref()
            && bridge.members.contains(&binding.server_switch_id)
        {
            targets.push(BridgeEndpoint {
                switch_id: binding.server_switch_id,
                endpoint: Endpoint::Client(fd),
            });
        }
    }
    targets
}

fn emit_bridge_frame(
    epfd: RawFd,
    ingress: BridgeEndpoint,
    target: BridgeEndpoint,
    frame: &[u8],
    switches: &mut HashMap<u16, ServerSwitchState>,
    clients: &mut HashMap<RawFd, ClientMuxState>,
) -> Result<()> {
    if target == ingress {
        return Ok(());
    }
    match target.endpoint {
        Endpoint::Client(fd) => enqueue_frame_mux(epfd, fd, target.switch_id, frame, clients),
        Endpoint::LocalTap => {
            let sw = switches
                .get(&target.switch_id)
                .ok_or_else(|| anyhow!("missing switch id {}", target.switch_id))?;
            if should_write_frame_to_tap(frame, sw.tap_has_ipv6) {
                write_frame_to_tap(&sw.tap.file, frame)?;
            }
            Ok(())
        }
    }
}

fn enqueue_frame_mux(
    epfd: RawFd,
    fd: RawFd,
    server_switch_id: u16,
    frame: &[u8],
    clients: &mut HashMap<RawFd, ClientMuxState>,
) -> Result<()> {
    let client = match clients.get_mut(&fd) {
        Some(c) => c,
        None => return Ok(()),
    };
    let Some(binding) = client.binding.as_mut() else {
        return Ok(());
    };
    if binding.server_switch_id != server_switch_id {
        return Ok(());
    }

    let payload = if let Some(crypto) = binding.crypto.as_mut() {
        let p = encrypt_payload_aes_gcm(
            &crypto.key,
            NONCE_DIR_SERVER_TO_CLIENT,
            crypto.tx_counter,
            frame,
        )?;
        crypto.tx_counter = crypto
            .tx_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("tx nonce counter overflow"))?;
        p
    } else {
        frame.to_vec()
    };
    let len = u16::try_from(payload.len()).map_err(|_| anyhow!("frame too large to enqueue"))?;
    let msg_size = 1usize + 2usize + payload.len();
    if client.out_buf.len().saturating_add(msg_size) > MAX_OUT_BUF_BYTES_PER_CLIENT {
        let now_ms = unix_now_ms();
        if should_emit_drop_log(now_ms) {
            warn!(
                "dropped frame enqueue for client fd={} switch_id={} due to output queue full current_bytes={} cap={}",
                fd,
                server_switch_id,
                client.out_buf.len(),
                MAX_OUT_BUF_BYTES_PER_CLIENT
            );
        }
        return Ok(());
    }
    client.out_buf.push_u8(CTRL_DATA)?;
    client.out_buf.push_slice(&len.to_be_bytes())?;
    client.out_buf.push_slice(&payload)?;
    client.last_to_client_ms = Some(unix_now_ms());
    epoll_mod(epfd, fd, mux_client_interest(client))?;
    Ok(())
}

fn flush_mux_client(client: &mut ClientMuxState) -> Result<()> {
    while !client.out_buf.is_empty() {
        let (first, second) = client.out_buf.head_slices();
        let bufs = [IoSlice::new(first), IoSlice::new(second)];
        match client.stream.write_vectored(&bufs) {
            Ok(0) => bail!("socket closed while writing"),
            Ok(n) => {
                client.out_buf.consume(n)?;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn remove_mux_client(
    epfd: RawFd,
    fd: RawFd,
    clients: &mut HashMap<RawFd, ClientMuxState>,
    switches: &mut HashMap<u16, ServerSwitchState>,
    control: &mut ControlPlaneState,
    bridges: &mut [BridgeState],
) -> Result<()> {
    let _ = epoll_del(epfd, fd);
    if let Some(client) = clients.remove(&fd) {
        let mut removed: Vec<(String, Mac)> = Vec::new();
        for sw in switches.values_mut() {
            let mut to_remove: Vec<Mac> = Vec::new();
            for (mac, ep) in &sw.mac_table {
                if matches!(ep, Endpoint::Client(existing_fd) if *existing_fd == fd) {
                    to_remove.push(*mac);
                }
            }
            for mac in to_remove {
                sw.mac_table.remove(&mac);
                removed.push((sw.name.clone(), mac));
            }
        }
        if !removed.is_empty() {
            for (sw_name, mac) in removed {
                if let Some(peers) = control.peers.get_mut(&sw_name) {
                    let macs = format_mac(&mac);
                    peers.retain(|p| p.mac != macs);
                }
            }
        }
        for bridge in bridges.iter_mut() {
            bridge.mac_table.retain(
                |_, ep| !matches!(ep.endpoint, Endpoint::Client(existing_fd) if existing_fd == fd),
            );
        }
        let _ = client.stream.shutdown(Shutdown::Both);
        info!("removed mux client fd={fd}");
    }
    Ok(())
}

fn mux_client_interest(client: &ClientMuxState) -> u32 {
    let mut ev = libc::EPOLLIN as u32;
    if !client.out_buf.is_empty() {
        ev |= libc::EPOLLOUT as u32;
    }
    ev
}

fn write_register_msg(
    stream: &mut TcpStream,
    switch_name: &str,
    join_token: Option<&str>,
    mac: Mac,
) -> Result<()> {
    let name_bytes = switch_name.as_bytes();
    let token_bytes = join_token.unwrap_or("").as_bytes();
    let name_len = u8::try_from(name_bytes.len())
        .map_err(|_| anyhow!("switch name too long for protocol: {switch_name}"))?;
    let token_len = u16::try_from(token_bytes.len())
        .map_err(|_| anyhow!("join token too long for protocol"))?;
    stream.write_all(&[CTRL_REGISTER])?;
    stream.write_all(&[name_len])?;
    stream.write_all(&token_len.to_be_bytes())?;
    stream.write_all(name_bytes)?;
    stream.write_all(token_bytes)?;
    stream.write_all(&mac)?;
    Ok(())
}

fn write_data_msg(stream: &mut TcpStream, frame: &[u8]) -> Result<()> {
    let len = u16::try_from(frame.len()).map_err(|_| anyhow!("frame too large for protocol"))?;
    stream.write_all(&[CTRL_DATA])?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(frame)?;
    Ok(())
}

fn wait_for_registration_acks(stream: &mut TcpStream, expected: usize) -> Result<()> {
    let mut got = 0usize;
    while got < expected {
        let mut kind = [0u8; 1];
        stream.read_exact(&mut kind)?;
        match kind[0] {
            CTRL_ACK => {
                debug!("registration ack received");
                got += 1;
            }
            CTRL_ERROR => {
                let mut err = [0u8; 1];
                stream.read_exact(&mut err)?;
                let code = err[0];
                let reason = match code {
                    ERR_UNKNOWN_SWITCH => "unknown switch",
                    ERR_INVALID_TOKEN => "invalid join token",
                    _ => "unknown error",
                };
                bail!(
                    "server rejected switch registration: code={} reason={}",
                    code, reason
                );
            }
            other => bail!("unexpected message type during handshake: {other}"),
        }
    }
    Ok(())
}

fn is_io_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn read_exact_until_deadline_or_stop(
    stream: &mut TcpStream,
    buf: &mut [u8],
    stop: &AtomicBool,
) -> Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        if stop.load(Ordering::Relaxed) {
            bail!("client session stopping");
        }
        match stream.read(&mut buf[off..]) {
            Ok(0) => bail!("server closed connection"),
            Ok(n) => off += n,
            Err(err) if is_io_timeout(&err) => continue,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn validate_join_token(
    state: &mut ControlPlaneState,
    switch_name: &str,
    token: &str,
    reg_mac: &Mac,
) -> Result<JoinGrantInfo> {
    prune_grants(state);
    let Some(secret) = state.jwt_secret.as_deref() else {
        return Ok(JoinGrantInfo {
            assigned_ip: None,
            assigned_ipv4: None,
            crypto: None,
        });
    };
    if token.is_empty() {
        bail!("missing join token for switch={switch_name}");
    }

    let decoded = decode::<JoinClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| anyhow!("invalid join token"))?;
    let claims = decoded.claims;
    if claims.switch != switch_name {
        bail!(
            "join token switch mismatch token={} requested={}",
            claims.switch,
            switch_name
        );
    }
    let reg_mac_s = format_mac(reg_mac);
    if claims.mac != reg_mac_s {
        bail!(
            "join token mac mismatch token={} requested={}",
            claims.mac,
            reg_mac_s
        );
    }
    let now = unix_now();
    if claims.exp <= now {
        bail!("join token expired");
    }

    let _grant = state
        .grants
        .remove(&claims.jti)
        .ok_or_else(|| anyhow!("join token not granted"))?;

    let (assigned_ip, _) = parse_ipv4_with_prefix(&claims.ipv4)
        .with_context(|| format!("invalid ipv4 in token: {}", claims.ipv4))?;
    let crypto = if claims.crypt_method == "AES-GCM-256" {
        Some(BindingCrypto {
            key: parse_hex_key_32(&claims.crypt_key)?,
            tx_counter: 0,
        })
    } else {
        bail!("unsupported crypt_method in token: {}", claims.crypt_method);
    };
    debug!(
        "validated join token for switch={} assigned_ip={}",
        switch_name,
        assigned_ip
    );
    Ok(JoinGrantInfo {
        assigned_ip: Some(assigned_ip),
        assigned_ipv4: Some(claims.ipv4),
        crypto,
    })
}

fn update_peer_register(
    state: &mut ControlPlaneState,
    switch_name: &str,
    mac: Mac,
    assigned_ip: Option<Ipv4Addr>,
) {
    let peers = state.peers.entry(switch_name.to_string()).or_default();
    let mac_s = format_mac(&mac);
    let ip_s = assigned_ip.map(|v| v.to_string());
    if let Some(p) = peers.iter_mut().find(|p| p.mac == mac_s) {
        p.ip = ip_s;
    } else {
        peers.push(RpcPeer {
            mac: mac_s,
            ip: ip_s,
        });
    }
}

fn build_rpc_authz_state(
    cfg: &ServerConfig,
    switches: &HashMap<String, RpcSwitchView>,
) -> Result<Option<RpcAuthzState>> {
    let has_structured_auth =
        cfg.principals.is_some() || cfg.groups.is_some() || cfg.acl.is_some();
    if !has_structured_auth {
        return Ok(None);
    }

    let principals = cfg
        .principals
        .as_ref()
        .ok_or_else(|| anyhow!("principals must be configured when groups or acl is used"))?;
    if principals.is_empty() {
        bail!("principals is configured but empty");
    }

    let mut known_groups: HashSet<String> = HashSet::new();
    if let Some(groups) = cfg.groups.as_ref() {
        for g in groups {
            let name = g.name.trim().to_lowercase();
            if name.is_empty() {
                bail!("group name must not be empty");
            }
            if !known_groups.insert(name.clone()) {
                bail!("duplicate group name: {name}");
            }
        }
    }
    // Built-in implicit group for admin UI authorization.
    known_groups.insert("admin".to_string());

    let mut known_principals: HashSet<String> = HashSet::new();
    let mut api_credentials: HashMap<String, ApiAuthCredential> = HashMap::default();
    let mut web_logins: HashMap<String, WebLoginCredential> = HashMap::default();
    let mut principal_groups: HashMap<String, HashSet<String>> = HashMap::default();
    for p in principals {
        let principal_name = p.name.trim().to_lowercase();
        if principal_name.is_empty() {
            bail!("principal name must not be empty");
        }
        if !known_principals.insert(principal_name.clone()) {
            bail!("duplicate principal name: {principal_name}");
        }
        if p.credentials.api_keys.is_empty() && p.credentials.web_logins.is_empty() {
            bail!("principal {principal_name} must define at least one credentials entry");
        }

        let mut groups_for_principal: HashSet<String> = HashSet::new();
        if let Some(groups) = p.groups.as_ref() {
            for group_name in groups {
                let group_name = group_name.trim().to_lowercase();
                if group_name.is_empty() {
                    bail!("principal {principal_name} has empty group membership");
                }
                if !known_groups.contains(&group_name) {
                    bail!("principal {principal_name} references unknown group {group_name}");
                }
                groups_for_principal.insert(group_name);
            }
        }
        principal_groups.insert(principal_name.clone(), groups_for_principal);

        for cred in &p.credentials.api_keys {
            let (key, secret) = cred
                .split_once(':')
                .ok_or_else(|| anyhow!("principal {principal_name} has invalid api_keys entry"))?;
            let key = key.trim();
            let secret = secret.trim();
            if key.is_empty() || secret.is_empty() {
                bail!("principal {principal_name} has empty api key/secret in api_keys");
            }
            if api_credentials.contains_key(key) {
                panic!("duplicate api_key across principals: {key}");
            }
            api_credentials.insert(
                key.to_string(),
                ApiAuthCredential {
                    principal: principal_name.clone(),
                    api_secret: secret.to_string(),
                },
            );
        }
        for login in &p.credentials.web_logins {
            let (username, password_hash) = login.split_once(':').ok_or_else(|| {
                anyhow!("principal {principal_name} has invalid web_logins entry")
            })?;
            let username = username.trim().to_lowercase();
            let password_hash = password_hash.trim();
            if username.is_empty() || password_hash.is_empty() {
                bail!("principal {principal_name} has empty username/password hash in web_logins");
            }
            if web_logins.contains_key(&username) {
                panic!("duplicate web login username across principals: {username}");
            }
            web_logins.insert(
                username,
                WebLoginCredential {
                    principal: principal_name.clone(),
                    password_hash: password_hash.to_string(),
                },
            );
        }
    }

    let mut switch_acl: HashMap<String, SwitchJoinAcl> = HashMap::default();
    if let Some(rules) = cfg.acl.as_ref() {
        for rule in rules {
            let switch_name = rule.switch.trim();
            if switch_name.is_empty() {
                bail!("acl switch must not be empty");
            }
            if !switches.contains_key(switch_name) {
                bail!("acl references unknown switch: {switch_name}");
            }
            if switch_acl.contains_key(switch_name) {
                bail!("duplicate acl rule for switch: {switch_name}");
            }

            let mut acl_principals: HashSet<String> = HashSet::new();
            if let Some(entries) = rule.principals.as_ref() {
                for principal in entries {
                    let principal = principal.trim().to_lowercase();
                    if principal.is_empty() {
                        bail!("acl for switch {switch_name} has empty principal entry");
                    }
                    if !known_principals.contains(&principal) {
                        bail!(
                            "acl for switch {switch_name} references unknown principal: {principal}"
                        );
                    }
                    acl_principals.insert(principal);
                }
            }

            let mut acl_groups: HashSet<String> = HashSet::new();
            if let Some(entries) = rule.groups.as_ref() {
                for group in entries {
                    let group = group.trim().to_lowercase();
                    if group.is_empty() {
                        bail!("acl for switch {switch_name} has empty group entry");
                    }
                    if !known_groups.contains(&group) {
                        bail!("acl for switch {switch_name} references unknown group: {group}");
                    }
                    acl_groups.insert(group);
                }
            }

            if acl_principals.is_empty() && acl_groups.is_empty() {
                bail!("acl for switch {switch_name} must include principals and/or groups");
            }

            switch_acl.insert(
                switch_name.to_string(),
                SwitchJoinAcl {
                    principals: acl_principals,
                    groups: acl_groups,
                },
            );
        }
    }

    let mut admin_groups: HashSet<String> = HashSet::new();
    let configured_admin_groups = match cfg.admin_groups.clone() {
        Some(v) if !v.is_empty() => v,
        _ => vec!["admin".to_string()],
    };
    for group_name in configured_admin_groups {
        let group_name = group_name.trim().to_lowercase();
        if group_name.is_empty() {
            bail!("admin_groups contains empty group name");
        }
        if !known_groups.contains(&group_name) {
            bail!("admin_groups references unknown group: {group_name}");
        }
        admin_groups.insert(group_name);
    }
    if admin_groups.is_empty() {
        bail!("admin_groups resolution produced empty set");
    }

    Ok(Some(RpcAuthzState {
        api_credentials,
        web_logins,
        principal_groups,
        switch_acl,
        admin_groups,
        has_acl_rules: cfg.acl.is_some(),
    }))
}

fn run_rpc_server(bind: String, state: RpcState) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for rpc")?;
    rt.block_on(async move {
        let admin_routes = Router::new()
            .route(
                "/vswitch/admin/login",
                get(admin_login_page).post(admin_login_submit),
            )
            .route("/vswitch/admin/logout", get(admin_logout))
            .route("/vswitch/admin", get(admin_dashboard))
            .route("/vswitch/admin/switches/{name}", get(admin_switch_detail))
            .route("/vswitch/admin/reservations", get(admin_reservations))
            .route("/vswitch/admin/server-routes", get(admin_server_routes))
            .route("/vswitch/admin/client-routes", get(admin_client_routes))
            .route("/vswitch/admin/bridges", get(admin_bridges))
            .route("/vswitch/admin/networks", get(admin_networks))
            .route("/vswitch/admin/assets/app.css", get(admin_asset_css))
            .route("/vswitch/admin/assets/app.js", get(admin_asset_js))
            .layer(middleware::from_fn(admin_security_headers_middleware));

        let app = Router::new()
            .route("/vswitch/switches/list", get(rpc_list_switches))
            .route("/vswitch/switches/{name}/join", get(rpc_join_switch))
            .route("/vswitch/switches/{name}/peers", get(rpc_list_peers))
            .merge(admin_routes)
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .with_context(|| format!("failed to bind rpc {bind}"))?;
        info!("rpc listening on {bind}");
        axum::serve(listener, app)
            .await
            .context("rpc server terminated")?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

#[derive(Serialize)]
struct RpcSwitchList {
    switches: Vec<RpcSwitchView>,
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len && value.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("invalid hex length");
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex"))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex"))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

fn hmac_sha256_hex(secret: &str, msg: &str) -> Result<String> {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow!("invalid hmac key"))?;
    mac.update(msg.as_bytes());
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn verify_hmac_sha256(secret: &str, msg: &str, signature_hex: &str) -> bool {
    let sig = match decode_hex(signature_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut mac = match <HmacSha256 as hmac::Mac>::new_from_slice(secret.as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    mac.update(msg.as_bytes());
    mac.verify_slice(&sig).is_ok()
}

fn validate_and_mark_nonce(
    state: &RpcState,
    api_key: &str,
    nonce: &str,
    ts_ms: u64,
) -> Result<(), axum::http::StatusCode> {
    let now_ms = unix_now_ms();
    if now_ms > ts_ms.saturating_add(RPC_MAX_PAST_SKEW_MS) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    let mut cache = state
        .seen_nonces
        .lock()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    cache.retain(|_, seen_ms| now_ms.saturating_sub(*seen_ms) <= RPC_NONCE_TTL_MS);

    let cache_key = format!("{api_key}:{nonce}");
    if cache.contains_key(&cache_key) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    cache.insert(cache_key, now_ms);
    Ok(())
}

fn authenticate_principal(
    headers: &HeaderMap,
    state: &RpcState,
    query_string: &str,
) -> Result<String, axum::http::StatusCode> {
    let authz = state
        .authz
        .as_ref()
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let api_key = header_value(headers, "x-api-key")
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let nonce = header_value(headers, "x-client-nounce")
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let ts = header_value(headers, "x-client-ts")
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let signature = header_value(headers, "x-signature")
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    if !is_hex_of_len(&nonce, 64) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    if !is_hex_of_len(&signature, 64) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let ts_ms = ts
        .parse::<u64>()
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    let cred = authz
        .api_credentials
        .get(&api_key)
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let msg = format!("{query_string}{nonce}{ts_ms}");
    if !verify_hmac_sha256(&cred.api_secret, &msg, &signature) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    validate_and_mark_nonce(state, &api_key, &nonce, ts_ms)?;
    Ok(cred.principal.clone())
}

fn can_principal_join_switch(authz: &RpcAuthzState, principal: &str, switch_name: &str) -> bool {
    let principal = principal.to_lowercase();
    // Built-in admin group is a global ACL bypass.
    if authz
        .principal_groups
        .get(&principal)
        .is_some_and(|groups| groups.contains("admin"))
    {
        return true;
    }
    if !authz.has_acl_rules {
        return true;
    }
    let Some(rule) = authz.switch_acl.get(switch_name) else {
        return false;
    };
    if rule.principals.contains(&principal) {
        return true;
    }
    authz
        .principal_groups
        .get(&principal)
        .is_some_and(|groups| groups.iter().any(|g| rule.groups.contains(g)))
}

fn can_principal_access_admin(authz: &RpcAuthzState, principal: &str) -> bool {
    let principal = principal.to_lowercase();
    authz
        .principal_groups
        .get(&principal)
        .is_some_and(|groups| groups.iter().any(|g| authz.admin_groups.contains(g)))
}

fn parse_cookie(headers: &HeaderMap, key: &str) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn create_admin_session(state: &RpcState, principal: &str) -> Result<String, axum::http::StatusCode> {
    let mut raw = [0u8; 32];
    fill_random_bytes(&mut raw).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let sid = hex_encode(&raw);
    let now_ms = unix_now_ms();
    let mut sessions = state
        .admin_sessions
        .lock()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    sessions.retain(|_, sess| sess.expires_at_ms > now_ms);
    sessions.insert(
        sid.clone(),
        AdminSession {
            principal: principal.to_string(),
            expires_at_ms: now_ms.saturating_add(ADMIN_SESSION_TTL_MS),
        },
    );
    Ok(sid)
}

fn authenticate_admin_session(
    headers: &HeaderMap,
    state: &RpcState,
) -> Result<String, axum::http::StatusCode> {
    let authz = state
        .authz
        .as_ref()
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let sid = parse_cookie(headers, "vswitch_admin_session")
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let now_ms = unix_now_ms();
    let mut sessions = state
        .admin_sessions
        .lock()
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    sessions.retain(|_, sess| sess.expires_at_ms > now_ms);
    let session = sessions
        .get_mut(&sid)
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    if !can_principal_access_admin(authz, &session.principal) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    // Sliding expiration.
    session.expires_at_ms = now_ms.saturating_add(ADMIN_SESSION_TTL_MS);
    Ok(session.principal.clone())
}

async fn fetch_admin_snapshot(state: &RpcState) -> Result<AdminSnapshot, axum::http::StatusCode> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .cmd_tx
        .send(ControlPlaneCmd::AdminSnapshot { resp: tx })
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    signal_eventfd(state.event_fd).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    rx.await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn rpc_list_switches(
    State(state): State<RpcState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<RpcSwitchList>, axum::http::StatusCode> {
    let _ = authenticate_principal(&headers, &state, uri.query().unwrap_or(""))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    if state
        .cmd_tx
        .send(ControlPlaneCmd::ListSwitches { resp: tx })
        .is_err()
    {
        return Ok(Json(RpcSwitchList {
            switches: Vec::new(),
        }));
    }
    if signal_eventfd(state.event_fd).is_err() {
        return Ok(Json(RpcSwitchList {
            switches: Vec::new(),
        }));
    }
    let switches = rx.await.unwrap_or_default();
    Ok(Json(RpcSwitchList { switches }))
}

#[derive(Serialize, Deserialize, Clone)]
struct JoinResponse {
    token: String,
    listener: String,
    ipv4: String,
    crypt_method: String,
    crypt_key: String,
    gateway: Option<String>,
    routes: Vec<RouteSpec>,
    dns: Option<String>,
}

async fn rpc_join_switch(
    AxumPath(name): AxumPath<String>,
    Query(query): Query<JoinQuery>,
    State(state): State<RpcState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<JoinResponse>, axum::http::StatusCode> {
    let principal = authenticate_principal(&headers, &state, uri.query().unwrap_or(""))?;
    if let Some(authz) = state.authz.as_ref()
        && !can_principal_join_switch(authz, &principal, &name)
    {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    if let Some(qs) = query.switch.as_deref()
        && qs != name
    {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    let mac = query
        .mac
        .as_deref()
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let req_mac = parse_mac(mac).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let requested_ip = match query.requested_ip.as_deref() {
        Some(v) => Some(v.parse::<Ipv4Addr>().map_err(|_| axum::http::StatusCode::BAD_REQUEST)?),
        None => None,
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .cmd_tx
        .send(ControlPlaneCmd::Join {
            switch_name: name,
            mac: format_mac(&req_mac),
            principal,
            requested_ip: requested_ip.map(|v| v.to_string()),
            resp: tx,
        })
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    signal_eventfd(state.event_fd).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let res = rx
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    match res {
        Ok(v) => Ok(Json(v)),
        Err(code) => match code {
            400 => Err(axum::http::StatusCode::BAD_REQUEST),
            404 => Err(axum::http::StatusCode::NOT_FOUND),
            409 => Err(axum::http::StatusCode::CONFLICT),
            503 => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
            _ => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}

#[derive(Serialize)]
struct PeersResponse {
    switch: String,
    peers: Vec<RpcPeer>,
}

async fn rpc_list_peers(
    AxumPath(name): AxumPath<String>,
    State(state): State<RpcState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<PeersResponse>, axum::http::StatusCode> {
    let _ = authenticate_principal(&headers, &state, uri.query().unwrap_or(""))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .cmd_tx
        .send(ControlPlaneCmd::ListPeers {
            switch_name: name.clone(),
            resp: tx,
        })
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    signal_eventfd(state.event_fd).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let res = rx
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let peers = match res {
        Ok(p) => p,
        Err(404) => return Err(axum::http::StatusCode::NOT_FOUND),
        Err(_) => return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
    };
    Ok(Json(PeersResponse { switch: name, peers }))
}

const ADMIN_SHELL_HTML: &[u8] = include_bytes!("../templates/admin/shell.html");
const ADMIN_LOGIN_HTML: &[u8] = include_bytes!("../templates/admin/login.html");
const ADMIN_DASHBOARD_HTML: &[u8] = include_bytes!("../templates/admin/dashboard.html");
const ADMIN_SWITCH_DETAIL_HTML: &[u8] = include_bytes!("../templates/admin/switch_detail.html");
const ADMIN_RESERVATIONS_HTML: &[u8] = include_bytes!("../templates/admin/reservations.html");
const ADMIN_ROUTES_HTML: &[u8] = include_bytes!("../templates/admin/routes.html");
const ADMIN_BRIDGES_HTML: &[u8] = include_bytes!("../templates/admin/bridges.html");
const ADMIN_NETWORKS_HTML: &[u8] = include_bytes!("../templates/admin/networks.html");
const ADMIN_CSS: &[u8] = include_bytes!("../templates/admin/app.css");
const ADMIN_JS: &[u8] = include_bytes!("../templates/admin/app.js");

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn embedded_utf8(bytes: &'static [u8], name: &str) -> String {
    std::str::from_utf8(bytes)
        .unwrap_or_else(|_| panic!("embedded template is not utf-8: {name}"))
        .to_string()
}

fn render_template(mut template: String, vars: &[(&str, String)]) -> String {
    for (key, value) in vars {
        let needle = format!("{{{{{}}}}}", key);
        template = template.replace(&needle, value);
    }
    template
}

fn build_bridge_tree_html(snapshot: &AdminSnapshot) -> String {
    if snapshot.bridges.is_empty() {
        return "<div class=\"tree-empty\">No bridges configured</div>".to_string();
    }
    let mut out = String::new();
    out.push_str("<div class=\"tree\"><ul>");
    for bridge in &snapshot.bridges {
        out.push_str("<li><span class=\"node bridge\">");
        out.push_str(&html_escape(&bridge.name));
        out.push_str("</span>");
        if bridge.members.is_empty() {
            out.push_str("<ul><li><span class=\"tree-empty\">(no members)</span></li></ul>");
        } else {
            out.push_str("<ul>");
            for member in &bridge.members {
                out.push_str("<li><span class=\"node switch\">");
                out.push_str(&html_escape(member));
                out.push_str("</span></li>");
            }
            out.push_str("</ul>");
        }
        out.push_str("</li>");
    }
    out.push_str("</ul></div>");
    out
}

fn admin_nav() -> &'static str {
    r#"<div class="nav">
<a href="/vswitch/admin">Dashboard</a>
<a href="/vswitch/admin/bridges">Bridges</a>
<a href="/vswitch/admin/networks">Networks</a>
<a href="/vswitch/admin/logout">Logout</a>
</div>"#
}

fn render_admin_shell(title: &str, principal: Option<&str>, body: String) -> Html<String> {
    let principal_html = principal
        .map(|p| format!(r#"<div class="sub">Signed in as <b>{}</b></div>"#, html_escape(p)))
        .unwrap_or_else(|| r#"<div class="sub">Authentication required</div>"#.to_string());
    let html = render_template(
        embedded_utf8(ADMIN_SHELL_HTML, "shell.html"),
        &[
            ("title", html_escape(title)),
            ("principal_html", principal_html),
            (
                "nav_html",
                if principal.is_some() {
                    admin_nav().to_string()
                } else {
                    String::new()
                },
            ),
            ("body", body),
        ],
    );
    Html(html)
}

fn render_admin_forbidden_page() -> Html<String> {
    let body = r#"
<div class="login-wrap">
  <div class="card">
    <h1 class="title">Admin Access Required</h1>
    <p class="muted">You are authenticated but not in an allowed admin group.</p>
    <div class="alert">Please log in using an account that belongs to an admin group.</div>
    <p class="mb14"><a class="btn" href="/vswitch/admin/logout">Logout</a></p>
  </div>
</div>
"#
    .to_string();
    render_admin_shell("admin access required", None, body)
}

async fn admin_asset_css() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        embedded_utf8(ADMIN_CSS, "app.css"),
    )
}

async fn admin_asset_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        embedded_utf8(ADMIN_JS, "app.js"),
    )
}

async fn admin_security_headers_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut res = next.run(req).await;
    if res.status() == axum::http::StatusCode::UNAUTHORIZED {
        res = Redirect::to("/vswitch/admin/login").into_response();
    } else if res.status() == axum::http::StatusCode::FORBIDDEN {
        res = render_admin_forbidden_page().into_response();
    }
    // Strict CSP without inline script/style.
    res.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    res.headers_mut()
        .insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    res.headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    res.headers_mut().insert(
        "referrer-policy",
        HeaderValue::from_static("no-referrer"),
    );
    res
}

fn render_admin_login_body(error: Option<&str>) -> String {
    let error_html = error
        .map(|msg| format!(r#"<div class="alert mb14">{}</div>"#, html_escape(msg)))
        .unwrap_or_default();
    render_template(
        embedded_utf8(ADMIN_LOGIN_HTML, "login.html"),
        &[("error_html", error_html)],
    )
}

async fn admin_login_page() -> Html<String> {
    let body = render_admin_login_body(None);
    render_admin_shell("vswitch admin login", None, body)
}

async fn admin_login_submit(
    State(state): State<RpcState>,
    Form(form): Form<AdminLoginForm>,
) -> Result<Response, axum::http::StatusCode> {
    let authz = state
        .authz
        .as_ref()
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
    let username = form.username.trim().to_lowercase();
    let Some(login) = authz.web_logins.get(&username) else {
        let body = render_admin_login_body(Some("Invalid username or password."));
        return Ok(render_admin_shell("vswitch admin login", None, body).into_response());
    };
    let verified = verify_bcrypt(&form.password, &login.password_hash).unwrap_or(false);
    if !verified {
        let body = render_admin_login_body(Some("Invalid username or password."));
        return Ok(render_admin_shell("vswitch admin login", None, body).into_response());
    }
    if !can_principal_access_admin(authz, &login.principal) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    let sid = create_admin_session(&state, &login.principal)?;
    let cookie = format!(
        "vswitch_admin_session={sid}; HttpOnly; Path=/; Max-Age={}; SameSite=Lax",
        ADMIN_SESSION_TTL_MS / 1000
    );
    let cookie_header =
        HeaderValue::from_str(&cookie).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(([(SET_COOKIE, cookie_header)], Redirect::to("/vswitch/admin")).into_response())
}

async fn admin_logout(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    if let Some(sid) = parse_cookie(&headers, "vswitch_admin_session")
        && let Ok(mut sessions) = state.admin_sessions.lock()
    {
        sessions.remove(&sid);
    }
    let cookie =
        "vswitch_admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax".to_string();
    let cookie_header =
        HeaderValue::from_str(&cookie).map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        [(SET_COOKIE, cookie_header)],
        Redirect::to("/vswitch/admin/login"),
    ))
}

async fn admin_dashboard(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let total_clients: usize = snapshot.switches.iter().map(|s| s.clients.len()).sum();
    let total_resv: usize = snapshot
        .switches
        .iter()
        .map(|s| s.address_reservations.len())
        .sum();
    let mut switch_to_bridge: HashMap<String, String> = HashMap::default();
    for bridge in &snapshot.bridges {
        for member in &bridge.members {
            switch_to_bridge.insert(member.clone(), bridge.name.clone());
        }
    }
    let bridge_tree = build_bridge_tree_html(&snapshot);
    let switch_rows = snapshot
        .switches
        .iter()
        .map(|sw| format!(
            "<tr><td><a href=\"/vswitch/admin/switches/{n}\">{n}</a></td><td>{bridge}</td><td>{tap}</td><td>{cidr}</td><td>{hip}</td><td>{cc}</td></tr>",
            n = html_escape(&sw.name),
            bridge = html_escape(
                switch_to_bridge
                    .get(&sw.name)
                    .map(String::as_str)
                    .unwrap_or("-")
            ),
            tap = html_escape(&sw.tap),
            cidr = html_escape(sw.cidr.as_deref().unwrap_or("-")),
            hip = html_escape(sw.host_ip.as_deref().unwrap_or("-")),
            cc = sw.clients.len()
        ))
        .collect::<String>();
    let body = render_template(
        embedded_utf8(ADMIN_DASHBOARD_HTML, "dashboard.html"),
        &[
            ("generated_at_ms", snapshot.generated_at_ms.to_string()),
            ("switches_count", snapshot.switches.len().to_string()),
            ("clients_count", total_clients.to_string()),
            ("reservations_count", total_resv.to_string()),
            ("bridges_count", snapshot.bridges.len().to_string()),
            ("bridge_tree_html", bridge_tree),
            ("switch_rows", switch_rows),
        ],
    );
    Ok(render_admin_shell("vswitch admin", Some(&principal), body))
}

async fn admin_switch_detail(
    AxumPath(name): AxumPath<String>,
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let sw = snapshot
        .switches
        .iter()
        .find(|s| s.name == name)
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    let client_rows = sw
        .clients
        .iter()
        .map(|c| format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.mac),
            html_escape(c.source_addr.as_deref().unwrap_or("-")),
            html_escape(c.assigned_ip.as_deref().unwrap_or("-")),
            html_escape(c.assigned_network.as_deref().unwrap_or("-")),
            c.last_packet_from_client_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            c.last_packet_to_client_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ))
        .collect::<String>();
    let server_route_rows = if sw.server_routes.is_empty() {
        "<tr><td colspan=\"2\" class=\"muted\">No server routes</td></tr>".to_string()
    } else {
        sw.server_routes
            .iter()
            .map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html_escape(&r.to),
                    html_escape(r.via.as_deref().unwrap_or("on-link"))
                )
            })
            .collect::<String>()
    };
    let client_route_rows = if sw.client_routes.is_empty() {
        "<tr><td colspan=\"2\" class=\"muted\">No client routes</td></tr>".to_string()
    } else {
        sw.client_routes
            .iter()
            .map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html_escape(&r.to),
                    html_escape(r.via.as_deref().unwrap_or("on-link"))
                )
            })
            .collect::<String>()
    };
    let reservation_rows = if sw.address_reservations.is_empty() {
        "<tr><td colspan=\"2\" class=\"muted\">No address reservations</td></tr>".to_string()
    } else {
        sw.address_reservations
            .iter()
            .map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html_escape(&r.mac),
                    html_escape(&r.ipv4),
                )
            })
            .collect::<String>()
    };
    let body = render_template(
        embedded_utf8(ADMIN_SWITCH_DETAIL_HTML, "switch_detail.html"),
        &[
            ("switch_name", html_escape(&sw.name)),
            ("tap", html_escape(&sw.tap)),
            ("host_mac", html_escape(&sw.host_mac)),
            ("host_ip", html_escape(sw.host_ip.as_deref().unwrap_or("-"))),
            ("cidr", html_escape(sw.cidr.as_deref().unwrap_or("-"))),
            ("client_rows", client_rows),
            ("server_route_rows", server_route_rows),
            ("client_route_rows", client_route_rows),
            ("reservation_rows", reservation_rows),
        ],
    );
    Ok(render_admin_shell(
        &format!("switch {}", sw.name),
        Some(&principal),
        body,
    ))
}

async fn admin_reservations(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let rows = snapshot
        .switches
        .iter()
        .flat_map(|sw| {
            sw.address_reservations.iter().map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&sw.name),
                    html_escape(&r.mac),
                    html_escape(&r.ipv4),
                )
            })
        })
        .collect::<String>();
    let body = render_template(
        embedded_utf8(ADMIN_RESERVATIONS_HTML, "reservations.html"),
        &[("rows", rows)],
    );
    Ok(render_admin_shell("reservations", Some(&principal), body))
}

async fn admin_server_routes(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let rows = snapshot
        .switches
        .iter()
        .flat_map(|sw| {
            sw.server_routes.iter().map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&sw.name),
                    html_escape(&r.to),
                    html_escape(r.via.as_deref().unwrap_or("on-link")),
                )
            })
        })
        .collect::<String>();
    let body = render_template(
        embedded_utf8(ADMIN_ROUTES_HTML, "routes.html"),
        &[
            ("title", "Server routes".to_string()),
            ("table_id", "tbl-sroutes".to_string()),
            ("rows", rows),
        ],
    );
    Ok(render_admin_shell("server routes", Some(&principal), body))
}

async fn admin_client_routes(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let rows = snapshot
        .switches
        .iter()
        .flat_map(|sw| {
            sw.client_routes.iter().map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&sw.name),
                    html_escape(&r.to),
                    html_escape(r.via.as_deref().unwrap_or("on-link")),
                )
            })
        })
        .collect::<String>();
    let body = render_template(
        embedded_utf8(ADMIN_ROUTES_HTML, "routes.html"),
        &[
            ("title", "Client routes".to_string()),
            ("table_id", "tbl-croutes".to_string()),
            ("rows", rows),
        ],
    );
    Ok(render_admin_shell("client routes", Some(&principal), body))
}

async fn admin_bridges(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let rows = snapshot
        .bridges
        .iter()
        .map(|b| format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape(&b.name),
            html_escape(&b.members.join(", ")),
        ))
        .collect::<String>();
    let body = render_template(
        embedded_utf8(ADMIN_BRIDGES_HTML, "bridges.html"),
        &[("rows", rows)],
    );
    Ok(render_admin_shell("bridges", Some(&principal), body))
}

async fn admin_networks(
    State(state): State<RpcState>,
    headers: HeaderMap,
) -> Result<Html<String>, axum::http::StatusCode> {
    let principal = authenticate_admin_session(&headers, &state)?;
    let snapshot = fetch_admin_snapshot(&state).await?;
    let mut switch_to_bridge: HashMap<String, String> = HashMap::default();
    for bridge in &snapshot.bridges {
        for member in &bridge.members {
            switch_to_bridge.insert(member.clone(), bridge.name.clone());
        }
    }
    let bridge_tree = build_bridge_tree_html(&snapshot);
    let rows = snapshot
        .switches
        .iter()
        .map(|sw| format!(
            "<tr><td><a href=\"/vswitch/admin/switches/{name}\">{name}</a></td><td>{bridge}</td><td>{cidr}</td><td>{host_ip}</td><td>{host_mac}</td><td>{tap}</td></tr>",
            name = html_escape(&sw.name),
            bridge = html_escape(
                switch_to_bridge
                    .get(&sw.name)
                    .map(String::as_str)
                    .unwrap_or("-")
            ),
            cidr = html_escape(sw.cidr.as_deref().unwrap_or("-")),
            host_ip = html_escape(sw.host_ip.as_deref().unwrap_or("-")),
            host_mac = html_escape(&sw.host_mac),
            tap = html_escape(&sw.tap),
        ))
        .collect::<String>();
    let body = render_template(
        embedded_utf8(ADMIN_NETWORKS_HTML, "networks.html"),
        &[("bridge_tree_html", bridge_tree), ("rows", rows)],
    );
    Ok(render_admin_shell("networks", Some(&principal), body))
}

fn process_control_plane_cmds(
    control: &mut ControlPlaneState,
    rx: &mpsc::Receiver<ControlPlaneCmd>,
    switches: &HashMap<u16, ServerSwitchState>,
    clients: &HashMap<RawFd, ClientMuxState>,
    bridges: &[BridgeState],
) -> Result<()> {
    loop {
        match rx.try_recv() {
            Ok(ControlPlaneCmd::ListSwitches { resp }) => {
                let _ = resp.send(control.switches.values().cloned().collect::<Vec<_>>());
            }
            Ok(ControlPlaneCmd::Join {
                switch_name,
                mac,
                principal,
                requested_ip,
                resp,
            }) => {
                let res = issue_join_token(
                    control,
                    &switch_name,
                    &mac,
                    &principal,
                    requested_ip.as_deref(),
                )
                    .map_err(|code| code as u16);
                let _ = resp.send(res);
            }
            Ok(ControlPlaneCmd::ListPeers { switch_name, resp }) => {
                if !control.switches.contains_key(&switch_name) {
                    let _ = resp.send(Err(404));
                } else {
                    let peers = control.peers.get(&switch_name).cloned().unwrap_or_default();
                    let _ = resp.send(Ok(peers));
                }
            }
            Ok(ControlPlaneCmd::AdminSnapshot { resp }) => {
                let _ = resp.send(build_admin_snapshot(control, switches, clients, bridges));
            }
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
    Ok(())
}

fn build_admin_snapshot(
    control: &ControlPlaneState,
    switches: &HashMap<u16, ServerSwitchState>,
    clients: &HashMap<RawFd, ClientMuxState>,
    bridges: &[BridgeState],
) -> AdminSnapshot {
    let mut switch_rows: Vec<AdminSwitchSnapshot> = Vec::new();
    for sw_view in control.switches.values() {
        let mut switch_clients: Vec<AdminClientSnapshot> = Vec::new();
        let switch_id = switches
            .iter()
            .find_map(|(id, sw)| (sw.name == sw_view.name).then_some(*id));
        if let Some(sid) = switch_id {
            for client in clients.values() {
                if let Some(binding) = client.binding.as_ref()
                    && binding.server_switch_id == sid
                {
                    let assigned_ip = binding
                        .assigned_ipv4
                        .as_deref()
                        .map(|v| v.split('/').next().unwrap_or(v).to_string());
                    switch_clients.push(AdminClientSnapshot {
                        mac: format_mac(&binding.mac),
                        source_addr: client.peer_addr.clone(),
                        assigned_ip,
                        assigned_network: binding.assigned_ipv4.clone(),
                        last_packet_from_client_ms: client.last_from_client_ms,
                        last_packet_to_client_ms: client.last_to_client_ms,
                    });
                }
            }
        }
        switch_clients.sort_by(|a, b| a.mac.cmp(&b.mac));

        let mut reservations: Vec<AdminReservationSnapshot> = sw_view
            .address_reservations
            .iter()
            .map(|(mac, v)| AdminReservationSnapshot {
                mac: mac.clone(),
                ipv4: v.ip.to_string(),
            })
            .collect();
        reservations.sort_by(|a, b| a.mac.cmp(&b.mac));

        switch_rows.push(AdminSwitchSnapshot {
            name: sw_view.name.clone(),
            tap: sw_view.tap.clone(),
            host_ip: sw_view.host_ip.clone(),
            cidr: sw_view.cidr.clone(),
            host_mac: sw_view.host_mac.clone(),
            server_routes: sw_view.server_routes.clone(),
            client_routes: sw_view.client_routes.clone(),
            address_reservations: reservations,
            clients: switch_clients,
        });
    }
    switch_rows.sort_by(|a, b| a.name.cmp(&b.name));

    let mut bridge_rows = Vec::new();
    for bridge in bridges {
        let mut members: Vec<String> = bridge
            .members
            .iter()
            .filter_map(|sid| switches.get(sid).map(|sw| sw.name.clone()))
            .collect();
        members.sort();
        bridge_rows.push(AdminBridgeSnapshot {
            name: bridge.name.clone(),
            members,
        });
    }

    AdminSnapshot {
        generated_at_ms: unix_now_ms(),
        switches: switch_rows,
        bridges: bridge_rows,
    }
}

fn issue_join_token(
    control: &mut ControlPlaneState,
    switch_name: &str,
    mac: &str,
    principal: &str,
    requested_ip: Option<&str>,
) -> std::result::Result<JoinResponse, i32> {
    let principal = principal.to_lowercase();
    prune_grants(control);
    if control.crypto_method != "AES-GCM-256" {
        return Err(503);
    }
    let sw = control.switches.get(switch_name).cloned().ok_or(404)?;
    let secret = control.jwt_secret.clone().ok_or(503)?;
    let req_mac = parse_mac(mac).map_err(|_| 400)?;
    let requested_ip = match requested_ip {
        Some(v) => Some(v.parse::<Ipv4Addr>().map_err(|_| 400)?),
        None => None,
    };
    let (assigned_ip, cidr) =
        assign_ip_for_switch(control, switch_name, &sw, &req_mac, requested_ip).ok_or(409)?;
    let (_, prefix) = parse_cidr(&cidr).map_err(|_| 500)?;
    let assigned_ipv4 = format!("{assigned_ip}/{prefix}");
    let now = unix_now();
    let jti = format!(
        "{}-{}",
        now,
        NEXT_JTI.fetch_add(1, AtomicOrdering::Relaxed)
    );
    let claims = JoinClaims {
        iat: now,
        exp: now + 60,
        principal,
        switch: switch_name.to_string(),
        mac: format_mac(&req_mac),
        ipv4: assigned_ipv4,
        crypt_method: control.crypto_method.clone(),
        crypt_key: generate_session_key_hex(32)?,
        gateway: sw.host_ip.clone(),
        routes: sw.client_routes.clone(),
        dns: None,
        jti: jti.clone(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| 500)?;
    control.grants.insert(
        jti,
        JoinGrantState {
            claims: claims.clone(),
        },
    );
    Ok(JoinResponse {
        token,
        listener: control.advertised_listener.clone(),
        ipv4: claims.ipv4.clone(),
        crypt_method: claims.crypt_method.clone(),
        crypt_key: claims.crypt_key.clone(),
        gateway: claims.gateway.clone(),
        routes: claims.routes.clone(),
        dns: claims.dns.clone(),
    })
}

fn create_eventfd() -> Result<RawFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn signal_eventfd(fd: RawFd) -> Result<()> {
    let one: u64 = 1;
    let ptr = &one as *const u64 as *const libc::c_void;
    let n = unsafe { libc::write(fd, ptr, std::mem::size_of::<u64>()) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn drain_eventfd(fd: RawFd) -> Result<()> {
    loop {
        let mut buf: u64 = 0;
        let ptr = &mut buf as *mut u64 as *mut libc::c_void;
        let n = unsafe { libc::read(fd, ptr, std::mem::size_of::<u64>()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            return Err(err.into());
        }
        if n == 0 {
            break;
        }
    }
    Ok(())
}

fn generate_session_key_hex(bytes: usize) -> std::result::Result<String, i32> {
    let mut buf = vec![0u8; bytes];
    fill_random_bytes(&mut buf).map_err(|_| 500)?;
    Ok(hex_encode(&buf))
}

fn fill_random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - filled,
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        filled += n as usize;
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn parse_hex_key_32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("invalid AES-256 key length: expected 64 hex chars");
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let pos = i * 2;
        *slot = u8::from_str_radix(&s[pos..pos + 2], 16)
            .with_context(|| format!("invalid hex key at byte {i}"))?;
    }
    Ok(out)
}

fn encrypt_payload_aes_gcm(
    key: &[u8; 32],
    direction: u8,
    counter: u64,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid AES key length"))?;
    let nonce_bytes = build_nonce(direction, counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plain, aad: &[] })
        .map_err(|_| anyhow!("aes-gcm encrypt failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_payload_aes_gcm(
    key: &[u8; 32],
    expected_direction: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() < 12 + 16 {
        bail!("encrypted payload too short");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&payload[..12]);
    if nonce_bytes[0] != expected_direction {
        bail!("nonce direction mismatch");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("invalid AES key length"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &payload[12..],
                aad: &[],
            },
        )
        .map_err(|_| anyhow!("aes-gcm decrypt failed"))
}

fn build_nonce(direction: u8, counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn assign_ip_for_switch(
    state: &ControlPlaneState,
    switch_name: &str,
    sw: &RpcSwitchView,
    req_mac: &Mac,
    requested_ip: Option<Ipv4Addr>,
) -> Option<(Ipv4Addr, String)> {
    let (cidr, first, last, network_u, broadcast_u) = if let Some(pool) = sw.client_ip_pool.as_ref() {
        let (network, prefix) = parse_cidr(&pool.cidr).ok()?;
        let mask = prefix_to_mask(prefix);
        let network_u = u32::from(network) & mask;
        let broadcast_u = network_u | !mask;
        (
            pool.cidr.clone(),
            pool.start,
            pool.end,
            network_u,
            broadcast_u,
        )
    } else {
        let cidr = sw.cidr.clone()?;
        let (network, prefix) = parse_cidr(&cidr).ok()?;
        let mask = prefix_to_mask(prefix);
        let network_u = u32::from(network) & mask;
        let broadcast_u = network_u | !mask;
        (
            cidr,
            network_u + 1,
            broadcast_u.saturating_sub(1),
            network_u,
            broadcast_u,
        )
    };
    let host_ip = sw
        .host_ip
        .as_deref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .map(u32::from);
    let req_mac_s = format_mac(req_mac);

    if let Some(reserved) = sw.address_reservations.get(&req_mac_s) {
        if let Some(req_ip) = requested_ip
            && req_ip != reserved.ip
        {
            return None;
        }
        let res_u = u32::from(reserved.ip);
        if Some(res_u) == host_ip {
            return None;
        }
        if state
            .peers
            .get(switch_name)
            .is_some_and(|peers| {
                peers.iter().any(|p| {
                    p.mac != req_mac_s
                        && p.ip
                            .as_deref()
                            .and_then(|v| v.parse::<Ipv4Addr>().ok())
                            .is_some_and(|ip| ip == reserved.ip)
                })
            })
        {
            return None;
        }
        for grant in state.grants.values() {
            if grant.claims.switch != switch_name || grant.claims.exp <= unix_now() {
                continue;
            }
            if grant.claims.mac == req_mac_s {
                continue;
            }
            if parse_ipv4_with_prefix(&grant.claims.ipv4)
                .ok()
                .is_some_and(|(ip, _)| ip == reserved.ip)
            {
                return None;
            }
        }
        return Some((reserved.ip, reserved.cidr.clone()));
    }

    if let Some(peers) = state.peers.get(switch_name)
        && let Some(existing) = peers.iter().find(|p| p.mac == req_mac_s)
        && let Some(ip_s) = existing.ip.as_deref()
        && let Ok(ip) = ip_s.parse::<Ipv4Addr>()
    {
        return Some((ip, cidr.clone()));
    }
    let mut used: Vec<u32> = state
        .peers
        .get(switch_name)
        .map(|p| {
            p.iter()
                .filter_map(|pp| pp.ip.as_deref().and_then(|v| v.parse::<Ipv4Addr>().ok()))
                .map(u32::from)
                .collect()
        })
        .unwrap_or_default();
    for grant in state.grants.values() {
        if grant.claims.switch != switch_name {
            continue;
        }
        if grant.claims.exp <= unix_now() {
            continue;
        }
        if grant.claims.mac == req_mac_s
            && let Ok((ip, _)) = parse_ipv4_with_prefix(&grant.claims.ipv4)
        {
            return Some((ip, cidr.clone()));
        }
        if let Ok((ip, _)) = parse_ipv4_with_prefix(&grant.claims.ipv4) {
            used.push(u32::from(ip));
        }
    }

    if let Some(req_ip) = requested_ip {
        let req_u = u32::from(req_ip);
        if req_u == network_u || req_u == broadcast_u {
            return None;
        }
        if req_u < first || req_u > last {
            return None;
        }
        if Some(req_u) == host_ip {
            return None;
        }
        if used.contains(&req_u) {
            return None;
        }
        return Some((req_ip, cidr));
    }

    for ip_u in first..=last {
        if Some(ip_u) == host_ip {
            continue;
        }
        if used.contains(&ip_u) {
            continue;
        }
        return Some((Ipv4Addr::from(ip_u), cidr));
    }
    None
}

fn prune_grants(state: &mut ControlPlaneState) {
    let now = unix_now();
    state.grants.retain(|_, grant| grant.claims.exp > now);
}

fn unix_now() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

fn unix_now_ms() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis().try_into().unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

static NEXT_JTI: AtomicU64 = AtomicU64::new(1);
static LAST_DROP_LOG_MS: AtomicU64 = AtomicU64::new(0);

fn should_emit_drop_log(now_ms: u64) -> bool {
    let mut last = LAST_DROP_LOG_MS.load(AtomicOrdering::Relaxed);
    loop {
        if now_ms.saturating_sub(last) < DROP_LOG_INTERVAL_MS {
            return false;
        }
        match LAST_DROP_LOG_MS.compare_exchange_weak(
            last,
            now_ms,
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => last = observed,
        }
    }
}

fn fetch_join_from_rpc(
    rpc_base: &str,
    api_key: Option<&str>,
    api_secret: Option<&str>,
    switch_name: &str,
    mac: &Mac,
    requested_ip: Option<Ipv4Addr>,
) -> Result<JoinResponse> {
    let base = rpc_base.trim_end_matches('/');
    let mut url = reqwest::Url::parse(&format!("{base}/vswitch/switches/{switch_name}/join"))
        .context("invalid rpc URL")?;
    let client = reqwest::blocking::Client::new();
    let mac_s = format_mac(mac);
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("switch", switch_name);
        qp.append_pair("mac", &mac_s);
        if let Some(ip) = requested_ip {
            qp.append_pair("requested_ip", &ip.to_string());
        }
    }

    let mut req = client.get(url.clone());
    if let Some(key) = api_key {
        req = req.header("x-api-key", key);
    }
    if let Some(secret) = api_secret {
        let mut nonce_bytes = [0u8; 32];
        fill_random_bytes(&mut nonce_bytes).context("failed to generate rpc nonce")?;
        let nonce = hex_encode(&nonce_bytes);
        let ts_ms = unix_now_ms();
        let query_string = url.query().unwrap_or("");
        let msg = format!("{query_string}{nonce}{ts_ms}");
        let signature =
            hmac_sha256_hex(secret, &msg).context("failed to create rpc hmac signature")?;
        req = req
            .header("x-client-nounce", nonce)
            .header("x-client-ts", ts_ms.to_string())
            .header("x-signature", signature);
    }
    let resp = req.send().context("rpc join request failed")?;
    if !resp.status().is_success() {
        bail!("rpc join failed with status {}", resp.status());
    }
    resp.json::<JoinResponse>()
        .context("invalid rpc join response")
}

fn write_error_msg_best_effort(
    stream: &mut TcpStream,
    code: u8,
) -> Result<()> {
    let buf = [CTRL_ERROR, code];
    match stream.write(&buf) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn resolve_config_path(mode: &str, config: Option<String>) -> Result<String> {
    if let Some(path) = config {
        return Ok(path);
    }

    let candidates: &[&str] = match mode {
        "server" => &["vswitch-server.yml", "server.yml", "vswitch.yml"],
        "client" => &["vswitch-client.yml", "client.yml", "vswitch.yml"],
        _ => &["vswitch.yml"],
    };
    for cand in candidates {
        if Path::new(cand).exists() {
            info!("auto-loaded config: {cand}");
            return Ok((*cand).to_string());
        }
    }

    Err(anyhow!(
        "no config found for mode `{mode}`. pass -c/--config or create one of: {}",
        candidates.join(", ")
    ))
}

#[derive(Clone)]
struct ClientSwitchConfigTop {
    switch: String,
    tap: String,
    mac: Option<String>,
}

fn single_client_switch_from_config(cfg: &ClientConfig) -> Result<ClientSwitchConfigTop> {
    if let (Some(switch), Some(tap)) = (cfg.switch.as_deref(), cfg.tap.as_deref()) {
        return Ok(ClientSwitchConfigTop {
            switch: switch.to_string(),
            tap: tap.to_string(),
            mac: cfg.mac.clone(),
        });
    }

    Err(anyhow!(
        "client config requires top-level `switch` and `tap`"
    ))
}

fn read_frame_from_tap(file: &File, out: &mut [u8; ETH_MAX_FRAME]) -> io::Result<Option<Vec<u8>>> {
    let mut reader = file;
    match reader.read(out) {
        Ok(0) => Ok(None),
        Ok(n) => Ok(Some(out[..n].to_vec())),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(err),
    }
}

fn write_frame_to_tap(file: &File, frame: &[u8]) -> Result<()> {
    let mut writer = file;
    write_all_tap_retry(&mut writer, frame).map_err(Into::into)
}

fn write_all_tap_retry(writer: &mut dyn Write, frame: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < frame.len() {
        match writer.write(&frame[written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TAP write returned zero bytes",
                ));
            }
            Ok(n) => written += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn is_broadcast(mac: &Mac) -> bool {
    mac.iter().all(|b| *b == 0xff)
}

fn is_multicast(mac: &Mac) -> bool {
    !is_broadcast(mac) && (mac[0] & 0x01) != 0
}

fn should_write_frame_to_tap(frame: &[u8], tap_has_ipv6: bool) -> bool {
    if is_ipv6_frame(frame) {
        tap_has_ipv6
    } else {
        true
    }
}

fn is_ipv6_frame(frame: &[u8]) -> bool {
    matches!(frame_ethertype(frame), Some(0x86DD))
}

fn frame_ethertype(frame: &[u8]) -> Option<u16> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == 0x8100 || ethertype == 0x88A8 {
        if frame.len() < 18 {
            return None;
        }
        return Some(u16::from_be_bytes([frame[16], frame[17]]));
    }
    Some(ethertype)
}

fn format_mac(mac: &Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn parse_mac(s: &str) -> Result<Mac> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC format: {s}");
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            bail!("invalid MAC octet: {p}");
        }
        mac[i] = u8::from_str_radix(p, 16).with_context(|| format!("invalid MAC octet: {p}"))?;
    }
    Ok(mac)
}

fn create_tap(requested_name: &str, nonblock: bool) -> Result<TapDevice> {
    let mut flags = libc::O_RDWR;
    if nonblock {
        flags |= libc::O_NONBLOCK;
    }

    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let mut ifr = IfReqFlags {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: IFF_TAP | IFF_NO_PI,
        _pad: [0; 24 - std::mem::size_of::<libc::c_short>()],
    };
    write_ifname(&mut ifr.ifr_name, requested_name)?;

    let ret = unsafe { libc::ioctl(fd, TUNSETIFF as _, &ifr) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err.into());
    }

    let file = unsafe { File::from_raw_fd(fd) };
    let name = ifname_from_c(&ifr.ifr_name);
    Ok(TapDevice { file, name })
}

fn get_iface_mac(if_name: &str) -> Result<Mac> {
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let mut ifr = IfReqHwaddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_hwaddr: libc::sockaddr {
            sa_family: 0,
            sa_data: [0; 14],
        },
        _pad: [0; 24 - std::mem::size_of::<libc::sockaddr>()],
    };
    write_ifname(&mut ifr.ifr_name, if_name)?;

    let ret = unsafe { libc::ioctl(s, libc::SIOCGIFHWADDR as _, &mut ifr) };
    let close_ret = unsafe { libc::close(s) };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if close_ret < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let mut mac = [0u8; 6];
    for (i, slot) in mac.iter_mut().enumerate() {
        *slot = ifr.ifr_hwaddr.sa_data[i] as u8;
    }
    Ok(mac)
}

fn set_iface_mac(if_name: &str, mac: Mac) -> Result<()> {
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let mut ifr = IfReqHwaddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_hwaddr: libc::sockaddr {
            sa_family: libc::ARPHRD_ETHER as libc::sa_family_t,
            sa_data: [0; 14],
        },
        _pad: [0; 24 - std::mem::size_of::<libc::sockaddr>()],
    };
    write_ifname(&mut ifr.ifr_name, if_name)?;
    for (idx, b) in mac.iter().enumerate() {
        ifr.ifr_hwaddr.sa_data[idx] = *b as libc::c_char;
    }

    let ret = unsafe { libc::ioctl(s, libc::SIOCSIFHWADDR as _, &ifr) };
    let close_ret = unsafe { libc::close(s) };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if close_ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn configure_iface_ipv4(if_name: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    // Prefer `ip` because it reliably sets address + connected route across distros.
    if configure_iface_with_ip_cmd(if_name, ip, prefix).is_ok() {
        return Ok(());
    }

    let netmask = prefix_to_netmask(prefix);
    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        return Err(io::Error::last_os_error().into());
    }

    let config_result = (|| -> Result<()> {
        set_iface_up(s, if_name)?;
        set_iface_addr(s, if_name, libc::SIOCSIFADDR as _, ip)?;
        set_iface_addr(s, if_name, libc::SIOCSIFNETMASK as _, netmask)?;
        Ok(())
    })();

    let close_ret = unsafe { libc::close(s) };
    config_result?;
    if close_ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn configure_iface_with_ip_cmd(if_name: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    let addr = format!("{ip}/{prefix}");
    run_ip_cmd(&["link", "set", "dev", if_name, "up"])?;
    run_ip_cmd(&["addr", "replace", &addr, "dev", if_name])?;
    Ok(())
}

fn run_ip_cmd(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!(
            "`ip {}` failed: {}",
            args.join(" "),
            if stderr.is_empty() { "unknown error" } else { &stderr }
        );
    }
    Ok(())
}

fn configure_tcp_keepalive(
    stream: &TcpStream,
    idle_secs: i32,
    interval_secs: i32,
    probes: i32,
) -> Result<()> {
    let fd = stream.as_raw_fd();
    let on: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error()).context("setsockopt SO_KEEPALIVE failed");
    }
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            (&idle_secs as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error()).context("setsockopt TCP_KEEPIDLE failed");
    }
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            (&interval_secs as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error()).context("setsockopt TCP_KEEPINTVL failed");
    }
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            (&probes as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error()).context("setsockopt TCP_KEEPCNT failed");
    }
    Ok(())
}

fn add_route_via_iface(route: &RouteSpec, if_name: &str) -> Result<()> {
    let (network, prefix) = parse_cidr(&route.to)?;
    let mask = prefix_to_mask(prefix);
    let normalized = Ipv4Addr::from(u32::from(network) & mask);
    let to = format!("{normalized}/{prefix}");
    if let Some(via) = route.via.as_deref() {
        let via = via
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid route via: {via}"))?;
        let via_s = via.to_string();
        run_ip_cmd(&["route", "replace", &to, "via", &via_s, "dev", if_name])
    } else {
        run_ip_cmd(&["route", "replace", &to, "dev", if_name])
    }
}


fn set_iface_addr(sock: RawFd, if_name: &str, req: libc::c_ulong, addr: Ipv4Addr) -> Result<()> {
    let mut ifr = IfReqAddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_addr: sockaddr_from_ipv4(addr),
        _pad: [0; 24 - std::mem::size_of::<libc::sockaddr>()],
    };
    write_ifname(&mut ifr.ifr_name, if_name)?;
    let ret = unsafe { libc::ioctl(sock, req as _, &ifr) };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_iface_up(sock: RawFd, if_name: &str) -> Result<()> {
    let mut ifr = IfReqFlags {
        ifr_name: [0; IFNAMSIZ],
        ifr_flags: 0,
        _pad: [0; 24 - std::mem::size_of::<libc::c_short>()],
    };
    write_ifname(&mut ifr.ifr_name, if_name)?;

    let ret_get = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) };
    if ret_get < 0 {
        return Err(io::Error::last_os_error().into());
    }

    ifr.ifr_flags |= libc::IFF_UP as libc::c_short;
    ifr.ifr_flags &= !(libc::IFF_NOARP as libc::c_short);
    let ret_set = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
    if ret_set < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn sockaddr_from_ipv4(ip: Ipv4Addr) -> libc::sockaddr {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr) }
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (network, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR format: {cidr}"))?;
    let network = network
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid CIDR network address: {network}"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid CIDR prefix: {prefix}"))?;
    if prefix > 32 {
        bail!("CIDR prefix must be <= 32: {prefix}");
    }
    Ok((network, prefix))
}

fn cidr_to_range(cidr: &str) -> Result<(u32, u32)> {
    let (network, prefix) = parse_cidr(cidr)?;
    let mask = prefix_to_mask(prefix);
    let start = u32::from(network) & mask;
    let end = start | !mask;
    Ok((start, end))
}

fn parse_ignore_server_routes(ignore_server_routes: &[String]) -> Result<Vec<(u32, u32)>> {
    let mut ranges = Vec::with_capacity(ignore_server_routes.len());
    for cidr in ignore_server_routes {
        ranges.push(
            cidr_to_range(cidr)
                .with_context(|| format!("invalid ignore_server_routes CIDR: {cidr}"))?,
        );
    }
    Ok(ranges)
}

fn is_server_route_ignored(route: &RouteSpec, ignored_ranges: &[(u32, u32)]) -> Result<bool> {
    if ignored_ranges.is_empty() {
        return Ok(false);
    }
    let (route_start, route_end) =
        cidr_to_range(&route.to).with_context(|| format!("invalid server route CIDR: {}", route.to))?;
    Ok(ignored_ranges
        .iter()
        .any(|(ignore_start, ignore_end)| route_start <= *ignore_end && *ignore_start <= route_end))
}

fn route_via_is_self(route: &RouteSpec, self_ip: Ipv4Addr) -> Result<bool> {
    let Some(via) = route.via.as_deref() else {
        return Ok(false);
    };
    let via_ip = via
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid route via: {via}"))?;
    Ok(via_ip == self_ip)
}

fn normalize_route(route: &RouteSpec) -> Result<RouteSpec> {
    let (network, prefix) = parse_cidr(&route.to)?;
    let mask = prefix_to_mask(prefix);
    let normalized = Ipv4Addr::from(u32::from(network) & mask);
    Ok(RouteSpec {
        to: format!("{normalized}/{prefix}"),
        via: route.via.clone(),
    })
}

fn normalize_routes(routes: Vec<RouteSpec>, context: &str) -> Result<Vec<RouteSpec>> {
    routes
        .into_iter()
        .map(|route| {
            normalize_route(&route).with_context(|| {
                format!(
                    "invalid {} entry: to={} via={}",
                    context,
                    route.to,
                    route.via.as_deref().unwrap_or("on-link")
                )
            })
        })
        .collect()
}

fn parse_ipv4_with_prefix(addr: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip_s, prefix_s) = addr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid ipv4/prefix format: {addr}"))?;
    let ip = ip_s
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid ipv4 address: {ip_s}"))?;
    let prefix = prefix_s
        .parse::<u8>()
        .with_context(|| format!("invalid ipv4 prefix: {prefix_s}"))?;
    if prefix > 32 {
        bail!("ipv4 prefix must be <= 32: {prefix}");
    }
    Ok((ip, prefix))
}

fn parse_client_ip_pool(spec: &str) -> Result<ClientIpPool> {
    let (range, prefix_s) = spec
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid client_ip_pool format: {spec}"))?;
    let (start_s, end_s) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("invalid client_ip_pool range format: {range}"))?;
    let start_ip = start_s
        .trim()
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid client_ip_pool start IP: {start_s}"))?;
    let end_ip = end_s
        .trim()
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid client_ip_pool end IP: {end_s}"))?;
    let prefix = prefix_s
        .trim()
        .parse::<u8>()
        .with_context(|| format!("invalid client_ip_pool prefix: {prefix_s}"))?;
    if prefix > 32 {
        bail!("client_ip_pool prefix must be <= 32: {prefix}");
    }

    let start_u = u32::from(start_ip);
    let end_u = u32::from(end_ip);
    if start_u > end_u {
        bail!("client_ip_pool start must be <= end: {spec}");
    }

    let mask = prefix_to_mask(prefix);
    let network_u = start_u & mask;
    let broadcast_u = network_u | !mask;
    if (end_u & mask) != network_u {
        bail!("client_ip_pool range must be inside one /{prefix} network: {spec}");
    }
    if start_u == network_u || end_u == broadcast_u {
        bail!("client_ip_pool range must not include network/broadcast address: {spec}");
    }

    Ok(ClientIpPool {
        start: start_u,
        end: end_u,
        cidr: format!("{}/{}", Ipv4Addr::from(network_u), prefix),
    })
}

fn iface_has_ipv6(if_name: &str) -> Result<bool> {
    let data = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(d) => d,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        let _addr = parts.next();
        let _if_idx = parts.next();
        let _prefix = parts.next();
        let _scope = parts.next();
        let _flags = parts.next();
        let name = parts.next();
        if name == Some(if_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(prefix_to_mask(prefix))
}

fn write_ifname(dst: &mut [libc::c_char; IFNAMSIZ], name: &str) -> Result<()> {
    if name.len() >= IFNAMSIZ {
        bail!("interface name too long: {name}");
    }
    for b in dst.iter_mut() {
        *b = 0;
    }
    for (i, b) in name.as_bytes().iter().enumerate() {
        dst[i] = *b as libc::c_char;
    }
    Ok(())
}

fn ifname_from_c(src: &[libc::c_char; IFNAMSIZ]) -> String {
    let bytes: Vec<u8> = src
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

fn epoll_create() -> Result<RawFd> {
    let fd = unsafe { libc::epoll_create1(0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn epoll_add(epfd: RawFd, fd: RawFd, events: u32) -> Result<()> {
    let mut event = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    let ret = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut event) };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn epoll_mod(epfd: RawFd, fd: RawFd, events: u32) -> Result<()> {
    let mut event = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    let ret = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, fd, &mut event) };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn epoll_del(epfd: RawFd, fd: RawFd) -> Result<()> {
    let ret = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
    if ret < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn epoll_wait(epfd: RawFd, events: &mut [libc::epoll_event], timeout_ms: i32) -> Result<usize> {
    let n = unsafe {
        libc::epoll_wait(
            epfd,
            events.as_mut_ptr(),
            i32::try_from(events.len()).map_err(|_| anyhow!("events len overflow"))?,
            timeout_ms,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(n as usize)
}
