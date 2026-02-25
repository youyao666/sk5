#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use fast_socks5::{
    server::{DnsResolveHelper as _, Socks5ServerProtocol},
    util::target_addr::TargetAddr,
    ReplyError, Socks5Command, SocksError,
};
use socket2::{Domain, Protocol, Socket, Type};
use ipnet::Ipv6Net;
use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::signal;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct RotationState {
    next_cidr_idx: Mutex<usize>,
    next_host_by_cidr: Mutex<Vec<u128>>,
}

impl RotationState {
    fn new(allowed_ipv6_cidrs: &[Ipv6Net]) -> Self {
        Self {
            next_cidr_idx: Mutex::new(0),
            next_host_by_cidr: Mutex::new(vec![0; allowed_ipv6_cidrs.len()]),
        }
    }
}

#[derive(Clone, Debug)]
struct RuntimeConfig {
    listen_port: u16,
    request_timeout: Duration,
    shutdown_grace_period: Duration,
    max_connections: usize,
    auth_password: String,
    fixed_public_ipv6: Option<Ipv6Addr>,
    allowed_ipv6_cidrs: Vec<Ipv6Net>,
    rotation_state: Arc<RotationState>,
}

impl RuntimeConfig {
    async fn from_env() -> Result<Self> {
        let listen_port = env::var("SOCKS5_LISTEN_PORT")
            .ok()
            .map(|v| {
                v.parse::<u16>()
                    .with_context(|| format!("SOCKS5_LISTEN_PORT 非法: {v}"))
            })
            .transpose()?
            .unwrap_or(1080);

        let request_timeout_secs = env::var("SOCKS5_REQUEST_TIMEOUT_SECS")
            .ok()
            .map(|v| {
                v.parse::<u64>()
                    .with_context(|| format!("SOCKS5_REQUEST_TIMEOUT_SECS 非法: {v}"))
            })
            .transpose()?
            .unwrap_or(10);

        let shutdown_grace_secs = env::var("SOCKS5_SHUTDOWN_GRACE_SECS")
            .ok()
            .map(|v| {
                v.parse::<u64>()
                    .with_context(|| format!("SOCKS5_SHUTDOWN_GRACE_SECS 非法: {v}"))
            })
            .transpose()?
            .unwrap_or(30);

        let max_connections = env::var("SOCKS5_MAX_CONNECTIONS")
            .ok()
            .map(|v| {
                v.parse::<usize>()
                    .with_context(|| format!("SOCKS5_MAX_CONNECTIONS 非法: {v}"))
            })
            .transpose()?
            .unwrap_or(1024);

        if max_connections == 0 {
            anyhow::bail!("SOCKS5_MAX_CONNECTIONS 不能为 0");
        }

        let auth_password = env::var("SOCKS5_PASSWORD")
            .context("缺少必填环境变量 SOCKS5_PASSWORD（全局固定连接密码）")?;

        if auth_password.trim().is_empty() {
            anyhow::bail!("SOCKS5_PASSWORD 不能为空");
        }

        let allowed_ipv6_cidrs = parse_allowed_ipv6_cidrs_from_env()?;
        let fixed_public_ipv6 = if allowed_ipv6_cidrs.is_empty() {
            Some(detect_public_ipv6().await?)
        } else {
            None
        };

        let rotation_state = Arc::new(RotationState::new(&allowed_ipv6_cidrs));

        Ok(Self {
            listen_port,
            request_timeout: Duration::from_secs(request_timeout_secs),
            shutdown_grace_period: Duration::from_secs(shutdown_grace_secs),
            max_connections,
            auth_password,
            fixed_public_ipv6,
            allowed_ipv6_cidrs,
            rotation_state,
        })
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();

    let cfg = Arc::new(RuntimeConfig::from_env().await?);
    let listener = bind_dual_stack_single_port(cfg.listen_port)
        .with_context(|| format!("监听端口 {} 失败", cfg.listen_port))?;

    if cfg.allowed_ipv6_cidrs.is_empty() {
        if let Some(v6) = cfg.fixed_public_ipv6 {
            info!(
                listen = %format!("[::]:{}", cfg.listen_port),
                auth_user_decimal = %ipv6_to_decimal_string(v6),
                source_ipv6 = %v6,
                "SOCKS5 代理服务已启动（用户名=IPv6转u128十进制字符串）"
            );
        }
    } else {
        let cidr_list = cfg
            .allowed_ipv6_cidrs
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        info!(
            listen = %format!("[::]:{}", cfg.listen_port),
            allowed_ipv6_cidrs = %cidr_list,
            "SOCKS5 代理服务已启动（支持 username=rotation 轮询轮换；或 username=IPv6转u128十进制）"
        );
    }

    run_accept_loop(listener, cfg).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}

fn bind_dual_stack_single_port(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
        .context("创建 IPv6 TCP socket 失败")?;

    socket
        .set_reuse_address(true)
        .context("设置 SO_REUSEADDR 失败")?;

    socket
        .set_only_v6(false)
        .context("设置 IPV6_V6ONLY=false 失败（无法启用双栈）")?;

    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("绑定地址 {bind_addr} 失败"))?;

    socket.listen(4096).context("socket listen 失败")?;
    socket
        .set_nonblocking(true)
        .context("设置非阻塞失败")?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).context("转换为 tokio TcpListener 失败")
}

async fn run_accept_loop(listener: TcpListener, cfg: Arc<RuntimeConfig>) -> Result<()> {
    let mut join_set: JoinSet<()> = JoinSet::new();
    let connection_limiter = Arc::new(tokio::sync::Semaphore::new(cfg.max_connections));

    loop {
        tokio::select! {
            signal = signal::ctrl_c() => {
                match signal {
                    Ok(()) => info!("收到 Ctrl+C，开始优雅关闭"),
                    Err(err) => warn!(error = %err, "监听 Ctrl+C 失败，仍继续执行关闭流程"),
                }
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, client_addr)) => {
                        info!(client = %client_addr, "客户端已连接");
                        let permit = match Arc::clone(&connection_limiter).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!(
                                    client = %client_addr,
                                    max_connections = cfg.max_connections,
                                    "连接数已达上限，拒绝新连接（内存保护）"
                                );
                                continue;
                            }
                        };

                        let task_cfg = Arc::clone(&cfg);
                        join_set.spawn(async move {
                            let _permit = permit;
                            if let Err(err) = handle_client(stream, client_addr, task_cfg).await {
                                warn!(client = %client_addr, "连接处理失败/已拒绝: {err}");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "accept 失败，继续监听");
                    }
                }
            }
        }
    }

    let grace_timer = tokio::time::sleep(cfg.shutdown_grace_period);
    tokio::pin!(grace_timer);

    while !join_set.is_empty() {
        tokio::select! {
            _ = &mut grace_timer => {
                warn!(
                    timeout_secs = cfg.shutdown_grace_period.as_secs(),
                    "优雅关闭超时，终止剩余连接任务"
                );
                join_set.abort_all();
                break;
            }
            next = join_set.join_next() => {
                if let Some(Err(err)) = next {
                    warn!(error = %err, "连接任务异常结束");
                }
            }
        }
    }

    while let Some(res) = join_set.join_next().await {
        if let Err(err) = res {
            warn!(error = %err, "终止阶段连接任务回收异常");
        }
    }

    info!("SOCKS5 服务已退出");
    Ok(())
}

async fn handle_client(
    stream: TcpStream,
    client_addr: SocketAddr,
    cfg: Arc<RuntimeConfig>,
) -> std::result::Result<(), SocksError> {
    let expected_password = cfg.auth_password.clone();
    let allowed_ipv6_cidrs = cfg.allowed_ipv6_cidrs.clone();
    let fixed_public_ipv6 = cfg.fixed_public_ipv6;
    let rotation_state = Arc::clone(&cfg.rotation_state);
    let selected_source_ipv6 = Arc::new(OnceLock::<Ipv6Addr>::new());
    let selected_source_ipv6_closure = Arc::clone(&selected_source_ipv6);

    let (proto_authed, _auth_ok) = Socks5ServerProtocol::accept_password_auth(
        stream,
        move |username, password| {
            let pass_ok = password == expected_password;
            let user_ok = select_source_ipv6_from_username(
                &username,
                fixed_public_ipv6,
                &allowed_ipv6_cidrs,
                &rotation_state,
            );

            if pass_ok {
                if let Some(v6) = user_ok {
                    match selected_source_ipv6_closure.set(v6) {
                        Ok(()) => return true,
                        Err(set_v6) => {
                            let existing = selected_source_ipv6_closure.get().copied();
                            warn!(
                                client = %client_addr,
                                attempted_source_ipv6 = %set_v6,
                                existing_source_ipv6 = ?existing,
                                "认证态写入 source IPv6 失败，拒绝本次认证"
                            );
                            return false;
                        }
                    }
                }
            }

            warn!(
                client = %client_addr,
                provided_user = %username.trim(),
                "认证失败：用户名或密码错误"
            );
            false
        },
    )
    .await?;

    let outbound_source_v6 = selected_source_ipv6.get().copied();

    info!(client = %client_addr, source_ipv6 = ?outbound_source_v6, "认证通过");

    let (proto, cmd, target_addr) = proto_authed
        .read_command()
        .await?
        .resolve_dns()
        .await?;

    info!(
        client = %client_addr,
        command = ?cmd,
        target = %target_addr,
        "收到代理请求（域名由服务端解析）"
    );

    match cmd {
        Socks5Command::TCPConnect => {
            run_tcp_proxy_with_ipv6_source(proto, &target_addr, cfg.request_timeout, outbound_source_v6).await?;
            info!(client = %client_addr, target = %target_addr, source_ipv6 = ?outbound_source_v6, "TCP 转发完成");
            Ok(())
        }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            warn!(client = %client_addr, command = ?cmd, "不支持的 SOCKS5 命令，已拒绝");
            Err(ReplyError::CommandNotSupported.into())
        }
    }
}

async fn detect_public_ipv6() -> Result<Ipv6Addr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("初始化 HTTP 客户端失败")?;

    // 多服务兜底，避免单点不可用。
    let providers = [
        "https://api64.ipify.org",
        "https://ifconfig.co/ip",
        "https://ipv6.icanhazip.com",
    ];

    let mut last_err = String::new();

    for url in providers {
        match client.get(url).send().await {
            Ok(resp) => match resp.error_for_status() {
                Ok(ok_resp) => match ok_resp.text().await {
                    Ok(body) => {
                        let ip_text = body.trim();
                        match ip_text.parse::<IpAddr>() {
                            Ok(IpAddr::V6(v6)) => {
                                info!(provider = %url, ipv6 = %v6, "成功获取公网出口 IPv6");
                                return Ok(v6);
                            }
                            Ok(IpAddr::V4(v4)) => {
                                warn!(provider = %url, ipv4 = %v4, "返回了 IPv4，继续尝试获取 IPv6");
                                last_err = format!("{url} 返回 IPv4: {v4}");
                            }
                            Err(parse_err) => {
                                warn!(provider = %url, error = %parse_err, body = %ip_text, "返回内容不是合法 IP");
                                last_err = format!("{url} 解析失败: {parse_err}");
                            }
                        }
                    }
                    Err(err) => {
                        warn!(provider = %url, error = %err, "读取响应内容失败");
                        last_err = format!("{url} 读取 body 失败: {err}");
                    }
                },
                Err(err) => {
                    warn!(provider = %url, error = %err, "HTTP 状态码异常");
                    last_err = format!("{url} 状态码错误: {err}");
                }
            },
            Err(err) => {
                warn!(provider = %url, error = %err, "请求公网 IPv6 服务失败");
                last_err = format!("{url} 请求失败: {err}");
            }
        }
    }

    error!(last_error = %last_err, "获取公网出口 IPv6 失败，服务拒绝启动");
    anyhow::bail!(
        "无法获取公网出口 IPv6，服务拒绝启动。当前认证规则要求“用户名=启动时自动获取的公网IPv6地址”，因此纯IPv4环境不受支持。最后错误: {}",
        last_err
    )
}

fn normalize_username(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn parse_allowed_ipv6_cidrs_from_env() -> Result<Vec<Ipv6Net>> {
    let raw = match env::var("SOCKS5_ALLOWED_IPV6_CIDRS") {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };

    let mut nets = Vec::new();
    for part in raw.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        let net: Ipv6Net = token
            .parse()
            .with_context(|| format!("SOCKS5_ALLOWED_IPV6_CIDRS 含非法 IPv6 CIDR: {token}"))?;
        nets.push(net);
    }

    Ok(nets)
}

fn ipv6_to_decimal_string(ipv6: Ipv6Addr) -> String {
    u128::from(ipv6).to_string()
}

fn ipv6_from_cidr_and_host_part(cidr: Ipv6Net, host_part: u128) -> Ipv6Addr {
    let prefix_len = cidr.prefix_len() as u32;
    if prefix_len >= 128 {
        return cidr.network();
    }

    let base = u128::from(cidr.network());
    let host_bits = 128 - prefix_len;

    let normalized_host_part = if host_bits == 128 {
        host_part
    } else {
        let host_mask = (1u128 << host_bits) - 1;
        host_part & host_mask
    };

    Ipv6Addr::from(base | normalized_host_part)
}

fn pick_rotation_ipv6(allowed_ipv6_cidrs: &[Ipv6Net], rotation_state: &RotationState) -> Option<Ipv6Addr> {
    if allowed_ipv6_cidrs.is_empty() {
        return None;
    }

    let cidr_idx = {
        let mut idx_guard = rotation_state.next_cidr_idx.lock().ok()?;
        let idx = *idx_guard % allowed_ipv6_cidrs.len();
        *idx_guard = idx_guard.wrapping_add(1);
        idx
    };

    let cidr = allowed_ipv6_cidrs[cidr_idx];

    let host_part = {
        let mut counters = rotation_state.next_host_by_cidr.lock().ok()?;
        if counters.len() != allowed_ipv6_cidrs.len() {
            return None;
        }

        let host_bits = 128u32.saturating_sub(cidr.prefix_len() as u32);
        if host_bits == 0 {
            counters[cidr_idx] = 0;
            0
        } else if host_bits == 128 {
            let counter = counters[cidr_idx];
            counters[cidr_idx] = counter.wrapping_add(1);
            counter
        } else {
            let host_space = 1u128 << host_bits;
            let counter = counters[cidr_idx] % host_space;
            counters[cidr_idx] = (counter + 1) % host_space;
            counter
        }
    };

    Some(ipv6_from_cidr_and_host_part(cidr, host_part))
}

fn select_source_ipv6_from_username(
    username: &str,
    fixed_public_ipv6: Option<Ipv6Addr>,
    allowed_ipv6_cidrs: &[Ipv6Net],
    rotation_state: &RotationState,
) -> Option<Ipv6Addr> {
    let normalized = normalize_username(username);

    if normalized == "rotation" {
        if allowed_ipv6_cidrs.is_empty() {
            return fixed_public_ipv6;
        }

        return pick_rotation_ipv6(allowed_ipv6_cidrs, rotation_state);
    }

    let user_decimal = normalized.parse::<u128>().ok()?;
    let user_v6 = Ipv6Addr::from(user_decimal);

    if allowed_ipv6_cidrs.is_empty() {
        if Some(user_v6) == fixed_public_ipv6 {
            return Some(user_v6);
        }
        return None;
    }

    if allowed_ipv6_cidrs.iter().any(|net| net.contains(&user_v6)) {
        return Some(user_v6);
    }

    None
}

async fn run_tcp_proxy_with_ipv6_source(
    proto: Socks5ServerProtocol<TcpStream, fast_socks5::server::states::CommandRead>,
    target_addr: &TargetAddr,
    request_timeout: Duration,
    source_ipv6: Option<Ipv6Addr>,
) -> std::result::Result<(), SocksError> {
    let remote_addr = target_addr
        .to_socket_addrs()
        .map_err(SocksError::from)?
        .next()
        .ok_or_else(|| SocksError::from(io::Error::other("no socket addrs")))?;

    let mut outbound = connect_with_optional_v6_source(remote_addr, request_timeout, source_ipv6)
        .await
        .map_err(SocksError::from)?;

    let mut inbound = proto
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await?;

    proxy_bidirectional(&mut inbound, &mut { outbound }).await;
    Ok(())
}

async fn proxy_bidirectional(inbound: &mut TcpStream, outbound: &mut TcpStream) {
    #[cfg(target_os = "linux")]
    {
        match tokio_splice::zero_copy_bidirectional(inbound, outbound).await {
            Ok((up, down)) => {
                info!(upstream_bytes = up, downstream_bytes = down, zero_copy = true, "零拷贝双向转发结束");
            }
            Err(err) => {
                warn!(error = %err, "splice 零拷贝失败，回退 copy_bidirectional");
                match tokio::io::copy_bidirectional(inbound, outbound).await {
                    Ok((up, down)) => {
                        info!(upstream_bytes = up, downstream_bytes = down, zero_copy = false, "回退双向转发结束");
                    }
                    Err(copy_err) => {
                        warn!(error = %copy_err, "回退 copy_bidirectional 失败");
                    }
                }
            }
        }
        return;
    }

    #[cfg(not(target_os = "linux"))]
    {
        match tokio::io::copy_bidirectional(inbound, outbound).await {
            Ok((up, down)) => {
                info!(upstream_bytes = up, downstream_bytes = down, zero_copy = false, "双向转发结束");
            }
            Err(err) => {
                warn!(error = %err, "双向转发失败");
            }
        }
    }
}

async fn connect_with_optional_v6_source(
    remote_addr: SocketAddr,
    timeout: Duration,
    source_ipv6: Option<Ipv6Addr>,
) -> io::Result<TcpStream> {
    match (remote_addr, source_ipv6) {
        (SocketAddr::V6(remote_v6), Some(src_v6)) => {
            let socket = TcpSocket::new_v6()?;
            socket.bind(SocketAddr::V6(SocketAddrV6::new(src_v6, 0, 0, 0)))?;
            match tokio::time::timeout(timeout, socket.connect(SocketAddr::V6(remote_v6))).await {
                Ok(conn_res) => conn_res,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
            }
        }
        (remote, Some(src_v6)) => {
            warn!(target = %remote, source_ipv6 = %src_v6, "目标是 IPv4，无法绑定 IPv6 出口地址，回退默认路由连接");
            match tokio::time::timeout(timeout, TcpStream::connect(remote)).await {
                Ok(conn_res) => conn_res,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
            }
        }
        (remote, None) => match tokio::time::timeout(timeout, TcpStream::connect(remote)).await {
            Ok(conn_res) => conn_res,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
        },
    }
}
