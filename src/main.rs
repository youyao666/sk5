#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use fast_socks5::{
    server::{DnsResolveHelper as _, Socks5ServerProtocol},
    util::target_addr::TargetAddr,
    ReplyError, Socks5Command, SocksError,
};
use ipnet::Ipv6Net;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
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

#[derive(Debug)]
struct Metrics {
    started_at: Instant,
    active_connections: AtomicUsize,
    total_connections: AtomicUsize,
}

impl Metrics {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
struct RuntimeConfig {
    listen_port: u16,
    webui_port: u16,
    request_timeout: Duration,
    shutdown_grace_period: Duration,
    max_connections: usize,
    auth_password: String,
    fixed_public_ipv6: Option<Ipv6Addr>,
    allowed_ipv6_cidrs: Vec<Ipv6Net>,
    rotation_state: Arc<RotationState>,
    /// 订阅链接中使用的服务器地址
    server_host: String,
    /// 订阅链接中生成的独立 IPv6 节点数量（可在线修改）
    sub_node_count: AtomicUsize,
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

        let webui_port = env::var("SOCKS5_WEBUI_PORT")
            .ok()
            .map(|v| {
                v.parse::<u16>()
                    .with_context(|| format!("SOCKS5_WEBUI_PORT 非法: {v}"))
            })
            .transpose()?
            .unwrap_or(18080);

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

        let sub_node_count = env::var("SOCKS5_SUB_NODE_COUNT")
            .ok()
            .map(|v| {
                v.parse::<usize>()
                    .with_context(|| format!("SOCKS5_SUB_NODE_COUNT 非法: {v}"))
            })
            .transpose()?
            .unwrap_or(10);

        let allowed_ipv6_cidrs = parse_allowed_ipv6_cidrs_from_env()?;
        let fixed_public_ipv6 = if allowed_ipv6_cidrs.is_empty() {
            Some(detect_public_ipv6().await?)
        } else {
            None
        };

        // 订阅链接中使用的服务器地址：优先使用环境变量，否则自动检测公网 IP
        let server_host = match env::var("SOCKS5_SERVER_HOST") {
            Ok(h) if !h.trim().is_empty() => h.trim().to_string(),
            _ => detect_public_ipv4()
                .await
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| {
                    fixed_public_ipv6
                        .map(|v6| format!("[{}]", v6))
                        .unwrap_or_else(|| "YOUR_SERVER_IP".to_string())
                }),
        };

        let rotation_state = Arc::new(RotationState::new(&allowed_ipv6_cidrs));

        Ok(Self {
            listen_port,
            webui_port,
            request_timeout: Duration::from_secs(request_timeout_secs),
            shutdown_grace_period: Duration::from_secs(shutdown_grace_secs),
            max_connections,
            auth_password,
            fixed_public_ipv6,
            allowed_ipv6_cidrs,
            rotation_state,
            server_host,
            sub_node_count: AtomicUsize::new(sub_node_count),
        })
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();

    let cfg = Arc::new(RuntimeConfig::from_env().await?);
    let metrics = Arc::new(Metrics::new());

    let listener = bind_dual_stack_single_port(cfg.listen_port)
        .with_context(|| format!("监听端口 {} 失败", cfg.listen_port))?;

    tokio::spawn(start_webui_server(Arc::clone(&cfg), Arc::clone(&metrics)));

    if cfg.allowed_ipv6_cidrs.is_empty() {
        if let Some(v6) = cfg.fixed_public_ipv6 {
            info!(
                listen = %format!("[::]:{}", cfg.listen_port),
                webui = %format!("http://127.0.0.1:{}", cfg.webui_port),
                auth_user_decimal = %ipv6_to_decimal_string(v6),
                source_ipv6 = %v6,
            server_host = %cfg.server_host,
            sub_nodes = cfg.sub_node_count.load(Ordering::Relaxed),
            subscribe = %format!("http://{}:{}/sub/clash", cfg.server_host, cfg.webui_port),
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
            webui = %format!("http://127.0.0.1:{}", cfg.webui_port),
            allowed_ipv6_cidrs = %cidr_list,
            server_host = %cfg.server_host,
            sub_nodes = cfg.sub_node_count.load(Ordering::Relaxed),
            subscribe = %format!("http://{}:{}/sub/clash", cfg.server_host, cfg.webui_port),
            "SOCKS5 代理服务已启动（支持 username=rotation 轮询轮换；或 username=IPv6转u128十进制）"
        );
    }

    run_accept_loop(listener, cfg, metrics).await
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

#[derive(Clone)]
struct WebUiState {
    cfg: Arc<RuntimeConfig>,
    metrics: Arc<Metrics>,
}

async fn start_webui_server(cfg: Arc<RuntimeConfig>, metrics: Arc<Metrics>) {
    let state = WebUiState { cfg, metrics };
    let app = Router::new()
        .route("/", get(webui_index))
        .route("/sub/clash", get(sub_clash))
        .route("/sub/base64", get(sub_base64))
        .route("/sub/plain", get(sub_plain))
        .route("/api/settings", post(api_update_settings))
        .route("/api/nodes", get(api_get_nodes))
        .with_state(state.clone());

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], state.cfg.webui_port));
    match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => {
            info!(webui_listen = %bind_addr, "WebUI 面板已启动（只读展示）");
            if let Err(err) = axum::serve(listener, app).await {
                error!(error = %err, "WebUI 服务异常退出");
            }
        }
        Err(err) => {
            error!(error = %err, webui_listen = %bind_addr, "WebUI 监听失败");
        }
    }
}

async fn webui_index(State(state): State<WebUiState>) -> Html<String> {
    let uptime_secs = state.metrics.started_at.elapsed().as_secs();
    let hours = uptime_secs / 3600;
    let minutes = (uptime_secs % 3600) / 60;
    let secs = uptime_secs % 60;
    let uptime_text = format!("{}h {}m {}s", hours, minutes, secs);

    let active_connections = state.metrics.active_connections.load(Ordering::Relaxed);
    let total_connections = state.metrics.total_connections.load(Ordering::Relaxed);
    let sub_node_count = state.cfg.sub_node_count.load(Ordering::Relaxed);

    let mode_text = if state.cfg.allowed_ipv6_cidrs.is_empty() {
        "固定 IPv6"
    } else {
        "IPv6 池轮询"
    };

    let fixed_ipv6_text = state
        .cfg
        .fixed_public_ipv6
        .map(|v| v.to_string())
        .unwrap_or_else(|| "N/A".to_string());

    let cidrs_text = if state.cfg.allowed_ipv6_cidrs.is_empty() {
        "未配置".to_string()
    } else {
        state
            .cfg
            .allowed_ipv6_cidrs
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let has_pool = !state.cfg.allowed_ipv6_cidrs.is_empty();

    let html = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SOCKS5 控制面板</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e1a; color: #e5e7eb; min-height: 100vh; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
    .header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #1f2a44; }}
    .header h1 {{ font-size: 22px; color: #fff; }}
    .header .status {{ display: flex; align-items: center; gap: 8px; font-size: 13px; color: #34d399; }}
    .header .status::before {{ content: ''; width: 8px; height: 8px; border-radius: 50%; background: #34d399; animation: pulse 2s infinite; }}
    @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}

    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 24px; }}
    .stat {{ background: #111827; border: 1px solid #1f2a44; border-radius: 10px; padding: 14px; }}
    .stat .label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
    .stat .val {{ font-size: 20px; font-weight: 700; font-family: ui-monospace, monospace; }}

    .section {{ background: #111827; border: 1px solid #1f2a44; border-radius: 12px; padding: 20px; margin-bottom: 16px; }}
    .section h2 {{ font-size: 16px; color: #60a5fa; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }}

    .setting-row {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
    .setting-row label {{ font-size: 14px; color: #9ca3af; min-width: 100px; }}
    .setting-row input[type=number] {{ width: 120px; padding: 8px 12px; background: #0a0e1a; border: 1px solid #374151; border-radius: 8px; color: #fff; font-size: 16px; font-family: ui-monospace, monospace; outline: none; }}
    .setting-row input[type=number]:focus {{ border-color: #60a5fa; }}
    .btn {{ padding: 8px 20px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.15s; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .btn-sm {{ padding: 4px 12px; font-size: 12px; }}
    .btn-ghost {{ background: transparent; border: 1px solid #374151; color: #9ca3af; }}
    .btn-ghost:hover {{ background: #1f2a44; color: #fff; }}
    .toast {{ position: fixed; top: 20px; right: 20px; background: #065f46; color: #fff; padding: 10px 20px; border-radius: 8px; font-size: 14px; opacity: 0; transition: opacity 0.3s; z-index: 999; pointer-events: none; }}
    .toast.show {{ opacity: 1; }}

    .sub-links {{ display: grid; grid-template-columns: 1fr; gap: 8px; }}
    .sub-item {{ display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #0a0e1a; border-radius: 8px; }}
    .sub-item .sub-url {{ flex: 1; font-family: ui-monospace, monospace; font-size: 13px; color: #60a5fa; word-break: break-all; }}
    .sub-item .sub-tag {{ font-size: 11px; color: #6b7280; background: #1f2a44; padding: 2px 8px; border-radius: 4px; white-space: nowrap; }}

    .quick-box {{ background: #0a0e1a; border-radius: 8px; padding: 12px 16px; font-family: ui-monospace, monospace; font-size: 13px; color: #34d399; word-break: break-all; position: relative; cursor: pointer; margin-bottom: 8px; }}
    .quick-box:hover {{ background: #111827; }}
    .quick-box::after {{ content: '点击复制'; position: absolute; right: 12px; top: 50%; transform: translateY(-50%); font-size: 11px; color: #6b7280; }}

    .node-list {{ max-height: 400px; overflow-y: auto; margin-top: 12px; }}
    .node-list::-webkit-scrollbar {{ width: 6px; }}
    .node-list::-webkit-scrollbar-thumb {{ background: #374151; border-radius: 3px; }}
    .node-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    .node-table th {{ text-align: left; padding: 8px 12px; color: #6b7280; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #1f2a44; position: sticky; top: 0; background: #111827; }}
    .node-table td {{ padding: 6px 12px; border-bottom: 1px solid #0f172a; font-family: ui-monospace, monospace; }}
    .node-table tr:hover td {{ background: #0f172a; }}
    .copy-cell {{ cursor: pointer; color: #60a5fa; }}
    .copy-cell:hover {{ text-decoration: underline; }}

    .pw-toggle {{ display: inline-flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px; color: #6b7280; }}
    .pw-toggle:hover {{ color: #9ca3af; }}

    @media (max-width: 640px) {{
      .stats {{ grid-template-columns: repeat(2, 1fr); }}
      .setting-row {{ flex-direction: column; align-items: flex-start; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>SOCKS5 控制面板</h1>
      <div class="status">运行中 · {uptime_text}</div>
    </div>

    <div class="stats">
      <div class="stat"><div class="label">监听端口</div><div class="val">{listen_port}</div></div>
      <div class="stat"><div class="label">运行模式</div><div class="val" style="font-size:14px;">{mode_text}</div></div>
      <div class="stat"><div class="label">活跃连接</div><div class="val" style="color:#34d399;">{active_connections}</div></div>
      <div class="stat"><div class="label">累计连接</div><div class="val">{total_connections}</div></div>
      <div class="stat"><div class="label">订阅节点</div><div class="val" style="color:#f59e0b;" id="node-count-display">{sub_node_count}</div></div>
      <div class="stat"><div class="label">固定 IPv6</div><div class="val" style="font-size:11px;">{fixed_ipv6_text}</div></div>
      <div class="stat"><div class="label">IPv6 CIDRs</div><div class="val" style="font-size:12px;">{cidrs_text}</div></div>
    </div>

    <div class="section">
      <h2>设置</h2>
      <div class="setting-row">
        <label>代理节点数</label>
        <input type="number" id="node-count" value="{sub_node_count}" min="0" max="10000" step="1" />
        <button class="btn btn-primary" onclick="updateNodeCount()">应用</button>
        <span id="setting-msg" style="font-size:13px; color:#6b7280;"></span>
      </div>
      <div style="margin-top: 8px; font-size: 12px; color: #6b7280;">
        修改后订阅链接立即生效，无需重启服务。{pool_hint}
      </div>
    </div>

    <div class="section">
      <h2>订阅链接</h2>
      <div class="sub-links">
        <div class="sub-item">
          <span class="sub-tag">Clash</span>
          <span class="sub-url" id="url-clash"></span>
          <button class="btn btn-sm btn-ghost" onclick="copySub('url-clash')">复制</button>
        </div>
        <div class="sub-item">
          <span class="sub-tag">Base64</span>
          <span class="sub-url" id="url-base64"></span>
          <button class="btn btn-sm btn-ghost" onclick="copySub('url-base64')">复制</button>
        </div>
        <div class="sub-item">
          <span class="sub-tag">Plain</span>
          <span class="sub-url" id="url-plain"></span>
          <button class="btn btn-sm btn-ghost" onclick="copySub('url-plain')">复制</button>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>快速连接</h2>
      <div style="margin-bottom: 6px;">
        <span class="pw-toggle" onclick="togglePw()">密码: <span id="pw-display">******</span> <span id="pw-toggle-text">[显示]</span></span>
      </div>
      <div class="quick-box" onclick="copyText(this.dataset.text)" data-text="socks5://rotation:{password}@{server_host}:{listen_port}">
        socks5://rotation:<span class="pw-mask">******</span>@{server_host}:{listen_port}
      </div>
      <div class="quick-box" onclick="copyText(this.dataset.text)" data-text="curl -x socks5://rotation:{password}@{server_host}:{listen_port} https://ipinfo.io">
        curl -x socks5://rotation:<span class="pw-mask">******</span>@{server_host}:{listen_port} https://ipinfo.io
      </div>
    </div>

    <div class="section">
      <h2>节点列表 <span style="font-size:13px; color:#6b7280; font-weight:400;" id="node-total"></span></h2>
      <div style="display:flex; gap:8px; margin-bottom: 10px;">
        <button class="btn btn-sm btn-ghost" onclick="copyAllNodes()">复制全部链接</button>
        <button class="btn btn-sm btn-ghost" onclick="loadNodes()">刷新列表</button>
      </div>
      <div class="node-list" id="node-list">
        <table class="node-table">
          <thead><tr><th>#</th><th>名称</th><th>用户名</th><th>链接</th></tr></thead>
          <tbody id="node-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    var PASSWORD = '{password}';
    var SERVER = '{server_host}';
    var PORT = {listen_port};
    var pwVisible = false;

    function init() {{
      var origin = window.location.origin;
      document.getElementById('url-clash').textContent = origin + '/sub/clash';
      document.getElementById('url-base64').textContent = origin + '/sub/base64';
      document.getElementById('url-plain').textContent = origin + '/sub/plain';
      loadNodes();
    }}

    function showToast(msg) {{
      var t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(function() {{ t.classList.remove('show'); }}, 2000);
    }}

    function copyText(text) {{
      navigator.clipboard.writeText(text).then(function() {{ showToast('已复制'); }});
    }}

    function copySub(id) {{
      var url = document.getElementById(id).textContent;
      copyText(url);
    }}

    function togglePw() {{
      pwVisible = !pwVisible;
      document.getElementById('pw-display').textContent = pwVisible ? PASSWORD : '******';
      document.getElementById('pw-toggle-text').textContent = pwVisible ? '[隐藏]' : '[显示]';
      var masks = document.querySelectorAll('.pw-mask');
      masks.forEach(function(el) {{ el.textContent = pwVisible ? PASSWORD : '******'; }});
    }}

    function updateNodeCount() {{
      var val = parseInt(document.getElementById('node-count').value);
      if (isNaN(val) || val < 0) {{ showToast('请输入有效数字'); return; }}
      fetch('/api/settings', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ sub_node_count: val }})
      }})
      .then(function(r) {{ return r.json(); }})
      .then(function(data) {{
        if (data.ok) {{
          document.getElementById('node-count-display').textContent = val;
          document.getElementById('setting-msg').textContent = '已更新为 ' + val + ' 个节点';
          document.getElementById('setting-msg').style.color = '#34d399';
          loadNodes();
          setTimeout(function() {{ document.getElementById('setting-msg').textContent = ''; }}, 3000);
        }} else {{
          document.getElementById('setting-msg').textContent = data.error || '更新失败';
          document.getElementById('setting-msg').style.color = '#ef4444';
        }}
      }})
      .catch(function(err) {{
        document.getElementById('setting-msg').textContent = '请求失败: ' + err;
        document.getElementById('setting-msg').style.color = '#ef4444';
      }});
    }}

    function loadNodes() {{
      fetch('/api/nodes')
        .then(function(r) {{ return r.json(); }})
        .then(function(nodes) {{
          document.getElementById('node-total').textContent = '共 ' + nodes.length + ' 个';
          var tbody = document.getElementById('node-tbody');
          tbody.innerHTML = '';
          nodes.forEach(function(n, i) {{
            var link = 'socks5://' + n.username + ':' + n.password + '@' + n.server + ':' + n.port;
            var tr = document.createElement('tr');
            tr.innerHTML = '<td>' + (i+1) + '</td>'
              + '<td>' + n.name + '</td>'
              + '<td style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + n.username + '</td>'
              + '<td class="copy-cell" onclick="copyText(\'' + link.replace(/'/g, "\\'") + '\')">[复制链接]</td>';
            tbody.appendChild(tr);
          }});
        }});
    }}

    function copyAllNodes() {{
      fetch('/api/nodes')
        .then(function(r) {{ return r.json(); }})
        .then(function(nodes) {{
          var lines = nodes.map(function(n) {{
            return 'socks5://' + n.username + ':' + n.password + '@' + n.server + ':' + n.port + '#' + n.name;
          }});
          copyText(lines.join('\n'));
          showToast('已复制 ' + nodes.length + ' 个节点');
        }});
    }}

    init();
    setInterval(function() {{ location.reload(); }}, 30000);
  </script>
</body>
</html>"#,
        listen_port = state.cfg.listen_port,
        mode_text = mode_text,
        uptime_text = uptime_text,
        active_connections = active_connections,
        total_connections = total_connections,
        sub_node_count = sub_node_count,
        cidrs_text = cidrs_text,
        fixed_ipv6_text = fixed_ipv6_text,
        server_host = state.cfg.server_host,
        password = state.cfg.auth_password,
        pool_hint = if has_pool {
            format!("当前 IPv6 池可生成海量独立出口节点。")
        } else {
            "未配置 IPv6 池（SOCKS5_ALLOWED_IPV6_CIDRS），仅有固定 IPv6 节点。".to_string()
        },
    );

    Html(html)
}

#[derive(Deserialize)]
struct UpdateSettings {
    sub_node_count: Option<usize>,
}

/// POST /api/settings — 动态修改配置
async fn api_update_settings(
    State(state): State<WebUiState>,
    Json(body): Json<UpdateSettings>,
) -> impl IntoResponse {
    if let Some(count) = body.sub_node_count {
        if count > 100_000 {
            return Json(serde_json::json!({"ok": false, "error": "节点数不能超过 100000"}));
        }
        state.cfg.sub_node_count.store(count, Ordering::Relaxed);
        info!(new_sub_node_count = count, "订阅节点数已在线更新");
        return Json(serde_json::json!({"ok": true, "sub_node_count": count}));
    }
    Json(serde_json::json!({"ok": false, "error": "无有效参数"}))
}

/// GET /api/nodes — 返回当前所有节点的 JSON 列表
async fn api_get_nodes(State(state): State<WebUiState>) -> impl IntoResponse {
    let entries = build_proxy_entries(&state.cfg);
    let nodes: Vec<serde_json::Value> = entries
        .iter()
        .map(|(name, server, port, username, password)| {
            serde_json::json!({
                "name": name,
                "server": server,
                "port": port,
                "username": username,
                "password": password,
            })
        })
        .collect();
    Json(serde_json::Value::Array(nodes))
}

/// 生成 SOCKS5 代理节点列表（用于各种订阅格式）
/// 当配置了 IPv6 CIDR 池时，会从池中均匀生成 sub_node_count 个不同 IPv6 出口的节点
fn build_proxy_entries(cfg: &RuntimeConfig) -> Vec<(String, String, u16, String, String)> {
    // 返回 (名称, 服务器, 端口, 用户名, 密码)
    let mut entries = Vec::new();

    // 始终添加 rotation 节点（自动轮换）
    entries.push((
        "SK5-Rotation".to_string(),
        cfg.server_host.clone(),
        cfg.listen_port,
        "rotation".to_string(),
        cfg.auth_password.clone(),
    ));

    if !cfg.allowed_ipv6_cidrs.is_empty() && cfg.sub_node_count.load(Ordering::Relaxed) > 0 {
        // 有 IPv6 池，从池中批量生成节点
        let total_count = cfg.sub_node_count.load(Ordering::Relaxed);
        // 在多个 CIDR 之间均匀分配节点数
        let cidr_count = cfg.allowed_ipv6_cidrs.len();
        let mut generated = 0usize;

        for (cidr_idx, cidr) in cfg.allowed_ipv6_cidrs.iter().enumerate() {
            // 每个 CIDR 分配的节点数（最后一个 CIDR 拿走剩余的）
            let nodes_for_this_cidr = if cidr_idx == cidr_count - 1 {
                total_count - generated
            } else {
                total_count / cidr_count
            };

            let prefix_len = cidr.prefix_len() as u32;
            let host_bits = 128u32.saturating_sub(prefix_len);
            // 可用地址空间（上限 u128::MAX）
            let addr_space: u128 = if host_bits >= 128 {
                u128::MAX
            } else if host_bits == 0 {
                1
            } else {
                1u128 << host_bits
            };

            // 步长：在地址空间中均匀分布节点
            let step = if nodes_for_this_cidr as u128 >= addr_space {
                1u128
            } else if addr_space == u128::MAX {
                // 超大地址空间，用简单的大步长
                u128::MAX / (nodes_for_this_cidr as u128 + 1)
            } else {
                addr_space / (nodes_for_this_cidr as u128 + 1)
            };

            for i in 0..nodes_for_this_cidr {
                // 从 1 开始（跳过网络地址 ::0）
                let host_part = step * (i as u128 + 1);
                let ipv6 = ipv6_from_cidr_and_host_part(*cidr, host_part);
                let decimal_username = ipv6_to_decimal_string(ipv6);
                let node_index = generated + i + 1;

                entries.push((
                    format!("SK5-{:03}", node_index),
                    cfg.server_host.clone(),
                    cfg.listen_port,
                    decimal_username,
                    cfg.auth_password.clone(),
                ));
            }
            generated += nodes_for_this_cidr;
        }
    } else if let Some(v6) = cfg.fixed_public_ipv6 {
        // 没有 IPv6 池，只有固定 IPv6，添加一个固定节点
        let decimal_username = ipv6_to_decimal_string(v6);
        entries.push((
            format!("SK5-{}", v6),
            cfg.server_host.clone(),
            cfg.listen_port,
            decimal_username,
            cfg.auth_password.clone(),
        ));
    }

    entries
}

/// /sub/clash — 返回 Clash/Mihomo 兼容的 YAML 订阅配置
async fn sub_clash(State(state): State<WebUiState>) -> impl IntoResponse {
    let entries = build_proxy_entries(&state.cfg);

    let mut yaml = String::from("proxies:\n");
    let mut names = Vec::new();

    for (name, server, port, username, password) in &entries {
        names.push(name.clone());
        yaml.push_str(&format!(
            r#"  - name: "{name}"
    type: socks5
    server: "{server}"
    port: {port}
    username: "{username}"
    password: "{password}"
    udp: false
"#,
        ));
    }

    // 添加一个简单的 proxy-group
    yaml.push_str("\nproxy-groups:\n");
    yaml.push_str("  - name: \"SK5-Proxy\"\n");
    yaml.push_str("    type: select\n");
    yaml.push_str("    proxies:\n");
    for name in &names {
        yaml.push_str(&format!("      - \"{name}\"\n"));
    }

    yaml.push_str("\nrules:\n");
    yaml.push_str("  - MATCH,SK5-Proxy\n");

    (
        [
            ("Content-Type", "text/yaml; charset=utf-8"),
            (
                "Content-Disposition",
                "inline; filename=\"clash-sub.yaml\"",
            ),
            ("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0"),
        ],
        yaml,
    )
}

/// /sub/base64 — 返回 Base64 编码的订阅内容（兼容 v2rayN、Shadowrocket 等）
async fn sub_base64(State(state): State<WebUiState>) -> impl IntoResponse {
    let entries = build_proxy_entries(&state.cfg);

    // SOCKS5 链接格式：socks5://base64(username:password)@server:port#name
    let mut links = Vec::new();
    for (name, server, port, username, password) in &entries {
        let user_info = BASE64.encode(format!("{username}:{password}"));
        let link = format!(
            "socks5://{}@{}:{}#{}",
            user_info,
            server,
            port,
            urlencoded(name),
        );
        links.push(link);
    }

    let plain = links.join("\n");
    let encoded = BASE64.encode(&plain);

    (
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0"),
        ],
        encoded,
    )
}

/// /sub/plain — 返回纯文本 SOCKS5 链接
async fn sub_plain(State(state): State<WebUiState>) -> impl IntoResponse {
    let entries = build_proxy_entries(&state.cfg);

    let mut lines = Vec::new();
    for (name, server, port, username, password) in &entries {
        lines.push(format!(
            "socks5://{username}:{password}@{server}:{port}#{name}"
        ));
    }

    (
        [("Content-Type", "text/plain; charset=utf-8")],
        lines.join("\n"),
    )
}

/// 简易 URL 编码（仅编码 # 和空格等特殊字符）
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('?', "%3F")
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
    socket.set_nonblocking(true).context("设置非阻塞失败")?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).context("转换为 tokio TcpListener 失败")
}

async fn run_accept_loop(
    listener: TcpListener,
    cfg: Arc<RuntimeConfig>,
    metrics: Arc<Metrics>,
) -> Result<()> {
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
                        let task_metrics = Arc::clone(&metrics);
                        join_set.spawn(async move {
                            let _permit = permit;
                            task_metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.active_connections.fetch_add(1, Ordering::Relaxed);

                            if let Err(err) = handle_client(stream, client_addr, task_cfg).await {
                                warn!(client = %client_addr, "连接处理失败/已拒绝: {err}");
                            }

                            task_metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
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

    let (proto_authed, _auth_ok) =
        Socks5ServerProtocol::accept_password_auth(stream, move |username, password| {
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
        })
        .await?;

    let outbound_source_v6 = selected_source_ipv6.get().copied();

    info!(client = %client_addr, source_ipv6 = ?outbound_source_v6, "认证通过");

    let (proto, cmd, target_addr) = proto_authed.read_command().await?.resolve_dns().await?;

    info!(
        client = %client_addr,
        command = ?cmd,
        target = %target_addr,
        "收到代理请求（域名由服务端解析）"
    );

    match cmd {
        Socks5Command::TCPConnect => {
            run_tcp_proxy_with_ipv6_source(
                proto,
                &target_addr,
                cfg.request_timeout,
                outbound_source_v6,
            )
            .await?;
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
        "无法获取公网出口 IPv6，服务拒绝启动。当前认证规则要求 用户名=启动时自动获取的公网IPv6地址，因此纯IPv4环境不受支持。最后错误: {}",
        last_err
    )
}

/// 检测公网 IPv4 地址（用于订阅链接生成），失败返回 None
async fn detect_public_ipv4() -> Option<Ipv4Addr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let providers = [
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://ifconfig.me/ip",
    ];

    for url in providers {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(ok_resp) = resp.error_for_status() {
                if let Ok(body) = ok_resp.text().await {
                    if let Ok(IpAddr::V4(v4)) = body.trim().parse::<IpAddr>() {
                        info!(provider = %url, ipv4 = %v4, "成功获取公网 IPv4（用于订阅链接）");
                        return Some(v4);
                    }
                }
            }
        }
    }

    warn!("无法获取公网 IPv4，订阅链接将使用 IPv6 或占位符");
    None
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

fn pick_rotation_ipv6(
    allowed_ipv6_cidrs: &[Ipv6Net],
    rotation_state: &RotationState,
) -> Option<Ipv6Addr> {
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
                info!(
                    upstream_bytes = up,
                    downstream_bytes = down,
                    zero_copy = true,
                    "零拷贝双向转发结束"
                );
            }
            Err(err) => {
                warn!(error = %err, "splice 零拷贝失败，回退 copy_bidirectional");
                match tokio::io::copy_bidirectional(inbound, outbound).await {
                    Ok((up, down)) => {
                        info!(
                            upstream_bytes = up,
                            downstream_bytes = down,
                            zero_copy = false,
                            "回退双向转发结束"
                        );
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
                info!(
                    upstream_bytes = up,
                    downstream_bytes = down,
                    zero_copy = false,
                    "双向转发结束"
                );
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
