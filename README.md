# 高性能 SOCKS5 代理（Rust / Tokio / fast-socks5）

本项目实现了一个**单端口双栈** SOCKS5 代理服务，满足以下关键要求：

- 单个 TCP 端口同时接入 IPv4/IPv6 客户端
- 强制用户名密码认证（禁止无认证）
- 用户名支持 `rotation` 轮换出口，或使用“IPv6 转 `u128` 十进制字符串”精确指定出口（认证时忽略大小写和前后空格）
- 密码通过环境变量配置（全局固定连接密码）
- 基于 Tokio 多线程运行时 + fast-socks5 协议库
- 服务端执行域名解析
- 分级日志（info/warn/error）
- 支持 Ctrl+C 优雅关闭

## 1. 目录结构

- `Cargo.toml`
- `src/main.rs`

## 2. 环境变量

运行前请设置（并满足前置条件）：

- `SOCKS5_PASSWORD`（必填）：全局固定连接密码
- `SOCKS5_LISTEN_PORT`（可选，默认 `1080`）
- `SOCKS5_REQUEST_TIMEOUT_SECS`（可选，默认 `10`）
- `SOCKS5_SHUTDOWN_GRACE_SECS`（可选，默认 `30`）
- `RUST_LOG`（可选，默认 `info`）
- `SOCKS5_MAX_CONNECTIONS`（可选，默认 `1024`，用于低内存机器的并发上限保护）

- `SOCKS5_ALLOWED_IPV6_CIDRS`（可选，逗号分隔；配置后将启用 IPv6 池策略，例如 `2001:db8:1::/64,2001:db8:2::/64`）

前置条件（必须）：

- 服务器必须具备可用的公网 IPv6 出口地址
- 若未设置 `SOCKS5_ALLOWED_IPV6_CIDRS`：
  - 用户名 `rotation` 会退化为固定公网 IPv6 出口
  - 普通用户名必须是“该固定公网 IPv6 转 `u128` 后的十进制字符串”
- 若设置了 `SOCKS5_ALLOWED_IPV6_CIDRS`：
  - 用户名 `rotation` 会在允许网段中按轮询序列分配出口 IPv6（每个网段独立 host 计数）
  - 普通用户名必须是“目标 IPv6 转 `u128` 后的十进制字符串”，且该 IPv6 必须落在允许网段内

示例：

```bash
export SOCKS5_PASSWORD='YourStrongPassword'
export SOCKS5_LISTEN_PORT=1080
export SOCKS5_REQUEST_TIMEOUT_SECS=10
export SOCKS5_SHUTDOWN_GRACE_SECS=30
export RUST_LOG=info
export SOCKS5_MAX_CONNECTIONS=256
```

## 3. Linux 部署步骤

### 3.1 安装 Rust 工具链

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

### 3.2 构建

在项目目录执行：

```bash
cargo build --release
```

生成二进制：

- `target/release/ipv6-username-socks5`

### 3.3 启动

```bash
SOCKS5_PASSWORD='YourStrongPassword' \
SOCKS5_LISTEN_PORT=1080 \
RUST_LOG=info \
./target/release/ipv6-username-socks5
```

启动后：
- 未配置 `SOCKS5_ALLOWED_IPV6_CIDRS`：日志输出固定公网 IPv6 与对应十进制用户名
- 已配置 `SOCKS5_ALLOWED_IPV6_CIDRS`：日志输出允许网段；可用 `rotation` 或十进制用户名登录

### 3.4 防火墙放行（示例）

以 `ufw` 为例：

```bash
sudo ufw allow 1080/tcp
sudo ufw reload
```

### 3.5 使用 systemd 托管（推荐）

创建 `/etc/systemd/system/ipv6-username-socks5.service`：

```ini
[Unit]
Description=IPv6 Username SOCKS5 Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
Environment=SOCKS5_PASSWORD=YourStrongPassword
Environment=SOCKS5_LISTEN_PORT=1080
Environment=SOCKS5_REQUEST_TIMEOUT_SECS=10
Environment=SOCKS5_SHUTDOWN_GRACE_SECS=30
Environment=RUST_LOG=info
Environment=SOCKS5_MAX_CONNECTIONS=256
WorkingDirectory=/opt/ipv6-username-socks5
ExecStart=/opt/ipv6-username-socks5/target/release/ipv6-username-socks5
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ipv6-username-socks5
sudo systemctl status ipv6-username-socks5
```

查看日志：

```bash
journalctl -u ipv6-username-socks5 -f
```

## 4. 认证规则说明

- 仅支持用户名/密码认证（SOCKS5 RFC 1929）
- 不开放无认证方式
- 认证时先对用户名执行：`trim + ASCII lower-case`
- 密码必须等于环境变量 `SOCKS5_PASSWORD`
- 用户名规则：
  - `rotation`：启用轮询出口模式
  - 非 `rotation`：必须为 IPv6 对应的 `u128` 十进制字符串
- 当未配置 `SOCKS5_ALLOWED_IPV6_CIDRS`：
  - `rotation` 使用固定公网 IPv6
  - 非 `rotation` 必须映射为固定公网 IPv6
- 当配置了 `SOCKS5_ALLOWED_IPV6_CIDRS`：
  - `rotation` 从允许网段中轮询选取 IPv6（每个网段独立 host 计数）
  - 非 `rotation` 映射出的 IPv6 必须落在允许网段内
- 任一项不匹配立即拒绝

### 4.1 十进制用户名示例

假设目标 IPv6 为 `2408:xxxx:xxxx::1234`，客户端用户名应填写：

```text
<该IPv6转换为u128后的十进制字符串>
```

服务端内部等价逻辑为：

```text
username(十进制) -> parse u128 -> Ipv6Addr::from(u128)
```

## 5. 代理行为说明

- 仅支持 `TCP CONNECT`
- 目标为域名时，服务端执行 DNS 解析（符合“服务端解析”要求）
- 当用户名为十进制字符串时，服务端会先反解到 IPv6，再将该 IPv6 绑定为出站 TCP 源地址
- 当用户名为 `rotation` 时，服务端会按 IPv6 池轮询策略选择出站源 IPv6（更省资源，行为稳定）
- Linux 下优先使用 `splice()` 零拷贝双向转发（失败自动回退 `copy_bidirectional`）
- 不支持的 SOCKS5 命令返回 `CommandNotSupported`

## 6. 优雅关闭

服务接收 `Ctrl+C`（SIGINT）后：

1. 停止接收新连接
2. 等待已有连接在宽限时间内完成
3. 超时后中止剩余任务并退出

## 7. 说明

当前实现依赖 `fast-socks5` 的服务器协议流程与转发逻辑，保持高并发场景下的稳定性与性能。

## 8. Docker 镜像部署

### 8.1 本地构建镜像

```bash
docker build -t ipv6-username-socks5:local .
```

### 8.2 本地运行容器

```bash
docker run -d \
  --name ipv6-username-socks5 \
  --restart unless-stopped \
  -p 1080:1080/tcp \
  -e SOCKS5_PASSWORD='YourStrongPassword' \
  -e SOCKS5_LISTEN_PORT=1080 \
  -e SOCKS5_REQUEST_TIMEOUT_SECS=10 \
  -e SOCKS5_SHUTDOWN_GRACE_SECS=30 \
  -e SOCKS5_MAX_CONNECTIONS=256 \
  -e RUST_LOG=info \
  ipv6-username-socks5:local
```

如需开启“IPv6 池 + rotation/十进制用户名”模式，增加环境变量：

```bash
-e SOCKS5_ALLOWED_IPV6_CIDRS='2001:db8:1::/64,2001:db8:2::/64'
```

## 9. GitHub Actions 自动构建并推送 GHCR

项目已提供工作流文件：

- `.github/workflows/docker-ghcr.yml`

触发条件：

- push 到 `main`
- push `v*` tag（如 `v1.0.0`）
- 手动触发（workflow_dispatch）

镜像仓库命名：

- `ghcr.io/<你的 GitHub 用户名或组织>/ipv6-username-socks5`

首次使用前请确认：

1. 仓库 `Settings -> Actions -> General` 中允许工作流读写包（`packages: write`）
2. 仓库可使用默认 `GITHUB_TOKEN` 推送到 GHCR

## 10. ciallo.ee 服务器拉取并运行 GHCR 镜像

### 10.1 登录 GHCR

```bash
echo '<YOUR_GITHUB_TOKEN>' | docker login ghcr.io -u <YOUR_GITHUB_USERNAME> --password-stdin
```

> `<YOUR_GITHUB_TOKEN>` 需要具备读取 GHCR 包权限（私有包通常需 `read:packages`）。

### 10.2 拉取镜像

```bash
docker pull ghcr.io/<YOUR_GITHUB_USERNAME>/ipv6-username-socks5:latest
```

### 10.3 运行容器

```bash
docker run -d \
  --name ipv6-username-socks5 \
  --restart unless-stopped \
  --network host \
  -e SOCKS5_PASSWORD='YourStrongPassword' \
  -e SOCKS5_LISTEN_PORT=1080 \
  -e SOCKS5_REQUEST_TIMEOUT_SECS=10 \
  -e SOCKS5_SHUTDOWN_GRACE_SECS=30 \
  -e SOCKS5_MAX_CONNECTIONS=256 \
  -e RUST_LOG=info \
  ghcr.io/<YOUR_GITHUB_USERNAME>/ipv6-username-socks5:latest
```

若不使用 `host` 网络，也可改用端口映射：

```bash
-p 1080:1080/tcp
```

至此可实现：本地提交代码 -> GitHub Actions 自动构建推送 GHCR -> ciallo.ee 拉取最新镜像部署。

## 11. Clash 客户端接入（直接使用 SOCKS5）

当前服务本质是 SOCKS5 代理，不需要先改造成 HTTPS 才能给 Clash 使用。可直接在 Clash 中新增 SOCKS5 节点：

```yaml
proxies:
  - name: sk5-ipv6-rotation
    type: socks5
    server: <你的服务器IP或域名>
    port: 1080
    username: rotation
    password: <你的SOCKS5_PASSWORD>
    udp: false

  - name: sk5-ipv6-fixed
    type: socks5
    server: <你的服务器IP或域名>
    port: 1080
    username: <IPv6转u128后的十进制字符串>
    password: <你的SOCKS5_PASSWORD>
    udp: false

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - sk5-ipv6-rotation
      - sk5-ipv6-fixed

rules:
  - MATCH,Proxy
```

说明：

- `type: socks5` 为直连 SOCKS5 方式，最简单可用。
- `username: rotation` 表示自动按轮询序列轮换出口 IPv6。
- `username: <十进制字符串>` 表示精确绑定到某个 IPv6 出口。
- `udp: false` 建议保持关闭（当前服务聚焦 TCP CONNECT）。
- 该方式已可用于 Clash，不依赖订阅链接。

## 12. 关于“HTTPS/订阅链接”

如果你想给别人发“一个 https 订阅链接”，需要额外中间层（当前仓库未内置）：

1. 订阅分发层：托管一个可通过 HTTPS 访问的配置文件（YAML）。
2. 协议转换层（可选）：若要从 SOCKS5 升级为更强混淆/抗封锁协议，需要新增 sing-box/xray/hysteria 等入口。
3. Clash 客户端导入订阅 URL 后，按分组策略使用。

结论：当前项目可直接给 Clash 用；“HTTPS 订阅”属于第二阶段增强能力。