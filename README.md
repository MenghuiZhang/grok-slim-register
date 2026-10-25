# Grok 注册机（UI 注册流程 + Web 控制台）

基于 Camoufox（Firefox 内核）的 xAI / Grok 账号注册工具。注册全程走浏览器真实交互：
临时邮箱 → 邮箱注册 → 收验证码 → 资料页填姓名密码 → 点击 Cloudflare Turnstile 的
`Verify you are human` checkbox → 提交拿到 `sso`。

配套一个 Flask Web 控制台，用于管理邮箱配置、域名池、代理池、导入分发与运行日志。

## 目录结构

```
.
├── app.py                  # Web 控制台（Flask，端口 3333）
├── g/
│   ├── ui_register.py      # 注册流程主入口（命令行 / 控制台子进程）
│   ├── email_service.py    # 临时邮箱（freemail / yyds / cloudflare_temp / outlook）
│   ├── email_config.py     # 邮箱配置解析与校验
│   ├── domain_pool.py      # 邮箱域名池（data/domain_pool.json）
│   ├── proxy_pool.py       # 代理池（data/proxy_pool.json）
│   ├── import_services.py  # 注册结果分发到下游（sub2api / cpa / grok2api）
│   ├── device_flow.py      # SSO → OIDC device flow → access_token
│   └── log_buffer.py       # 控制台日志环形缓冲
├── convert_sso_json.py     # SSO 结果转 CPA/上游格式
├── log_storage.py          # 日志与磁盘占用保护
├── templates/ static/      # 控制台页面
├── data/                   # 运行时状态（域名池/代理池，已 gitignore）
├── register_sso/           # 注册结果 JSON（运行时自动创建）
├── Dockerfile              # 生产镜像（控制台）
├── Dockerfile.debug        # 调试镜像（Xvfb + noVNC 可视化）
├── compose.yaml            # 生产编排
└── compose.debug.yaml      # 调试编排
```

## 环境要求

- Python 3.10+
- Camoufox 浏览器（首次 `python -m camoufox fetch` 下载）
- macOS 下可用系统级键盘输入提升兼容性（无权限时自动回退到 Playwright 注入）
- `camoufox` 版本已锁在 `0.5.8`：它对应的浏览器 build 是 `156.0.1-beta.36`，
  升级 camoufox 会同时换浏览器版本，需要同步 `vendor/` 离线包和 CI 下载的 zip

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m camoufox fetch
```

## 配置

复制 `.env.example` 为 `.env` 并按需填写，常用项：

| 变量 | 说明 |
|---|---|
| `EMAIL_PROVIDER` | `cloudflare_temp` / `freemail` / `yyds` / `outlook` |
| `EMAIL_CF_TEMP_BASE_URL` | cloudflare_temp_email 服务地址 |
| `EMAIL_CF_TEMP_SITE_TOKEN` / `EMAIL_CF_TEMP_ADMIN_KEY` | 站点令牌 / 管理员密钥 |
| `EMAIL_CF_TEMP_DOMAINS_JSON` | 域名数组；留空 + `AUTO_DOMAIN=1` 由服务端选 |
| `UI_HOST` / `UI_PORT` | 控制台监听地址（默认 127.0.0.1:3333） |
| `MONITOR_TOKEN` | 运维 API（存储/导入）鉴权 |
| `GROK_CAMOUFOX_HEADLESS` | `1` 无头（默认）/ `0` 有头（调试镜像观察） |
| `GROK_PROXY_LEASE_WAIT` | 代理池无可用节点时最多等几秒再跳过该轮（默认 120，0 = 不等待） |
| `GROK_SUBMIT_NAV_TIMEOUT` | 提交邮箱后等待进入验证码页的秒数（默认 20；期间持续检测报错文本，命中立即放弃） |
| `GROK_AUTO_EXCHANGE_TOKEN` | `1` 注册成功后自动换 token（默认）/ `0` 关闭；取消勾选会同时落盘保存 |
| `GROK_BROWSER_CONVERT` | `1` 注册浏览器内顺手换票（默认）/ `0` 关闭；取消勾选「自动换 token」时自动置 0 |
| `GROK_DEVICE_CODE_PROXY` | 换票代理模式（device flow 整链路）：`auto` 与注册节点一致，注册浏览器内顺手换票（默认）/ `direct` 关闭浏览器内换票，注册后注入 SSO 独立换票、全链路直连 / `http://user:pass@host:port` 独立换票走特定代理。机场按域名拦截 auth.x.ai 时选 direct/specific。配置页「换票代理」可视化设置 |
| `SUB2API_*` / `UPSTREAM_*` | 导入下游配置（也可在控制台里改） |

`data/domain_pool.json`、`data/proxy_pool.json` 为运行时状态，由控制台维护，不需要手填。

## 本机运行

### 命令行注册（一次一个号）

```bash
python -m g.ui_register                       # 自动建临时邮箱 + 有头窗口
python -m g.ui_register --headless            # 无头
python -m g.ui_register --email a@b.com       # 复用已有邮箱
python -m g.ui_register --proxy http://...    # 走指定代理
```

结果写入 `register_sso/ui_<ts>.json`（`ok` / `email` / `sso` / `steps` / `error`）。
控制台启动的注册还会在后台补写 `auth_token` / `token_status`（见下文「注册后自动换 token」）。

### Web 控制台

```bash
python app.py     # http://127.0.0.1:3333
```

- 「启动注册」会后台串行执行 `python -m g.ui_register --headless`（一轮一个号），日志实时回显
- 页面：首页（运行/统计/日志）、邮箱配置、代理设置、导入服务
- 停止按钮会终止当前轮；已完成账号自动进入右侧列表并可被导入服务引用

### 注册走代理（账号级租约）

每轮注册**开始前**由控制台从代理池租一个节点，通过 `GROK_REGISTER_PROXY`
注入子进程，注册浏览器和收码邮箱（`EMAIL_PROXY_MODE=register` 时）走同一出口：

- 租到节点 → 日志打印 `本轮注册开始 · 节点 http://***:port`，账号 JSON 里写脱敏的 `proxy` / `proxy_mode`
- 池子为空 → 本轮直连（日志明确写「直连（代理池为空）」）
- 池里有节点但全被占用/冷却/停用 → 等 `GROK_PROXY_LEASE_WAIT` 秒（默认 120，0 = 不等），
  仍没有就**跳过该轮**并计失败，不会偷偷直连
- 轮次结束按结果释放：成功记 healthy，`ERR_*` / timeout 等网络类失败进冷却，其他只计数
- 初始化时的 `GROK_PROXY` / `DEBUG_PROXY` 已废弃：控制台会从子进程环境里剔除，
  单轮排查请用 `python -m g.ui_register --proxy http://...`

### 注册后自动换 token

每个号注册成功拿到 `sso` 后会立即在后台异步跑 device flow
（`g/device_flow.py`，SSO → OIDC device approve → `access_token`）：

- 换票复用节点：优先账号记录的注册节点，其次从代理池租一个（`wait=False`，不阻塞），
  池子为空/无可用节点时才继承环境代理或直连；全局串行 + 限流冷却，避免 approve 互相踩踏
- 成功结果回写 `register_sso/ui_*.json`（`auth_token` / `token_status`）并进入成功列表缓存
- 换票完成（成功或失败）后才交给导入服务：成功直接用缓存 token 直写，
  失败则由导入服务再跑一次 device flow 兜底
- 日志走右侧「Risk · Token · NSFW」副区；不阻塞注册主循环，吞吐不受影响
- 关闭方式：启动面板取消勾选「注册后自动换 token」，或设 `GROK_AUTO_EXCHANGE_TOKEN=0`。
  取消勾选后会同时关闭注册浏览器内的顺手换票（`GROK_BROWSER_CONVERT=0`）并把开关写进 `.env`，
  重启后仍生效。关闭后注册阶段（含浏览器内）完全不做 device flow；
  注册触发的自动导入也只导纯 SSO（sub2api 走服务端 sso-to-oauth，无 token 的 CPA/grok2api
  目标跳过并标记原因）；导入中心手动创建的任务不受影响，仍可正常换票导入

## Docker 部署

### 生产（控制台）

构建镜像需要 Camoufox 的 Linux 浏览器包。三种方式，优先级从高到低：

| 方式 | 构建参数 | 说明 |
|---|---|---|
| 直连 URL（最可控） | `CAMOUFOX_ZIP_URL` (+`CAMOUFOX_MODEL_URL`) | 自己给 zip 地址，镜像/反代/私有仓库都行，**不同步版本、不查 release** |
| 在线 fetch | `CAMOUFOX_INSTALL=online` (+`CAMOUFOX_VERSION`) | 用 camoufox 自带下载器，会先同步 3 个仓库的版本列表 |
| 离线包 | 默认 `offline` | 解压 `vendor/` 里的 zip，版本固定，无网络依赖 |

```bash
# 1) 直连镜像（推荐国内网络）：浏览器 ~1.28GB，绕开 GitHub 直连
CAMOUFOX_ZIP_URL=https://<你的镜像>/https://github.com/daijro/camoufox/releases/download/v156.0.1-beta.36/camoufox-156.0.1-beta.36-lin.arm64.zip \
CAMOUFOX_MODEL_URL=https://<你的镜像>/https://github.com/scrapfly/fingerprint-generator/releases/download/model-2/2026/model-release.zip \
docker compose up -d --build

# 2) 在线 fetch，并指定仓库：Official / CoryKing / JWriter20（见 camoufox 包内 repos.yml）
CAMOUFOX_INSTALL=online CAMOUFOX_VERSION=Official/stable/156.0.1-beta.36 docker compose up -d --build
```

> **为什么“一直在查找 camoufox 版本”**：走 `online` 时 camoufox 会先 `Syncing repositories...`，
> 依次拉 `Official`(约 0.5s)、`CoryKing`(常 30s+)、`JWriter20`，共 30–60s；之后才开始下载 1.28GB 浏览器包，
> 非 TTY 下没有进度条，看着就像卡住。指定 `CAMOUFOX_ZIP_URL` 可以完全跳过这两步。
>
> **注意**：camoufox 包用 `browser-pin.json` 固定浏览器 build（当前 `156.0.1-beta.36`），
> 镜像里的 zip 必须是同一个 release，否则 `camoufox path` 找不到可用版本。换版本要连 `requirements.txt` 里的
> camoufox 一起升级。

离线构建则把两个文件放进 `vendor/`（目录已 gitignore，仅保留 `.gitkeep` 占位）：

1. `camoufox-156.0.1-beta.36-lin.arm64.zip`
   <https://github.com/daijro/camoufox/releases/download/v156.0.1-beta.36/camoufox-156.0.1-beta.36-lin.arm64.zip>
2. `model-release.zip`
   <https://github.com/scrapfly/fingerprint-generator/releases/download/model-2/2026/model-release.zip>

（支持 `curl -L -C -` 断点续传；缓存元数据 config.json/version.json/geoip 已内置。）

```bash
docker compose up -d --build
# 访问 http://127.0.0.1:3333
```

`compose.yaml` 会挂载 `.env`、`data/`、`logs/`、`register_sso/`、`converted_auth/`，
容器内运行 `python app.py`。

### GitHub Actions 构建（不需要 vendor/）

`.github/workflows/docker-image.yml` 已配好，三种触发：

| 触发 | 行为 |
|---|---|
| push 到 `main` | 构建 + 推送 GHCR（`latest`、分支名、`sha-xxxx`），默认**双架构** `linux/amd64,linux/arm64` |
| push `v*` tag | 构建 + 推送 GHCR（tag 名） |
| Actions 页手动 `Run workflow` | 可选平台（`linux/amd64` / `linux/arm64` / 两个都用）与是否推送 |
| Pull Request | 只构建不推送，验证 Dockerfile 能编过 |

- CI 默认用 `build-args: CAMOUFOX_INSTALL=online`，构建时 `python -m camoufox fetch` + 安装 fpgen 模型，
  不依赖 `vendor/`；要用固定版本就再加 `CAMOUFOX_VERSION=Official/stable/<版本>`
- 想走镜像/反代：在仓库 **Settings → Variables** 配 `CAMOUFOX_ZIP_URL` / `CAMOUFOX_MODEL_URL`，workflow 会自动传入
- 镜像地址：`ghcr.io/<owner>/<repo>:<tag>`，默认私有，需 `GITHUB_TOKEN`（workflow 已用内置 `GITHUB_TOKEN` 登录）
- 镜像约 3.5GB（见下“镜像体积”），GitHub runner 直连 GitHub Releases 通常 10–20 分钟；
  选了 `linux/arm64` 会走 QEMU，明显更慢
- 缓存用 `type=gha`（仓库上限 10GB，`mode=max` 可能被频繁淘汰，可改 registry cache）

### VPS 部署（直接拉 GHCR 镜像，不在服务器上构建）

服务器上**不需要** `vendor/`、不需要下载 1.28GB 浏览器，也不需要几 GB 的构建缓存 —— 镜像里已经带好了。
建议配置：2 核 4G 起，磁盘 ≥ 20G（镜像约 1.5GB 压缩 / 3.4GB 解压，加日志截图会慢慢涨）。

> 懒人版：`deploy/vps-deploy.sh` 把下面第 1–3 步全做了，见文末「一键部署脚本」。手动部署就按 1→6 走。

#### 1. 装 Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
docker compose version        # 需要 v2（compose 插件）
```

#### 2. 拉代码 + 填 `.env`

```bash
git clone https://github.com/MenghuiZhang/grok-slim-register.git /opt/grok
cd /opt/grok
cp .env.example .env
sed -i "s|^MONITOR_TOKEN=.*|MONITOR_TOKEN=$(openssl rand -hex 32)|" .env
mkdir -p data logs keys register_sso converted_auth
chmod 600 .env
```

至少确认这几项：

| 变量 | 说明 |
|---|---|
| `MONITOR_TOKEN` | 运维 API（存储/导入）鉴权，上面的命令已生成随机值 |
| `EMAIL_PROVIDER` | `cloudflare_temp` / `freemail` / `yyds` / `outlook`，并填对应 `EMAIL_*` 块 |
| `SUB2API_URL`、`UPSTREAM_URL` | 下游在同一台机器时用 `http://host.docker.internal:9898`，**不要写 127.0.0.1**（那是容器自己） |
| `UPSTREAM_ADMIN_EMAIL` / `UPSTREAM_ADMIN_PASSWORD` | sub2api 管理员账号 |
| `UI_HOST` | 默认 `127.0.0.1`，只监听本机；要公网访问请走反代（见第 4 步） |

代理池、域名池、导入服务目标这些不用手改 `.env`，启动后到控制台页面里配，会存到 `data/`。

#### 3. 拉镜像并启动

```bash
export GROK_IMAGE_REF=ghcr.io/menghuizhang/grok-slim-register:latest
docker compose pull
docker compose up -d --no-build
docker compose ps
curl -s http://127.0.0.1:3333/api/health     # {"ok":true,...}
```

- `--no-build` 强制只用镜像；`compose.yaml` 里的 `build:` 段只在本地构建时才生效
- 不用 compose 的话，等价命令：

```bash
docker run -d --name grok-web --init --restart unless-stopped --shm-size=2gb \
  -p 127.0.0.1:3333:3333 \
  -v "$PWD/.env:/app/.env" -v "$PWD/data:/app/data" -v "$PWD/logs:/app/logs" \
  -v "$PWD/keys:/app/keys" -v "$PWD/register_sso:/app/register_sso" \
  -v "$PWD/converted_auth:/app/converted_auth" \
  ghcr.io/menghuizhang/grok-slim-register:latest
```

> ⚠️ 别在生产机上 `docker compose build`：那会重新下载浏览器包并占几 GB 构建缓存，VPS 上没必要。

#### 4. 怎么访问控制台

最省事：SSH 隧道（不暴露公网）

```bash
ssh -L 3333:127.0.0.1:3333 user@your-vps
# 然后本地浏览器打开 http://127.0.0.1:3333
```

要公网访问就用反代 + HTTPS，并把 3333 关在防火墙内：

```caddy
# Caddy（自动证书）
grok.example.com {
    basic_auth {
        admin <bcrypt-hash>     # caddy hash-password 生成
    }
    reverse_proxy 127.0.0.1:3333
}
```

```nginx
# Nginx
location / {
    proxy_pass http://127.0.0.1:3333;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 300s;
}
```

```bash
ufw allow 22/tcp && ufw allow 80,443/tcp && ufw enable   # 不放行 3333
```

> 注册是容器内的浏览器发起的，不经过你的反代；反代只影响你访问控制台。

#### 5. 升级 / 运维 / 备份

```bash
docker compose pull && docker compose up -d --no-build   # 升级到新镜像
docker compose logs -f --tail=200                        # 看实时日志
docker compose restart                                   # 重启
docker stats --no-stream                                 # 资源占用
```

备份（换机器时直接拷走这些就够）：

```bash
tar czf ~/grok-$(date +%F).tgz .env data keys register_sso converted_auth
```

- `register_sso/`：注册结果（含 SSO / 换到的 token）
- `converted_auth/`：CPA / OAuth 凭证
- `data/`：代理池、域名池、导入服务配置
- 日志靠 `LOG_MAX_MB` / `LOG_ROTATE_FILE_COUNT` 自动轮转；截图/诊断包可用控制台「存储」面板清理

#### 6. 常见问题（VPS）

| 现象 | 处理 |
|---|---|
| `docker compose up` 报 `.env` 挂载失败 | `compose.yaml` 用 `create_host_path: false`，必须先 `cp .env.example .env` |
| 公网打不开 3333 | 默认 `UI_HOST=127.0.0.1`，是设计如此；用 SSH 隧道或反代 |
| 端口冲突 | `.env` 里设 `GROK_HOST_PORT=3334`（compose 会用它做宿主机端口） |
| 启动注册提示「邮箱配置不可用」 | 到「邮箱配置」页填好并点测试；`cloudflare_temp` 需要 base_url + site_token + 至少一个启用域名 |
| 容器一直 `starting` / `unhealthy` | 首次启动有 90s 的 start-period；超时就看 `docker compose logs` |
| ARM VPS（Oracle A1、树莓派等） | `latest` 默认已是多架构 manifest（amd64 + arm64），直接 `docker compose pull` 即可；手动 `Run workflow` 时**别只选 arm64**，那会把 `latest` 覆盖成单架构 |

#### 7. 一键部署脚本

`deploy/vps-deploy.sh` 等价于上面 1–3 步：装/校验 Docker → 克隆代码 → 生成 `.env`（自动填随机 `MONITOR_TOKEN`）→ 建挂载目录 → 拉镜像 → `up -d --no-build` → 等健康检查 → 打印访问方式。

```bash
# 在 VPS 上（首次，不想 clone 仓库也行）
curl -fsSL https://raw.githubusercontent.com/MenghuiZhang/grok-slim-register/main/deploy/vps-deploy.sh -o deploy.sh
sudo bash deploy.sh                     # 默认 /opt/grok + 3333 端口
# 或者已经 clone 了仓库
sudo bash deploy/vps-deploy.sh --dir /opt/grok --port 3333

# 先看看它会做什么（不执行）
bash deploy/vps-deploy.sh --dir /opt/grok --dry-run
```

> 脚本自带 shebang，`chmod +x deploy/vps-deploy.sh` 后可以直接 `./deploy/vps-deploy.sh`；没执行权限就用 `bash` 前缀。

| 命令 | 作用 |
|---|---|
| `bash deploy.sh` | 首次部署 / 幂等重跑 |
| `bash deploy.sh --update` | 拉新镜像并重建容器（升级用） |
| `bash deploy.sh --status` | 容器状态 + 健康检查 |
| `bash deploy.sh --logs` | 跟踪日志（`logs -f --tail=200`） |
| `bash deploy.sh --restart` / `--stop` | 重启 / 停止并删容器（数据目录保留） |
| `bash deploy.sh --dry-run` | 只打印将要执行的命令 |

可选参数：`--dir`（安装目录）、`--port`（宿主机端口）、`--bind`（监听地址，默认 `127.0.0.1`）、`--image`（换镜像地址）、`--repo`（换仓库）、`-y`（缺 Docker 时自动装）。
私有镜像用 `GHCR_USER=xxx GHCR_TOKEN=xxx ./deploy.sh`。
脚本会把 `GROK_IMAGE_REF` / `GROK_HOST_PORT` / `GROK_BIND_ADDRESS` 写进 `.env`，之后直接 `docker compose up -d --no-build` 也能复现同样的配置。

### 镜像体积

`Dockerfile` 分两阶段：`builder` 装依赖、下浏览器，最终镜像只 `COPY --from` venv 和 `~/.cache/camoufox`。
实测（linux/arm64，`CAMOUFOX_ZIP_URL` 模式）：镜像内容 **3.36GB**，压缩后 **1.50GB**
（`docker image inspect .Size`）

| 内容 | 约体积 |
|---|---|
| 浏览器 `~/.cache/camoufox` | 2.5GB |
| venv（flask / curl_cffi / camoufox / playwright…） | 347MB |
| 浏览器系统库（apt） | 341MB |
| 运行代码 | ~1MB |

> Docker Desktop 的 `docker images` 数字会因共享层/统计口径偏大（同一镜像可能显示 5GB），
> 以 `docker image inspect --format '{{.Size}}'` 或 `docker save | wc -c` 为准。

旧版 10GB 的原因（已修）：
1. `COPY vendor/ /tmp/vendor/` 把 1.28GB 离线包永久写进镜像层（后来又 `rm` 也没用，层不会缩小）
2. `COPY . .` 又把 `vendor/` 复制进 `/app/vendor`，同一个包打了两份
3. 在旧镜像上叠加构建，把历史层一起继承

现在的处理：`vendor` 不下发到最终镜像（离线安装只在 builder 里发生），运行代码按白名单 `COPY`（不含 `vendor/`、`logs/`、`data/`）。

### 可视化调试（noVNC）

```bash
# 没有 vendor/ 时加 --build-arg CAMOUFOX_INSTALL=online
docker build -t cloudtemp-grokzhuce:local .
docker build -f Dockerfile.debug -t cloudtemp-grokzhuce:debug .
docker compose -f compose.yaml -f compose.debug.yaml up -d --no-build
# 观察浏览器：http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale
```

调试镜像通过 `GROK_CAMOUFOX_HEADLESS=0` 强制有头，配合 Xvfb + x11vnc + noVNC 观察每一步。

## Turnstile 勾选机制

资料页的 Turnstile widget 位于跨域 iframe / closed shadow DOM 内，DOM 无法定位。
注册流程按视觉位置点击 checkbox：

1. 读取「Complete sign up」按钮的 bounding box，按固定相对偏移推算 checkbox 位置（布局无关，有头/无头通用）
2. 兜底坐标候选（按 `1500x950` 测得），按钮定位优先
3. **每次只点一下**，然后轮询 `cf-turnstile-response` 最多 12s；期间绝不重复点击
4. 只有等满仍没有 token 才换下一个候选坐标（Turnstile 进入 Verifying 后再点会 reset，
   表现就是"刚勾上又立刻弹回未勾选"）
5. 拿到 token 后等 1.5s 让 React 写进表单状态，再点提交

不使用外部 Solver，也不注入 token——必须让 widget 自身变绿才能通过提交。
若日志里 `solved=False` 反复出现且 widget 一直回落，优先怀疑出口 IP 被判定为 bot
（机房直连 / 无头），换住宅代理或用 `GROK_CAMOUFOX_HEADLESS=0` 复现。

## 导入分发（import-services）

控制台「导入服务」页可把注册成功的 `sso` 分发到 sub2api / CPA / grok2api 等目标：

- 账号来源：`register_sso/*.json`、`keys/`、控制台会话内最近成功列表
- OAuth 目标会先用 `g/device_flow.py` 把 sso 换成 access_token 再写入
- 支持自动分发（注册成功即入队）、重试、取消与任务历史

## 常见问题

- **邮箱配置不可用**：先在「邮箱配置」页填好并测试 provider，或检查 `.env` 中对应变量
- **"Email sign-up isn't available right now"**：域名/IP 被 xAI 拒绝邮箱注册；脚本提交后
  每 0.5s 检测一次页面文本，命中报错 1–2s 内即放弃本轮（默认最多等 20s 进验证码页，
  可用 `GROK_SUBMIT_NAV_TIMEOUT` 调整），worker 自动开下一轮换邮箱换节点
- **控制台「自动换 token」勾选被弹回**：已修复——checkbox 只在页面首次加载时同步服务端值，
  之后不再被轮询覆盖；且取消勾选时会写入 `.env` 持久保存，重启不再弹回默认勾选
- **域名池没有已启用域名**：邮箱配置页启用至少一个域名，或清空域名池让其自动选域
- **Turnstile 点不中 / 勾上又弹回**：确认窗口尺寸与实际一致（坐标兜底按 `1500x950` 测得）；
  若一直回落，先看日志的节点出口，机房 IP + 无头最容易触发 reset
- **无头模式下邮箱输入**：macOS OS 键盘在无头下不可用，脚本会自动回退到 Playwright `fill`
