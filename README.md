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

### Web 控制台

```bash
python app.py     # http://127.0.0.1:3333
```

- 「启动注册」会后台串行执行 `python -m g.ui_register --headless`（一轮一个号），日志实时回显
- 页面：首页（运行/统计/日志）、邮箱配置、代理设置、导入服务
- 停止按钮会终止当前轮；已完成账号自动进入右侧列表并可被导入服务引用

## Docker 部署

### 生产（控制台）

构建镜像需要 Camoufox 的 Linux 浏览器包（GitHub Releases 在部分网络下不可达）。
首次构建前把两个文件放进 `vendor/`（目录已 gitignore）：

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

### 可视化调试（noVNC）

```bash
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
2. 兜底坐标候选 + 整轮重试（首次点击可能只是"预热" 0×1 iframe）
3. 每次点击后校验 `cf-turnstile-response` token 是否下发，命中即返回

不使用外部 Solver，也不注入 token——必须让 widget 自身变绿才能通过提交。

## 导入分发（import-services）

控制台「导入服务」页可把注册成功的 `sso` 分发到 sub2api / CPA / grok2api 等目标：

- 账号来源：`register_sso/*.json`、`keys/`、控制台会话内最近成功列表
- OAuth 目标会先用 `g/device_flow.py` 把 sso 换成 access_token 再写入
- 支持自动分发（注册成功即入队）、重试、取消与任务历史

## 常见问题

- **邮箱配置不可用**：先在「邮箱配置」页填好并测试 provider，或检查 `.env` 中对应变量
- **域名池没有已启用域名**：邮箱配置页启用至少一个域名，或清空域名池让其自动选域
- **Turnstile 点不中**：确认窗口尺寸与实际一致；坐标兜底按 `1500x950` 测得，换尺寸优先依赖按钮相对定位
- **无头模式下邮箱输入**：macOS OS 键盘在无头下不可用，脚本会自动回退到 Playwright `fill`
