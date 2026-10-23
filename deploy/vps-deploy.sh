#!/usr/bin/env bash
# Grok 注册机 · VPS 一键部署（拉 GHCR 镜像，不在服务器上构建）
#
# 用法：
#   ./deploy/vps-deploy.sh                     # 默认装到 /opt/grok 并启动
#   sudo ./deploy/vps-deploy.sh                # 需要写 /opt 时
#   ./deploy/vps-deploy.sh --dir ~/grok --port 3334
#   ./deploy/vps-deploy.sh --update            # 拉新镜像并重建容器
#   ./deploy/vps-deploy.sh --status|--logs|--restart|--stop
#   ./deploy/vps-deploy.sh --dry-run           # 只打印要做什么
#
# 环境变量（可选）：
#   GROK_REPO_URL   代码仓库（默认 GitHub）
#   GROK_IMAGE_REF  镜像地址（默认 ghcr.io/menghuizhang/grok-slim-register:latest）
#   GHCR_USER / GHCR_TOKEN  私有镜像登录用
set -euo pipefail

REPO_URL="${GROK_REPO_URL:-https://github.com/MenghuiZhang/grok-slim-register.git}"
DEFAULT_IMAGE="ghcr.io/menghuizhang/grok-slim-register:latest"
DEFAULT_DIR="/opt/grok"

DIR="$DEFAULT_DIR"
IMAGE="${GROK_IMAGE_REF:-$DEFAULT_IMAGE}"
PORT="${GROK_HOST_PORT:-3333}"
BIND="${GROK_BIND_ADDRESS:-127.0.0.1}"
ACTION="deploy"
DRY_RUN=0
ASSUME_YES=0

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then printf '  + %s\n' "$*"; else "$@"; fi; }

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)        DIR="${2:?--dir 需要路径}"; shift 2 ;;
    --image)      IMAGE="${2:?--image 需要镜像地址}"; shift 2 ;;
    --port)       PORT="${2:?--port 需要端口}"; shift 2 ;;
    --bind)       BIND="${2:?--bind 需要地址}"; shift 2 ;;
    --repo)       REPO_URL="${2:?--repo 需要地址}"; shift 2 ;;
    --update)     ACTION="update"; shift ;;
    --status)     ACTION="status"; shift ;;
    --logs)       ACTION="logs"; shift ;;
    --restart)    ACTION="restart"; shift ;;
    --stop)       ACTION="stop"; shift ;;
    --dry-run)    DRY_RUN=1; shift ;;
    -y|--yes)     ASSUME_YES=1; shift ;;
    -h|--help)    usage ;;
    *)            die "未知参数: ${1}（--help 看用法）" ;;
  esac
done

# ---------------------------------------------------------------- 基础检查
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *)             echo "$(uname -m)" ;;
  esac
}

HOST_ARCH="$(detect_arch)"

check_docker() {
  command -v docker >/dev/null 2>&1 || {
    if command -v curl >/dev/null 2>&1 && { [ "$ASSUME_YES" = 1 ] || [ -t 0 ]; }; then
      warn "未检测到 docker，准备执行官方安装脚本（get.docker.com）"
      run sh -c 'curl -fsSL https://get.docker.com | sh'
    else
      die "未安装 docker：curl -fsSL https://get.docker.com | sh"
    fi
  }
  if ! docker compose version >/dev/null 2>&1; then
    die "缺少 docker compose v2 插件（docker-compose-plugin）"
  fi
  docker info >/dev/null 2>&1 || die "docker 守护进程未运行：sudo systemctl start docker"
}
[ "$DRY_RUN" = 1 ] || check_docker

# ---------------------------------------------------------------- 代码目录
resolve_dir() {
  mkdir -p "$DIR" 2>/dev/null || true
  [ -d "$DIR" ] || die "无法创建/访问目录 ${DIR}（写 /opt 需要 sudo）"
  DIR="$(cd "$DIR" && pwd)"
}
[ "$DRY_RUN" = 1 ] || resolve_dir

ensure_code() {
  if [ -f "$DIR/compose.yaml" ]; then
    log "使用已有代码：$DIR"
    if [ "$ACTION" = "update" ] && [ -d "$DIR/.git" ] && [ "$DRY_RUN" = 0 ]; then
      log "同步代码（git pull --ff-only）"
      git -C "$DIR" pull --ff-only || warn "git pull 失败，继续用当前代码"
    fi
    return
  fi
  command -v git >/dev/null 2>&1 || die "缺少 git：apt install -y git"
  log "克隆代码到 $DIR"
  run git clone --depth 1 "$REPO_URL" "$DIR"
}

# ---------------------------------------------------------------- .env
set_env() { # key value  —— 有则替换，无则追加
  local key="$1" value="$2" file="$DIR/.env"
  if [ "$DRY_RUN" = 1 ]; then
    printf '  + .env %s=%s\n' "$key" "$value"
    return
  fi
  awk -v k="$key" -v v="$value" '
    BEGIN { done = 0 }
    $0 ~ "^[[:space:]]*" k "=" { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
  chmod 600 "$file"
}

get_env() { # key -> value
  local file="$DIR/.env"
  [ -f "$file" ] || return 0
  awk -v k="$1" -F= '$1 ~ "^[[:space:]]*" k "$" { sub("^[^=]*=", ""); print; exit }' "$file"
}

ensure_env() {
  if [ ! -f "$DIR/.env" ]; then
    if [ "$DRY_RUN" = 0 ] && [ ! -f "$DIR/.env.example" ]; then
      die "$DIR 里没有 .env.example"
    fi
    log "生成 $DIR/.env（来自 .env.example）"
    run cp "$DIR/.env.example" "$DIR/.env"
  fi
  local token
  token="$(get_env MONITOR_TOKEN)"
  if [ -z "$token" ] || printf '%s' "$token" | grep -q "replace-with-a-long-random-token"; then
    local new_token=""
    if command -v openssl >/dev/null 2>&1; then
      new_token="$(openssl rand -hex 32)"
    fi
    [ -n "$new_token" ] || new_token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    log "写入随机 MONITOR_TOKEN"
    set_env MONITOR_TOKEN "$new_token"
  fi
  set_env GROK_IMAGE_REF "$IMAGE"
  set_env GROK_HOST_PORT "$PORT"
  set_env GROK_BIND_ADDRESS "$BIND"
}

ensure_dirs() {
  log "创建挂载目录"
  run mkdir -p "$DIR"/{data,logs,keys,register_sso,converted_auth}
}

# ---------------------------------------------------------------- 镜像
ghcr_login() {
  [ -n "${GHCR_TOKEN:-}" ] || return 0
  log "登录 GHCR（user=${GHCR_USER:-$USER}）"
  if [ "$DRY_RUN" = 1 ]; then
    echo "  + docker login ghcr.io"
  else
    printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "${GHCR_USER:-$USER}" --password-stdin
  fi
}

pull_image() {
  log "拉取镜像 $IMAGE"
  run docker pull "$IMAGE"
  if [ "$DRY_RUN" = 1 ]; then
    return 0
  fi
  local img_arch
  img_arch="$(docker image inspect "$IMAGE" --format '{{.Architecture}}' 2>/dev/null || echo "")"
  if [ -n "$img_arch" ] && [ "$img_arch" != "$HOST_ARCH" ]; then
    warn "镜像架构 $img_arch 与本机 $HOST_ARCH 不一致，可能无法启动/极慢。"
    warn "ARM 机器请在 Actions 手动 Run workflow 选 linux/amd64,linux/arm64 重新构建。"
  fi
}

# ---------------------------------------------------------------- 生命周期
compose() { ( cd "$DIR" && docker compose "$@" ); }

wait_health() {
  local cid="" i=0
  if [ "$DRY_RUN" = 1 ]; then
    echo "  + 等待健康检查 http://$BIND:$PORT/api/health"
    return 0
  fi
  cid="$(compose ps -q grok-web 2>/dev/null || true)"
  [ -n "$cid" ] || die "容器没起来，看日志：$0 --logs"
  while [ "$i" -lt 60 ]; do
    local state
    state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)"
    case "$state" in
      healthy) log "容器健康（${state}）"; return 0 ;;
      exited|dead) break ;;
    esac
    i=$((i + 1))
    sleep 2
  done
  warn "健康检查未通过，最近日志："
  compose logs --tail=40 || true
  die "部署后容器未就绪"
}

do_deploy() {
  ensure_code
  ensure_env
  ensure_dirs
  ghcr_login
  pull_image
  log "启动/更新容器（--no-build）"
  run bash -c "cd '$DIR' && docker compose up -d --no-build"
  wait_health
  print_summary
}

do_update() {
  ensure_code
  ensure_env
  ghcr_login
  pull_image
  log "重建容器"
  run bash -c "cd '$DIR' && docker compose up -d --no-build"
  wait_health
  print_summary
}

print_summary() {
  local provider
  provider="$(get_env EMAIL_PROVIDER)"
  cat <<EOF

────────────────────────────────────────────────
 容器已就绪
 目录      : $DIR
 镜像      : $IMAGE
 监听      : ${BIND}:${PORT}（仅本机，公网请走反代）
 健康检查  : curl -s http://127.0.0.1:$PORT/api/health

 下一步：
 1. 本机访问（推荐 SSH 隧道）：
      ssh -L $PORT:127.0.0.1:$PORT <user>@<this-vps>
      浏览器打开 http://127.0.0.1:$PORT
 2. 配置邮箱：控制台「邮箱配置」页填好并点测试
EOF
  if [ -z "$provider" ]; then
    cat <<EOF
    （当前 .env 里 EMAIL_PROVIDER 为空，必须先在页面配置或改 .env）
EOF
  fi
  cat <<EOF
 3. 配置下游：控制台「导入服务」页（sub2api / CPA / grok2api）
 4. 常用命令：
      $0 --status     查看状态
      $0 --logs       跟踪日志
      $0 --update     升级镜像
      $0 --stop       停止并删除容器（保留数据目录）
────────────────────────────────────────────────
EOF
}

do_status() {
  [ -f "$DIR/compose.yaml" ] || die "目录里没有 compose.yaml：$DIR"
  compose ps || true
  local cid state
  cid="$(compose ps -q grok-web 2>/dev/null || true)"
  if [ -n "$cid" ]; then
    state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)"
    echo "健康状态: $state"
  fi
  curl -fsS -m 3 "http://127.0.0.1:$PORT/api/health" && echo || warn "本机 $PORT 端口健康检查失败"
}

do_logs() {
  [ -f "$DIR/compose.yaml" ] || die "目录里没有 compose.yaml：$DIR"
  compose logs -f --tail=200
}

do_restart() {
  [ -f "$DIR/compose.yaml" ] || die "目录里没有 compose.yaml：$DIR"
  log "重启容器"
  run bash -c "cd '$DIR' && docker compose restart"
  wait_health
}

do_stop() {
  [ -f "$DIR/compose.yaml" ] || die "目录里没有 compose.yaml：$DIR"
  log "停止并删除容器（数据目录、.env 保留）"
  run bash -c "cd '$DIR' && docker compose down"
}

case "$ACTION" in
  deploy)  do_deploy ;;
  update)  do_update ;;
  status)  do_status ;;
  logs)    do_logs ;;
  restart) do_restart ;;
  stop)    do_stop ;;
esac
