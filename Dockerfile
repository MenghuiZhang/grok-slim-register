# syntax=docker/dockerfile:1

# =============================================================================
# 阶段 1：依赖 + Camoufox 浏览器缓存（体积都来自这里，但只有必要部分进最终镜像）
# =============================================================================
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN python -m venv "$VIRTUAL_ENV" \
    && python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

# Camoufox 安装方式（build-arg），优先级：指定 URL > online > offline
#   CAMOUFOX_ZIP_URL    — 直接下载浏览器 zip（官方 release / 自建镜像 / ghproxy 等反代），
#                         路径最可控、不查版本、不同步仓库
#   CAMOUFOX_MODEL_URL  — 可选，配套的 fpgen 模型 zip；不填则跳过模型（指纹功能受限）
#   CAMOUFOX_INSTALL    — offline（默认，解压 vendor/ 离线包）/ online（camoufox fetch）
#   CAMOUFOX_VERSION    — online 模式下的仓库/版本，如 Official/stable/156.0.1-beta.36
ARG CAMOUFOX_INSTALL=offline
ARG CAMOUFOX_VERSION=""
ARG CAMOUFOX_ZIP_URL=""
ARG CAMOUFOX_MODEL_URL=""
# 直连 URL 且文件名不是 camoufox-<version>-<build>-... 时，用它显式声明版本，如 156.0.1-beta.36
ARG CAMOUFOX_BROWSER_SPEC=""
ENV CAMOUFOX_BROWSER_SPEC=${CAMOUFOX_BROWSER_SPEC}

# 离线资产（约 1.2GB，已 gitignore）：非 offline 模式只需要 vendor/ 目录存在（保留 .gitkeep 占位）
COPY docker/install_camoufox_offline.py /tmp/install_camoufox_offline.py
COPY docker/install_camoufox_zip.py /tmp/install_camoufox_zip.py
COPY vendor/ /tmp/vendor/

RUN set -eux; \
    if [ -n "$CAMOUFOX_ZIP_URL" ]; then \
        zip_name="$(basename "${CAMOUFOX_ZIP_URL%%\?*}")"; \
        case "$zip_name" in \
            *.zip) : ;; \
            *) zip_name="camoufox-${CAMOUFOX_BROWSER_SPEC:-browser}.zip" ;; \
        esac; \
        curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 -o "/tmp/$zip_name" "$CAMOUFOX_ZIP_URL"; \
        if [ -n "$CAMOUFOX_MODEL_URL" ]; then \
            curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 -o /tmp/model-release.zip "$CAMOUFOX_MODEL_URL"; \
        fi; \
        python /tmp/install_camoufox_zip.py "/tmp/$zip_name" /tmp/model-release.zip; \
    elif [ "$CAMOUFOX_INSTALL" = "online" ]; then \
        if [ -n "$CAMOUFOX_VERSION" ]; then \
            python -m camoufox set "$CAMOUFOX_VERSION"; \
        else \
            python -m camoufox fetch; \
        fi; \
        python -c "import camoufox.fpgen_model as fm; fm.ensure_fpgen_model(force=True)"; \
    else \
        python /tmp/install_camoufox_offline.py; \
    fi; \
    rm -rf /tmp/vendor /tmp/camoufox.zip /tmp/model-release.zip /tmp/camoufox_extract
RUN test -x "$(python -m camoufox path)" && echo "BROWSER_BINARY_OK"

# =============================================================================
# 阶段 2：运行镜像（只带 venv + 浏览器缓存 + 运行代码）
# =============================================================================
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH

# 浏览器运行所需的系统库（不含编译工具链）
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-liberation \
        fonts-noto-color-emoji \
        libasound2 \
        libdbus-glib-1-2 \
        libegl1 \
        libgbm1 \
        libgl1-mesa-dri \
        libgtk-3-0 \
        libnss3 \
        libx11-xcb1 \
        libxcomposite1 \
        libxcursor1 \
        libxdamage1 \
        libxfixes3 \
        libxi6 \
        libxkbcommon0 \
        libxrandr2 \
        libxrender1 \
        libxss1 \
        libxt6 \
        libxtst6 \
        lsof \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 直接复用 builder 的 venv 与浏览器缓存，避免在最终镜像里再装一遍/再解压一遍
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /root/.cache/camoufox /root/.cache/camoufox
RUN test -x "$(python -m camoufox path)" && echo "BROWSER_BINARY_OK"

# 只复制运行所需代码：vendor/、logs/、data/、keys/ 等不会进镜像
COPY app.py convert_sso_json.py log_storage.py ./
COPY g/ ./g/
COPY templates/ ./templates/

ENV RUNNING_IN_DOCKER=1

EXPOSE 3333

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=4 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:3333/api/health', timeout=3)" || exit 1

CMD ["python", "app.py"]
