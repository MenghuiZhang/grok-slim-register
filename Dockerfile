FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH

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

COPY requirements.txt ./
RUN python -m venv "$VIRTUAL_ENV" \
    && python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

# Offline Camoufox install: browser zip + fpgen model are pre-downloaded into
# vendor/ (GitHub releases are unreliable from build networks). The cache
# metadata (config.json / version.json / geoip) comes from a working install.
COPY vendor/ /tmp/vendor/
RUN python - <<'PY'
import pathlib
import shutil
import zipfile

VENDOR = pathlib.Path("/tmp/vendor")
CACHE = pathlib.Path("/root/.cache/camoufox")
DEST = CACHE / "browsers" / "official" / "156.0.1-beta.36-0ad5663e"

# 1) 浏览器：解压 vendor zip（zipfile 不保留 unix 权限，需按 external_attr 恢复）
extract = pathlib.Path("/tmp/camoufox_extract")
shutil.rmtree(extract, ignore_errors=True)
with zipfile.ZipFile(VENDOR / "camoufox-156.0.1-beta.36-lin.arm64.zip") as zf:
    for info in zf.infolist():
        zf.extract(info, extract)
        mode = info.external_attr >> 16
        if mode:
            target = extract / info.filename
            if target.exists():
                target.chmod(mode & 0o7777)
entries = list(extract.iterdir())
src = entries[0] if len(entries) == 1 and entries[0].is_dir() else extract
DEST.parent.mkdir(parents=True, exist_ok=True)
shutil.rmtree(DEST, ignore_errors=True)
shutil.move(str(src), str(DEST))

# 2) 缓存元数据：config.json（active_version）/ version.json / geoip / 兼容标记
meta = VENDOR / "camoufox-cache"
if not (DEST / "version.json").exists():
    shutil.copy(meta / "version.json", DEST / "version.json")
for name in ("config.json", ".0.5_FLAG"):
    shutil.copy(meta / name, CACHE / name)
if (meta / "geoip").exists():
    shutil.rmtree(CACHE / "geoip", ignore_errors=True)
    shutil.copytree(meta / "geoip", CACHE / "geoip")

# 3) fpgen 指纹模型：离线安装到 fpgen 包的 data/ 目录（sha256 由 camoufox 校验）
import camoufox.fpgen_model as fm
import io

zip_bytes = (VENDOR / "model-release.zip").read_bytes()
fm.webdl = lambda url, progress_callback=None: io.BytesIO(zip_bytes)
fm.ensure_fpgen_model(force=True)

# 4) 验证：启动路径存在且可执行（不访问网络）
launch = pathlib.Path("/root/.cache/camoufox") / __import__(
    "json"
).loads((CACHE / "config.json").read_text())["active_version"]
assert (launch / "version.json").exists(), "version.json missing"
print("camoufox offline install OK:", DEST)
PY
RUN test -x "$(python -m camoufox path)" && echo "BROWSER_BINARY_OK"

COPY . .

ENV RUNNING_IN_DOCKER=1

EXPOSE 3333

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=4 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:3333/api/health', timeout=3)" || exit 1

CMD ["python", "app.py"]
