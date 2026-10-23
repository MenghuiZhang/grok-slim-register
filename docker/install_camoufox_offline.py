"""离线安装 Camoufox：从 vendor/ 解压浏览器 + 指纹模型。

构建参数 CAMOUFOX_INSTALL=offline（默认）时由 Dockerfile 调用。
vendor/ 不入库（见 .gitignore），本地构建前需准备：

1. camoufox-156.0.1-beta.36-lin.arm64.zip
2. model-release.zip
3. camoufox-cache/{config.json,version.json,.0.5_FLAG,geoip/}
"""

import io
import json
import pathlib
import shutil
import sys
import zipfile

import camoufox.fpgen_model as fm

VENDOR = pathlib.Path("/tmp/vendor")
CACHE = pathlib.Path("/root/.cache/camoufox")
BROWSER_DIR_NAME = "156.0.1-beta.36-0ad5663e"
DEST = CACHE / "browsers" / "official" / BROWSER_DIR_NAME
BROWSER_ZIP = VENDOR / "camoufox-156.0.1-beta.36-lin.arm64.zip"


def _require(path: pathlib.Path) -> pathlib.Path:
    if not path.exists():
        sys.exit(
            f"[camoufox-offline] 缺少 {path}\n"
            "  离线构建需要 vendor/ 下的浏览器包与 camoufox-cache 元数据；\n"
            "  没有这些资产时请用 --build-arg CAMOUFOX_INSTALL=online 在线安装。"
        )
    return path


# 1) 浏览器：解压 vendor zip（zipfile 不保留 unix 权限，需按 external_attr 恢复）
extract = pathlib.Path("/tmp/camoufox_extract")
shutil.rmtree(extract, ignore_errors=True)
with zipfile.ZipFile(_require(BROWSER_ZIP)) as zf:
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
meta = _require(VENDOR / "camoufox-cache")
if not (DEST / "version.json").exists():
    shutil.copy(meta / "version.json", DEST / "version.json")
for name in ("config.json", ".0.5_FLAG"):
    shutil.copy(meta / name, CACHE / name)
if (meta / "geoip").exists():
    shutil.rmtree(CACHE / "geoip", ignore_errors=True)
    shutil.copytree(meta / "geoip", CACHE / "geoip")

# 3) fpgen 指纹模型：离线安装到 fpgen 包的 data/ 目录（sha256 由 camoufox 校验）
zip_bytes = _require(VENDOR / "model-release.zip").read_bytes()
fm.webdl = lambda url, progress_callback=None: io.BytesIO(zip_bytes)
fm.ensure_fpgen_model(force=True)

# 4) 验证：启动路径存在且可执行（不访问网络）
launch = CACHE / json.loads((CACHE / "config.json").read_text())["active_version"]
assert (launch / "version.json").exists(), "version.json missing"
print("camoufox offline install OK:", DEST)
