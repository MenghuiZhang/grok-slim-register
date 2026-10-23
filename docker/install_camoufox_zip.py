"""从任意 zip 安装 Camoufox 浏览器（官方 release / 自建镜像 / 反代都行）。

用法：
    python install_camoufox_zip.py /tmp/camoufox.zip [/tmp/model-release.zip]

行为：
1. 解压 zip 到 /root/.cache/camoufox/browsers/official/<version>-<build>-<sha8>
2. 写 config.json 的 active_version（camoufox 靠它找浏览器）
3. 若给了 model-release.zip，离线装 fpgen 指纹模型（否则跳过）

注意：camoufox 包会按 browser-pin.json 固定浏览器 build
（当前为 156.0.1-beta.36），镜像里的 zip 必须是同一个 release，
否则 `python -m camoufox path` 找不到可用版本。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import sys
import zipfile

CACHE = pathlib.Path("/root/.cache/camoufox")
REPO_NAME = "official"
DEST_ROOT = CACHE / "browsers" / REPO_NAME
EXTRACT = pathlib.Path("/tmp/camoufox_extract")
# camoufox-156.0.1-beta.36-lin.arm64.zip
NAME_RE = re.compile(r"camoufox-(\d+\.\d+\.\d+)-([A-Za-z0-9.]+)-(?:lin|win|mac)", re.I)
# 156.0.1-beta.36
SPEC_RE = re.compile(r"^(\d+\.\d+\.\d+)-([A-Za-z0-9.]+)$")


def _sha8_of_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:8]


def _read_meta(zf: zipfile.ZipFile, zip_path: pathlib.Path) -> dict:
    """版本信息：zip 内 version.json → 环境变量 CAMOUFOX_BROWSER_SPEC → 文件名。"""
    for name in zf.namelist():
        if name.rstrip("/").endswith("version.json"):
            try:
                data = json.loads(zf.read(name).decode("utf-8"))
            except Exception:
                continue
            if isinstance(data, dict) and data.get("version") and data.get("build"):
                return data

    # 官方 release 资源本身不带 version.json，允许显式指定 156.0.1-beta.36
    spec = os.environ.get("CAMOUFOX_BROWSER_SPEC", "").strip()
    if spec:
        match = SPEC_RE.match(spec)
        if not match:
            sys.exit(
                f"[camoufox-zip] CAMOUFOX_BROWSER_SPEC={spec!r} 格式应为 <version>-<build>，"
                "例如 156.0.1-beta.36"
            )
        return {"version": match.group(1), "build": match.group(2)}

    match = NAME_RE.search(zip_path.name)
    if not match:
        sys.exit(
            f"[camoufox-zip] 无法识别版本：{zip_path.name} 里没有 version.json，"
            "文件名也不符合 camoufox-<version>-<build>-<os>.<arch>.zip。\n"
            "  办法：把下载文件按原名保存（camoufox-<版本>-<build>-lin.arm64.zip），"
            "或加 --build-arg CAMOUFOX_BROWSER_SPEC=156.0.1-beta.36"
        )
    return {"version": match.group(1), "build": match.group(2)}


def _install_model(zip_path: pathlib.Path) -> None:
    try:
        import camoufox.fpgen_model as fm
    except Exception as exc:  # pragma: no cover - camoufox 必装
        print(f"[camoufox-zip] 跳过 fpgen 模型：{exc}")
        return
    payload = zip_path.read_bytes()
    fm.webdl = lambda url, progress_callback=None: io.BytesIO(payload)
    fm.ensure_fpgen_model(force=True)
    print(f"[camoufox-zip] fpgen 模型已安装（{len(payload)} 字节）")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.exit("用法: install_camoufox_zip.py <camoufox.zip> [model-release.zip]")
    zip_path = pathlib.Path(argv[1])
    model_zip = pathlib.Path(argv[2]) if len(argv) > 2 else None
    if not zip_path.is_file():
        sys.exit(f"[camoufox-zip] 找不到 {zip_path}")

    with zipfile.ZipFile(zip_path) as zf:
        meta = _read_meta(zf, zip_path)
        version = str(meta["version"])
        build = str(meta["build"])
        sha8 = str(meta.get("sha256") or "")[:8] or _sha8_of_file(zip_path)

        shutil.rmtree(EXTRACT, ignore_errors=True)
        for info in zf.infolist():
            zf.extract(info, EXTRACT)
            mode = info.external_attr >> 16
            if mode:
                target = EXTRACT / info.filename
                if target.exists():
                    target.chmod(mode & 0o7777)

    entries = list(EXTRACT.iterdir())
    src = entries[0] if len(entries) == 1 and entries[0].is_dir() else EXTRACT
    folder = f"{version}-{build}-{sha8}"
    dest = DEST_ROOT / folder
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(src), str(dest))
    shutil.rmtree(EXTRACT, ignore_errors=True)

    if not (dest / "version.json").exists():
        # 官方 zip 不含 version.json，camoufox 靠它识别版本（缺 interface 时按 1 处理）
        (dest / "version.json").write_text(
            json.dumps(
                {
                    "version": version,
                    "build": build,
                    "prerelease": "beta" in build or "alpha" in build,
                    "sha256": str(meta.get("sha256") or ""),
                    "interface": int(meta.get("interface") or 1),
                }
            ),
            encoding="utf-8",
        )

    config_path = CACHE / "config.json"
    config = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            config = {}
    config["active_version"] = f"browsers/{REPO_NAME}/{folder}"
    CACHE.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print(f"[camoufox-zip] 已安装 {version}-{build} → {dest}")
    print(f"[camoufox-zip] active_version = {config['active_version']}")

    if model_zip is not None:
        if model_zip.is_file():
            _install_model(model_zip)
        else:
            print(f"[camoufox-zip] 跳过 fpgen 模型：找不到 {model_zip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
