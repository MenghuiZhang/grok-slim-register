#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量读取注册 JSON，把 SSO 换成 CPA / sub2api 可用的 xAI OAuth JSON。"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable




BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = BASE_DIR / "register_sso"
DEFAULT_OUTPUT_DIR = BASE_DIR / "converted_auth"
FAILED_DIRNAME = "失败"
XAI_ISSUER = "https://auth.x.ai"
XAI_TOKEN_ENDPOINT = f"{XAI_ISSUER}/oauth2/token"
XAI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
GROK_BUILD_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
GROK_BUILD_HEADERS = {
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-grok-client-version": "0.2.118",
    "x-grok-client-identifier": "grok-shell",
}
SUB2API_CHECKPOINT_EVERY = 100
PROXY_ENV_KEYS = (
    "GROK_PROXY",
    "XAI_PROXY",
    "GROK_SAME_SESSION_PROXY",
    "SAME_SESSION_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@dataclass(frozen=True)
class SSORecord:
    source: Path
    email: str
    sso: str
    session_id: str = ""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: Any, *, fallback_seconds: int | None = None) -> str:
    """把 Unix 时间或 ISO 时间统一成 RFC3339 秒精度。"""
    dt: datetime | None = None
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            dt = None
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        if re.fullmatch(r"\d+(?:\.\d+)?", raw):
            try:
                dt = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                dt = None
        else:
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dt = dt.astimezone(timezone.utc)
            except ValueError:
                dt = None
    if dt is None and fallback_seconds is not None:
        dt = utc_now().replace(microsecond=0)
        dt = datetime.fromtimestamp(
            dt.timestamp() + max(0, int(fallback_seconds)),
            tz=timezone.utc,
        )
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return {}
        raw = parts[1] + "=" * (-len(parts[1]) % 4)
        value = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def token_expiry(token: dict[str, Any]) -> str:
    access = str(token.get("access_token") or token.get("key") or "")
    payload = decode_jwt_payload(access)
    expires_in = int(token.get("expires_in") or 21600)
    return iso_utc(
        token.get("expires_at") or payload.get("exp"),
        fallback_seconds=expires_in,
    )


def safe_name(value: str, fallback: str = "unknown") -> str:
    cleaned = "".join(
        char if char.isalnum() or char in "._-@" else "_" for char in value
    ).strip("._")
    return cleaned or fallback


def cpa_path_for_record(output_dir: Path, record: SSORecord) -> Path:
    identifier = record.email or record.session_id or record.source.stem
    return output_dir / "cpa" / f"xai-{safe_name(identifier)}.json"


def is_access_denied_failure(error: Any) -> bool:
    """仅匹配已明确被拒绝的 invalid_grant，避免移走临时网络失败账号。"""
    message = str(error or "").lower()
    return "invalid_grant" in message and (
        "access denied" in message or "access_denied" in message
    )


def move_to_failed_dir(source: Path, failed_dir: Path) -> Path:
    """移动失败账号 JSON；如有同名文件则保留两者。"""
    failed_dir.mkdir(parents=True, exist_ok=True)
    target = failed_dir / source.name
    counter = 2
    while target.exists():
        target = failed_dir / f"{source.stem}-{counter}{source.suffix}"
        counter += 1
    shutil.move(str(source), str(target))
    return target


def load_cpa_token(path: Path) -> dict[str, Any] | None:
    """读取已生成的 CPA OAuth 文件，供断点续跑直接复用。"""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("type") != "xai":
        return None
    if not data.get("access_token") or not data.get("refresh_token"):
        return None
    token = {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "id_token": data.get("id_token") or "",
        "token_type": data.get("token_type") or "Bearer",
        "expires_in": data.get("expires_in") or 21600,
        "expires_at": data.get("expired") or "",
    }
    override = data.get("bfs_override")
    if isinstance(override, dict):
        token["bfs_override"] = dict(override)
    return token


def configure_network(proxy: str = "") -> str:
    """配置本次转换网络；空代理时强制直连，不继承终端或系统代理变量。"""
    proxy = str(proxy or "").strip()
    for key in PROXY_ENV_KEYS:
        os.environ.pop(key, None)
    if proxy:
        for key in ("GROK_PROXY", "XAI_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
            os.environ[key] = proxy
        os.environ.pop("NO_PROXY", None)
        os.environ.pop("no_proxy", None)
        return f"代理 {proxy.rsplit('@', 1)[-1]}"

    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"
    return "直连"


def read_sso_record(path: Path) -> SSORecord:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON 无效（第 {exc.lineno} 行）") from exc
    except OSError as exc:
        raise ValueError(f"读取失败: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("顶层必须是 JSON 对象")

    sso = str(data.get("sso") or data.get("sso_cookie") or "").strip()
    if not sso:
        raise ValueError("缺少 sso / sso_cookie")
    if len(sso.split(".")) != 3:
        raise ValueError("sso 不是 JWT 形态")
    return SSORecord(
        source=path,
        email=str(data.get("email") or "").strip(),
        sso=sso,
        session_id=str(data.get("session_id") or "").strip(),
    )


def discover_records(
    input_dir: Path,
    *,
    recursive: bool = False,
    limit: int = 0,
    excluded_dir: Path | None = None,
) -> tuple[list[SSORecord], list[dict[str, str]]]:
    pattern = "**/*.json" if recursive else "*.json"
    excluded_dir = excluded_dir.resolve() if excluded_dir else None
    paths = sorted(
        path
        for path in input_dir.glob(pattern)
        if path.is_file()
        and not (
            excluded_dir
            and (path.resolve() == excluded_dir or excluded_dir in path.resolve().parents)
        )
    )
    records: list[SSORecord] = []
    errors: list[dict[str, str]] = []
    seen: set[str] = set()

    for path in paths:
        try:
            record = read_sso_record(path)
        except ValueError as exc:
            errors.append({"file": str(path), "error": str(exc)})
            continue
        if record.sso in seen:
            errors.append({"file": str(path), "error": "重复 SSO，已跳过"})
            continue
        seen.add(record.sso)
        records.append(record)
        if limit > 0 and len(records) >= limit:
            break
    return records, errors


def build_cpa_record(
    token: dict[str, Any],
    *,
    email: str = "",
    sso: str = "",
    disabled: bool = False,
) -> dict[str, Any]:
    access = str(token.get("access_token") or token.get("key") or "")
    refresh = str(token.get("refresh_token") or "")
    id_token = str(token.get("id_token") or "")
    access_payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token)
    resolved_email = str(
        email
        or id_payload.get("email")
        or access_payload.get("email")
        or ""
    ).strip()
    sub = str(
        id_payload.get("sub")
        or access_payload.get("sub")
        or access_payload.get("principal_id")
        or ""
    )
    expires_in = int(token.get("expires_in") or 21600)

    record = {
        "type": "xai",
        "auth_kind": "oauth",
        "email": resolved_email,
        "sub": sub,
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "token_type": str(token.get("token_type") or "Bearer"),
        "expires_in": expires_in,
        "expired": token_expiry(token),
        "last_refresh": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "redirect_uri": "",
        "token_endpoint": XAI_TOKEN_ENDPOINT,
        "base_url": GROK_BUILD_BASE_URL,
        "disabled": bool(disabled),
        "headers": dict(GROK_BUILD_HEADERS),
    }
    # BFS 检查已随精简移除：不再附加 bfs 元数据
    return record


def build_sub2api_account(
    token: dict[str, Any],
    *,
    email: str = "",
    group_ids: Iterable[int] = (),
) -> dict[str, Any]:
    access = str(token.get("access_token") or token.get("key") or "")
    refresh = str(token.get("refresh_token") or "")
    payload = decode_jwt_payload(access)
    user_id = str(payload.get("sub") or payload.get("principal_id") or "")
    principal_id = str(payload.get("principal_id") or user_id)
    resolved_email = str(email or payload.get("email") or "").strip()
    auth_key = f"{XAI_ISSUER}::{user_id}" if user_id else ""
    credentials: dict[str, Any] = {
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": token_expiry(token),
        "base_url": GROK_BUILD_BASE_URL,
        "auth_key": auth_key,
        "user_id": user_id,
        "auth_mode": "oidc",
        "client_id": XAI_CLIENT_ID,
        "oidc_issuer": XAI_ISSUER,
        "email": resolved_email,
        "token_type": str(token.get("token_type") or "Bearer"),
        "principal_id": principal_id,
        "principal_type": str(payload.get("principal_type") or "User"),
    }
    for key in ("scope", "team_id", "sub"):
        if payload.get(key):
            credentials[key] = payload[key]

    account: dict[str, Any] = {
        "name": resolved_email or (f"Grok {user_id}" if user_id else "Grok OAuth"),
        "platform": "grok",
        "type": "oauth",
        "concurrency": 10,
        "priority": 1,
        "credentials": credentials,
        "extra": {
            "email": resolved_email,
            "email_key": re.sub(r"[^a-z0-9]+", "_", resolved_email.lower()).strip("_"),
            "last_refresh": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }
    normalized_groups = list(dict.fromkeys(int(group_id) for group_id in group_ids))
    if normalized_groups:
        account["group_ids"] = normalized_groups
    return account


def build_sub2api_document(accounts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "exported_at": utc_now().isoformat().replace("+00:00", "Z"),
        "proxies": [],
        "accounts": accounts,
    }


def write_private_json(path: Path, data: Any, *, overwrite: bool = False) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return False
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return True


def exchange_one(record: SSORecord, timeout: int) -> dict[str, Any]:
    try:
        from g.device_flow import sso_device_flow_to_token

        result = sso_device_flow_to_token(
            record.sso,
            timeout=timeout,
            issue_token=True,
        )
    except Exception as exc:
        return {
            "ok": False,
            "record": record,
            "error": f"OAuth 换票异常: {exc}",
        }
    token = result.get("token") if isinstance(result, dict) else None
    if not isinstance(result, dict) or not result.get("ok") or not isinstance(token, dict):
        return {
            "ok": False,
            "record": record,
            "error": str(
                result.get("error") if isinstance(result, dict) else ""
            )
            or "OAuth 换票失败",
        }
    if not (token.get("access_token") or token.get("key")):
        return {
            "ok": False,
            "record": record,
            "error": "OAuth 响应缺少 access_token",
        }
    return {"ok": True, "record": record, "token": token}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="读取文件夹内注册 JSON 的 SSO，换成 CPA / sub2api OAuth JSON",
    )
    parser.add_argument(
        "input_dir",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="注册 JSON 文件夹（默认: register_sso）",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="输出目录（默认: converted_auth）",
    )
    parser.add_argument(
        "--failed-dir",
        type=Path,
        default=None,
        help="Access denied 账号移入目录（默认: 输入目录/失败）",
    )
    parser.add_argument(
        "--format",
        choices=("cpa", "sub2api", "both"),
        default="both",
        help="输出格式（默认: both）",
    )
    parser.add_argument(
        "--workers",
        type=int,
        choices=range(1, 33),
        default=8,
        metavar="1-32",
        help="OAuth 并发数（默认: 8；遇到限流可降到 4）",
    )
    parser.add_argument("--timeout", type=int, default=28, help="单次 HTTP 超时秒数")
    parser.add_argument("--limit", type=int, default=0, help="最多处理数量，0 表示全部")
    parser.add_argument("--recursive", action="store_true", help="递归查找 JSON")
    network = parser.add_mutually_exclusive_group()
    network.add_argument("--proxy", default="", help="HTTP/HTTPS/SOCKS5 代理")
    network.add_argument(
        "--direct",
        action="store_true",
        help="强制直连（默认行为，不继承环境代理）",
    )
    parser.add_argument(
        "--group-id",
        type=int,
        action="append",
        default=[],
        help="sub2api 分组 ID，可重复传入",
    )
    parser.add_argument("--disabled", action="store_true", help="CPA 文件默认禁用")
    parser.add_argument("--overwrite", action="store_true", help="覆盖同名 CPA 文件")
    parser.add_argument(
        "--refresh-existing",
        action="store_true",
        help="不复用已有 CPA 文件，强制重新换票",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只扫描和校验输入，不联网、不写认证文件",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_dir = args.input_dir.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    failed_dir = (
        args.failed_dir.expanduser().resolve()
        if args.failed_dir
        else input_dir / FAILED_DIRNAME
    )
    if not input_dir.is_dir():
        print(f"错误：输入目录不存在: {input_dir}", file=sys.stderr)
        return 2
    if args.timeout <= 0 or args.limit < 0:
        print("错误：--timeout 必须大于 0，--limit 不能小于 0", file=sys.stderr)
        return 2

    network_mode = configure_network(args.proxy)
    # grok 模块在 worker 首次换票时才加载，因此这里设置可控制底层信号量。
    os.environ["GROK_DEVICE_FLOW_MAX_CONCURRENT"] = str(args.workers)
    print(f"网络模式：{network_mode}", flush=True)

    records, scan_errors = discover_records(
        input_dir,
        recursive=args.recursive,
        limit=args.limit,
        excluded_dir=failed_dir,
    )
    print(
        f"扫描完成：有效 {len(records)}，跳过/错误 {len(scan_errors)}",
        flush=True,
    )
    for item in scan_errors[:20]:
        print(f"  跳过 {Path(item['file']).name}: {item['error']}", flush=True)
    if len(scan_errors) > 20:
        print(f"  另有 {len(scan_errors) - 20} 条未显示", flush=True)
    if not records:
        return 1
    if args.dry_run:
        print("dry-run 完成：未联网，未生成认证文件", flush=True)
        return 0

    stamp = utc_now().strftime("%Y%m%d_%H%M%S")
    failures: list[dict[str, Any]] = []
    success_count = 0
    cpa_written = 0
    cpa_skipped = 0
    cached_reused = 0
    failed_moved = 0
    bfs_marked = 0
    bfs_unknown = 0
    sub2_accounts: list[dict[str, Any]] = []
    sub2_path = (
        output_dir / "sub2api" / f"sub2api-grok-{stamp}.json"
        if args.format in ("sub2api", "both")
        else None
    )

    def save_result(result: dict[str, Any]) -> None:
        nonlocal success_count, cpa_written, cpa_skipped, cached_reused, failed_moved
        nonlocal bfs_marked, bfs_unknown
        record: SSORecord = result["record"]
        if not result.get("ok"):
            error = result.get("error") or "unknown error"
            if is_access_denied_failure(error):
                try:
                    moved_to = move_to_failed_dir(record.source, failed_dir)
                    result["moved_to"] = str(moved_to)
                    failed_moved += 1
                    print(f"  已移入失败文件夹: {moved_to}", flush=True)
                except OSError as exc:
                    result["move_error"] = str(exc)
                    print(f"  移动失败账号文件失败: {exc}", flush=True)
            failures.append(result)
            print(
                f"  失败: {error}",
                flush=True,
            )
            return

        success_count += 1
        if result.get("cached"):
            cached_reused += 1
        token: dict[str, Any] = result["token"]
        # BFS 检查已移除：不阻断下游分发
        blocked_downstream = False
        if args.format in ("cpa", "both"):
            target = cpa_path_for_record(output_dir, record)
            if write_private_json(
                target,
                build_cpa_record(
                    token,
                    email=record.email,
                    sso=record.sso,
                    disabled=bool(args.disabled or blocked_downstream),
                ),
                overwrite=args.overwrite,
            ):
                cpa_written += 1
            else:
                cpa_skipped += 1
        if sub2_path is not None and not blocked_downstream:
            sub2_accounts.append(
                build_sub2api_account(
                    token,
                    email=record.email,
                    group_ids=args.group_id,
                )
            )
            # CPA 已逐条落盘；合并文件每 100 条检查点一次，避免数千账号时
            # 每成功一条都重写整个大 JSON，产生 O(n²) 磁盘开销。
            if len(sub2_accounts) % SUB2API_CHECKPOINT_EVERY == 0:
                write_private_json(
                    sub2_path,
                    build_sub2api_document(sub2_accounts),
                    overwrite=True,
                )

    pending: list[SSORecord] = []
    if not args.refresh_existing:
        for record in records:
            cached_token = load_cpa_token(cpa_path_for_record(output_dir, record))
            if cached_token:
                save_result(
                    {
                        "ok": True,
                        "record": record,
                        "token": cached_token,
                        "cached": True,
                    }
                )
            else:
                pending.append(record)
    else:
        pending = list(records)

    if cached_reused:
        print(f"断点续跑：复用已有 CPA 凭证 {cached_reused} 条", flush=True)
    print(
        f"待换票：{len(pending)} 条，OAuth 并发：{args.workers}",
        flush=True,
    )

    if args.workers == 1:
        for index, record in enumerate(pending, start=1):
            print(f"[{index}/{len(pending)}] 换票 {record.email or record.source.name}", flush=True)
            save_result(exchange_one(record, args.timeout))
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(exchange_one, record, args.timeout): record
                for record in pending
            }
            for index, future in enumerate(as_completed(futures), start=1):
                result = future.result()
                record = result["record"]
                state = "成功" if result["ok"] else "失败"
                print(
                    f"[{index}/{len(pending)}] {state} {record.email or record.source.name}",
                    flush=True,
                )
                save_result(result)

    if sub2_accounts and sub2_path:
        write_private_json(
            sub2_path,
            build_sub2api_document(sub2_accounts),
            overwrite=True,
        )

    report = {
        "created_at": utc_now().isoformat().replace("+00:00", "Z"),
        "input_dir": str(input_dir),
        "network_mode": network_mode,
        "format": args.format,
        "total": len(records),
        "success": success_count,
        "failed": len(failures),
        "cpa_written": cpa_written,
        "cpa_skipped_existing": cpa_skipped,
        "cached_reused": cached_reused,
        "failed_moved": failed_moved,
        "bfs_marked": bfs_marked,
        "bfs_unknown": bfs_unknown,
        "failed_dir": str(failed_dir),
        "workers": args.workers,
        "sub2api_file": str(sub2_path) if sub2_accounts and sub2_path else None,
        "scan_errors": scan_errors,
        "failures": [
            {
                "file": str(result["record"].source),
                "email": result["record"].email,
                "error": result.get("error") or "unknown error",
                "moved_to": result.get("moved_to"),
                "move_error": result.get("move_error"),
            }
            for result in failures
        ],
    }
    report_path = output_dir / f"report-{stamp}.json"
    write_private_json(report_path, report)

    for result in failures:
        record = result["record"]
        print(
            f"失败 {record.email or record.source.name}: {result.get('error')}",
            flush=True,
        )
    print(
        f"完成：成功 {success_count}，失败 {len(failures)}，"
        f"CPA 写入 {cpa_written}，已有跳过 {cpa_skipped}，"
        f"移入失败文件夹 {failed_moved}",
        flush=True,
    )
    if sub2_accounts and sub2_path:
        print(f"sub2api: {sub2_path}", flush=True)
    print(f"报告: {report_path}", flush=True)
    return 0 if success_count and not failures else (1 if success_count else 2)


if __name__ == "__main__":
    raise SystemExit(main())
