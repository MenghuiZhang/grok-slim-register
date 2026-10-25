"""SSO device flow 换 token 工具（拆自旧 grok.py，供 import-services 上游分发使用）。

路径与 grokcli-2api sso_to_auth_json 一致：
SSO cookie → 登录态探测 → OIDC device verify/approve → access_token。
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from curl_cffi import requests

from g.proxy_pool import parse_proxy_line

# 基础配置
site_url = "https://accounts.x.ai"
# device code / token 端点仍走 curl_cffi；浏览器批准路径见 _approve_with_browser
DEFAULT_IMPERSONATE = "chrome131"
# 与 grokcli-2api sso_to_auth_json 保持一致：只有 device flow 换到 token 才算可导入
OIDC_ISSUER = "https://auth.x.ai"
GROK_CLI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_SCOPES = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)
# device flow 有限并发：默认仍保守为 2；批量转换脚本可通过环境变量提升。
# 上限 32，避免配置错误产生无界并发。
try:
    _DEVICE_FLOW_MAX_CONCURRENT = max(
        1,
        min(int(os.environ.get("GROK_DEVICE_FLOW_MAX_CONCURRENT") or "2"), 32),
    )
except (TypeError, ValueError):
    _DEVICE_FLOW_MAX_CONCURRENT = 2
_DEVICE_FLOW_SEM = threading.Semaphore(_DEVICE_FLOW_MAX_CONCURRENT)
# 全局冷却：遇到 rate_limited 后，后续 device flow 至少隔这么久
_device_flow_cooldown_until = 0.0
_device_flow_cooldown_lock = threading.Lock()
# 成功后的轻冷却：压连打限流，又别像旧 2s 那样白白垫时间
_DEVICE_FLOW_SUCCESS_COOLDOWN = 0.6
# 是否在 device approve 后轮询 token。默认开启（生产要最终换到 token）。
# 仅诊断「假批准」时设 GROK_DEVICE_FLOW_ISSUE_TOKEN=0 跳过换票。
DEVICE_FLOW_ISSUE_TOKEN = os.environ.get("GROK_DEVICE_FLOW_ISSUE_TOKEN", "1").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)

PROXIES = {
    # "http": "http://127.0.0.1:10808",
    # "https": "http://127.0.0.1:10808"
}


def _proxy_map(proxy_spec: str = "") -> dict[str, str]:
    raw = str(proxy_spec or "").strip()
    if not raw:
        return {"http": "", "https": ""}
    try:
        url = parse_proxy_line(raw)["spec"]
    except Exception:
        url = raw if "://" in raw else f"http://{raw}"
    return {"http": url, "https": url}


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    """解析 JWT payload（不验签），失败返回空 dict。"""
    try:
        parts = (token or "").strip().split(".")
        if len(parts) != 3:
            return {}
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def is_auth_token_usable(token: Any, *, skew_seconds: float = 60.0) -> bool:
    """
    判断注册时缓存的 device flow token 是否还能直接写上游。
    有 access_token，且 JWT exp 未过期（留 skew 余量）才算可用。
    """
    if not isinstance(token, dict):
        return False
    access = (token.get("access_token") or token.get("key") or "").strip()
    if not access:
        return False
    payload = decode_jwt_payload(access)
    exp = payload.get("exp")
    if exp is not None:
        try:
            if float(exp) <= time.time() + float(skew_seconds):
                return False
        except (TypeError, ValueError):
            return False
    return True


def is_sso_jwt_shape(sso: str) -> bool:
    """粗检：xAI sso cookie 一般为 eyJ 开头的 JWT。"""
    s = (sso or "").strip()
    if not s or not s.startswith("eyJ"):
        return False
    parts = s.split(".")
    if len(parts) != 3:
        return False
    payload = decode_jwt_payload(s)
    return bool(payload)


def _device_flow_error_kind(err: str) -> str:
    """分类 device flow 错误，便于退避策略。"""
    e = (err or "").lower()
    if "rate_limited" in e or "rate limit" in e or "too many" in e:
        return "rate_limited"
    if "curl: (35)" in e or "tls" in e or "ssl" in e or "openssl" in e:
        return "tls"
    if (
        "timed out" in e
        or "timeout" in e
        or "curl: (28)" in e
        or "connection timed out" in e
    ):
        return "timeout"
    if "device/code" in e or "device code" in e:
        return "device_code"
    if "authorization_pending" in e or "未拿到 access_token" in e:
        return "token_poll"
    if "会话无效" in e or "非有效 jwt" in e:
        return "invalid"
    return "other"


def _device_flow_wait_seconds(err: str, attempt: int = 1) -> float:
    """按错误类型返回建议等待秒数。"""
    kind = _device_flow_error_kind(err)
    a = max(1, int(attempt))
    if kind == "rate_limited":
        return min(90.0, 18.0 * a + random.uniform(2, 6))
    if kind == "timeout":
        return min(45.0, 6.0 * a + random.uniform(1, 3))
    if kind == "tls":
        return min(30.0, 4.0 * a + random.uniform(0.5, 2))
    if kind == "device_code":
        return min(40.0, 8.0 * a)
    if kind == "token_poll":
        return min(20.0, 3.0 * a)
    return min(20.0, 3.0 * a)


def _mark_device_flow_cooldown(seconds: float) -> None:
    global _device_flow_cooldown_until
    until = time.time() + max(0.0, float(seconds))
    with _device_flow_cooldown_lock:
        if until > _device_flow_cooldown_until:
            _device_flow_cooldown_until = until


def _wait_device_flow_cooldown() -> None:
    """若处于 rate_limited 冷却期则阻塞等待。"""
    with _device_flow_cooldown_lock:
        until = float(_device_flow_cooldown_until or 0.0)
    remain = until - time.time()
    if remain > 0:
        time.sleep(min(remain, 120.0))


def _device_flow_log(message: str, level: str = "info") -> None:
    """浏览器批准日志转发：走 OpenCode 日志面板时由 app 注入；此处默认打印。"""
    try:
        print(f"[device-flow] {message}", flush=True)
    except Exception:
        pass


def _device_flow_debug_on() -> bool:
    return str(os.getenv("GROK_DEVICE_FLOW_DEBUG", "")).strip().lower() in (
        "1", "true", "yes", "on",
    )


def _new_device_flow_shot_dir(tag: str = "") -> Path | None:
    """独立浏览器换票的截图目录：logs/device_flow/<时间>-<tag>/，失败留证。

    注册浏览器内路径不建目录（复用注册流程现成的 round-* 目录）；
    返回 None 表示调用方自行截图到已有目录。
    """
    base = Path(__file__).resolve().parent.parent / "logs" / "device_flow"
    try:
        name = time.strftime("%Y%m%d-%H%M%S")
        if tag:
            name += f"-{tag}"
        shot_dir = base / name
        shot_dir.mkdir(parents=True, exist_ok=True)
        # 只留最近 20 组，防磁盘膨胀
        dirs = sorted(d for d in base.iterdir() if d.is_dir())
        for old in dirs[:-20]:
            shutil.rmtree(old, ignore_errors=True)
        return shot_dir
    except Exception:
        return None


def _write_flow_meta(shot_dir: Path | None, **fields: Any) -> None:
    """把换票现场摘要（URL/错误/页面文本）写进目录，不看图也能初判。"""
    if shot_dir is None:
        return
    try:
        lines = [f"{time.strftime('%Y-%m-%d %H:%M:%S')}"]
        lines += [f"{k}: {v}" for k, v in fields.items() if v]
        (shot_dir / "meta.txt").open("a", encoding="utf-8").write("\n".join(lines) + "\n")
    except Exception:
        pass


def _proxy_kw(proxy_spec: str | None = None, *, force_direct: bool = False) -> dict:
    """统一代理参数；账号级显式值优先，空值表示直连。"""
    if force_direct:
        return {"proxies": {"http": "", "https": ""}}
    if proxy_spec is not None:
        mapped = _proxy_map(proxy_spec)
        return {"proxies": mapped} if mapped else {"proxies": {"http": "", "https": ""}}
    return {"proxies": PROXIES} if PROXIES else {}


def _request_device_code(timeout: int = 20, *, proxy_spec: str | None = None) -> dict | None:
    """申请 device_code；优先 curl_cffi（与 session 同栈），失败再回落 urllib。"""
    data = {
        "client_id": GROK_CLI_CLIENT_ID,
        "scope": OIDC_SCOPES,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
    }
    curl_error = ""
    for attempt in range(2):
        try:
            r = requests.post(
                f"{OIDC_ISSUER}/oauth2/device/code",
                data=data,
                headers=headers,
                impersonate=DEFAULT_IMPERSONATE,
                timeout=timeout,
                **_proxy_kw(proxy_spec),
            )
            if r.status_code == 429 or "rate" in (r.text or "").lower():
                return {
                    "_error": f"device/code rate_limited HTTP {r.status_code}: {(r.text or '')[:200]}"
                }
            if r.status_code >= 400:
                return {
                    "_error": f"device/code HTTP {r.status_code}: {(r.text or '')[:200]}"
                }
            return r.json()
        except Exception as e:
            curl_error = str(e)
            if attempt == 0:
                time.sleep(0.25)
    # 仅直连时回落 urllib；代理租约不得中途变为直连。
    if proxy_spec:
        return {"_error": f"device/code 异常: {curl_error or '代理请求失败'}"}
    try:
        req = urllib.request.Request(
            f"{OIDC_ISSUER}/oauth2/device/code",
            data=urllib.parse.urlencode(data).encode(),
            method="POST",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="ignore")[:200]
        except Exception:
            pass
        if e.code == 429 or "rate" in body.lower():
            return {"_error": f"device/code rate_limited HTTP {e.code}: {body}"}
        return {"_error": f"device/code HTTP {e.code}: {body}"}
    except Exception as e:
        detail = f"{e}"
        if curl_error:
            detail += f"；curl_cffi: {curl_error}"
        return {"_error": f"device/code 异常: {detail}"}


def _poll_device_token(
    device_code: str,
    interval: int,
    expires_in: int,
    timeout: int = 60,
    *,
    proxy_spec: str | None = None,
) -> dict | None:
    """
    approve 之后立刻查 token，不再先傻等一个 interval。
    仍遵守 slow_down / authorization_pending，保证成功率。

    成功返回 token dict；失败返回 None 或 {"_error": "..."}。
    """
    deadline = time.time() + min(int(expires_in or 1800), timeout)
    # 服务端 interval 常为 5；我们用更短的本地间隔，被 slow_down 再拉长
    server_interval = max(1, int(interval or 5))
    wait = min(1.2, float(server_interval))
    net_fail = 0
    first = True
    last_err = "token poll timeout"
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": GROK_CLI_CLIENT_ID,
        "device_code": device_code,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    while time.time() < deadline:
        if not first:
            time.sleep(wait)
        first = False
        try:
            r = requests.post(
                f"{OIDC_ISSUER}/oauth2/token",
                data=form,
                headers=headers,
                impersonate=DEFAULT_IMPERSONATE,
                timeout=20,
                **_proxy_kw(proxy_spec),
            )
            body_text = r.text or ""
            try:
                body = r.json() if body_text else {}
            except Exception:
                body = {}
            if r.status_code < 400 and (body.get("access_token") or body.get("key")):
                return body
            error = (body.get("error") if isinstance(body, dict) else "") or ""
            if error == "authorization_pending":
                net_fail = 0
                wait = min(max(wait, float(server_interval) * 0.6), 6.0)
                last_err = "authorization_pending"
                continue
            if error == "slow_down":
                wait = min(wait + 3.0, 15.0)
                last_err = "slow_down"
                continue
            if error:
                desc = body.get("error_description") or ""
                last_err = f"{error}" + (f": {desc}" if desc else "")
                # invalid_grant / access_denied / expired_token：别空转
                return {"_error": last_err}
            net_fail += 1
            last_err = f"token HTTP {r.status_code}: {body_text[:160]}"
            if net_fail >= 5:
                return {"_error": last_err}
            wait = min(wait + 1.5, 12.0)
            continue
        except Exception as e:
            # 瞬时网络：多试几次，别一次超时就放弃已 approve 的 flow
            net_fail += 1
            last_err = f"token poll 异常: {e}"
            if net_fail >= 6:
                return {"_error": last_err}
            wait = min(wait + 1.0, 10.0)
            continue
    return {"_error": last_err}


# ---------------------------------------------------------------------------
# 浏览器批准路径：2026-10 起 approve 表单需要浏览器内 Castle SDK 现场生成
# castle_request_token，纯 HTTP 提交（无论是否带 consent_token）都会 403
# "Request could not be verified"。因此 verify→consent→approve 必须走真浏览器。
# 实测 Camoufox 可过 Cloudflare；普通 Playwright headless 会被 "Sorry, you
# have been blocked" 拦截。device/code 与 oauth2/token 仍走纯 HTTP（不受限）。
# ---------------------------------------------------------------------------

# 浏览器批准各步超时（秒）
_BROWSER_NAV_TIMEOUT = 60_000
_BROWSER_CONFIRM_TIMEOUT = 20_000
_BROWSER_CONSENT_TIMEOUT = 25_000


def _page_body(page: Any, limit: int = 200) -> str:
    """抓页面可见文本前若干字符，供 meta/错误信息定位现场。"""
    try:
        return (page.locator("body").inner_text() or "")[:limit].replace("\n", " | ")
    except Exception:
        return ""


def _browser_click_allow(
    page: Any,
    *,
    log=None,
    shot_dir: Path | None = None,
) -> dict[str, Any]:
    """在已打开的浏览器 page 上完成 device flow 批准。

    page 登录态由调用方保证：注册流程传注册浏览器现成 page（无需注入 SSO），
    存量转换走 _approve_with_browser 自启 Camoufox 并注入 sso cookie。

    shot_dir 提供时（或 GROK_DEVICE_FLOW_DEBUG=1 时自建）每步截图 + meta.txt，
    失败时留现场供排障。

    返回 {"ok": True} 或 {"ok": False, "error": "..."}；
    error 命中 rate_limited / 会话无效 / denied 语义，与旧 HTTP 路径一致。
    """

    def _emit(msg: str, level: str = "info") -> None:
        if callable(log):
            try:
                log(msg, level)
            except TypeError:
                log(msg)
        else:
            _device_flow_log(msg, level)

    try:
        page.set_default_timeout(_BROWSER_NAV_TIMEOUT)
    except Exception:
        pass

    debug = _device_flow_debug_on()
    if shot_dir is None and debug:
        shot_dir = _new_device_flow_shot_dir("browser")

    def _shot(name: str) -> None:
        # shot_dir 提供（失败留证 / 调用方目录）或 GROK_DEVICE_FLOW_DEBUG=1 时截图
        if shot_dir is None:
            return
        try:
            page.screenshot(path=str(Path(shot_dir) / f"{int(time.time())}-device_flow_{name}.png"))
        except Exception:
            pass

    def _meta(**fields: Any) -> None:
        if shot_dir is not None:
            try:
                fields.setdefault("url", page.url)
            except Exception:
                pass
            _write_flow_meta(shot_dir, **fields)

    # 已在确认页（verification_uri_complete 落地）或中途页都直接用当前 URL
    url_now = (page.url or "").lower()
    _emit(f"device flow: 授权页 {page.url}")

    # sign-in / sign-up：SSO 登录态失效（注入场景）——与旧路径语义一致
    if "sign-in" in url_now or "sign-up" in url_now:
        _shot("invalid-session")
        _meta(error="会话无效", body=_page_body(page))
        return {"ok": False, "error": f"会话无效（跳转 {page.url}）"}
    if "rate_limited" in url_now:
        _shot("rate-limited")
        _meta(error="rate_limited", body=_page_body(page))
        return {"ok": False, "error": f"探测 rate_limited: {page.url}"}

    # 确认页（"Sign in to Grok Build" + Continue）：点击进入同意页。
    # verification_uri_complete 自带 user_code 时页面直接显示确认码。
    try:
        cont = page.locator(
            "button:has-text('Continue'), button:has-text('Fortfahren'), "
            "button[type='submit']"
        ).first
        cont.wait_for(state="visible", timeout=_BROWSER_CONFIRM_TIMEOUT)
        cont.click()
        _emit("device flow: 已点击 Continue")
    except Exception as exc:
        # 可能已在同意页（无 Continue 的版本），不视为致命
        _emit(f"device flow: Continue 未点击（{str(exc)[:80]}，可能已在同意页）", "warn")
    try:
        page.wait_for_load_state("networkidle", timeout=15_000)
    except Exception:
        pass
    _shot("consent")
    _meta(step="consent")

    url_now = (page.url or "").lower()
    if "sign-in" in url_now or "sign-up" in url_now:
        _shot("invalid-session")
        _meta(error="会话无效", body=_page_body(page))
        return {"ok": False, "error": f"会话无效（跳转 {page.url}）"}
    if "rate_limited" in url_now:
        _shot("rate-limited")
        _meta(error="rate_limited", body=_page_body(page))
        return {"ok": False, "error": f"device verify 失败: {page.url}"}

    # 同意页：点 Allow（页面 JS 现场生成 castle_request_token 后自动重提交）
    try:
        allow = page.locator("button[value='allow']").first
        allow.wait_for(state="visible", timeout=_BROWSER_CONSENT_TIMEOUT)
    except Exception as exc:
        _shot("no-allow")
        text = _page_body(page)
        _meta(error="同意页未出现 Allow", body=text)
        return {
            "ok": False,
            "error": f"device verify 失败（同意页未出现 Allow: {str(exc)[:80]}）: {text[:120]}",
        }
    try:
        allow.click()
        _emit("device flow: 已点击 Allow")
    except Exception as exc:
        _shot("allow-click-failed")
        _meta(error="Allow 点击异常", body=_page_body(page))
        return {"ok": False, "error": f"device approve 异常: {exc}"}
    try:
        page.wait_for_load_state("networkidle", timeout=20_000)
    except Exception:
        pass
    # approve 表单 POST + Castle mint 需要一点时间
    page.wait_for_timeout(2500)
    _shot("done")

    url_now = (page.url or "").lower()
    if "denied=1" in url_now:
        _meta(error="approve 被拒绝", body=_page_body(page))
        return {"ok": False, "error": f"device approve 被拒绝: {page.url}"}
    if "rate_limited" in url_now:
        _shot("rate-limited")
        _meta(error="rate_limited", body=_page_body(page))
        return {"ok": False, "error": f"device approve 失败: {page.url}"}
    # 成功页：URL 落 done，或页面出现 Authorized 文案
    body_text = ""
    try:
        body_text = page.locator("body").inner_text()[:400].lower()
    except Exception:
        pass
    if "done" in url_now or "authorized" in body_text:
        _meta(result="approve 成功")
        return {"ok": True, "error": None}
    _shot("unknown-final")
    _meta(error="页面未见授权成功", body=_page_body(page))
    return {
        "ok": False,
        "error": f"device approve 失败: {page.url}（页面未见授权成功）",
    }


def _browser_launch_kwargs(proxy_spec: str | None) -> dict[str, Any]:
    """换票专用 Camoufox 启动参数（对齐 ui_register 的约定）。"""
    headless = str(os.getenv("GROK_CAMOUFOX_HEADLESS", "1")).strip().lower() not in (
        "0", "false", "no", "off",
    )
    kwargs: dict[str, Any] = {
        "headless": headless,
        "os": "macos" if sys.platform == "darwin" else "linux",
        "locale": "en-US",
        "humanize": True,
    }
    if proxy_spec:
        try:
            from g.proxy_pool import build_proxy_option, probe_proxy_geo

            option, loopback = build_proxy_option(proxy_spec)
            kwargs["proxy"] = option
            if not loopback:
                # 指纹与出口 IP 对齐；预检失败仅跳过对齐，不阻断换票
                try:
                    geo = probe_proxy_geo(option)
                    if geo and geo.get("ip"):
                        from camoufox.geolocation import get_geolocation

                        get_geolocation(str(geo["ip"]))
                        kwargs["geoip"] = str(geo["ip"])
                except Exception:
                    pass
        except Exception:
            # 代理解析失败按直连走（与注册子进程行为一致）
            kwargs.pop("proxy", None)
    return kwargs


def _approve_with_browser(
    sso: str,
    verify_uri: str,
    *,
    proxy_spec: str | None = None,
    log=None,
) -> dict[str, Any]:
    """存量转换路径：自启 Camoufox、注入 sso cookie、完成批准。"""
    from camoufox.sync_api import Camoufox

    kwargs = _browser_launch_kwargs(proxy_spec)
    # 失败留证：每次独立浏览器换票建专属目录（成功也会清掉旧目录，保留最近 20 组）
    shot_dir = _new_device_flow_shot_dir("browser")
    _write_flow_meta(shot_dir, verify_uri=verify_uri, proxy=proxy_spec or "direct")
    with Camoufox(**kwargs) as browser:
        ctx = browser.new_context()
        ctx.add_cookies([
            {"name": "sso", "value": sso, "domain": ".x.ai", "path": "/"},
        ])
        page = ctx.new_page()
        page.goto(verify_uri, wait_until="domcontentloaded", timeout=_BROWSER_NAV_TIMEOUT)
        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            pass
        result = _browser_click_allow(page, log=log, shot_dir=shot_dir)
        if shot_dir is not None and result.get("ok"):
            # 成功不留现场，目录清掉（debug 模式保留）
            if not _device_flow_debug_on():
                shutil.rmtree(shot_dir, ignore_errors=True)
        return result


def _rfc3339_ns(ts: float) -> str:
    """与 grokcli-2api 一致的 expires_at 格式。"""
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond * 1000):09d}Z"


def token_to_auth_entry(token: dict, email: str = "") -> dict[str, Any]:
    """
    将 device flow 得到的 token 转成上游 /accounts/import 可接受的 entry。
    与 grokcli-2api sso_to_auth_json.token_to_auth_entry 字段对齐。
    """
    access = (token or {}).get("access_token") or (token or {}).get("key") or ""
    refresh = (token or {}).get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int((token or {}).get("expires_in") or 21600)
    if "exp" in payload:
        expires_at = _rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = _rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = _rfc3339_ns(float(iat) if iat else time.time())

    return {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or payload.get("email") or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": GROK_CLI_CLIENT_ID,
    }


def sso_device_flow_to_token(
    sso: str,
    *,
    impersonate: str | None = None,
    timeout: int = 28,
    issue_token: bool | None = None,
    proxy_spec: str | None = None,
    log=None,
) -> dict[str, Any]:
    """
    SSO cookie → device code（HTTP）→ 浏览器批准 → access_token（HTTP 轮询）。

    log 提供时（如控制台 logs.emit）批准过程逐步回显到面板；缺省打印 stdout。

    2026-10 起 approve 表单需要浏览器内 Castle SDK 现场生成 castle_request_token，
    纯 HTTP 提交一律 403，因此 verify→consent→approve 固定走 Camoufox
    （存量转换场景由本函数自启浏览器并注入 sso cookie），不再有 HTTP 回退。

    issue_token:
      - None: 跟全局 DEVICE_FLOW_ISSUE_TOKEN（默认 True，换到 access_token）
      - True: 批准后轮询 token（生产路径）
      - False: 批准成功即返回（仅诊断用）

    impersonate 参数保留仅为兼容旧调用方签名，已无实际作用。
    """

    def _emit(msg: str, level: str = "info") -> None:
        if callable(log):
            try:
                log(msg, level)
            except TypeError:
                log(msg)
        elif log is None:
            _device_flow_log(msg, level)

    s = (sso or "").strip()
    if not s:
        return {"ok": False, "error": "空 sso", "token": None, "payload": {}}
    if not is_sso_jwt_shape(s):
        return {"ok": False, "error": "非有效 JWT 形态", "token": None, "payload": {}}

    do_token = DEVICE_FLOW_ISSUE_TOKEN if issue_token is None else bool(issue_token)
    payload = decode_jwt_payload(s)
    del impersonate  # 兼容保留：浏览器路径不再使用 TLS 指纹轮换

    # 有限并发 + 全局冷却：限流时大家一起让路，不把成功率打穿
    with _DEVICE_FLOW_SEM:
        _wait_device_flow_cooldown()
        last_err = "device flow 失败"

        dc = _request_device_code(timeout=max(15, int(timeout)), proxy_spec=proxy_spec)
        if not dc or dc.get("_error"):
            last_err = (dc or {}).get("_error") or "device/code 申请失败"
            _emit(f"device flow: device/code 申请失败 · {last_err}", "warn")
            if _device_flow_error_kind(last_err) == "rate_limited":
                _mark_device_flow_cooldown(30)
            return {
                "ok": False,
                "error": last_err,
                "token": None,
                "payload": payload,
            }
        if not dc.get("device_code") or not dc.get("user_code"):
            last_err = "device/code 申请失败（无 device_code）"
            return {
                "ok": False,
                "error": last_err,
                "token": None,
                "payload": payload,
            }

        user_code = str(dc["user_code"])
        verify_uri = (
            dc.get("verification_uri_complete")
            or f"{site_url}/oauth2/device?user_code={user_code}"
        )
        _emit(f"device flow: user_code={user_code} · 开始浏览器批准")

        try:
            approved = _approve_with_browser(
                s, verify_uri, proxy_spec=proxy_spec, log=_emit
            )
        except Exception as e:
            last_err = f"device approve 浏览器异常: {e}"
            _emit(f"device flow: {last_err}", "error")
            kind = _device_flow_error_kind(last_err)
            if kind == "rate_limited":
                _mark_device_flow_cooldown(30)
            return {
                "ok": False,
                "error": last_err,
                "token": None,
                "payload": payload,
            }
        if not approved.get("ok"):
            last_err = str(approved.get("error") or "device approve 失败")
            _emit(f"device flow: 批准失败 · {last_err}", "warn")
            kind = _device_flow_error_kind(last_err)
            if kind == "rate_limited":
                _mark_device_flow_cooldown(30)
            result: dict[str, Any] = {
                "ok": False,
                "error": last_err,
                "token": None,
                "payload": payload,
            }
            if "denied" in last_err:
                result["approved"] = False
            return result

        # 诊断模式：只验证同意授权，不下发 token
        if not do_token:
            _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
            return {
                "ok": True,
                "error": None,
                "token": None,
                "payload": payload,
                "has_refresh": False,
                "approved": True,
                "issue_token": False,
                "user_code": user_code,
                "note": "device approve 成功；已跳过 token 下发（GROK_DEVICE_FLOW_ISSUE_TOKEN=0）",
            }

        token = _poll_device_token(
            dc["device_code"],
            int(dc.get("interval") or 5),
            int(dc.get("expires_in") or 1800),
            timeout=45,
            proxy_spec=proxy_spec,
        )
        if isinstance(token, dict) and token.get("_error"):
            last_err = f"device approve 后 token 失败: {token.get('_error')}"
            _emit(f"device flow: {last_err}", "warn")
            return {
                "ok": False,
                "error": last_err,
                "token": None,
                "payload": payload,
                "approved": True,
            }
        if not token or not (token.get("access_token") or token.get("key")):
            last_err = "device approve 后未拿到 access_token"
            _emit(f"device flow: {last_err}", "warn")
            return {
                "ok": False,
                "error": last_err,
                "token": None,
                "payload": payload,
                "approved": True,
            }

        # 成功后轻冷却，降低连打 rate_limited（比旧 2s 更省）
        _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
        return {
            "ok": True,
            "error": None,
            "token": token,
            "payload": payload,
            "has_refresh": bool(token.get("refresh_token")),
            "approved": True,
            "issue_token": True,
        }
