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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from curl_cffi import requests

from g.proxy_pool import parse_proxy_line

# 基础配置
site_url = "https://accounts.x.ai"
# chrome120 在部分 Windows/curl_cffi 组合下连 accounts.x.ai 会 curl(28) 超时，改用更稳指纹
DEFAULT_IMPERSONATE = "chrome131"
# device flow / 导入专用指纹池（TLS 失败时轮换）
DEVICE_FLOW_IMPERSONATES = ("chrome131", "chrome136", "chrome124", "chrome")
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


def _proxy_kw(proxy_spec: str | None = None, *, force_direct: bool = False) -> dict:
    """统一代理参数；账号级显式值优先，空值表示直连。"""
    if force_direct:
        return {"proxies": {"http": "", "https": ""}}
    if proxy_spec is not None:
        mapped = _proxy_map(proxy_spec)
        return {"proxies": mapped} if mapped else {"proxies": {"http": "", "https": ""}}
    return {"proxies": PROXIES} if PROXIES else {}


def _parse_device_consent_page(html: str, page_url: str = "") -> dict[str, str]:
    """
    从 OAuth 同意页 HTML 解析当前版本的 approve form。
    页面仍是 form POST（非 server action）；字段/action URL 以页面为准自动跟随。
    """
    out = {
        "approve_url": f"{OIDC_ISSUER}/oauth2/device/approve",
        "user_code": "",
        "principal_type": "User",
        "principal_id": "",
        "user_id": "",
    }
    text = html or ""
    try:
        soup = BeautifulSoup(text, "html.parser")
        form = None
        for f in soup.find_all("form"):
            action = (f.get("action") or "").lower()
            if "device/approve" in action or "approve" in action:
                form = f
                break
        if form is None and soup.find("form"):
            form = soup.find("form")
        if form is not None:
            action = (form.get("action") or "").strip()
            if action:
                out["approve_url"] = urljoin(page_url or f"{site_url}/", action)
            for inp in form.find_all("input"):
                name = (inp.get("name") or "").strip()
                val = inp.get("value")
                if val is None:
                    val = ""
                if name == "user_code" and val:
                    out["user_code"] = str(val)
                elif name == "principal_type" and val:
                    out["principal_type"] = str(val)
                elif name == "principal_id":
                    out["principal_id"] = str(val)
    except Exception:
        pass
    # RSC/flight 里的 userId（表单 principal_id 常为空，由前端 state 填）
    m = re.search(r'"userId":"([0-9a-fA-F-]{36})"', text)
    if m:
        out["user_id"] = m.group(1)
        if not out["principal_id"]:
            out["principal_id"] = m.group(1)
    m = re.search(
        r'approveUrl\\?":\\?"(https:[^"\\]+device/approve[^"\\]*)"',
        text,
    )
    if m and not out.get("approve_url"):
        out["approve_url"] = m.group(1).replace("\\/", "/")
    m = re.search(r'"approveUrl":"(https:[^"]+device/approve[^"]*)"', text)
    if m:
        out["approve_url"] = m.group(1)
    return out


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
) -> dict[str, Any]:
    """
    与 grokcli-2api sso_to_auth_json.sso_to_token 同路径：
    SSO cookie → 登录态探测 → OIDC device verify/approve → access_token。

    issue_token:
      - None: 跟全局 DEVICE_FLOW_ISSUE_TOKEN（默认 True，换到 access_token）
      - True: 批准后轮询 token（生产路径）
      - False: 批准成功即返回（仅诊断用）

    加固：
    - 同意页字段/approve URL 从当前 HTML 自动解析（跟随页面版本）
    - 全局冷却（rate_limited 后拉长间隔）
    - TLS/超时失败时轮换 impersonate
    """
    s = (sso or "").strip()
    if not s:
        return {"ok": False, "error": "空 sso", "token": None, "payload": {}}
    if not is_sso_jwt_shape(s):
        return {"ok": False, "error": "非有效 JWT 形态", "token": None, "payload": {}}

    do_token = DEVICE_FLOW_ISSUE_TOKEN if issue_token is None else bool(issue_token)
    payload = decode_jwt_payload(s)
    proxy_kw = _proxy_kw(proxy_spec)

    # 指纹列表：调用方指定的优先，再轮换稳妥指纹
    fps: list[str] = []
    if impersonate:
        fps.append(impersonate)
    for x in DEVICE_FLOW_IMPERSONATES:
        if x not in fps:
            fps.append(x)
    # 最多试 3 个指纹，避免一次导入拖太久
    fps = fps[:3]

    # 有限并发 + 全局冷却：限流时大家一起让路，不把成功率打穿
    with _DEVICE_FLOW_SEM:
        _wait_device_flow_cooldown()
        last_err = "device flow 失败"

        for fp_idx, fp in enumerate(fps):
            try:
                sess = requests.Session(impersonate=fp)
                # 浏览器同源 cookie：.x.ai 即可覆盖 accounts / auth
                sess.cookies.set("sso", s, domain=".x.ai", path="/")

                r = sess.get(
                    "https://accounts.x.ai/",
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                final_url = (r.url or "").lower()
                if "error=rate_limited" in final_url or "rate_limited" in final_url:
                    last_err = f"探测 rate_limited: {r.url}"
                    _mark_device_flow_cooldown(25 + 10 * fp_idx)
                    # 限流：立刻让路，别继续换指纹连打
                    break
                if "sign-in" in final_url or "sign-up" in final_url:
                    return {
                        "ok": False,
                        "error": f"会话无效（跳转 {r.url}）",
                        "token": None,
                        "payload": payload,
                    }
                if r.status_code >= 400:
                    last_err = f"探测 HTTP {r.status_code}"
                    continue
            except Exception as e:
                last_err = f"探测异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    # 换指纹再试
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            dc = _request_device_code(timeout=max(15, int(timeout)), proxy_spec=proxy_spec)
            if not dc or dc.get("_error"):
                last_err = (dc or {}).get("_error") or "device/code 申请失败"
                if _device_flow_error_kind(last_err) == "rate_limited":
                    _mark_device_flow_cooldown(30)
                # device/code 与指纹无关，不必换指纹空转
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
            consent_html = ""
            consent_url = ""
            try:
                # 浏览器顺序：先打开 complete URI，再 POST verify
                sess.get(
                    verify_uri,
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                r = sess.post(
                    f"{OIDC_ISSUER}/oauth2/device/verify",
                    data={"user_code": user_code},
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": site_url,
                        "Referer": verify_uri,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                    timeout=timeout,
                    allow_redirects=True,
                    **proxy_kw,
                )
                ru = r.url or ""
                consent_url = ru
                consent_html = r.text or ""
                if "rate_limited" in ru.lower() or "error=rate_limited" in ru.lower():
                    last_err = f"device verify 失败: {ru}"
                    _mark_device_flow_cooldown(30 + 10 * fp_idx)
                    time.sleep(1.5)
                    break
                if "consent" not in ru:
                    last_err = f"device verify 失败: {ru}"
                    # 非限流的 verify 失败（如 code 过期）换指纹意义不大，直接返回
                    if "error=" in ru.lower() and "rate_limited" not in ru.lower():
                        return {
                            "ok": False,
                            "error": last_err,
                            "token": None,
                            "payload": payload,
                        }
                    continue
            except Exception as e:
                last_err = f"device verify 异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            # 关键：同意页 form 字段 / approve URL 跟随当前页面版本，不写死
            page = _parse_device_consent_page(consent_html, consent_url)
            approve_url = page.get("approve_url") or f"{OIDC_ISSUER}/oauth2/device/approve"
            # 浏览器 SSR 表单 principal_id 为空；部分号带 userId 也能过——两种都试
            pid_candidates: list[str] = []
            page_pid = (page.get("principal_id") or page.get("user_id") or "").strip()
            # 先空（与页面 hidden 默认一致），再 userId
            pid_candidates.append("")
            if page_pid and page_pid not in pid_candidates:
                pid_candidates.append(page_pid)

            approve_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": site_url,
                "Referer": consent_url or verify_uri,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-User": "?1",
            }
            approved_ok = False
            try:
                for pid in pid_candidates:
                    approve_data = {
                        "user_code": page.get("user_code") or user_code,
                        "action": "allow",
                        "principal_type": page.get("principal_type") or "User",
                        "principal_id": pid,
                    }
                    r = sess.post(
                        approve_url,
                        data=approve_data,
                        headers=approve_headers,
                        timeout=timeout,
                        allow_redirects=True,
                        **proxy_kw,
                    )
                    ru = r.url or ""
                    body_low = (r.text or "").lower()
                    if "rate_limited" in ru.lower():
                        last_err = f"device approve 失败: {ru}"
                        _mark_device_flow_cooldown(30)
                        approved_ok = False
                        break
                    # deny 会落到 done?denied=1 —— 这是真拒绝，不是假成功
                    if "denied=1" in ru.lower():
                        last_err = f"device approve 被拒绝: {ru}"
                        return {
                            "ok": False,
                            "error": last_err,
                            "token": None,
                            "payload": payload,
                            "approved": False,
                        }
                    if "done" in ru or "authorized" in body_low:
                        approved_ok = True
                        # 有多个 pid 候选时，本轮只 approve 一次（code 已消耗）
                        break
                if not approved_ok and "rate_limited" not in str(last_err):
                    last_err = f"device approve 失败: {ru if 'ru' in locals() else 'no response'}"
                    return {
                        "ok": False,
                        "error": last_err,
                        "token": None,
                        "payload": payload,
                        "approved": False,
                    }
                if not approved_ok:
                    break
            except Exception as e:
                last_err = f"device approve 异常: {e}"
                kind = _device_flow_error_kind(last_err)
                if kind in ("timeout", "tls"):
                    time.sleep(0.6 + 0.4 * fp_idx)
                    continue
                return {
                    "ok": False,
                    "error": last_err,
                    "token": None,
                    "payload": payload,
                }

            # 诊断模式：只验证同意授权，不下发 token
            if not do_token:
                _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
                return {
                    "ok": True,
                    "error": None,
                    "token": None,
                    "payload": payload,
                    "has_refresh": False,
                    "impersonate": fp,
                    "approved": True,
                    "issue_token": False,
                    "approve_url": approve_url,
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
                last_err = (
                    f"device approve 后 token 失败: {token.get('_error')}"
                )
                # code 已完成 approve 后仍 invalid_grant / access_denied，属于明确终止；
                # 换 TLS 指纹重做整条 flow 不会修复，只会把坏号耗时放大数倍。
                terminal = str(token.get("_error") or "").lower()
                if any(
                    marker in terminal
                    for marker in ("invalid_grant", "access denied", "access_denied")
                ):
                    return {
                        "ok": False,
                        "error": last_err,
                        "token": None,
                        "payload": payload,
                        "approved": True,
                    }
                time.sleep(1.0)
                continue
            if not token or not (token.get("access_token") or token.get("key")):
                # 假批准典型症状：页面已 done，但 token 仍 invalid_grant
                last_err = (
                    "device approve 后未拿到 access_token"
                    "（常见 invalid_grant/Access denied：会话无法真正授权）"
                )
                # approve 已成功但 token 轮询失败：短歇后换指纹整条重来
                time.sleep(1.0)
                continue

            # 成功后轻冷却，降低连打 rate_limited（比旧 2s 更省）
            _mark_device_flow_cooldown(_DEVICE_FLOW_SUCCESS_COOLDOWN)
            return {
                "ok": True,
                "error": None,
                "token": token,
                "payload": payload,
                "has_refresh": bool(token.get("refresh_token")),
                "impersonate": fp,
                "approved": True,
                "issue_token": True,
            }

        if _device_flow_error_kind(last_err) == "rate_limited":
            _mark_device_flow_cooldown(20)
        return {
            "ok": False,
            "error": last_err,
            "token": None,
            "payload": payload,
        }
