#!/usr/bin/env python3
"""新版 accounts.x.ai（无 CastleProvider）的可视化 UI 注册流程。

流程：打开注册页 → 点「邮箱注册」→ 填邮箱 → 提交 → 读邮箱验证码 → 填码
      → 可能的密码/姓名表单 → 拿 sso cookie。

用途：新版页面已移除 Castle / React fiber，原协议路径（castle mint + 页内 fetch）
失效，本脚本走浏览器真实点击，便于人工观察每一步。

容器内用法：
    cd /app && python -m g.ui_register                 # 自动建邮箱 + 有头
    cd /app && python -m g.ui_register --email a@b.com # 复用已有邮箱
    cd /app && python -m g.ui_register --headless      # 无头（排障用）
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Optional

SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"

# 验证码是 3-3 分格的 6 个单字符输入框；不同版本属性不一致，尽量放宽匹配。
CODE_SEL = (
    "input[autocomplete='one-time-code'], input[inputmode='numeric'], input[maxlength='1']"
)

# 在页面脚本执行前 patch attachShadow，拿到 closed shadow root 的引用。
# Turnstile 的 checkbox iframe 位于 closed shadow DOM 内，常规查询拿不到。
SHADOW_PATCH_JS = """
(() => {
  if (window.__shadowPatched) return;
  window.__shadowPatched = true;
  window.__shadowRoots = [];
  const orig = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) {
    const root = orig.call(this, init);
    try {
      if (init && init.mode === 'closed') window.__shadowRoots.push(root);
    } catch (e) {}
    return root;
  };
})();
"""

EMAIL_ENTRY_TEXTS = (
    "Mit E-Mail",
    "Sign up with email",
    "S'inscrire avec un e-mail",
    "Registrarse con correo",
    "メールで登録",
    "이메일로 가입",
    "email",
)
SUBMIT_TEXTS = (
    "Complete sign up",          # 资料页提交
    "Registrierung abschließen",
    "Complete registration",
    "Konto erstellen",
    "Create account",
    "Registrieren",
    "Sign up",                   # 首屏提交邮箱（不能少，否则发码点不到）
    "Weiter",
    "Continue",
)
CONFIRM_TEXTS = ("E-Mail bestätigen", "Bestätigen", "Verify", "Confirm", "Weiter", "Continue")
ERROR_HINTS = (
    "too many code requests",
    "isn't available",
    "is not available",
    "nicht verfügbar",
    "rate limit",
    "try again later",
    "sign up another way",
    "email sign-up isn",
)


def log(message: str) -> None:
    print(f"[ui-register] {message}", flush=True)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="新版页面 UI 注册（可见点击 + 读码）")
    parser.add_argument("--email", default="", help="复用已有邮箱；留空自动创建")
    parser.add_argument("--password", default="", help="账号密码；留空随机生成")
    parser.add_argument("--given", default="Michael", help="名")
    parser.add_argument("--family", default="Schmidt", help="姓")
    parser.add_argument(
        "--locale",
        default=os.getenv("GROK_LOCALE") or "en-US",
        help="固定英文，避免随机指纹抽到阿拉伯语导致浏览器 UI 乱码",
    )
    parser.add_argument(
        "--os",
        default=os.getenv("GROK_FP_OS") or ("macos" if sys.platform == "darwin" else ""),
        help="与真实系统一致（macOS 上不要伪装 windows）",
    )
    parser.add_argument(
        "--proxy",
        default=(
            os.getenv("GROK_REGISTER_PROXY")
            or os.getenv("GROK_PROXY")
            or os.getenv("DEBUG_PROXY")
            or ""
        ),
        help="账号级代理（控制台按轮次租约注入；留空直连）",
    )
    parser.add_argument("--url", default=SIGNUP_URL)
    parser.add_argument(
        "--from-grok",
        action="store_true",
        help="先从 grok.com 点注册，再跳 accounts.x.ai（更自然的入口）",
    )
    parser.add_argument("--headless", action="store_true", help="无头模式（默认有头便于观察）")
    parser.add_argument("--humanize", action="store_true", help="开启拟人化（默认关）")
    parser.add_argument("--code-timeout", type=int, default=180, help="等待邮件验证码秒数")
    parser.add_argument(
        "--submit-nav-timeout",
        type=int,
        default=int(os.getenv("GROK_SUBMIT_NAV_TIMEOUT") or 20),
        help="提交邮箱后等待进入验证码页的秒数；期间持续检测报错文本，命中即快速失败",
    )
    parser.add_argument("--out", default="", help="SSO 保存路径")
    parser.add_argument("--shot-dir", default="", help="截图目录，默认 logs/ui_register")
    parser.add_argument("--profile", default="", help="持久化 profile 目录（留空则每次临时）")
    parser.add_argument("--window", default="", help="窗口尺寸，如 1500x950")
    parser.add_argument("--hold", action="store_true", help="资料页就绪后停住，等待手动操作")
    return parser.parse_args(argv)


def rand_password(length: int = 14) -> str:
    """纯字母数字：系统级键盘（xdotool）不受键盘布局影响。"""
    core = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
    ]
    alphabet = string.ascii_letters + string.digits
    core += [random.choice(alphabet) for _ in range(max(4, length - len(core)))]
    random.shuffle(core)
    return "".join(core)


def click_first(page, texts, timeout: int = 8000) -> Optional[str]:
    for text in texts:
        try:
            locator = page.get_by_text(text, exact=False)
            if locator.count():
                locator.first.click(timeout=timeout)
                return text
        except Exception:
            continue
    return None


def click_button(page, texts, timeout: int = 8000) -> Optional[str]:
    for text in texts:
        selectors = (
            f"button:has-text('{text}')",
            f"[role=button]:has-text('{text}')",
        )
        for selector in selectors:
            try:
                locator = page.locator(selector)
                if locator.count():
                    locator.first.click(timeout=timeout)
                    return text
            except Exception:
                continue
    return click_first(page, texts, timeout=timeout)


def page_text(page) -> str:
    try:
        return page.inner_text("body")
    except Exception:
        return ""


def has_error(text: str) -> Optional[str]:
    low = text.lower()
    for hint in ERROR_HINTS:
        if hint in low:
            return hint
    return None


def get_cookies(browser) -> list:
    """兼容 Browser 与 persistent BrowserContext 两种返回。"""
    try:
        if getattr(browser, "contexts", None):
            return browser.contexts[0].cookies()
    except Exception:
        pass
    try:
        return browser.cookies()
    except Exception:
        return []


def find_sso(cookies: list[dict[str, Any]]) -> tuple[str, str]:
    sso = ""
    sso_rw = ""
    for cookie in cookies:
        name = str(cookie.get("name") or "")
        if name == "sso":
            sso = str(cookie.get("value") or "")
        elif name in ("sso-rw", "sso_rw"):
            sso_rw = str(cookie.get("value") or "")
    return sso, sso_rw


def fill_code(page, code: str) -> str:
    digits = re.sub(r"[^0-9A-Za-z]", "", code)
    boxes = page.locator(CODE_SEL)
    total = boxes.count()
    if total >= 6:
        for index, char in enumerate(digits[:6]):
            box = boxes.nth(index)
            try:
                box.click()
                box.press(char)
            except Exception:
                try:
                    box.fill(char)
                except Exception:
                    pass
            page.wait_for_timeout(80)
        values = []
        for index in range(min(total, 8)):
            try:
                values.append(boxes.nth(index).input_value())
            except Exception:
                values.append("?")
        return f"boxes:{total}:{''.join(values)}"
    if total:
        first = boxes.first
        first.click()
        page.wait_for_timeout(150)
        page.keyboard.type(digits, delay=80)
        try:
            value = first.input_value()
        except Exception:
            value = "?"
        return f"typed:{total}:{value}"
    return "no-box"


def set_input_value(page, element, value: str) -> bool:
    """用真实键盘事件填值；所有等待都限 1s，避免页面异常时长时间卡住。"""
    try:
        element.click(timeout=1000)
    except Exception:
        pass
    try:
        element.focus(timeout=1000)
    except Exception:
        pass
    try:
        element.fill("", timeout=1000)
    except Exception:
        pass
    try:
        page.keyboard.type(value, delay=25)
    except Exception:
        return False
    try:
        return (element.input_value(timeout=800) or "") == value
    except Exception:
        return False


def fill_possible_profile(page, args, budget_s: float = 10.0) -> list[str]:
    """填写密码/姓名；总预算默认 10s，超时立即返回，不反复重试。"""
    deadline = time.time() + budget_s
    filled: list[str] = []
    # 密码最后填：密码只写进 DOM、不进 React state，任何后续输入都会把它重置。
    fields = (
        ("input[autocomplete='given-name']", args.given),
        ("input[autocomplete='family-name']", args.family),
        ("input[name*='first' i]", args.given),
        ("input[name*='last' i]", args.family),
        ("input[type='password']", args.password),
    )
    for selector, value in fields:
        if time.time() >= deadline:
            log("资料页填写超出预算，停止")
            break
        try:
            locator = page.locator(selector)
            total = locator.count()
        except Exception:
            continue
        for index in range(min(total, 2)):
            if time.time() >= deadline:
                break
            try:
                element = locator.nth(index)
                if not element.is_visible():
                    continue
                if (element.input_value(timeout=600) or "").strip():
                    continue
                if set_input_value(page, element, value):
                    filled.append(f"{selector}#{index}")
            except Exception:
                continue
    return filled


def xrun(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=False).stdout.strip()


def find_browser_window() -> tuple[str, int, int, int, int]:
    """返回浏览器主窗口 (wid, x, y, w, h)：跳过根/桌面窗口，取面积最大的那个。"""
    screen_w = screen_h = 0
    disp = xrun("xdotool", "getdisplaygeometry").split()
    if len(disp) == 2:
        try:
            screen_w, screen_h = int(disp[0]), int(disp[1])
        except ValueError:
            screen_w = screen_h = 0
    best = ("", 0, 0, 0, 0)
    best_area = 0
    for wid in xrun("xdotool", "search", "--onlyvisible", "--name", "").split():
        geo = xrun("xdotool", "getwindowgeometry", "--shell", wid)
        vals = dict(
            line.split("=", 1) for line in geo.splitlines() if "=" in line
        )
        try:
            x, y = int(vals["X"]), int(vals["Y"])
            w, h = int(vals["WIDTH"]), int(vals["HEIGHT"])
        except Exception:
            continue
        # 跳过铺满整屏的窗口（Xvfb 根窗口/openbox 桌面），它们会抢走焦点
        if screen_w and w >= screen_w and h >= screen_h:
            continue
        if w * h > best_area:
            best_area = w * h
            best = (wid, x, y, w, h)
    return best


def type_via_xdotool(page, value: str) -> bool:
    """XTEST 系统级键盘输入（React 受控组件只认真实 OS 事件）。"""
    if not shutil.which("xdotool"):
        log("未安装 xdotool，无法使用系统级键盘")
        return False
    os.environ.setdefault("DISPLAY", ":99")
    wid, wx, wy, ww, wh = find_browser_window()
    if not wid:
        log("未找到浏览器窗口")
        return False
    log(f"浏览器窗口 {wid} @ ({wx},{wy}) {ww}x{wh}")
    # 不碰窗口焦点（windowactivate/windowfocus 都会触发重绘，noVNC 会黑屏）
    try:
        element = page.locator("input[type='password']").first
        element.click(timeout=1500)
        element.focus(timeout=1500)
    except Exception as exc:
        log(f"聚焦密码框失败: {exc}")
    try:
        active = page.evaluate(
            "() => { const a = document.activeElement;"
            " return a ? [a.tagName, a.type || '', a.id || ''] : null; }"
        )
    except Exception:
        active = None
    log(f"当前焦点元素: {active}")
    time.sleep(0.2)
    xrun("xdotool", "key", "--clearmodifiers", "ctrl+a")
    time.sleep(0.2)
    xrun("xdotool", "type", "--clearmodifiers", "--delay", "60", value)
    time.sleep(0.4)
    try:
        filled = page.locator("input[type='password']").first.input_value(timeout=800)
    except Exception:
        filled = ""
    log(f"XTEST 输入后密码长度={len(filled)}")
    return bool(filled)


def _macos_click(x: int, y: int) -> None:
    from Quartz import (  # type: ignore
        CGEventCreateMouseEvent,
        CGEventPost,
        kCGEventLeftMouseDown,
        kCGEventLeftMouseUp,
        kCGEventMouseMoved,
        kCGHIDEventTap,
    )

    for event_type in (kCGEventMouseMoved, kCGEventLeftMouseDown, kCGEventLeftMouseUp):
        event = CGEventCreateMouseEvent(None, event_type, (x, y), 0)
        CGEventPost(kCGHIDEventTap, event)
        time.sleep(0.05)


_MAC_KEYCODES = {
    "a": 0, "s": 1, "d": 2, "f": 3, "h": 4, "g": 5, "z": 6, "x": 7, "c": 8, "v": 9,
    "b": 11, "q": 12, "w": 13, "e": 14, "r": 15, "y": 16, "t": 17,
    "1": 18, "2": 19, "3": 20, "4": 21, "6": 22, "5": 23, "9": 25, "7": 26, "8": 28,
    "0": 29, "o": 31, "u": 32, "i": 34, "p": 35, "l": 37, "j": 38, "k": 40,
    "n": 45, "m": 46, ".": 47, "-": 27, " ": 49, "=": 24, "/": 44, ";": 41,
}
# 需要 Shift 的符号：(键码, 是否按 Shift)
_MAC_SPECIAL = {
    "@": (19, True), "_": (27, True), "+": (24, True), "!": (18, True),
    "#": (20, True), "$": (21, True), "%": (23, True), ":": (41, True),
    "?": (44, True), "&": (22, True), "*": (28, True), "(": (25, True),
    ")": (29, True), "~": (50, True), "|": (42, True), '"': (39, True),
    "'": (39, False), ",": (43, False),
}
_MAC_SHIFT = 56


def _macos_key(keycode: int, down: bool, shift: bool = False, text: str = "") -> None:
    from Quartz import (  # type: ignore
        CGEventCreateKeyboardEvent,
        CGEventKeyboardSetUnicodeString,
        CGEventPost,
        CGEventSetFlags,
        kCGEventFlagMaskShift,
        kCGHIDEventTap,
    )

    event = CGEventCreateKeyboardEvent(None, keycode, down)
    if shift:
        CGEventSetFlags(event, kCGEventFlagMaskShift)
    if text:
        # 同时写入 Unicode，避开中文输入法对首字符的组合拦截
        CGEventKeyboardSetUnicodeString(event, len(text), text)
    CGEventPost(kCGHIDEventTap, event)


def _macos_type(text: str) -> None:
    """Quartz 逐键输入（带 Unicode，避免中文输入法吞首字符）。"""
    for char in text:
        if char in _MAC_SPECIAL:
            keycode, need_shift = _MAC_SPECIAL[char]
        else:
            low = char.lower()
            if low not in _MAC_KEYCODES:
                continue
            keycode = _MAC_KEYCODES[low]
            need_shift = char.isalpha() and char.isupper()
        if need_shift:
            _macos_key(_MAC_SHIFT, True, shift=True)
        _macos_key(keycode, True, shift=need_shift)
        _macos_key(keycode, False, shift=need_shift)
        if need_shift:
            _macos_key(_MAC_SHIFT, False)
        time.sleep(0.04)


def _current_input_source() -> str:
    path = os.path.expanduser("~/Library/Preferences/com.apple.HIToolbox.plist")
    out = subprocess.run(
        ["defaults", "read", path, "AppleCurrentKeyboardLayoutInputSourceID"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return out


def macos_ensure_ascii_input() -> str:
    """切到 ABC 输入法，避免中文输入法吞掉首字符。"""
    current = _current_input_source()
    for _ in range(3):
        if "ABC" in current:
            return current
        subprocess.run(
            ["osascript", "-e", 'tell application "System Events" to key code 49 using control down'],
            capture_output=True,
            text=True,
            check=False,
        )
        time.sleep(0.6)
        current = _current_input_source()
    log(f"输入法切换后仍为: {current or 'unknown'}")
    return current


def os_type_into(page, locator, value: str) -> bool:
    """定位交给 Playwright（准），输入交给 OS 键盘（真实事件）。"""
    try:
        locator.click(timeout=1500)
        locator.focus(timeout=1500)
    except Exception as exc:
        log(f"聚焦失败: {exc}")
    try:
        page.bring_to_front()
    except Exception:
        pass
    time.sleep(0.3)
    if sys.platform == "darwin":
        try:
            _macos_type(value)
        except Exception as exc:
            log(f"OS 键盘输入失败: {exc}")
            return False
    elif shutil.which("xdotool"):
        os.environ.setdefault("DISPLAY", ":99")
        xrun("xdotool", "key", "--clearmodifiers", "ctrl+a")
        time.sleep(0.2)
        xrun("xdotool", "type", "--clearmodifiers", "--delay", "60", value)
    else:
        locator.fill(value)
    time.sleep(0.3)
    try:
        current = locator.input_value(timeout=800)
    except Exception:
        current = ""
    return current == value


def macos_window_bounds() -> Optional[tuple[int, int, int, int]]:
    from Quartz import (  # type: ignore
        CGWindowListCopyWindowInfo,
        kCGNullWindowID,
        kCGWindowListOptionOnScreenOnly,
    )

    for win in CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID):
        if (win.get("kCGWindowOwnerName") or "") == "Camoufox":
            bounds = win["kCGWindowBounds"]
            return int(bounds["X"]), int(bounds["Y"]), int(bounds["Width"]), int(bounds["Height"])
    return None


def macos_screen_xy(page, vx: float, vy: float) -> Optional[tuple[int, int]]:
    """视口坐标 → 屏幕坐标（用 CGWindowList 的真实窗口位置 + 标题栏高度）。"""
    win = macos_window_bounds()
    if not win:
        return None
    wx, wy, _ww, wh = win
    try:
        inner_h = page.evaluate("() => window.innerHeight")
    except Exception:
        return None
    return int(wx + vx), int(wy + (wh - inner_h) + vy)


def paste_into(page, locator, value: str) -> bool:
    """把值写入系统剪贴板，再用 Cmd+V 粘贴（浏览器原生流程，受控组件会收到 input）。"""
    try:
        locator.click(timeout=1500)
        locator.focus(timeout=1500)
    except Exception as exc:
        log(f"聚焦失败: {exc}")
    try:
        page.bring_to_front()
    except Exception:
        pass
    time.sleep(0.2)
    if sys.platform == "darwin":
        subprocess.run(["pbcopy"], input=value, text=True, check=False)
        time.sleep(0.12)
        result = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to keystroke "v" using command down'],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.stderr.strip():
            log(f"Cmd+V 失败: {result.stderr.strip()[:100]}")
    elif shutil.which("xdotool"):
        os.environ.setdefault("DISPLAY", ":99")
        xrun("xdotool", "key", "--clearmodifiers", "ctrl+v")
    else:
        return False
    time.sleep(0.5)
    try:
        return (locator.input_value(timeout=800) or "") == value
    except Exception:
        return False


def type_via_macos(page, value: str) -> bool:
    """三种写入方式依次尝试：insert_text → 剪贴板粘贴 → Quartz 键入。"""
    element = page.locator("input[type='password']").first
    try:
        element.click(timeout=1500)
        element.focus(timeout=1500)
    except Exception:
        pass
    # 1) 原生 setter + input/change 事件：标准 React 受控组件写入方式
    try:
        element.evaluate(
            """(el, v) => {
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(el, v);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
            }""",
            value,
        )
        time.sleep(0.4)
        current = element.input_value(timeout=800) or ""
        if current == value and value:
            log(f"native setter 成功，密码长度={len(current)}")
            return True
        log(f"native setter 未生效（当前长度={len(current)}）")
    except Exception as exc:
        log(f"native setter 异常: {exc}")
    # 2) Playwright 文本插入
    try:
        page.keyboard.insert_text(value)
        time.sleep(0.35)
        current = element.input_value(timeout=800) or ""
        if current == value and value:
            log(f"insert_text 成功，密码长度={len(current)}")
            return True
        log(f"insert_text 未生效（当前长度={len(current)}）")
    except Exception as exc:
        log(f"insert_text 异常: {exc}")
    # 2) 剪贴板 + 浏览器原生粘贴
    subprocess.run(["pbcopy"], input=value, text=True, check=False)
    time.sleep(0.1)
    try:
        page.keyboard.press("Meta+V")
        time.sleep(0.4)
        if (element.input_value(timeout=800) or "") == value:
            log(f"粘贴成功，密码长度={len(value)}")
            return True
        log("粘贴未生效，回退 Quartz 键入")
    except Exception as exc:
        log(f"粘贴异常: {exc}")
    try:
        box = element.bounding_box(timeout=1500)
    except Exception:
        box = None
    if not box:
        return False
    try:
        page.bring_to_front()
    except Exception:
        pass
    time.sleep(0.3)
    point = macos_screen_xy(page, box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    if not point:
        log("未找到 Camoufox 窗口")
        return False
    log(f"点击密码框 {point}")
    _macos_click(*point)
    time.sleep(0.35)
    try:
        _macos_type(value)
    except Exception as exc:
        log(f"Quartz 输入失败: {exc}")
        return False
    time.sleep(0.35)
    try:
        total = page.locator("input[type='password']").count()
        for index in range(total):
            item = page.locator("input[type='password']").nth(index)
            try:
                value_len = len(item.input_value() or "")
            except Exception:
                value_len = -1
            log(
                f"  pwd#{index} visible={item.is_visible()} "
                f"box={item.bounding_box()} value_len={value_len}"
            )
    except Exception:
        pass
    try:
        filled = element.input_value(timeout=800)
    except Exception:
        filled = ""
    log(f"Quartz 输入后密码长度={len(filled)}")
    return bool(filled)


def type_via_osascript(page, value: str) -> bool:
    """macOS 系统级键盘输入（System Events），绕开 React 对合成事件的过滤。"""
    try:
        element = page.locator("input[type='password']").first
        element.click(timeout=1500)
        element.focus(timeout=1500)
    except Exception as exc:
        log(f"聚焦密码框失败: {exc}")
    try:
        page.bring_to_front()
    except Exception:
        pass
    time.sleep(0.6)
    # 真实鼠标点击密码框（OS 级），让输入框进入“用户激活”状态
    try:
        box = element.bounding_box()
        info = page.evaluate(
            """() => ({sx: window.screenX, sy: window.screenY,
                       ow: window.outerWidth, iw: window.innerWidth})"""
        )
        if box:
            click_x = int(info["sx"] + (info["ow"] - info["iw"]) / 2 + box["x"] + box["width"] / 2)
            click_y = int(info["sy"] + box["y"] + box["height"] / 2)
            log(f"真实鼠标点击密码框: ({click_x}, {click_y})")
            subprocess.run(
                ["osascript", "-e",
                 f'tell application "System Events" to click at {{{click_x}, {click_y}}}'],
                capture_output=True, text=True, check=False,
            )
            time.sleep(0.4)
    except Exception as exc:
        log(f"真实鼠标点击失败: {exc}")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    result = subprocess.run(
        ["osascript", "-e", f'tell application "System Events" to keystroke "{escaped}"'],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stderr.strip():
        log(f"osascript 报错: {result.stderr.strip()[:120]}")
    time.sleep(0.5)
    try:
        filled = page.locator("input[type='password']").first.input_value(timeout=800)
    except Exception:
        filled = ""
    log(f"osascript 输入后密码长度={len(filled)}")
    return bool(filled)


def type_password_system(page, value: str) -> bool:
    """按平台选择系统级输入：macOS 用 System Events，Linux 用 XTEST。"""
    if sys.platform == "darwin":
        return type_via_macos(page, value)
    return type_via_xdotool(page, value)


def build_proxy_option(spec: str) -> tuple[dict[str, str], bool]:
    """把账号租约的 spec 拆成 Camoufox 的 proxy 参数。

    Playwright 的 ``proxy`` 不接受把账号密码塞进 server URL，必须分开传；
    返回 ``(option, is_loopback)``，loopback 决定是否开 geoip 对齐。
    """
    from g.proxy_pool import parse_proxy_line

    parsed = parse_proxy_line(spec)
    scheme = parsed["scheme"]
    # Playwright Firefox 只认 socks5:（socks5h: 会被当 HTTP 代理 → NS_ERROR_NET_RESET）
    if scheme == "socks5h":
        scheme = "socks5"
    option: dict[str, str] = {
        "server": f"{scheme}://{parsed['host']}:{parsed['port']}"
    }
    if parsed["username"]:
        option["username"] = parsed["username"]
        option["password"] = parsed["password"]
    loopback = parsed["host"] in ("127.0.0.1", "localhost", "::1")
    return option, loopback


GEO_PROBE_ENDPOINTS: tuple[tuple[str, str], ...] = (
    # ip-api 免费版只有 HTTP(80)，不少机场/节点只放行 443 或屏蔽明文 HTTP，
    # 所以按 HTTPS 端点优先的顺序逐个尝试，命中一个即返回。
    ("ipwho.is", "https://ipwho.is/"),
    ("ip.sb", "https://api.ip.sb/geoip"),
    ("ip-api", "http://ip-api.com/json/?fields=status,country,countryCode,timezone,lat,lon,query"),
)


def _normalize_geo(provider: str, data: object) -> Optional[dict]:
    """把不同探测端点的响应归一化为 {ip, cc, tz}；失败返回 None。"""
    if not isinstance(data, dict):
        return None
    if provider == "ip-api":
        if data.get("status") != "success" or not data.get("query"):
            return None
        return {"ip": data.get("query"), "cc": data.get("countryCode"), "tz": data.get("timezone")}
    if provider == "ipwho.is":
        tz = data.get("timezone")
        tz = tz.get("id") if isinstance(tz, dict) else tz
        if not data.get("ip"):
            return None
        return {"ip": data.get("ip"), "cc": data.get("country_code"), "tz": tz}
    if provider == "ip.sb":
        if not data.get("ip"):
            return None
        return {"ip": data.get("ip"), "cc": data.get("country_code"), "tz": data.get("timezone")}
    return None


def probe_proxy_geo(
    proxy_option: dict[str, str], timeout: float = 12.0, attempts: int = 2
) -> Optional[dict]:
    """通过节点出口探测一次 IP 地理，用于日志与 geoip 对齐决策。

    返回归一化的 {ip, cc, tz}；所有端点都失败返回 None。
    Camoufox 的 ``geoip=True`` 会在启动阶段自行查出口 IP，查不通会直接报错，
    所以这里先预探测：探测成功的节点才启用 geoip 对齐。
    """
    from urllib.parse import quote

    import requests

    server = proxy_option.get("server", "")
    url = server
    if proxy_option.get("username"):
        auth = quote(proxy_option["username"], safe="")
        pwd = quote(proxy_option.get("password", ""), safe="")
        url = server.replace("://", f"://{auth}:{pwd}@", 1)
    # Firefox 对 socks5 默认走代理远端解析 DNS，探测保持同语义（socks5h）
    url = url.replace("socks5://", "socks5h://", 1)
    proxies = {"http": url, "https": url}
    for provider, endpoint in GEO_PROBE_ENDPOINTS:
        for _ in range(max(1, attempts)):
            try:
                resp = requests.get(endpoint, proxies=proxies, timeout=timeout)
                geo = _normalize_geo(provider, resp.json())
            except Exception:
                continue
            if geo:
                return geo
    return None


def turnstile_solved(page) -> bool:
    """检查 Turnstile 是否已下发 token（含 shadow DOM）。"""
    try:
        return bool(
            page.evaluate(
                """() => {
                    const scan = (root) => {
                        const el = root.querySelector('input[name="cf-turnstile-response"]');
                        if (el && el.value && el.value.length > 20) return true;
                        for (const node of root.querySelectorAll('*')) {
                            if (node.shadowRoot && scan(node.shadowRoot)) return true;
                        }
                        return false;
                    };
                    return scan(document);
                }"""
            )
        )
    except Exception:
        return False


TURNSTILE_POLL_SECONDS = 12.0
TURNSTILE_POLL_INTERVAL = 0.5


def wait_turnstile(page, seconds: float = TURNSTILE_POLL_SECONDS) -> bool:
    """轮询等待 widget 下发 token。

    期间绝不重复点击：Turnstile 进入 Verifying 后再点一下就会 reset，
    表现出来的现象就是「刚勾上又立刻变回未勾选」。
    """
    deadline = time.time() + max(1.0, seconds)
    while time.time() < deadline:
        if turnstile_solved(page):
            return True
        page.wait_for_timeout(int(TURNSTILE_POLL_INTERVAL * 1000))
    return turnstile_solved(page)


def click_turnstile_macos(
    page,
    *,
    poll_seconds: float = TURNSTILE_POLL_SECONDS,
    max_candidates: int = 5,
) -> str:
    """点击 Turnstile checkbox：每次只点一下，然后等 token。

    widget 内部是跨域 iframe / closed shadow DOM，DOM 探测拿不到元素；
    资料页布局中 checkbox 与「Complete sign up」按钮同列，相对偏移固定，
    因此优先按按钮位置推算。点击后只轮询等待，不重复点击——
    重复点击会 reset 正在进行的挑战，token 永远拿不到。
    """
    try:
        page.bring_to_front()
    except Exception:
        pass

    if turnstile_solved(page):
        return "already-solved"

    btn_box = None
    for name in ("Complete sign up", "Sign up"):
        try:
            box = page.get_by_role("button", name=name, exact=True).first.bounding_box(timeout=1200)
        except Exception:
            box = None
        if box and box.get("width", 0) > 100:
            btn_box = box
            break

    try:
        inner_w = float(page.evaluate("() => window.innerWidth") or 0)
    except Exception:
        inner_w = 0.0

    primary: list[tuple[int, int, str]] = []
    tail: list[tuple[int, int, str]] = []
    if btn_box:
        # 纵向：checkbox 中心约在按钮顶边上方 49px（与视口高度无关）
        top = int(btn_box["y"] - 49)
        # 横向：表单居中，checkbox 中心 ≈ (innerWidth - 343) / 2（不同窗口宽度自适应）
        if inner_w >= 900:
            primary.append((int((inner_w - 343) / 2), top, "vw-rel"))
        base_x = int(btn_box["x"])
        primary += [(base_x + 3, top, "btn+3"), (base_x + 12, top, "btn+12")]
        tail = [(base_x + 21, top, "btn+21"), (base_x + 30, top, "btn+30")]
    # 坐标兜底按 1500x950 视口测得，放在按钮推算之后
    coords = [(609, 490, "coord"), (600, 480, "coord2"), (618, 500, "coord3"), (578, 505, "coord4")]
    candidates = primary + coords + tail

    # 去重，避免同一坐标点两次
    seen: set[tuple[int, int]] = set()
    unique: list[tuple[int, int, str]] = []
    for vx, vy, tag in candidates:
        if (vx, vy) in seen:
            continue
        seen.add((vx, vy))
        unique.append((vx, vy, tag))
    candidates = unique[: max(1, max_candidates)]

    for index, (vx, vy, tag) in enumerate(candidates):
        try:
            page.mouse.move(vx - 100, vy - 50, steps=6)
            page.mouse.move(vx, vy, steps=8)
            time.sleep(0.05)
            page.mouse.click(vx, vy)
        except Exception as exc:
            log(f"坐标点击失败: {exc}")
            continue
        try:
            page.screenshot(path=f"logs/ui_register/turnstile-{tag}-{vx}-{vy}.png")
        except Exception:
            pass
        solved = wait_turnstile(page, poll_seconds)
        log(f"点击 checkbox ({vx},{vy}) via {tag} → solved={solved}")
        if solved:
            return f"{tag}({vx},{vy})"
        if index + 1 < len(candidates):
            # 没点到 checkbox 或挑战失败：先等 widget 回落，再试下一个坐标
            page.wait_for_timeout(1500)
    return "no-iframe"


class BrowserCrashGuard:
    """浏览器阶段（Camoufox 启动 + 页面操作）崩溃兜底。

    任何 Exception 都打印完整 traceback 并写入 ``result["error"]``，
    随后吞掉异常、落到 main() 末尾的结果 JSON 写出，进程优雅退出（码 1），
    代替原来直接裸崩、结果文件不落盘的行为。
    KeyboardInterrupt / SystemExit 不拦截，保持 Ctrl+C 与提前 return 语义不变。
    """

    def __init__(self, log_fn, result: dict[str, Any]) -> None:
        self._log = log_fn
        self._result = result

    def __enter__(self) -> "BrowserCrashGuard":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None or not issubclass(exc_type, Exception):
            return False
        try:
            self._log(traceback.format_exc().rstrip())
            detail = f"浏览器阶段异常: {type(exc).__name__}: {exc}"
            self._result["error"] = detail[:300]
            self._log(self._result["error"])
        except Exception:
            pass
        return True  # 吞掉异常 → 继续走结果 JSON 写出 → 返回 1


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    sys_path = Path(__file__).resolve().parents[1]
    os.chdir(sys_path)
    if str(sys_path) not in os.sys.path:
        os.sys.path.insert(0, str(sys_path))

    from g.email_service import EmailService  # 延迟导入，避免无 env 时报错

    service = EmailService()
    # 控制台按轮次注入账号级代理（GROK_REGISTER_PROXY）；命令行仍可用 --proxy
    proxy_spec = str(args.proxy or "").strip()
    proxy_option: dict[str, str] | None = None
    proxy_label = ""
    if proxy_spec:
        try:
            proxy_option, _loopback = build_proxy_option(proxy_spec)
            from g.proxy_pool import mask_proxy

            proxy_label = mask_proxy(proxy_spec)
        except Exception as exc:
            log(f"代理解析失败（{exc}），本轮直连")
            proxy_spec, proxy_option = "", None
        else:
            log(f"节点 {proxy_label}")
            # 收码请求与注册浏览器同出口（仅 EMAIL_PROXY_MODE=register 时生效）
            try:
                service.set_register_proxy(proxy_spec)
            except Exception as exc:
                log(f"邮箱代理注入失败（不影响注册）: {exc}")
    email = args.email.strip()
    if not email:
        log("创建临时邮箱…")
        _, email = service.create_email()
        if not email:
            log("创建邮箱失败（检查 EMAIL_PROVIDER / 域名池）")
            return 2
    password = args.password or rand_password()
    # 回写：后续 fill_possible_profile / type_password_system 都读 args.password
    args.password = password
    log(f"邮箱 {email}")
    log(f"密码 {password}")

    shot_dir = Path(args.shot_dir) if args.shot_dir else Path("logs") / "ui_register"
    shot_dir.mkdir(parents=True, exist_ok=True)

    from camoufox.sync_api import Camoufox

    # 浏览器启动前先切到英文输入法：启动后再切会让 Firefox UI 字体错乱（地址栏乱码）
    if sys.platform == "darwin":
        source = macos_ensure_ascii_input()
        log(f"输入法: {source or 'unknown'}")

    # 只传 headless：os/locale/humanize 交给 Camoufox 默认（与手动启动一致）
    # GROK_CAMOUFOX_HEADLESS=0 可强制有头（Docker 调试镜像走 Xvfb + noVNC）
    headless_env = str(os.getenv("GROK_CAMOUFOX_HEADLESS", "1")).strip().lower()
    headless = bool(args.headless) and headless_env not in ("0", "false", "no", "off")
    kwargs: dict[str, Any] = {"headless": headless}
    kwargs["os"] = args.os or ("macos" if sys.platform == "darwin" else "linux")
    kwargs["locale"] = args.locale or "en-US"
    if args.humanize:
        kwargs["humanize"] = True
    if args.window:
        try:
            win_w, win_h = (int(v) for v in args.window.lower().split("x", 1))
            kwargs["window"] = (win_w, win_h)
        except Exception:
            log(f"--window 格式错误: {args.window}")
    if args.profile:
        kwargs["persistent_context"] = True
        kwargs["user_data_dir"] = args.profile
    if proxy_option:
        kwargs["proxy"] = proxy_option
        # 指纹与出口 IP 对齐：时区/经纬度跟随节点所在地，降低 Cloudflare 风控。
        # 预探测拿到出口 IP 后直接传给 Camoufox（geoip 参数支持传 IP），
        # 时区/经纬度由本地 MaxMind 库离线查询，启动阶段零网络请求——
        # 不依赖 Camoufox 自带的 IP 探测端点，也不受节点封 80 / 端点 403 影响。
        geo_ip = ""
        geo = None
        try:
            from camoufox.geolocation import geoip_allowed, get_geolocation

            geoip_allowed()  # 缺 camoufox[geoip] 依赖时直接跳过
            geo = probe_proxy_geo(proxy_option)
            if geo and geo.get("ip"):
                geo_ip = str(geo["ip"])
                # 预检：mmdb 缺失/过期会在此触发下载，失败就不进浏览器阶段
                get_geolocation(geo_ip)
            else:
                geo = None
        except Exception as exc:
            log(f"GeoIP 对齐预检失败（{exc}），跳过（时区/坐标可能与节点不匹配）")
            geo_ip = ""
            geo = None
        if geo_ip and geo:
            kwargs["geoip"] = geo_ip
            log(
                f"出口 {geo.get('cc')}（{geo_ip}）"
                f" 时区 {geo.get('tz')}，启用 geoip 对齐"
            )
        else:
            log("出口地理探测失败，跳过 geoip 对齐（时区/坐标可能与节点不匹配）")

    result: dict[str, Any] = {
        "email": email,
        "password": password,
        "ok": False,
        "sso": "",
        "sso_rw": "",
        "proxy": proxy_label,
        "proxy_mode": "pool" if proxy_label else "direct",
        "steps": [],
        "error": "",
    }

    def shot(page, name: str) -> None:
        try:
            page.screenshot(path=str(shot_dir / f"{int(time.time())}-{name}.png"))
        except Exception:
            pass

    with BrowserCrashGuard(log, result), Camoufox(**kwargs) as browser:
        page = browser.new_page()
        page.set_default_timeout(20000)
        try:
            page.add_init_script(SHADOW_PATCH_JS)
        except Exception as exc:
            log(f"attachShadow patch 注入失败: {exc}")
        if args.from_grok:
            log("打开 grok.com…")
            page.goto("https://grok.com", wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(6000)
            shot(page, "01-grok-home")
            before = len(browser.contexts[0].pages)
            entry = click_first(
                page,
                ("Sign up", "Registrieren", "Anmelden", "Get started", "Try Grok", "Kostenlos"),
                timeout=8000,
            )
            log(f"点击注册入口: {entry or '未找到'}")
            page.wait_for_timeout(5000)
            pages = browser.contexts[0].pages
            if len(pages) > before:
                page = pages[-1]
                log(f"切换到新标签页: {page.url}")
            log(f"当前 URL: {page.url}")
            shot(page, "01b-after-signup")
        else:
            log("打开注册页…")
            page.goto(args.url, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(7000)
        shot(page, "01-signup")

        clicked = click_first(page, EMAIL_ENTRY_TEXTS, timeout=12000)
        log(f"点击邮箱入口: {clicked or '未找到'}")
        result["steps"].append(f"entry:{clicked}")
        page.wait_for_timeout(3500)
        try:
            page.wait_for_selector("input[type='email']", timeout=20000)
        except Exception:
            log("未出现邮箱输入框，页面文本：")
            log(page_text(page)[:300].replace("\n", " | "))
            shot(page, "02-no-email-input")
            return 3

        email_input = page.locator("input[type='email']").first
        typed = os_type_into(page, email_input, email)
        log(f"邮箱输入: {'OS 键盘' if typed else '需回退'} · value={email_input.input_value()!r}")
        if not typed:
            email_input.fill(email)
        page.wait_for_timeout(900)
        shot(page, "02-email-filled")

        submit = click_button(page, SUBMIT_TEXTS, timeout=10000)
        log(f"提交邮箱: {submit or '未找到'}")
        result["steps"].append(f"submit:{submit}")

        # 点击后立刻轮询（0.5s 间隔）：进验证码页 → 继续；出现报错文本 → 立即放弃本轮；
        # 上限内都没出现 → 按超时失败。不再先死等 6s 再等 30s。
        nav_started = time.time()
        nav_timeout = max(5.0, float(args.submit_nav_timeout))
        entered_code_page = False
        rejected = ""
        text = ""
        while time.time() - nav_started < nav_timeout:
            page.wait_for_timeout(500)
            try:
                if page.locator(CODE_SEL).count():
                    entered_code_page = True
                    break
            except Exception:
                pass
            text = page_text(page)
            err = has_error(text)
            if err:
                rejected = err
                break
        nav_elapsed = round(time.time() - nav_started, 1)
        shot(page, "03-after-submit")

        if rejected:
            result["error"] = f"提交邮箱后被拒: {rejected}（{nav_elapsed}s）"
            log(result["error"])
            log(text[:300].replace("\n", " | "))
            result["steps"].append(f"submit_rejected:{nav_elapsed}s")
            shot(page, "04-submit-rejected")
            return 4

        if not entered_code_page:
            log(f"未进入验证码页（{nav_elapsed}s），页面文本：")
            log(page_text(page)[:300].replace("\n", " | "))
            result["error"] = f"未进入验证码页（{nav_timeout}s）"
            shot(page, "04-no-code-page")
            return 5

        log(f"已进入验证码页（{nav_elapsed}s）")
        result["steps"].append(f"code_page:{nav_elapsed}s")

        log(f"读取邮箱验证码（最多 {args.code_timeout}s）…")
        started = time.time()
        code = service.fetch_verification_code(email, max_attempts=max(10, args.code_timeout // 2))
        elapsed = round(time.time() - started, 1)
        if not code:
            result["error"] = f"读码失败（{elapsed}s）"
            log(result["error"])
            shot(page, "05-code-timeout")
            return 6
        log(f"验证码 {code}（{elapsed}s）")
        result["steps"].append(f"code:{code}")

        mode = fill_code(page, code)
        log(f"填写验证码: {mode}")
        result["steps"].append(f"code_fill:{mode}")
        page.wait_for_timeout(1200)
        shot(page, "06-code-filled")

        # 验证码填满后页面通常自动提交；只有仍停在验证码页时才点一次确认，避免长时间空转
        page.wait_for_timeout(1500)
        if page.locator("input[type='password']").count() == 0:
            confirm = click_button(page, CONFIRM_TEXTS, timeout=1200)
            log(f"确认验证码: {confirm or '未找到（依赖自动提交）'}")
            result["steps"].append(f"confirm:{confirm}")
        else:
            log("确认验证码: 已自动进入资料页")
        page.wait_for_timeout(1200)
        shot(page, "07-after-confirm")

        # 资料页：最多 10s 填完；密码为空直接结束，不再反复重试。
        text = page_text(page)
        has_password = page.locator("input[type='password']").count()
        if has_password or "abschließen" in text.lower():
            if args.hold:
                log("资料页已就绪，停住等待手动操作（5 分钟）…")
                page.wait_for_timeout(300000)
            try:
                frame_urls = ", ".join((f.url or "")[:60] for f in page.frames)
            except Exception:
                frame_urls = "?"
            log(f"frames: {frame_urls}")
            # 顺序：先填完资料（姓名+密码）→ 点一次 checkbox → 立即提交
            t_profile = time.time()
            filled = fill_possible_profile(page, args, budget_s=10.0)
            spent = round(time.time() - t_profile, 1)
            log(f"填写资料字段: {', '.join(filled) or '无'} · {spent}s")
            try:
                pwd_info = page.locator("input[type='password']").first.evaluate(
                    """el => ({minLength: el.minLength, maxLength: el.maxLength,
                              pattern: el.pattern, required: el.required, type: el.type,
                              disabled: el.disabled, readOnly: el.readOnly})"""
                )
                log(f"密码框属性: {pwd_info}")
            except Exception as exc:
                log(f"密码框属性读取失败: {exc}")
            for hint in re.findall(r"[^.|]{0,50}(?:Passwort|mindestens)[^.|]{0,50}", text)[:3]:
                log(f"密码提示: {hint.strip()}")
            result["steps"].append(f"profile:{len(filled)}:{spent}s")
            password_len = 0
            try:
                password_len = len(
                    page.locator("input[type='password']").first.input_value(timeout=800)
                )
            except Exception:
                pass
            if not password_len:
                log("Playwright 写入被 React 重置，改用系统级输入…")
                if type_password_system(page, args.password):
                    page.wait_for_timeout(600)
                    try:
                        password_len = len(
                            page.locator("input[type='password']").first.input_value(timeout=800)
                        )
                    except Exception:
                        pass
                    log(f"系统级输入后密码长度={password_len}")
            if not password_len:
                log("系统级输入仍未生效：请在窗口里手动填写密码并点击提交（最多等 180s）…")
                deadline = time.time() + 180
                while time.time() < deadline:
                    page.wait_for_timeout(3000)
                    cookies = get_cookies(browser)
                    sso_try, rw_try = find_sso(cookies)
                    if sso_try:
                        result.update(ok=True, sso=sso_try, sso_rw=rw_try)
                        log(f"手动完成后已拿到 sso（{len(sso_try)} 字符）")
                        break
                if not result["ok"] and not password_len:
                    result["error"] = f"资料页密码框为空（{spent}s 内未写入），已停止"
                    log(result["error"])
                    shot(page, "08-password-empty")
            else:
                # 主动点击 checkbox（按钮相对定位 + 坐标兜底，点击后只等待不重复点）
                clicked = click_turnstile_macos(page)
                log(f"Turnstile 点击: {clicked}")
                result["steps"].append(f"turnstile:click:{clicked}")
                solved = turnstile_solved(page) or wait_turnstile(page, 6.0)
                if solved:
                    # token 刚下发时 React 还会重渲染，等它写进表单状态再提交
                    page.wait_for_timeout(1500)
                log(f"Turnstile token: {'已下发' if solved else '未下发（提交大概率被拒）'}")
                result["steps"].append(f"turnstile:token:{'ok' if solved else 'missing'}")
                submit = click_button(page, SUBMIT_TEXTS, timeout=5000)
                log(f"提交资料: {submit or '未找到'} · 密码长度={password_len}")
                result["steps"].append(f"submit:{submit}")
                page.wait_for_timeout(12000)
                shot(page, "09-after-profile-submit")

        cookies = get_cookies(browser)
        sso, sso_rw = find_sso(cookies)
        if sso:
            result.update(ok=True, sso=sso, sso_rw=sso_rw)
            log(f"拿到 sso（{len(sso)} 字符）")
        elif not result["error"]:
            hint = has_error(page_text(page))
            result["error"] = f"页面报错: {hint}" if hint else "未拿到 sso"
            log(f"cookie 名称: {[c.get('name') for c in cookies]}")

        if not result["ok"]:
            shot(page, "10-failed")

    out_path = Path(args.out) if args.out else Path("register_sso") / f"ui_{int(time.time())}_{uuid.uuid4().hex[:6]}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"结果已写入 {out_path}")
    log("成功" if result["ok"] else f"失败：{result['error']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
