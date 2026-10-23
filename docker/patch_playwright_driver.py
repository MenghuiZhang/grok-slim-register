#!/usr/bin/env python3
"""给 Playwright Python 驱动 bundle 打 null-guard 补丁（构建期执行）。

修复 Firefox 驱动的上游竞态（microsoft/playwright#13444）：Turnstile 等
跨域 iframe 在导航提交瞬间被并发销毁时，FrameManager 的
removeChildFramesRecursively / _removeFramesRecursively 会拿到已被删除的
frame（undefined），抛 TypeError 直接杀死 Node 驱动进程，导致整轮注册失败。

补丁在两个函数入口各加一行 `if (!frame) return;`，把进程崩溃降级为无害跳过。
playwright 已在 requirements.txt 固定版本，bundle 文本稳定；若未来升级
playwright 导致目标文本变化，本脚本以非零码退出使构建失败，强制人工确认
新的补丁点，避免静默失效。重复执行幂等。
"""

import sys
from pathlib import Path

GUARDS = (
    (
        "removeChildFramesRecursively(frame) {",
        "removeChildFramesRecursively(frame) {\n        if (!frame) return;",
    ),
    (
        "_removeFramesRecursively(frame) {",
        "_removeFramesRecursively(frame) {\n        if (!frame) return;",
    ),
)


def main() -> int:
    try:
        import playwright

        driver_pkg = Path(playwright.__file__).parent / "driver" / "package"
    except Exception as exc:
        print(f"patch: cannot locate playwright package: {exc}", file=sys.stderr)
        return 1
    bundle = driver_pkg / "lib" / "coreBundle.js"
    if not bundle.exists():
        print(f"patch: bundle not found: {bundle}", file=sys.stderr)
        return 1

    text = bundle.read_text(encoding="utf-8")
    changed = False
    for target, patched in GUARDS:
        if patched in text:
            continue  # 已打过（构建层缓存重复执行时幂等）
        count = text.count(target)
        if count != 1:
            print(
                f"patch: expected exactly 1 occurrence of {target!r}, found {count};"
                " playwright 版本可能已变化，请人工确认补丁点",
                file=sys.stderr,
            )
            return 1
        text = text.replace(target, patched, 1)
        changed = True
    if changed:
        bundle.write_text(text, encoding="utf-8")
    print(f"patch: null-guard ok -> {bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
