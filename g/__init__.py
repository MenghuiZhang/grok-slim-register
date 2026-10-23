"""注册机配件包。

精简后的 g 包只承载注册流程与控制台所需的服务：
- email_service / email_config：临时邮箱（域名池）
- domain_pool / proxy_pool：运行时状态
- ui_register：Camoufox UI 注册流程（主入口）
- import_services：注册结果分发到上游目标
- device_flow / log_buffer：SSO 换 token 工具与控制台日志缓冲
"""
