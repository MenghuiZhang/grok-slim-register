"""Structured, backward-compatible configuration for email providers."""
from __future__ import annotations

import json
from typing import Any


PROVIDERS = ("outlook", "freemail", "yyds", "cloudflare_temp")
PROVIDER_LABELS = {
    "outlook": "Outlook / Hotmail Plus Alias",
    "freemail": "Cloudflare Freemail (idinging)",
    "yyds": "YYDS Mail",
    "cloudflare_temp": "Cloudflare Temp Email (dreamhunter2333)",
}

EMAIL_DEFAULTS = {
    "EMAIL_PROVIDER": "",
    "EMAIL_TIMEOUT_SECONDS": "120",
    "EMAIL_PROXY_MODE": "direct",
    "EMAIL_PROXY_URL": "",
    "EMAIL_TLS_VERIFY": "1",
    "EMAIL_OUTLOOK_ACCOUNTS_JSON": "[]",
    "EMAIL_OUTLOOK_DEFAULT_ALIAS_LIMIT": "5",
    "EMAIL_OUTLOOK_CONCURRENCY": "5",
    "EMAIL_FREEMAIL_BASE_URL": "",
    "EMAIL_FREEMAIL_TOKEN": "",
    "EMAIL_FREEMAIL_DOMAIN": "auto",
    "EMAIL_FREEMAIL_CONCURRENCY": "10",
    "EMAIL_YYDS_BASE_URL": "https://maliapi.215.im/v1",
    "EMAIL_YYDS_API_KEY": "",
    "EMAIL_YYDS_DOMAIN": "auto",
    "EMAIL_YYDS_PLATFORM_CODE": "grok",
    "EMAIL_YYDS_CONCURRENCY": "5",
    "EMAIL_CF_TEMP_BASE_URL": "",
    "EMAIL_CF_TEMP_SITE_TOKEN": "",
    "EMAIL_CF_TEMP_ADMIN_KEY": "",
    "EMAIL_CF_TEMP_DOMAINS_JSON": "[]",
    "EMAIL_CF_TEMP_AUTO_DOMAIN": "1",
    "EMAIL_CF_TEMP_RANDOM_SUBDOMAIN": "0",
    "EMAIL_CF_TEMP_CONCURRENCY": "10",
}

EMAIL_CONFIG_KEYS = tuple(EMAIL_DEFAULTS)
SECRET_FIELDS = {
    "freemail": ("token",),
    "yyds": ("api_key",),
    "cloudflare_temp": ("site_token", "admin_key"),
}


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def as_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(low, min(parsed, high))


def json_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def normalize_base_url(value: Any) -> str:
    url = str(value or "").strip().rstrip("/")
    if url and not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


def normalize_provider(value: Any, legacy_type: Any = "") -> str:
    raw = str(value or legacy_type or "").strip().lower().replace("-", "_")
    aliases = {
        "outlook_hotmail": "outlook",
        "cloudflare": "cloudflare_temp",
        "cf_temp": "cloudflare_temp",
        "cloudflare_temp_email": "cloudflare_temp",
    }
    raw = aliases.get(raw, raw)
    if raw == "freemail" and str(legacy_type or "").strip().lower() == "freemail":
        # Existing installs used FREEMAIL_API_STYLE to distinguish these below.
        return "freemail"
    return raw if raw in PROVIDERS else "cloudflare_temp"


def _legacy_outlook_accounts(cfg: dict) -> list[dict]:
    rows: list[dict] = []
    raw = str(cfg.get("OUTLOOK_ACCOUNTS") or "").replace("\\n", "\n")
    default_limit = as_int(cfg.get("OUTLOOK_ALIAS_LIMIT"), 5, 1, 999)
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "----" in line:
            parts = [part.strip() for part in line.split("----")]
            email = parts[0] if parts else ""
            password = parts[1] if len(parts) > 1 else ""
            refresh_token = parts[2] if len(parts) > 2 else ""
            client_id = parts[3] if len(parts) > 3 else ""
        elif ":" in line:
            email, password = [part.strip() for part in line.split(":", 1)]
            refresh_token = client_id = ""
        else:
            continue
        if email:
            rows.append({
                "email": email,
                "password": password,
                "refresh_token": refresh_token,
                "client_id": client_id,
                "alias_limit": default_limit,
            })
    return rows


def resolved_email_config(cfg: dict) -> dict:
    """Return the structured config, transparently reading legacy variables."""
    explicit_provider = str(cfg.get("EMAIL_PROVIDER") or "").strip()
    migrated = bool(explicit_provider)
    legacy_type = str(cfg.get("EMAIL_TYPE") or "freemail").strip().lower()
    if explicit_provider:
        provider = normalize_provider(explicit_provider, legacy_type)
    elif legacy_type in {"outlook", "outlook-hotmail"}:
        provider = "outlook"
    else:
        style = str(cfg.get("FREEMAIL_API_STYLE") or "auto").strip().lower()
        provider = "freemail" if style == "freemail" else "cloudflare_temp"

    outlook_accounts = json_list(cfg.get("EMAIL_OUTLOOK_ACCOUNTS_JSON"))
    if not outlook_accounts and not migrated:
        outlook_accounts = _legacy_outlook_accounts(cfg)

    legacy_worker = str(cfg.get("WORKER_DOMAIN") or "").strip()
    legacy_base = normalize_base_url(legacy_worker)
    cf_domains = [str(v).strip() for v in json_list(cfg.get("EMAIL_CF_TEMP_DOMAINS_JSON")) if str(v).strip()]
    legacy_domain = str(cfg.get("FREEMAIL_DOMAIN") or "auto").strip() or "auto"
    if not cf_domains and not migrated and legacy_domain.lower() != "auto":
        cf_domains = [legacy_domain]

    return {
        "provider": provider,
        "common": {
            "timeout_seconds": as_int(cfg.get("EMAIL_TIMEOUT_SECONDS"), 120, 30, 600),
            "proxy_mode": str(cfg.get("EMAIL_PROXY_MODE") or "direct").strip().lower(),
            "proxy_url": str(cfg.get("EMAIL_PROXY_URL") or "").strip(),
            "tls_verify": as_bool(cfg.get("EMAIL_TLS_VERIFY"), True),
        },
        "providers": {
            "outlook": {
                "accounts": outlook_accounts,
                "default_alias_limit": as_int(cfg.get("EMAIL_OUTLOOK_DEFAULT_ALIAS_LIMIT"), as_int(cfg.get("OUTLOOK_ALIAS_LIMIT"), 5, 1, 999), 1, 999),
                "concurrency": as_int(cfg.get("EMAIL_OUTLOOK_CONCURRENCY"), 5, 1, 64),
            },
            "freemail": {
                "base_url": normalize_base_url(cfg.get("EMAIL_FREEMAIL_BASE_URL") if migrated else (cfg.get("EMAIL_FREEMAIL_BASE_URL") or legacy_base)),
                "token": str((cfg.get("EMAIL_FREEMAIL_TOKEN") if migrated else (cfg.get("EMAIL_FREEMAIL_TOKEN") or (cfg.get("FREEMAIL_TOKEN") if provider == "freemail" else ""))) or ""),
                "domain": str((cfg.get("EMAIL_FREEMAIL_DOMAIN") if migrated else (cfg.get("EMAIL_FREEMAIL_DOMAIN") or legacy_domain)) or "auto"),
                "concurrency": as_int(cfg.get("EMAIL_FREEMAIL_CONCURRENCY"), 10, 1, 64),
            },
            "yyds": {
                "base_url": normalize_base_url(cfg.get("EMAIL_YYDS_BASE_URL") or EMAIL_DEFAULTS["EMAIL_YYDS_BASE_URL"]),
                "api_key": str(cfg.get("EMAIL_YYDS_API_KEY") or ""),
                "domain": str(cfg.get("EMAIL_YYDS_DOMAIN") or "auto"),
                "platform_code": str(cfg.get("EMAIL_YYDS_PLATFORM_CODE") or "grok"),
                "concurrency": as_int(cfg.get("EMAIL_YYDS_CONCURRENCY"), 5, 1, 64),
            },
            "cloudflare_temp": {
                "base_url": normalize_base_url(cfg.get("EMAIL_CF_TEMP_BASE_URL") if migrated else (cfg.get("EMAIL_CF_TEMP_BASE_URL") or legacy_base)),
                "site_token": str((cfg.get("EMAIL_CF_TEMP_SITE_TOKEN") if migrated else (cfg.get("EMAIL_CF_TEMP_SITE_TOKEN") or (cfg.get("FREEMAIL_TOKEN") if provider == "cloudflare_temp" else ""))) or ""),
                "admin_key": str((cfg.get("EMAIL_CF_TEMP_ADMIN_KEY") if migrated else (cfg.get("EMAIL_CF_TEMP_ADMIN_KEY") or cfg.get("FREEMAIL_ADMIN_KEY"))) or ""),
                "domains": cf_domains,
                "auto_domain": as_bool(cfg.get("EMAIL_CF_TEMP_AUTO_DOMAIN"), not cf_domains) if migrated else not cf_domains,
                "random_subdomain": as_bool(cfg.get("EMAIL_CF_TEMP_RANDOM_SUBDOMAIN"), False) if migrated else as_bool(cfg.get("FREEMAIL_RANDOM_SUBDOMAIN")),
                "concurrency": as_int(cfg.get("EMAIL_CF_TEMP_CONCURRENCY"), 10, 1, 64),
            },
        },
    }


def validate_provider_config(structured: dict, provider: str | None = None) -> list[str]:
    provider = normalize_provider(provider or structured.get("provider"))
    p = structured.get("providers", {}).get(provider, {})
    errors: list[str] = []
    if provider == "outlook":
        if not p.get("accounts"):
            errors.append("请至少配置一个 Outlook 账号")
        for index, account in enumerate(p.get("accounts") or [], 1):
            email = str(account.get("email") or "").strip()
            has_password = bool(str(account.get("password") or "").strip())
            has_oauth = bool(str(account.get("refresh_token") or "").strip() and str(account.get("client_id") or "").strip())
            if "@" not in email:
                errors.append(f"Outlook 第 {index} 个账号邮箱格式无效")
            if not (has_password or has_oauth):
                errors.append(f"Outlook 第 {index} 个账号缺少应用密码或 OAuth2 凭据")
    elif provider == "freemail":
        if not p.get("base_url"):
            errors.append("请填写 Freemail API 地址")
    elif provider == "yyds":
        if not p.get("base_url"):
            errors.append("请填写 YYDS API 地址")
        if not p.get("api_key"):
            errors.append("请填写 YYDS API Key")
    elif provider == "cloudflare_temp":
        if not p.get("base_url"):
            errors.append("请填写 Cloudflare Temp Worker 地址")
        if not p.get("auto_domain") and not p.get("domains"):
            errors.append("请选择至少一个域名，或启用服务端自动域名")
    return errors


def serialize_structured_config(current: dict, payload: dict) -> dict:
    """Merge a UI payload into env values. Empty secret fields retain old values."""
    old = resolved_email_config(current)
    common = {**old["common"], **(payload.get("common") or {})}
    incoming_providers = payload.get("providers") or {}
    providers = {name: {**old["providers"][name], **(incoming_providers.get(name) or {})} for name in PROVIDERS}

    clear = set(payload.get("clear_secrets") or [])
    for provider, fields in SECRET_FIELDS.items():
        for field in fields:
            marker = f"{provider}.{field}"
            incoming = (incoming_providers.get(provider) or {})
            if marker in clear:
                providers[provider][field] = ""
            elif field in incoming and not str(incoming.get(field) or "").strip():
                providers[provider][field] = old["providers"][provider].get(field, "")

    accounts = providers["outlook"].get("accounts") or []
    old_accounts = {str(a.get("email") or "").lower(): a for a in old["providers"]["outlook"].get("accounts") or []}
    normalized_accounts = []
    for raw in accounts if isinstance(accounts, list) else []:
        if not isinstance(raw, dict) or not str(raw.get("email") or "").strip():
            continue
        row = dict(raw)
        prior = old_accounts.get(str(row.get("email") or "").lower(), {})
        for field in ("password", "refresh_token"):
            if not str(row.get(field) or "").strip():
                row[field] = prior.get(field, "")
        row["alias_limit"] = as_int(row.get("alias_limit"), as_int(providers["outlook"].get("default_alias_limit"), 5, 1, 999), 1, 999)
        normalized_accounts.append(row)

    provider = normalize_provider(payload.get("provider") or old["provider"])
    cf_domains = []
    for value in providers["cloudflare_temp"].get("domains") or []:
        domain = str(value or "").strip().lower()
        if domain and domain not in cf_domains:
            cf_domains.append(domain)

    values = dict(current)
    values.update({
        "EMAIL_PROVIDER": provider,
        "EMAIL_TIMEOUT_SECONDS": str(as_int(common.get("timeout_seconds"), 120, 30, 600)),
        "EMAIL_PROXY_MODE": str(common.get("proxy_mode") or "direct"),
        "EMAIL_PROXY_URL": str(common.get("proxy_url") or ""),
        "EMAIL_TLS_VERIFY": "1" if as_bool(common.get("tls_verify"), True) else "0",
        "EMAIL_OUTLOOK_ACCOUNTS_JSON": json.dumps(normalized_accounts, ensure_ascii=False, separators=(",", ":")),
        "EMAIL_OUTLOOK_DEFAULT_ALIAS_LIMIT": str(as_int(providers["outlook"].get("default_alias_limit"), 5, 1, 999)),
        "EMAIL_OUTLOOK_CONCURRENCY": str(as_int(providers["outlook"].get("concurrency"), 5, 1, 64)),
        "EMAIL_FREEMAIL_BASE_URL": normalize_base_url(providers["freemail"].get("base_url")),
        "EMAIL_FREEMAIL_TOKEN": str(providers["freemail"].get("token") or ""),
        "EMAIL_FREEMAIL_DOMAIN": str(providers["freemail"].get("domain") or "auto"),
        "EMAIL_FREEMAIL_CONCURRENCY": str(as_int(providers["freemail"].get("concurrency"), 10, 1, 64)),
        "EMAIL_YYDS_BASE_URL": normalize_base_url(providers["yyds"].get("base_url")),
        "EMAIL_YYDS_API_KEY": str(providers["yyds"].get("api_key") or ""),
        "EMAIL_YYDS_DOMAIN": str(providers["yyds"].get("domain") or "auto"),
        "EMAIL_YYDS_PLATFORM_CODE": str(providers["yyds"].get("platform_code") or "grok"),
        "EMAIL_YYDS_CONCURRENCY": str(as_int(providers["yyds"].get("concurrency"), 5, 1, 64)),
        "EMAIL_CF_TEMP_BASE_URL": normalize_base_url(providers["cloudflare_temp"].get("base_url")),
        "EMAIL_CF_TEMP_SITE_TOKEN": str(providers["cloudflare_temp"].get("site_token") or ""),
        "EMAIL_CF_TEMP_ADMIN_KEY": str(providers["cloudflare_temp"].get("admin_key") or ""),
        "EMAIL_CF_TEMP_DOMAINS_JSON": json.dumps(cf_domains, ensure_ascii=False, separators=(",", ":")),
        "EMAIL_CF_TEMP_AUTO_DOMAIN": "1" if as_bool(providers["cloudflare_temp"].get("auto_domain"), not cf_domains) else "0",
        "EMAIL_CF_TEMP_RANDOM_SUBDOMAIN": "1" if as_bool(providers["cloudflare_temp"].get("random_subdomain")) else "0",
        "EMAIL_CF_TEMP_CONCURRENCY": str(as_int(providers["cloudflare_temp"].get("concurrency"), 10, 1, 64)),
    })

    # Compatibility writes for old binaries and scripts.
    legacy_type = "outlook-hotmail" if provider == "outlook" else "freemail"
    values["EMAIL_TYPE"] = legacy_type
    values["OUTLOOK_ALIAS_LIMIT"] = values["EMAIL_OUTLOOK_DEFAULT_ALIAS_LIMIT"]
    values["OUTLOOK_ACCOUNTS"] = "\n".join(
        "----".join([
            str(a.get("email") or ""), str(a.get("password") or ""),
            str(a.get("refresh_token") or ""), str(a.get("client_id") or ""),
        ]) for a in normalized_accounts
    )
    if provider == "freemail":
        selected = providers["freemail"]
        values.update({
            "WORKER_DOMAIN": normalize_base_url(selected.get("base_url")).replace("https://", "").replace("http://", ""),
            "FREEMAIL_TOKEN": str(selected.get("token") or ""),
            "FREEMAIL_ADMIN_KEY": "",
            "FREEMAIL_DOMAIN": str(selected.get("domain") or "auto"),
            "FREEMAIL_RANDOM_SUBDOMAIN": "0",
            "FREEMAIL_API_STYLE": "freemail",
        })
    elif provider == "cloudflare_temp":
        selected = providers["cloudflare_temp"]
        values.update({
            "WORKER_DOMAIN": normalize_base_url(selected.get("base_url")).replace("https://", "").replace("http://", ""),
            "FREEMAIL_TOKEN": str(selected.get("site_token") or ""),
            "FREEMAIL_ADMIN_KEY": str(selected.get("admin_key") or ""),
            "FREEMAIL_DOMAIN": cf_domains[0] if cf_domains else "auto",
            "FREEMAIL_RANDOM_SUBDOMAIN": "1" if as_bool(selected.get("random_subdomain")) else "0",
            "FREEMAIL_API_STYLE": "cf_temp",
        })
    return values


def redact_config(structured: dict, mask_fn) -> dict:
    """Return browser-safe config; credentials are never returned verbatim."""
    data = json.loads(json.dumps(structured))
    for provider, fields in SECRET_FIELDS.items():
        target = data["providers"][provider]
        for field in fields:
            raw = str(target.get(field) or "")
            target[field] = ""
            target[field + "_set"] = bool(raw)
            target[field + "_masked"] = mask_fn(raw)
    for account in data["providers"]["outlook"].get("accounts") or []:
        for field in ("password", "refresh_token"):
            raw = str(account.get(field) or "")
            account[field] = ""
            account[field + "_set"] = bool(raw)
            account[field + "_masked"] = mask_fn(raw)
    return data
