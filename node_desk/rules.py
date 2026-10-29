"""Subscription rule model for the Clash/Mihomo profile output.

Rules are stored in display order; in Mihomo the first matching rule wins.
``export_clash`` renders the enabled rules in order and always appends the
fixed ``MATCH,PROXY`` fallback afterwards. This module is deliberately pure:
no Qt and no YAML, so it can be unit tested offline.
"""

from __future__ import annotations

import ipaddress
import re
import uuid

MAX_RULES = 500
MAX_VALUE_LENGTH = 260

RULE_TYPES = {
    "DOMAIN": "精确域名",
    "DOMAIN-SUFFIX": "域名后缀",
    "DOMAIN-KEYWORD": "域名关键词",
    "GEOIP": "IP 国家/地区",
    "GEOSITE": "域名库分类",
    "IP-CIDR": "IPv4 网段",
    "IP-CIDR6": "IPv6 网段",
    "PROCESS-NAME": "进程名",
}

RULE_ACTIONS = {
    "PROXY": "走代理 (PROXY)",
    "AUTO": "自动选择 (AUTO)",
    "DIRECT": "直连 (DIRECT)",
    "REJECT": "拦截 (REJECT)",
}

RULE_HINTS = {
    "DOMAIN": "例如 www.example.com",
    "DOMAIN-SUFFIX": "例如 example.com",
    "DOMAIN-KEYWORD": "例如 google",
    "GEOIP": "两位国家代码，例如 CN",
    "GEOSITE": "例如 cn、category-ads-all",
    "IP-CIDR": "例如 192.168.0.0/16 或单个 IP",
    "IP-CIDR6": "例如 fc00::/7",
    "PROCESS-NAME": "例如 Telegram.exe",
}

# 只有这些类型支持 no-resolve（避免为匹配规则做额外的 DNS 解析）。
NO_RESOLVE_TYPES = {"IP-CIDR", "IP-CIDR6", "GEOIP"}

_DOMAIN = re.compile(r"^[a-z0-9*._-]+$")
_ALNUM = re.compile(r"[a-z0-9]")
_GEOIP = re.compile(r"^[A-Za-z]{2}$")
_GEOSITE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class RuleError(ValueError):
    """Invalid rule definition or an unusable rule set."""


def _value_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RuleError(f"{label}必须是文本。")
    result = value.strip()
    if not result:
        raise RuleError(f"{label}不能为空。")
    if len(result) > MAX_VALUE_LENGTH:
        raise RuleError(f"{label}不能超过 {MAX_VALUE_LENGTH} 个字符。")
    if any(ord(char) < 32 for char in result):
        raise RuleError(f"{label}包含控制字符。")
    return result


def _network(value: object, version: int) -> str:
    example = "192.168.0.0/16" if version == 4 else "fc00::/7"
    text = _value_text(value, "IP 网段")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise RuleError(f"IP 网段格式无效，例如 {example}。") from None
    if network.version != version:
        raise RuleError(f"网段版本与规则类型不符，例如 {example}。")
    return str(network)


def _normalize_value(rule_type: str, value: object) -> str:
    if rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
        text = _value_text(value, "域名").lower()
        if "," in text or any(char.isspace() for char in text) or not _DOMAIN.fullmatch(text):
            raise RuleError("域名只能包含字母、数字和 . _ - * 符号。")
        if not _ALNUM.search(text):
            raise RuleError("域名需要包含至少一个字母或数字。")
        return text
    if rule_type == "DOMAIN-KEYWORD":
        text = _value_text(value, "关键词")
        if "," in text:
            raise RuleError("关键词不能包含英文逗号。")
        return text
    if rule_type == "IP-CIDR":
        return _network(value, 4)
    if rule_type == "IP-CIDR6":
        return _network(value, 6)
    if rule_type == "GEOIP":
        text = _value_text(value, "国家代码")
        if not _GEOIP.fullmatch(text):
            raise RuleError("国家代码应为两位字母，例如 CN。")
        return text.upper()
    if rule_type == "GEOSITE":
        text = _value_text(value, "分类名").lower()
        if not _GEOSITE.fullmatch(text):
            raise RuleError("分类名只能包含字母、数字和连字符，例如 category-ads-all。")
        return text
    if rule_type == "PROCESS-NAME":
        text = _value_text(value, "进程名")
        if "," in text:
            raise RuleError("进程名不能包含英文逗号。")
        return text
    raise RuleError("不支持的规则类型。")


def validate_rule(rule: dict) -> dict:
    """Return a normalized copy of one rule or raise RuleError."""
    if not isinstance(rule, dict):
        raise RuleError("规则数据无效。")
    rule_type = rule.get("type")
    if rule_type not in RULE_TYPES:
        raise RuleError("请选择支持的规则类型。")
    value = _normalize_value(rule_type, rule.get("value"))
    action = rule.get("action")
    if action not in RULE_ACTIONS:
        raise RuleError("请选择规则动作（走代理 / 自动选择 / 直连 / 拦截）。")
    enabled = rule.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RuleError("启用状态必须是布尔值。")
    no_resolve = rule.get("no_resolve", False)
    if not isinstance(no_resolve, bool):
        raise RuleError("no-resolve 选项必须是布尔值。")
    result = {
        "type": rule_type,
        "value": value,
        "action": action,
        "no_resolve": no_resolve and rule_type in NO_RESOLVE_TYPES,
        "enabled": enabled,
    }
    if rule.get("id"):
        result["id"] = str(rule["id"])
    return result


def new_rule(rule_type: str, value: str, action: str, *,
             no_resolve: bool = False, enabled: bool = True) -> dict:
    """Build one validated rule with a fresh identifier."""
    rule = validate_rule({
        "type": rule_type, "value": value, "action": action,
        "no_resolve": no_resolve, "enabled": enabled,
    })
    rule["id"] = str(uuid.uuid4())
    return rule


def render_rule(rule: dict) -> str:
    """Render one rule as a Mihomo ``rules:`` line."""
    normalized = validate_rule(rule)
    fields = [normalized["type"], normalized["value"], normalized["action"]]
    if normalized["no_resolve"]:
        fields.append("no-resolve")
    return ",".join(fields)


def render_rules(rules: list | None) -> list[str]:
    """Render enabled rules in display order; the caller appends the fallback."""
    if rules is None:
        return []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise RuleError(f"规则数量必须在 {MAX_RULES} 条以内。")
    lines = []
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict) or not rule.get("enabled", True):
            continue
        try:
            lines.append(render_rule(rule))
        except RuleError as error:
            raise RuleError(f"第 {index} 条规则无效：{error}") from None
    return lines


def default_rules() -> list[dict]:
    """A fresh copy of the built-in rule set.

    Covers LAN/private direct, ad blocking, mainland-China direct, and the
    common service splits (Telegram, streaming) chosen in the feature spec.
    """
    entries = (
        # 局域网与私有地址直连
        ("IP-CIDR", "127.0.0.0/8", "DIRECT", True),
        ("IP-CIDR", "10.0.0.0/8", "DIRECT", True),
        ("IP-CIDR", "172.16.0.0/12", "DIRECT", True),
        ("IP-CIDR", "192.168.0.0/16", "DIRECT", True),
        ("IP-CIDR", "100.64.0.0/10", "DIRECT", True),
        ("IP-CIDR6", "fc00::/7", "DIRECT", True),
        ("IP-CIDR6", "fe80::/10", "DIRECT", True),
        ("DOMAIN-SUFFIX", "local", "DIRECT", False),
        # 广告与跟踪域名拦截
        ("GEOSITE", "category-ads-all", "REJECT", False),
        # 中国大陆流量直连
        ("GEOSITE", "cn", "DIRECT", False),
        ("GEOIP", "CN", "DIRECT", False),
        # Telegram 服务分流
        ("DOMAIN-SUFFIX", "t.me", "PROXY", False),
        ("DOMAIN-SUFFIX", "telegram.org", "PROXY", False),
        ("DOMAIN-SUFFIX", "telegram.me", "PROXY", False),
        ("DOMAIN-SUFFIX", "telegra.ph", "PROXY", False),
        ("DOMAIN-SUFFIX", "telesco.pe", "PROXY", False),
        ("IP-CIDR", "91.108.4.0/22", "PROXY", True),
        ("IP-CIDR", "91.108.8.0/22", "PROXY", True),
        ("IP-CIDR", "91.108.12.0/22", "PROXY", True),
        ("IP-CIDR", "91.108.16.0/22", "PROXY", True),
        ("IP-CIDR", "91.108.20.0/22", "PROXY", True),
        ("IP-CIDR", "91.108.56.0/22", "PROXY", True),
        ("IP-CIDR", "149.154.160.0/20", "PROXY", True),
        ("IP-CIDR", "91.105.192.0/23", "PROXY", True),
        ("IP-CIDR", "185.76.151.0/24", "PROXY", True),
        # 常见流媒体
        ("DOMAIN-SUFFIX", "netflix.com", "PROXY", False),
        ("DOMAIN-SUFFIX", "nflxvideo.net", "PROXY", False),
        ("DOMAIN-SUFFIX", "nflxso.net", "PROXY", False),
        ("DOMAIN-SUFFIX", "disneyplus.com", "PROXY", False),
        ("DOMAIN-SUFFIX", "hbomax.com", "PROXY", False),
        ("DOMAIN-SUFFIX", "primevideo.com", "PROXY", False),
        ("DOMAIN-SUFFIX", "youtube.com", "PROXY", False),
        ("DOMAIN-SUFFIX", "googlevideo.com", "PROXY", False),
    )
    return [new_rule(kind, value, action, no_resolve=no_resolve)
            for kind, value, action, no_resolve in entries]
