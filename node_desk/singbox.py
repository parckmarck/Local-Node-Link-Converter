"""sing-box subscription configuration export.

Builds a complete, directly usable sing-box JSON profile from the same stored
records used by the Clash and v2rayN exports. The output targets the stable
configuration format of sing-box 1.12 through 1.14: action-based route rules,
the current DNS server format, and WireGuard endpoints. Export only: NodeDesk
never parses sing-box profiles. This module is deliberately pure: no Qt, no
file or network access.

Protocol coverage and intentional whole-export errors (mirroring the fail-
explicit policy of the other exporters):

- Hysteria v1, Mieru, and ShadowsocksR nodes cannot be exported: current
  sing-box no longer implements them (SSR is a parse-only stub).
- Hysteria2 ``pinSHA256`` (certificate pinning) has no sing-box equivalent;
  exporting without it would silently weaken TLS verification.
- Trojan-Go ``encryption=ss`` has no sing-box equivalent (``ss-opts``).
- ``no_resolve`` rule hints are not needed: sing-box matches IP rules against
  the actual destination without forcing DNS resolution.
"""

from __future__ import annotations

import json
import re
import uuid as uuid_module
from urllib.parse import urlsplit

from .formats import (
    FormatError,
    _BAD_ESCAPE,
    _export_nodes,
    _integer,
    _plugin_string,
    _text,
    _unique_names,
)
from .rules import MAX_RULES, RuleError, validate_rule

_SING_BOX_UNSUPPORTED = ("hysteria", "mieru", "ssr")
_RULE_SET_BASE = {
    "geoip": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{name}.srs",
    "geosite": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{name}.srs",
}


def _check_test_url(test_url: str) -> None:
    _text(test_url, "Test URL", limit=2048)
    try:
        target = urlsplit(test_url)
        valid = (target.scheme in {"http", "https"} and target.hostname
                 and target.username is None and not target.fragment)
        if target.port is not None:
            _integer(target.port, "Test URL port", 1, 65535)
    except ValueError:
        raise FormatError("Test URL must be a valid HTTP(S) URL without credentials or fragment.") from None
    if not valid or any(char.isspace() for char in test_url) or _BAD_ESCAPE.search(test_url):
        raise FormatError("Test URL must be a valid HTTP(S) URL without credentials or fragment.")


def _client_uuid(value: str) -> str:
    """Canonical UUID, mapping custom Xray IDs the way Xray/Mihomo do.

    Xray accepts any string of at most 30 bytes and maps it to a UUIDv5 with
    a nil namespace (XTLS/Xray-core issue #158); the mapped UUID is fully
    equivalent. sing-box itself parses strict UUIDs, so emit the mapping.
    """
    try:
        return str(uuid_module.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return str(uuid_module.uuid5(uuid_module.UUID(int=0), value))


def _base(protocol: str, proxy: dict, name: str) -> dict:
    return {
        "type": protocol,
        "tag": name,
        "server": proxy["server"],
        "server_port": proxy["port"],
    }


def _tls_block(proxy: dict, *, server_name: str | None = None) -> dict:
    if server_name is None:
        server_name = proxy.get("sni") or proxy.get("servername") or ""
    tls: dict = {"enabled": True}
    if server_name:
        tls["server_name"] = server_name
    if proxy.get("skip-cert-verify"):
        tls["insecure"] = True
    alpn = proxy.get("alpn")
    if alpn:
        tls["alpn"] = list(alpn)
    fingerprint = proxy.get("client-fingerprint")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    return tls


def _transport(proxy: dict) -> dict | None:
    network = proxy.get("network", "tcp")
    if network == "ws":
        options = proxy.get("ws-opts") or {}
        path = options.get("path") or "/"
        transport: dict = {"type": "ws"}
        early_data = None
        if "?" in path:
            path, _, query = path.partition("?")
            kept = []
            for pair in query.split("&"):
                key, _, value = pair.partition("=")
                if key == "ed":
                    try:
                        early_data = int(value)
                    except ValueError:
                        kept.append(pair)
                else:
                    kept.append(pair)
            if kept:
                path = path + "?" + "&".join(kept)
        if early_data:
            # The ?ed= convention pairs with the Sec-WebSocket-Protocol
            # header; mihomo applies the same defaults for this path.
            transport["max_early_data"] = early_data
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        transport["path"] = path or "/"
        headers = options.get("headers")
        if headers:
            transport["headers"] = dict(headers)
        return transport
    if network == "grpc":
        service = (proxy.get("grpc-opts") or {}).get("grpc-service-name") or ""
        transport = {"type": "grpc"}
        if service:
            transport["service_name"] = service
        return transport
    if network == "http":
        options = proxy.get("http-opts") or {}
        transport = {"type": "http"}
        if options.get("method"):
            transport["method"] = options["method"]
        paths = options.get("path") or ["/"]
        transport["path"] = paths[0] if len(paths) == 1 else list(paths)
        hosts = (options.get("headers") or {}).get("Host") or []
        if hosts:
            transport["host"] = list(hosts)
        return transport
    return None


def _attach_transport(outbound: dict, proxy: dict) -> None:
    transport = _transport(proxy)
    if transport:
        outbound["transport"] = transport


def _vless(proxy: dict, name: str) -> dict:
    outbound = _base("vless", proxy, name)
    outbound["uuid"] = _client_uuid(proxy["uuid"])
    if proxy.get("flow"):
        outbound["flow"] = proxy["flow"]
    if proxy.get("tls"):
        tls = _tls_block(proxy)
        reality = proxy.get("reality-opts")
        if reality:
            block = {"enabled": True, "public_key": reality["public-key"]}
            if reality.get("short-id"):
                block["short_id"] = reality["short-id"]
            tls["reality"] = block
        outbound["tls"] = tls
    _attach_transport(outbound, proxy)
    return outbound


def _vmess(proxy: dict, name: str) -> dict:
    outbound = _base("vmess", proxy, name)
    outbound["uuid"] = _client_uuid(proxy["uuid"])
    if proxy.get("alterId"):
        outbound["alter_id"] = int(proxy["alterId"])
    security = proxy.get("cipher")
    if security and security != "auto":
        outbound["security"] = security
    if proxy.get("tls"):
        outbound["tls"] = _tls_block(proxy)
    _attach_transport(outbound, proxy)
    return outbound


def _trojan(proxy: dict, name: str) -> dict:
    outbound = _base("trojan", proxy, name)
    outbound["password"] = proxy["password"]
    outbound["tls"] = _tls_block(proxy)
    _attach_transport(outbound, proxy)
    return outbound


def _shadowsocks(proxy: dict, name: str) -> dict:
    outbound = _base("shadowsocks", proxy, name)
    outbound["method"] = proxy["cipher"]
    outbound["password"] = proxy["password"]
    plugin = proxy.get("plugin")
    options = proxy.get("plugin-opts") or {}
    if plugin == "obfs":
        outbound["plugin"] = "obfs-local"
        outbound["plugin_opts"] = _plugin_string("obfs-local", {
            "obfs": options.get("mode"), "obfs-host": options.get("host"),
        })
    elif plugin == "v2ray-plugin":
        raw = {
            "mode": "websocket", "host": options.get("host"),
            "path": options.get("path"), "mux": "1" if options.get("mux") else "0",
        }
        if options.get("tls"):
            raw["tls"] = None
        outbound["plugin"] = "v2ray-plugin"
        outbound["plugin_opts"] = _plugin_string("v2ray-plugin", raw)
    return outbound


def _hysteria2(proxy: dict, name: str) -> dict:
    outbound = {
        "type": "hysteria2", "tag": name,
        "server": proxy["server"], "password": proxy["password"],
    }
    ports = proxy.get("ports")
    if ports:
        # sing-box uses colon ranges and conflicts with server_port.
        outbound["server_ports"] = [
            item.replace("-", ":", 1) for item in ports.split(",")
        ]
    else:
        outbound["server_port"] = proxy["port"]
    if proxy.get("obfs") == "salamander":
        outbound["obfs"] = {"type": "salamander", "password": proxy.get("obfs-password", "")}
    for key, field in (("up", "up_mbps"), ("down", "down_mbps")):
        value = proxy.get(key)
        match = re.match(r"\s*(\d+(?:\.\d+)?)", str(value)) if value else None
        if match and int(float(match.group(1))) > 0:
            outbound[field] = int(float(match.group(1)))
    outbound["tls"] = _tls_block(proxy)
    return outbound


def _tuic(proxy: dict, name: str) -> dict:
    outbound = _base("tuic", proxy, name)
    outbound["uuid"] = _client_uuid(proxy["uuid"])
    outbound["password"] = proxy["password"]
    if proxy.get("congestion-controller"):
        outbound["congestion_control"] = proxy["congestion-controller"]
    if proxy.get("udp-relay-mode"):
        outbound["udp_relay_mode"] = proxy["udp-relay-mode"]
    tls = _tls_block(proxy)
    if proxy.get("disable-sni"):
        tls["disable_sni"] = True
    outbound["tls"] = tls
    return outbound


def _anytls(proxy: dict, name: str) -> dict:
    outbound = _base("anytls", proxy, name)
    outbound["password"] = proxy["password"]
    outbound["tls"] = _tls_block(proxy)
    return outbound


def _wireguard(proxy: dict, name: str) -> dict:
    address = []
    if proxy.get("ip"):
        address.append(f"{proxy['ip']}/32")
    if proxy.get("ipv6"):
        address.append(f"{proxy['ipv6']}/128")
    allowed = ["0.0.0.0/0"] if proxy.get("ip") else []
    if proxy.get("ipv6"):
        allowed.append("::/0")
    if not allowed:
        allowed = ["0.0.0.0/0", "::/0"]
    peer = {
        "address": proxy["server"],
        "port": proxy["port"],
        "public_key": proxy["public-key"],
        "allowed_ips": allowed,
    }
    if proxy.get("pre-shared-key"):
        peer["pre_shared_key"] = proxy["pre-shared-key"]
    if proxy.get("reserved"):
        peer["reserved"] = list(proxy["reserved"])
    endpoint = {
        "type": "wireguard", "tag": name,
        "address": address, "private_key": proxy["private-key"],
        "peers": [peer],
    }
    if proxy.get("mtu"):
        endpoint["mtu"] = int(proxy["mtu"])
    return endpoint


def _ssh(proxy: dict, name: str) -> dict:
    outbound = _base("ssh", proxy, name)
    outbound["user"] = proxy["username"]
    if proxy.get("password"):
        outbound["password"] = proxy["password"]
    return outbound


def _http(proxy: dict, name: str) -> dict:
    outbound = _base("http", proxy, name)
    if proxy.get("username"):
        outbound["username"] = proxy["username"]
    if proxy.get("password"):
        outbound["password"] = proxy["password"]
    if proxy.get("tls"):
        tls = {"enabled": True}
        if proxy.get("sni"):
            tls["server_name"] = proxy["sni"]
        if proxy.get("skip-cert-verify"):
            tls["insecure"] = True
        outbound["tls"] = tls
    return outbound


def _socks(proxy: dict, name: str) -> dict:
    outbound = _base("socks", proxy, name)
    outbound["version"] = "5"
    if proxy.get("username"):
        outbound["username"] = proxy["username"]
    if proxy.get("password"):
        outbound["password"] = proxy["password"]
    return outbound


def _build_outbound(node: dict, name: str) -> tuple[dict, bool]:
    """Return (entry, is_endpoint) for one node; endpoints are WireGuard."""
    protocol = node["protocol"]
    if protocol in _SING_BOX_UNSUPPORTED:
        raise FormatError(
            f"{protocol} nodes cannot be exported to sing-box; use the Clash subscription."
        )
    proxy = node["clash"]
    if protocol == "hysteria2" and proxy.get("fingerprint"):
        raise FormatError(
            "Hysteria2 pinSHA256 certificate pinning cannot be expressed in sing-box; "
            "use the Clash subscription."
        )
    if protocol == "trojan-go" and proxy.get("ss-opts"):
        raise FormatError(
            "Trojan-Go SS encryption cannot be expressed in sing-box; use the Clash subscription."
        )
    if protocol == "vless":
        return _vless(proxy, name), False
    if protocol == "vmess":
        return _vmess(proxy, name), False
    if protocol in ("trojan", "trojan-go"):
        return _trojan(proxy, name), False
    if protocol == "ss":
        return _shadowsocks(proxy, name), False
    if protocol == "hysteria2":
        return _hysteria2(proxy, name), False
    if protocol == "tuic":
        return _tuic(proxy, name), False
    if protocol == "anytls":
        return _anytls(proxy, name), False
    if protocol == "wireguard":
        return _wireguard(proxy, name), True
    if protocol == "ssh":
        return _ssh(proxy, name), False
    if protocol == "http":
        return _http(proxy, name), False
    return _socks(proxy, name), False


def _route_rules(rules: list | None) -> tuple[list, list]:
    """Convert stored rules into (route rules, rule set definitions)."""
    if rules is None:
        return [], []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise RuleError(f"规则数量必须在 {MAX_RULES} 条以内。")
    entries = []
    rule_sets: dict[str, dict] = {}
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict) or not rule.get("enabled", True):
            continue
        try:
            normalized = validate_rule(rule)
        except RuleError as error:
            raise RuleError(f"第 {index} 条规则无效：{error}") from None
        kind, value, action = normalized["type"], normalized["value"], normalized["action"]
        entry: dict = {}
        if action == "REJECT":
            entry["action"] = "reject"
        else:
            entry["action"] = "route"
            entry["outbound"] = action
        if kind == "DOMAIN":
            entry["domain"] = [value]
        elif kind == "DOMAIN-SUFFIX":
            entry["domain_suffix"] = [value]
        elif kind == "DOMAIN-KEYWORD":
            entry["domain_keyword"] = [value]
        elif kind in ("IP-CIDR", "IP-CIDR6"):
            entry["ip_cidr"] = [value]
        elif kind == "PROCESS-NAME":
            entry["process_name"] = [value]
        elif kind == "GEOIP":
            tag = f"geoip-{value.lower()}"
            rule_sets.setdefault(tag, {
                "type": "remote", "tag": tag, "format": "binary",
                "url": _RULE_SET_BASE["geoip"].format(name=value.lower()),
                "download_detour": "PROXY",
            })
            entry["rule_set"] = [tag]
        else:  # GEOSITE
            tag = f"geosite-{value.lower()}"
            rule_sets.setdefault(tag, {
                "type": "remote", "tag": tag, "format": "binary",
                "url": _RULE_SET_BASE["geosite"].format(name=value.lower()),
                "download_detour": "PROXY",
            })
            entry["rule_set"] = [tag]
        entries.append(entry)
    return entries, list(rule_sets.values())


def export_singbox(nodes: list[dict], test_url: str = "https://www.gstatic.com/generate_204",
                   rules: list | None = None) -> str:
    """Produce a complete, loopback-only sing-box JSON profile.

    The caller owns enabled/group filtering. ``rules`` are the user-managed
    subscription rules converted in display order; the fixed ``PROXY``
    fallback always matches last. DNS resolution for proxy servers uses the
    local resolver to avoid routing loops; everything else resolves through
    the proxy. GEOIP/GEOSITE rules download their binary rule sets on the
    client side. No TUN, LAN access, or system proxy is configured.
    """
    _check_test_url(test_url)
    parsed = _export_nodes(nodes)
    if not parsed:
        raise FormatError("At least one node is required for the sing-box export.")
    names = _unique_names(parsed)
    outbounds = []
    endpoints = []
    member_names = []
    for index, (node, name) in enumerate(zip(parsed, names), 1):
        try:
            entry, is_endpoint = _build_outbound(node, name)
        except FormatError as error:
            raise FormatError(f"Node {index}: {error}") from None
        (endpoints if is_endpoint else outbounds).append(entry)
        member_names.append(name)
    outbounds.extend([
        {"type": "selector", "tag": "PROXY", "outbounds": ["AUTO", *member_names, "DIRECT"],
         "default": "AUTO"},
        {"type": "urltest", "tag": "AUTO", "outbounds": member_names,
         "url": test_url, "interval": "5m", "tolerance": 50},
        {"type": "direct", "tag": "DIRECT"},
    ])
    rule_entries, rule_sets = _route_rules(rules)
    route = {
        "rules": [{"action": "sniff"}, *rule_entries],
        "final": "PROXY",
        "auto_detect_interface": True,
        "default_domain_resolver": {"server": "local"},
    }
    if rule_sets:
        route["rule_set"] = rule_sets
    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "PROXY"},
                {"type": "udp", "tag": "local", "server": "223.5.5.5", "detour": "DIRECT"},
            ],
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
        ],
    }
    if endpoints:
        config["endpoints"] = endpoints
    config["outbounds"] = outbounds
    config["route"] = route
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"
