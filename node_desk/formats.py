"""Offline, deliberately strict share-link adapters for Mihomo and v2rayN.

The URI is the persisted source of truth; names are editable metadata. This is
format conversion, not a proxy implementation. See docs/protocol-research.md
for the supported subset and the upstream compatibility boundaries.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import shlex
import uuid
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import yaml

from .rules import render_rules

__all__ = ["FormatError", "parse_uri", "parse_batch", "export_clash", "export_v2ray"]

MAX_URI_LENGTH = 16_384
MAX_BATCH_LENGTH = 4 * 1024 * 1024
MAX_BATCH_LINES = 10_000
MAX_NAME_LENGTH = 256
_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
_FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized", "chrome120", "firefox120", "safari16",
    "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle",
    "chrome_pq", "chrome_pq_psk",
}
_QUERY_ALIASES = {
    "serverName": "sni",
    "insecure": "allowInsecure",
    "skip-cert-verify": "allowInsecure",
}
_STREAM_OPTIONS = {
    "security", "type", "headerType", "host", "path", "serviceName",
    "authority", "mode", "sni", "alpn", "fp", "allowInsecure",
    "spx", "pqv", "ech", "pcs", "vcn",
}
_VLESS_OPTIONS = _STREAM_OPTIONS | {"encryption", "flow", "pbk", "sid"}
_VMESS_FIELDS = {
    "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host",
    "path", "tls", "sni", "alpn", "fp", "insecure", "allowInsecure",
    "vcn", "pcs",
}
_RESERVED_NAMES = {
    "PROXY", "AUTO", "GLOBAL", "DIRECT", "REJECT", "REJECT-DROP",
    "PASS", "COMPATIBLE",
}


class FormatError(ValueError):
    """Invalid input or a conversion that would lose protocol requirements."""


def _text(value: object, label: str, *, empty: bool = False,
          limit: int = MAX_URI_LENGTH) -> str:
    if not isinstance(value, str):
        raise FormatError(f"{label} must be text.")
    if len(value) > limit:
        raise FormatError(f"{label} is too long.")
    if _CONTROLS.search(value):
        raise FormatError(f"{label} contains control characters or invalid Unicode.")
    if not empty and not value:
        raise FormatError(f"{label} is required.")
    return value


def _decode(value: str, label: str) -> str:
    if _BAD_ESCAPE.search(value):
        raise FormatError(f"{label} contains an invalid percent escape.")
    try:
        return _text(unquote(value, encoding="utf-8", errors="strict"), label, empty=True)
    except UnicodeError:
        raise FormatError(f"{label} is not valid UTF-8.") from None


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise FormatError(f"{label} must be an integer.")
    token = str(value)
    if not re.fullmatch(r"[0-9]{1,10}", token):
        raise FormatError(f"{label} must be an unsigned decimal integer.")
    number = int(token)
    if not minimum <= number <= maximum:
        raise FormatError(f"{label} must be between {minimum} and {maximum}.")
    return number


def _boolean(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in {"0", "1", "false", "true"}:
        return value.lower() in {"1", "true"}
    raise FormatError(f"{label} must be true, false, 1, or 0.")


def _b64_bytes(value: str, label: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
        raise FormatError(f"{label} is not valid Base64.")
    core = value.rstrip("=")
    if len(core) % 4 == 1 or ("=" in value and len(value) % 4):
        raise FormatError(f"{label} has invalid Base64 padding.")
    try:
        return base64.b64decode(core + "=" * (-len(core) % 4),
                                altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise FormatError(f"{label} is not valid Base64.") from None


def _b64_text(value: str, label: str) -> str:
    try:
        return _b64_bytes(value, label).decode("utf-8", errors="strict")
    except UnicodeError:
        raise FormatError(f"{label} is not valid UTF-8.") from None


def _b64_encode(value: str, *, urlsafe: bool = False) -> str:
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encoder(value.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=") if urlsafe else encoded


def _hostname(value: object) -> str:
    host = _text(value, "Server", limit=253)
    if "%" in host or any(char.isspace() for char in host):
        raise FormatError("Server must be a hostname or an unscoped IP address.")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        if ":" in host or re.fullmatch(r"[0-9.]+", host):
            raise FormatError("Server contains an invalid IP address.") from None
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise FormatError("Server contains an invalid IDN hostname.") from None
    if len(host) > 253 or not all(
        _DNS_LABEL.fullmatch(label) for label in host.removesuffix(".").split(".")
    ):
        raise FormatError("Server contains an invalid hostname.")
    return host


def _authority(server: str, port: int) -> str:
    return f"[{server}]:{port}" if ":" in server else f"{server}:{port}"


def _split_uri(uri: str):
    try:
        parts = urlsplit(uri)
        server = parts.hostname
    except ValueError:
        raise FormatError("Malformed URI authority or bracketed IPv6 address.") from None
    if parts.path not in ("", "/"):
        raise FormatError("Put transport paths in the path query option, not after the port.")
    if parts.netloc.count("@") > 1:
        raise FormatError("Authentication delimiters must be percent-encoded.")
    auth, separator, endpoint = parts.netloc.rpartition("@")
    if not separator:
        auth, endpoint = None, parts.netloc
    if endpoint.startswith("["):
        if not re.fullmatch(r"\[[^\[\]]+\]:[0-9]+", endpoint):
            raise FormatError("IPv6 must be bracketed and followed by an explicit port.")
    elif endpoint.count(":") != 1:
        raise FormatError("An explicit port is required; IPv6 addresses must be bracketed.")
    port = _integer(endpoint.rpartition(":")[2], "Port", 1, 65535)
    return parts, auth, _hostname(server), port


def _query(query: str, allowed: set[str], *, aliases: bool = False) -> dict[str, str]:
    if not query:
        return {}
    if _BAD_ESCAPE.search(query):
        raise FormatError("Query contains an invalid percent escape.")
    try:
        # Share URLs use RFC3986 escaping, not HTML form '+' -> space rules.
        pairs = parse_qsl(query.replace("+", "%2B"), keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=64)
    except (ValueError, UnicodeError):
        raise FormatError("Malformed query or too many query options.") from None
    result = {}
    for key, value in pairs:
        if aliases:
            key = _QUERY_ALIASES.get(key, key)
        if key not in allowed:
            raise FormatError("Unsupported query option; refusing lossy conversion.")
        if key in result:
            raise FormatError("Repeated or conflicting query option.")
        result[key] = _text(value, "Query value", empty=True)
    return result


def _display_name(value: str, fallback: str) -> str:
    name = _text(value, "Name", empty=True, limit=MAX_NAME_LENGTH).strip()
    return name or fallback[:MAX_NAME_LENGTH]


def _link(scheme: str, auth: str | None, server: str, port: int,
          query: dict[str, str], name: str, *, slash: bool = False) -> str:
    userinfo = quote(auth, safe="") + "@" if auth is not None else ""
    suffix = "?" + urlencode(sorted(query.items()), quote_via=quote) if query else ""
    path = "/" if slash else ""
    return f"{scheme}://{userinfo}{_authority(server, port)}{path}{suffix}#{quote(name, safe='')}"


def _record(protocol: str, name: str, server: str, port: int,
            uri: str, proxy: dict) -> dict:
    if len(uri) > MAX_URI_LENGTH:
        raise FormatError("Canonical share URI is too long.")
    return {
        "name": name, "protocol": protocol, "server": server, "port": port,
        "uri": uri, "clash": {"name": name, **proxy},
    }


def _uuid(value: object) -> str:
    token = _text(value, "UUID")
    if not _UUID.fullmatch(token):
        raise FormatError("UUID must use the 8-4-4-4-12 hexadecimal form.")
    return str(uuid.UUID(token))


def _http_host(value: str) -> str:
    _text(value, "HTTP host")
    if any(char in value for char in "/\\?#") or value.endswith(":"):
        raise FormatError("Invalid HTTP host or authority.")
    try:
        parts = urlsplit("//" + value)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise FormatError("Invalid HTTP host or authority.") from None
    if parts.username is not None or parts.path or parts.query or parts.fragment:
        raise FormatError("Invalid HTTP host or authority.")
    _hostname(host)
    if port is not None:
        _integer(port, "HTTP host port", 1, 65535)
    return value


def _ws_path(value: str) -> str:
    _text(value, "WebSocket path")
    if not value.startswith("/") or value.startswith("//") or _BAD_ESCAPE.search(value):
        raise FormatError("WebSocket path must be an escaped absolute path.")
    if any(char.isspace() for char in value):
        raise FormatError("WebSocket path contains unescaped whitespace.")
    try:
        parts = urlsplit(value)
        pairs = parse_qsl(parts.query, keep_blank_values=True, errors="strict",
                          max_num_fields=64)
    except (ValueError, UnicodeError):
        raise FormatError("Invalid WebSocket path query.") from None
    if "#" in value:
        raise FormatError("WebSocket path cannot contain a fragment.")
    early_data = [item for key, item in pairs if key == "ed"]
    if len(early_data) > 1:
        raise FormatError("Repeated WebSocket early-data option.")
    if early_data:
        _integer(early_data[0], "WebSocket early data", 0, 65535)
    # Both cores recognize ?ed= in this path. Preserve it, including other queries.
    return value


def _stream(proxy: dict, options: dict[str, str], protocol: str) -> None:
    for key in ("security", "type", "sni", "alpn", "fp"):
        if key in options and not options[key]:
            raise FormatError(f"The {key} option cannot be empty.")
    network = options.get("type", "tcp")
    if network == "raw":
        network = "tcp"
    if network not in {"tcp", "ws", "grpc"}:
        raise FormatError("Unsupported transport; only TCP, WebSocket, and gRPC are supported.")
    options["type"] = network
    proxy["network"] = network
    security = options.get("security", "tls" if protocol == "trojan" else "none")
    allowed_security = {"none", "tls", "reality"} if protocol == "vless" else {"none", "tls"}
    if security not in allowed_security or (protocol == "trojan" and security != "tls"):
        raise FormatError("Unsupported security mode; Trojan requires TLS.")
    options["security"] = security
    tls = security != "none"
    if protocol != "trojan":
        proxy["tls"] = tls

    for key in ("spx", "pqv", "ech", "pcs", "vcn"):
        if options.get(key):
            raise FormatError(f"Nonempty {key} cannot be faithfully converted to Mihomo.")
    if options.get("headerType", "none") not in ("", "none"):
        raise FormatError("TCP/header obfuscation is not supported.")
    insecure = _boolean(options.get("allowInsecure", "0"), "Certificate verification flag")
    if "allowInsecure" in options:
        options["allowInsecure"] = "1" if insecure else "0"
    if not tls and (insecure or any(options.get(key) for key in ("sni", "alpn", "fp"))):
        raise FormatError("TLS options require TLS; refusing to ignore them.")
    if security != "reality" and any(key in options for key in ("pbk", "sid")):
        raise FormatError("Reality options require security=reality.")

    if tls:
        sni = _hostname(options.get("sni", proxy["server"]))
        fp = options.get("fp", "chrome")
        if fp not in _FINGERPRINTS:
            raise FormatError("Unsupported TLS client fingerprint.")
        options["sni"], options["fp"] = sni, fp
        proxy["sni" if protocol == "trojan" else "servername"] = sni
        proxy["client-fingerprint"] = fp
        proxy["skip-cert-verify"] = insecure
        if "alpn" in options:
            alpn = options["alpn"].split(",")
            if any(not item or len(item.encode("utf-8")) > 255
                   or not item.isascii() or any(char.isspace() for char in item)
                   for item in alpn):
                raise FormatError("ALPN must be a comma-separated list of nonempty ASCII tokens.")
            if len(set(alpn)) != len(alpn):
                raise FormatError("Repeated ALPN token.")
            fixed_alpn = ["h2"] if network == "grpc" else (
                ["http/1.1"] if network == "ws" and protocol != "trojan" else None
            )
            if fixed_alpn is not None and alpn != fixed_alpn:
                raise FormatError("Mihomo fixes ALPN for this transport; requested ALPN would be lost.")
            proxy["alpn"] = alpn

    if security == "reality":
        if network == "ws":
            raise FormatError("Mihomo WebSocket does not preserve Reality security.")
        public_key = options.get("pbk", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
            raise FormatError("Reality pbk must be a 32-byte unpadded Base64URL key.")
        if len(_b64_bytes(public_key, "Reality public key")) != 32:
            raise FormatError("Invalid Reality public key length.")
        short_id = options.get("sid", "")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
            raise FormatError("Reality sid must be even-length hex, at most 16 characters.")
        if insecure:
            raise FormatError("Reality cannot disable certificate authentication.")
        options["sid"] = short_id.lower()
        proxy["reality-opts"] = {"public-key": public_key, "short-id": short_id.lower()}

    flow = options.get("flow", "")
    if flow:
        if flow != "xtls-rprx-vision" or network != "tcp" or not tls:
            raise FormatError("Only xtls-rprx-vision over TLS/Reality TCP is supported.")
        proxy["flow"] = flow
    if network == "tcp":
        if any(options.get(key) for key in ("host", "path", "serviceName", "authority", "mode")):
            raise FormatError("Transport options cannot be applied to plain TCP.")
    elif network == "ws":
        if any(options.get(key) for key in ("serviceName", "authority", "mode")):
            raise FormatError("gRPC options cannot be applied to WebSocket.")
        ws = {"path": _ws_path(options.get("path", "/"))}
        if options.get("host"):
            ws["headers"] = {"Host": _http_host(options["host"])}
        elif not tls and protocol == "vless":
            # Mihomo otherwise invents a random Host for cleartext VLESS WS.
            ws["headers"] = {"Host": _authority(proxy["server"], proxy["port"])}
        proxy["ws-opts"] = ws
    else:
        if any(options.get(key) for key in ("host", "path")):
            raise FormatError("Use serviceName/authority, not path/host, for gRPC.")
        if options.get("mode", "gun") != "gun":
            raise FormatError("Only gRPC gun mode can be converted to Mihomo.")
        authority = options.get("authority", "")
        default_authority = options.get("sni") or _authority(proxy["server"], proxy["port"])
        if authority and _http_host(authority) != default_authority:
            raise FormatError("Mihomo cannot set gRPC authority independently of SNI.")
        proxy["grpc-opts"] = {"grpc-service-name": options.get("serviceName", "")}


def _parse_standard(uri: str, protocol: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    if auth is None:
        raise FormatError("Authentication is required.")
    password = _decode(auth, "Authentication")
    options = _query(parts.query, _VLESS_OPTIONS if protocol == "vless"
                     else _STREAM_OPTIONS, aliases=True)
    proxy = {"type": protocol, "server": server, "port": port, "udp": True}
    if protocol == "vless":
        password = _uuid(password)
        if options.get("encryption", "none") != "none":
            raise FormatError("Only VLESS encryption=none is supported by this adapter.")
        proxy["uuid"] = password
    else:
        proxy["password"] = _text(password, "Trojan password")
    _stream(proxy, options, protocol)
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    canonical = _link(protocol, password, server, port, options, name)
    return _record(protocol, name, server, port, canonical, proxy)


def _json_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FormatError("VMess JSON contains duplicate fields.")
        result[key] = value
    return result


def _json_constant(_value: str):
    raise FormatError("VMess JSON contains a non-finite number.")


def _vmess_json(payload: str) -> dict:
    try:
        data = json.loads(payload, object_pairs_hook=_json_object, parse_constant=_json_constant)
    except (ValueError, RecursionError):
        raise FormatError("VMess payload must be valid JSON without duplicate fields.") from None
    if not isinstance(data, dict):
        raise FormatError("VMess payload must be a JSON object.")
    if set(data) - _VMESS_FIELDS:
        raise FormatError("Unsupported VMess JSON field; refusing lossy conversion.")
    return data


def _vmess_link(data: dict) -> str:
    return "vmess://" + _b64_encode(json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ))


def _parse_vmess(uri: str) -> dict:
    body, _, fragment = uri.partition("://")[2].partition("#")
    if "@" in body or "?" in body:
        raise FormatError("VMess requires the v2rayN Base64 JSON share format.")
    data = _vmess_json(_b64_text(body, "VMess payload"))
    for key in _VMESS_FIELDS - {"v", "add", "port", "id", "aid"}:
        if key in data and data[key] is None:
            del data[key]
    if data.get("v", "2") not in ("2", 2):
        raise FormatError("Only VMess share JSON version 2 is supported.")
    server = _hostname(data.get("add"))
    port = _integer(data.get("port"), "Port", 1, 65535)
    identifier = _uuid(data.get("id"))
    alter_id = _integer(data.get("aid", 0), "VMess alterId", 0, 65535)
    for key in _VMESS_FIELDS - {"port", "aid", "v", "insecure", "allowInsecure"}:
        if key in data:
            _text(data[key], "VMess field", empty=True)
    cipher = data.get("scy") or "auto"
    if cipher not in _VMESS_CIPHERS:
        raise FormatError("Unsupported VMess cipher.")
    network = data.get("net") or "tcp"
    options = {"type": network, "security": data.get("tls") or "none"}
    for key in ("sni", "alpn", "fp", "vcn", "pcs"):
        if data.get(key):
            options[key] = data[key]
    if "insecure" in data and "allowInsecure" in data:
        raise FormatError("Repeated VMess certificate verification flag.")
    insecure_value = data.get("insecure", data.get("allowInsecure", "0"))
    if insecure_value == "":
        insecure_value = "0"
    insecure = _boolean(insecure_value, "VMess certificate verification flag")
    options["allowInsecure"] = "1" if insecure else "0"
    if network == "grpc":
        options.update({
            "serviceName": data.get("path", ""), "authority": data.get("host", ""),
            "mode": "gun" if data.get("type", "") in ("", "none") else data["type"],
        })
    else:
        options.update({
            "path": data.get("path", "") if network not in ("ws",) else data.get("path") or "/",
            "host": data.get("host", ""), "headerType": data.get("type") or "none",
        })
    proxy = {"type": "vmess", "server": server, "port": port, "uuid": identifier,
             "alterId": alter_id, "cipher": cipher, "udp": True}
    _stream(proxy, options, "vmess")
    name = _display_name(_decode(fragment, "Name") if fragment else data.get("ps", ""),
                         _authority(server, port))
    canonical_data = {
        "v": "2", "ps": name, "add": server, "port": port, "id": identifier,
        "aid": alter_id, "scy": cipher, "net": options["type"],
        "type": options.get("mode", "none"),
        "host": data.get("host", ""), "path": data.get("path", ""),
        "tls": "tls" if proxy["tls"] else "",
        "insecure": "1" if insecure else "0",
    }
    for key in ("sni", "alpn", "fp", "vcn", "pcs"):
        if key in options or key in data:
            canonical_data[key] = options.get(key, data.get(key, ""))
    return _record("vmess", name, server, port, _vmess_link(canonical_data), proxy)


def _credentials(auth: str, label: str) -> tuple[str, str]:
    username, separator, password = auth.partition(":")
    if not separator:
        raise FormatError(f"{label} must contain a username/method and password separator.")
    return username, password


def _parse_socks(uri: str) -> dict:
    body, _, fragment = uri.partition("://")[2].partition("#")
    legacy = "@" not in body and ":" not in body
    if legacy:
        decoded = _b64_text(body, "SOCKS payload")
        auth, separator, endpoint = decoded.rpartition("@")
        if not separator:
            raise FormatError("SOCKS payload requires credentials and an endpoint.")
        _text(auth, "SOCKS authentication", empty=True)
        parts, _, server, port = _split_uri("socks://" + endpoint)
        if parts.fragment:
            raise FormatError("SOCKS legacy payload cannot contain an inner fragment.")
    else:
        parts, raw_auth, server, port = _split_uri(uri)
        auth = None
        if raw_auth is not None:
            if ":" in raw_auth:
                user, password = raw_auth.split(":", 1)
                user, password = _decode(user, "SOCKS username"), _decode(password, "SOCKS password")
                if ":" in user:
                    raise FormatError("A colon in a SOCKS username cannot be shared with v2rayN.")
                auth = user + ":" + password
            else:
                auth = _b64_text(_decode(raw_auth, "SOCKS authentication"), "SOCKS authentication")
    _query(parts.query, set())
    proxy = {"type": "socks5", "server": server, "port": port, "udp": True}
    canonical_auth = None
    if auth is not None:
        username, password = _credentials(auth, "SOCKS authentication")
        _text(username, "SOCKS username", empty=True)
        _text(password, "SOCKS password", empty=True)
        if username or password:
            if not 1 <= len(username.encode("utf-8")) <= 255 or not 1 <= len(password.encode("utf-8")) <= 255:
                raise FormatError("SOCKS username and password must each be 1-255 UTF-8 bytes.")
            proxy.update(username=username, password=password)
            canonical_auth = _b64_encode(username + ":" + password, urlsafe=True)
    name = _display_name(_decode(fragment, "Name"), _authority(server, port))
    canonical = _link("socks", canonical_auth, server, port, {}, name)
    return _record("socks5", name, server, port, canonical, proxy)


def _plugin_tokens(value: str) -> tuple[str, dict[str, str | None]]:
    # SIP003 uses escaped semicolons, not shell quoting. shlex supplies the
    # escape-aware tokenizer; quotes remain literal characters.
    lexer = shlex.shlex(value, posix=True)
    lexer.whitespace = ";"
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.quotes = ""
    try:
        tokens = list(lexer)
    except ValueError:
        raise FormatError("Malformed Shadowsocks plugin escaping.") from None
    if not tokens:
        raise FormatError("Shadowsocks plugin name is required.")
    options = {}
    for token in tokens[1:]:
        key, separator, item = token.partition("=")
        if not key or key in options:
            raise FormatError("Repeated or malformed Shadowsocks plugin option.")
        options[key] = item if separator else None
    return tokens[0], options


def _plugin_string(name: str, options: dict[str, str | None]) -> str:
    def escape(value: str) -> str:
        return "".join("\\" + char if char in "\\;=,:" else char for char in value)
    return ";".join([name] + [
        key if value is None else key + "=" + escape(value)
        for key, value in sorted(options.items())
    ])


def _ss_plugin(value: str) -> tuple[dict, str]:
    name, options = _plugin_tokens(value)
    if name in {"obfs-local", "simple-obfs"}:
        if set(options) - {"obfs", "obfs-host"}:
            raise FormatError("Unsupported obfs plugin option; refusing lossy conversion.")
        mode = options.get("obfs")
        if mode not in {"http", "tls"}:
            raise FormatError("Shadowsocks obfs mode must be http or tls.")
        host = options.get("obfs-host")
        if not host:
            raise FormatError("An explicit obfs-host is required for portable plugin conversion.")
        _http_host(host)
        return ({"plugin": "obfs", "plugin-opts": {"mode": mode, "host": host}},
                _plugin_string("obfs-local", options))
    if name != "v2ray-plugin":
        raise FormatError("Unsupported Shadowsocks plugin; refusing to remove it.")
    if set(options) - {"mode", "host", "path", "tls", "mux"}:
        raise FormatError("Unsupported v2ray-plugin option; refusing lossy conversion.")
    if options.get("mode", "websocket") != "websocket":
        raise FormatError("Only v2ray-plugin WebSocket mode is supported.")
    if "tls" in options and options["tls"] is not None:
        raise FormatError("v2ray-plugin tls must be a bare flag.")
    host = _http_host(options.get("host", "cloudfront.com"))
    path = _ws_path(options.get("path", "/"))
    mux = _integer(options.get("mux", "1"), "v2ray-plugin mux", 0, 1)
    options.update(mode="websocket", host=host, path=path, mux=str(mux))
    plugin = {"mode": "websocket", "host": host, "path": path,
              "tls": "tls" in options, "mux": bool(mux)}
    return {"plugin": "v2ray-plugin", "plugin-opts": plugin}, _plugin_string(name, options)


def _parse_ss(uri: str) -> dict:
    body, _, fragment = uri.partition("://")[2].partition("#")
    if "@" not in body:
        decoded = _b64_text(body, "Shadowsocks payload")
        auth, separator, endpoint = decoded.rpartition("@")
        if not separator:
            raise FormatError("Shadowsocks payload requires authentication and an endpoint.")
        parts, _, server, port = _split_uri("ss://" + endpoint)
        cipher, password = _credentials(auth, "Shadowsocks authentication")
        if parts.fragment:
            raise FormatError("Shadowsocks legacy payload cannot contain an inner fragment.")
        if cipher.startswith("2022-"):
            raise FormatError("SIP002 requires percent-encoded, not Base64, SS2022 userinfo.")
    else:
        parts, raw_auth, server, port = _split_uri(uri)
        if raw_auth is None:
            raise FormatError("Shadowsocks authentication is required.")
        if ":" in raw_auth:
            raw_cipher, raw_password = _credentials(raw_auth, "Shadowsocks authentication")
            cipher, password = _decode(raw_cipher, "Cipher"), _decode(raw_password, "Password")
        else:
            auth = _b64_text(_decode(raw_auth, "Shadowsocks authentication"), "Shadowsocks authentication")
            cipher, password = _credentials(auth, "Shadowsocks authentication")
            if cipher.startswith("2022-"):
                raise FormatError("SIP002 requires percent-encoded, not Base64, SS2022 userinfo.")
    if cipher not in _SS_CIPHERS:
        raise FormatError("Unsupported Shadowsocks cipher; only AEAD/AEAD-2022 are supported.")
    _text(password, "Shadowsocks password")
    if cipher.startswith("2022-"):
        expected = 16 if cipher == "2022-blake3-aes-128-gcm" else 32
        keys = password.split(":")
        if len(keys) > 1 and cipher == "2022-blake3-chacha20-poly1305":
            raise FormatError("SS2022 identity key chains require an AES cipher.")
        normalized_keys = []
        for key in keys:
            decoded_key = _b64_bytes(key, "SS2022 key")
            if len(decoded_key) != expected:
                raise FormatError("SS2022 key has the wrong size for its cipher.")
            normalized_keys.append(base64.b64encode(decoded_key).decode("ascii"))
        password = ":".join(normalized_keys)
    query = _query(parts.query, {"plugin"})
    proxy = {"type": "ss", "server": server, "port": port,
             "cipher": cipher, "password": password, "udp": True}
    if "plugin" in query:
        plugin, query["plugin"] = _ss_plugin(query["plugin"])
        proxy.update(plugin)
    name = _display_name(_decode(fragment, "Name"), _authority(server, port))
    auth = cipher + ":" + password
    if cipher.startswith("2022-"):
        # SIP002 requires a literal delimiter between separately escaped fields.
        canonical = _link("ss", None, server, port, query, name, slash=bool(query))
        userinfo = quote(cipher, safe="") + ":" + quote(password, safe="") + "@"
        canonical = "ss://" + userinfo + canonical.removeprefix("ss://")
    else:
        canonical = _link("ss", _b64_encode(auth, urlsafe=True), server, port, query,
                          name, slash=bool(query))
    return _record("ss", name, server, port, canonical, proxy)


def parse_uri(uri: str) -> dict:
    """Parse one share URI; reject malformed or lossy security/transport options.

    Returns exactly name, protocol, server, port, uri and clash. No input,
    credential, or decoded payload is interpolated into exception messages.
    """
    uri = _text(uri, "Share URI").strip()
    if not uri:
        raise FormatError("Share URI is required.")
    if any(char.isspace() for char in uri.partition("#")[0]):
        raise FormatError("Share URI contains unescaped whitespace.")
    if _BAD_ESCAPE.search(uri):
        raise FormatError("Share URI contains an invalid percent escape.")
    scheme, separator, _ = uri.partition("://")
    scheme = scheme.lower()
    if not separator:
        raise FormatError("Expected a supported share URI.")
    if scheme in {"vless", "trojan"}:
        return _parse_standard(uri, scheme)
    if scheme == "vmess":
        return _parse_vmess(uri)
    if scheme in {"socks", "socks5"}:
        return _parse_socks(uri)
    if scheme == "ss":
        return _parse_ss(uri)
    raise FormatError("Unsupported protocol; expected VLESS, VMess, SOCKS5, Trojan, or Shadowsocks.")


def _identity(node: dict) -> str:
    return json.dumps({key: value for key, value in node["clash"].items() if key != "name"},
                      sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def parse_batch(text: str) -> dict:
    """Parse lines or one Base64 envelope, reporting decoded, one-based lines."""
    result = {"nodes": [], "errors": [], "duplicates": 0}
    if not isinstance(text, str) or len(text) > MAX_BATCH_LENGTH:
        result["errors"].append({"line": 1, "message": "Subscription must be text within the size limit."})
        return result
    text = text.removeprefix("\ufeff")
    if not text.strip():
        return result
    compact = re.sub(r"[ \t\r\n]", "", text)
    if "://" not in text and re.fullmatch(r"[A-Za-z0-9+/_=-]+", compact):
        try:
            decoded = _b64_text(compact, "Subscription").removeprefix("\ufeff")
        except FormatError as error:
            if len(text.strip().splitlines()) == 1:
                result["errors"].append({"line": 1, "message": str(error)})
                return result
        else:
            if not decoded.strip():
                return result
            if "://" in decoded:
                text = decoded
    lines = text.split("\n")
    if len(lines) > MAX_BATCH_LINES:
        result["errors"].append({"line": 1, "message": "Subscription contains too many lines."})
        return result
    seen = set()
    for number, line in enumerate(lines, 1):
        line = line.removesuffix("\r").strip(" \t")
        if not line or line.startswith("#"):
            continue
        try:
            node = parse_uri(line)
            identity = _identity(node)
        except FormatError as error:
            result["errors"].append({"line": number, "message": str(error)})
            continue
        if identity in seen:
            result["duplicates"] += 1
        else:
            seen.add(identity)
            result["nodes"].append(node)
    return result


def _export_nodes(nodes: list[dict]) -> list[dict]:
    if not isinstance(nodes, list) or len(nodes) > MAX_BATCH_LINES:
        raise FormatError("Nodes must be a list within the node count limit.")
    result = []
    for index, node in enumerate(nodes, 1):
        if not isinstance(node, dict):
            raise FormatError(f"Node {index} must be a record.")
        try:
            parsed = parse_uri(node.get("uri"))
            name = _display_name(node.get("name", parsed["name"]), parsed["name"])
            if any(key in node and node[key] != parsed[key] for key in ("protocol", "server", "port")):
                raise FormatError("Stored endpoint fields disagree with the share URI; re-import the node.")
            if "clash" in node and (
                not isinstance(node["clash"], dict) or _identity(node) != _identity(parsed)
            ):
                raise FormatError("Stored clash settings disagree with the share URI; re-import the node.")
        except FormatError as error:
            raise FormatError(f"Node {index}: {error}") from None
        except (TypeError, ValueError, RecursionError):
            raise FormatError(f"Node {index} has invalid or inconsistent settings; re-import it.") from None
        parsed["name"] = name
        parsed["clash"]["name"] = name
        result.append(parsed)
    return result


def _unique_names(nodes: list[dict]) -> list[str]:
    originals = {node["name"] for node in nodes}
    used = set(_RESERVED_NAMES)
    counters = {}
    result = []
    for node in nodes:
        base = node["name"]
        candidate = base
        if candidate in used:
            counter = counters.get(base, 2)
            while True:
                suffix = f" ({counter})"
                candidate = base[:MAX_NAME_LENGTH - len(suffix)] + suffix
                counter += 1
                if candidate not in used and candidate not in originals:
                    break
            counters[base] = counter
        used.add(candidate)
        result.append(candidate)
    return result


def export_clash(nodes: list[dict], test_url: str = "https://www.gstatic.com/generate_204",
                 rules: list[dict] | None = None) -> str:
    """Produce a complete, loopback-only Mihomo profile without mutating nodes.

    The caller owns enabled/group filtering. ``rules`` are the user-managed
    subscription rules rendered in display order; the fixed ``MATCH,PROXY``
    fallback always comes last. An empty profile rejects traffic.
    No controller, system proxy, TUN, external providers, or LAN access is enabled.
    """
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
    parsed = _export_nodes(nodes)
    names = _unique_names(parsed)
    for node, name in zip(parsed, names):
        node["clash"]["name"] = name
    rule_lines = render_rules(rules)
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "info",
        "proxies": [node["clash"] for node in parsed],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", *names, "DIRECT"]},
            {"name": "AUTO", "type": "url-test", "proxies": names or ["REJECT"],
             "url": test_url, "interval": 300, "tolerance": 50},
        ],
        "rules": [*rule_lines, "MATCH,PROXY"],
    }
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120)


def _check_v2ray_compatibility(node: dict) -> None:
    proxy = node["clash"]
    if proxy.get("skip-cert-verify"):
        raise FormatError("Current Xray/v2rayN cannot preserve allowInsecure; use verified TLS.")
    plugin = proxy.get("plugin")
    if plugin == "obfs" and proxy["plugin-opts"]["mode"] != "http":
        raise FormatError("v2rayN does not preserve the obfs-local TLS plugin; use Clash export.")
    if plugin == "v2ray-plugin" and proxy["plugin-opts"]["mux"]:
        raise FormatError("v2rayN cannot preserve v2ray-plugin mux; use Clash export.")
    if plugin:
        for value in proxy["plugin-opts"].values():
            if isinstance(value, str) and any(char in value for char in (";", "\\", ":")):
                raise FormatError("v2rayN cannot preserve this plugin escaping; use Clash export.")


def export_v2ray(nodes: list[dict]) -> str:
    """Return Base64 UTF-8 share URIs with current display names, including socks://."""
    links = []
    for index, node in enumerate(_export_nodes(nodes), 1):
        try:
            _check_v2ray_compatibility(node)
        except FormatError as error:
            raise FormatError(f"Node {index}: {error}") from None
        if node["protocol"] == "vmess":
            data = _vmess_json(_b64_text(node["uri"].partition("://")[2], "VMess payload"))
            data["ps"] = node["name"]
            link = _vmess_link(data)
        else:
            link = node["uri"].partition("#")[0] + "#" + quote(node["name"], safe="")
        if len(link) > MAX_URI_LENGTH:
            raise FormatError(f"Node {index}: renamed share URI is too long.")
        links.append(link)
    return _b64_encode("\n".join(links))
