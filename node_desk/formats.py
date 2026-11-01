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
_CUSTOM_ID_BYTES = 30  # Xray/Mihomo map non-UUID VLESS IDs of 1-30 bytes to a UUIDv5
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
# Display order for protocol filters; values are the ``protocol`` field of records.
PROTOCOLS = (
    "vless", "vmess", "trojan", "trojan-go", "ss", "ssr", "socks5", "http",
    "hysteria2", "hysteria", "tuic", "anytls", "wireguard", "mieru", "ssh",
)
# Protocols whose canonical links current v2rayN/Xray can import as-is.
_V2RAYN_PROTOCOLS = {
    "vless", "vmess", "trojan", "ss", "ssr", "socks5", "http",
    "hysteria2", "tuic", "anytls", "wireguard",
}
_HYSTERIA2_OPTIONS = {"sni", "insecure", "allowInsecure", "allow_insecure", "obfs",
                      "obfs-password", "pinSHA256", "alpn", "up", "down", "mport", "ports"}
_HYSTERIA_OPTIONS = {"protocol", "auth", "peer", "insecure", "upmbps", "downmbps", "alpn",
                     "obfs", "obfsParam"}
_TUIC_OPTIONS = {"congestion_control", "udp_relay_mode", "alpn", "sni", "allow_insecure",
                 "insecure", "allowInsecure", "disable_sni"}
_ANYTLS_OPTIONS = {"sni", "insecure", "allowInsecure", "alpn", "fp"}
_WIREGUARD_OPTIONS = {"publickey", "presharedkey", "address", "reserved", "mtu",
                      "wnoise", "wnoisecount", "wpayloadsize", "wnoisedelay"}
_MIERU_OPTIONS = {"profile", "mtu", "multiplexing", "transport"}
_MIERU_MULTIPLEXING = {"MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE",
                       "MULTIPLEXING_HIGH"}
_TROJAN_GO_OPTIONS = {"sni", "type", "host", "path", "encryption", "plugin"}
_TROJAN_GO_CIPHERS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}
_SSR_CIPHERS = {
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
    "aes-256-ctr", "rc4-md5", "chacha20", "chacha20-ietf", "xchacha20", "salsa20",
    "none", "dummy",
}
_SSR_PROTOCOLS = {"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
                  "auth_chain_a", "auth_chain_b"}
_SSR_OBFS = {"plain", "http_simple", "http_post", "tls1.2_ticket_auth",
             "tls1.2_ticket_fastauth", "random_head"}
_HTTP_OPTIONS = {"sni", "insecure", "allowInsecure"}
_BANDWIDTH = re.compile(r"[0-9]{1,9}(?: ?[kKmMgGtT]?bps)?")
_PORT_RANGES = re.compile(r"[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*")
_SHA256_PIN = re.compile(r"(?:[0-9a-fA-F]{2}:?){31}[0-9a-fA-F]{2}")
_WG_USERINFO = re.compile(r"^(wireguard://)([^@?#]+)@", re.IGNORECASE)


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
    sources = {}
    for position, (key, value) in enumerate(pairs, 1):
        original = key
        if aliases:
            key = _QUERY_ALIASES.get(key, key)
        if key not in allowed:
            # Identify the position only: option names are untrusted input and
            # are never echoed into error messages.
            raise FormatError(f"Unsupported query option (query parameter {position}); "
                              "refusing lossy conversion.")
        value = _text(value, "Query value", empty=True)
        if key in result:
            # Older v2rayN links spell the same flag twice
            # (insecure=1&allowInsecure=1); identical values are not a conflict.
            if original != sources[key] and value == result[key]:
                continue
            raise FormatError("Repeated or conflicting query option.")
        result[key] = value
        sources[key] = original
    return result


def _display_name(value: str, fallback: str) -> str:
    name = _text(value, "Name", empty=True, limit=MAX_NAME_LENGTH).strip()
    return name or fallback[:MAX_NAME_LENGTH]


def _link(scheme: str, auth: str | None, server: str, port: int,
          query: dict[str, str], name: str, *, slash: bool = False,
          encoded_auth: str | None = None) -> str:
    if encoded_auth is not None:
        userinfo = encoded_auth + "@"
    else:
        userinfo = quote(auth, safe="") + "@" if auth is not None else ""
    suffix = "?" + urlencode(sorted(query.items()), quote_via=quote) if query else ""
    path = "/" if slash else ""
    return f"{scheme}://{userinfo}{_authority(server, port)}{path}{suffix}#{quote(name, safe='')}"


def _userinfo(*fields: str) -> str:
    """Percent-encode each field but keep the ':' separator for uuid:password style links."""
    return ":".join(quote(field, safe="") for field in fields)


def _record(protocol: str, name: str, server: str, port: int,
            uri: str, proxy: dict) -> dict:
    if len(uri) > MAX_URI_LENGTH:
        raise FormatError("Canonical share URI is too long.")
    return {
        "name": name, "protocol": protocol, "server": server, "port": port,
        "uri": uri, "clash": {"name": name, **proxy},
    }


def _canonical_uuid(token: str) -> str | None:
    """Canonical dashed UUID for any standard form, or None when it is not a UUID."""
    try:
        return str(uuid.UUID(token))
    except (ValueError, AttributeError, TypeError):
        return None


def _uuid(value: object) -> str:
    token = _text(value, "UUID")
    canonical = _canonical_uuid(token)
    if canonical is None:
        raise FormatError("UUID must use the 8-4-4-4-12 hexadecimal form.")
    return canonical


def _proxy_id(value: object, label: str) -> str:
    """Return a canonical UUID, or a custom 1-30 byte ID kept verbatim.

    The bundled Mihomo maps non-UUID IDs through ``utils.UUIDMap`` (UUIDv5)
    for both VLESS and VMess (matching Xray issue #158), so the string itself
    is the portable identity. The 30-byte bound follows Xray's custom-ID
    limit so canonical links keep working in v2rayN.
    """
    token = _text(value, label)
    canonical = _canonical_uuid(token)
    if canonical is not None:
        return canonical
    if len(token.encode("utf-8")) > _CUSTOM_ID_BYTES:
        raise FormatError(f"{label} must be a UUID or a custom string of at most 30 bytes.")
    return token


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


def _http_hosts(value: str) -> list[str]:
    """Hosts for TCP HTTP header obfuscation; an empty value keeps Mihomo's default."""
    if not value:
        return []
    hosts = value.split(",")
    if any(not item for item in hosts):
        raise FormatError("HTTP header hosts must be a comma-separated list of nonempty values.")
    return [_http_host(item) for item in hosts]


def _http_paths(value: str) -> list[str]:
    paths = value.split(",") if value else ["/"]
    for item in paths:
        if (not item.startswith("/") or item.startswith("//") or "#" in item
                or _BAD_ESCAPE.search(item) or any(char.isspace() for char in item)):
            raise FormatError("HTTP header paths must be comma-separated escaped absolute paths.")
    return paths


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
    header = options.get("headerType") or "none"
    if header not in ("none", "http"):
        raise FormatError("Only HTTP header obfuscation can be converted to Mihomo.")
    if header == "http":
        if network != "tcp":
            raise FormatError("HTTP header obfuscation only applies to the TCP transport.")
        if protocol == "trojan":
            raise FormatError("Mihomo Trojan has no HTTP header obfuscation.")
    if "headerType" in options:
        options["headerType"] = header
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
        if header == "http":
            raise FormatError("xtls-rprx-vision cannot be combined with HTTP header obfuscation.")
        proxy["flow"] = flow
    if network == "tcp":
        if header == "http":
            if any(options.get(key) for key in ("serviceName", "authority", "mode")):
                raise FormatError("gRPC options cannot be applied to HTTP header obfuscation.")
            # Xray "tcp + http header" is Mihomo's http transport (TLS, if any, stays outside).
            proxy["network"] = "http"
            http_opts = {"method": "GET", "path": _http_paths(options.get("path", ""))}
            hosts = _http_hosts(options.get("host", ""))
            if hosts:
                http_opts["headers"] = {"Host": hosts}
            proxy["http-opts"] = http_opts
        elif any(options.get(key) for key in ("host", "path", "serviceName", "authority", "mode")):
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
        password = _proxy_id(password, "VLESS ID")
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
    identifier = _proxy_id(data.get("id"), "VMess id")
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
        "type": (options.get("mode", "none") if options["type"] == "grpc"
                 else options.get("headerType", "none")),
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


def _compact(options: dict[str, str]) -> dict[str, str]:
    """Drop empty query values so ``key=`` behaves like an absent key."""
    return {key: value for key, value in options.items() if value != ""}


def _flag(options: dict[str, str], *keys: str) -> bool:
    """Read one boolean from alias keys and remove them from the canonical query.

    Older v2rayN releases emitted both ``insecure`` and ``allowInsecure``; equal
    values are accepted, contradictory ones are rejected.
    """
    present = [key for key in keys if key in options]
    if not present:
        return False
    values = [_boolean(options.pop(key), "Certificate verification flag") for key in present]
    if any(value != values[0] for value in values):
        raise FormatError("Repeated or conflicting query option.")
    return values[0]


def _alpn_list(value: str) -> list[str]:
    alpn = value.split(",")
    if any(not item or len(item.encode("utf-8")) > 255 or not item.isascii()
           or any(char.isspace() for char in item) for item in alpn):
        raise FormatError("ALPN must be a comma-separated list of nonempty ASCII tokens.")
    if len(set(alpn)) != len(alpn):
        raise FormatError("Repeated ALPN token.")
    return alpn


def _port_ranges(value: str) -> str:
    if not _PORT_RANGES.fullmatch(value):
        raise FormatError("Port hopping ranges must be comma-separated ports or ranges.")
    for item in value.split(","):
        bounds = [int(part) for part in item.split("-")]
        if any(not 1 <= bound <= 65535 for bound in bounds) or bounds != sorted(bounds):
            raise FormatError("Port hopping ranges must be comma-separated ports or ranges.")
    return value


def _bandwidth(value: str) -> str:
    if not _BANDWIDTH.fullmatch(value):
        raise FormatError("Bandwidth must be a number optionally followed by bps units.")
    return value


def _split_auth(auth: str | None, user_label: str, password_label: str) -> tuple[str, str]:
    if auth is None or ":" not in auth:
        raise FormatError(f"{user_label} and {password_label} are both required before @.")
    raw_user, raw_password = auth.split(":", 1)
    return (_text(_decode(raw_user, user_label), user_label),
            _text(_decode(raw_password, password_label), password_label))


def _parse_hysteria2(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    if auth is None:
        raise FormatError("Authentication is required.")
    password = _text(_decode(auth, "Hysteria2 password"), "Hysteria2 password")
    options = _compact(_query(parts.query, _HYSTERIA2_OPTIONS))
    proxy = {"type": "hysteria2", "server": server, "port": port, "password": password}
    if _flag(options, "insecure", "allowInsecure", "allow_insecure"):
        proxy["skip-cert-verify"] = True
        options["insecure"] = "1"
    if "sni" in options:
        options["sni"] = proxy["sni"] = _hostname(options["sni"])
    if "obfs" in options or "obfs-password" in options:
        if options.get("obfs") != "salamander" or not options.get("obfs-password"):
            raise FormatError("Hysteria2 obfs must be salamander with an obfs-password.")
        proxy["obfs"], proxy["obfs-password"] = "salamander", options["obfs-password"]
    if "pinSHA256" in options:
        if not _SHA256_PIN.fullmatch(options["pinSHA256"]):
            raise FormatError("Hysteria2 pinSHA256 must be a SHA-256 hex fingerprint.")
        proxy["fingerprint"] = options["pinSHA256"]
    if "alpn" in options:
        proxy["alpn"] = _alpn_list(options["alpn"])
    for key in ("up", "down"):
        if key in options:
            proxy[key] = _bandwidth(options[key])
    if "mport" in options and "ports" in options:
        raise FormatError("Repeated or conflicting query option.")
    ports = options.pop("ports", None) or options.pop("mport", None)
    if ports:
        options["mport"] = proxy["ports"] = _port_ranges(ports)
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("hysteria2", name, server, port,
                   _link("hysteria2", password, server, port, options, name), proxy)


def _parse_hysteria(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    if auth is not None:
        raise FormatError("Hysteria v1 links carry credentials in the auth query option.")
    options = _compact(_query(parts.query, _HYSTERIA_OPTIONS))
    protocol = options.get("protocol", "udp")
    if protocol not in {"udp", "wechat-video", "faketcp"}:
        raise FormatError("Hysteria protocol must be udp, wechat-video, or faketcp.")
    proxy = {"type": "hysteria", "server": server, "port": port, "protocol": protocol}
    if "auth" in options:
        proxy["auth-str"] = options["auth"]
    if "peer" in options:
        options["peer"] = proxy["sni"] = _hostname(options["peer"])
    if _flag(options, "insecure"):
        proxy["skip-cert-verify"] = True
        options["insecure"] = "1"
    for key, target in (("upmbps", "up"), ("downmbps", "down")):
        if key in options:
            proxy[target] = str(_integer(options[key], f"Hysteria {key}", 1, 1_000_000))
    if "alpn" in options:
        proxy["alpn"] = _alpn_list(options["alpn"])
    if "obfs" in options or "obfsParam" in options:
        if options.get("obfs", "xplus") != "xplus" or not options.get("obfsParam"):
            raise FormatError("Hysteria obfs must be xplus with an obfsParam password.")
        options["obfs"], proxy["obfs"] = "xplus", options["obfsParam"]
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("hysteria", name, server, port,
                   _link("hysteria", None, server, port, options, name), proxy)


def _parse_tuic(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    if auth is None or ":" not in auth:
        raise FormatError("TUIC links must use the v5 uuid:password form.")
    raw_uuid, raw_password = auth.split(":", 1)
    identifier = _uuid(_decode(raw_uuid, "UUID"))
    password = _text(_decode(raw_password, "TUIC password"), "TUIC password")
    options = _compact(_query(parts.query, _TUIC_OPTIONS))
    proxy = {"type": "tuic", "server": server, "port": port, "uuid": identifier,
             "password": password}
    congestion = options.get("congestion_control", "cubic")
    if congestion not in {"cubic", "new_reno", "bbr"}:
        raise FormatError("TUIC congestion control must be cubic, new_reno, or bbr.")
    relay = options.get("udp_relay_mode", "native")
    if relay not in {"native", "quic"}:
        raise FormatError("TUIC UDP relay mode must be native or quic.")
    proxy["congestion-controller"], proxy["udp-relay-mode"] = congestion, relay
    proxy["alpn"] = _alpn_list(options["alpn"]) if "alpn" in options else ["h3"]
    if "sni" in options:
        options["sni"] = proxy["sni"] = _hostname(options["sni"])
    if _flag(options, "allow_insecure", "insecure", "allowInsecure"):
        proxy["skip-cert-verify"] = True
        options["allow_insecure"] = "1"
    if _flag(options, "disable_sni"):
        proxy["disable-sni"] = True
        options["disable_sni"] = "1"
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    canonical = _link("tuic", None, server, port, options, name,
                      encoded_auth=_userinfo(identifier, password))
    return _record("tuic", name, server, port, canonical, proxy)


def _parse_anytls(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    if auth is None:
        raise FormatError("Authentication is required.")
    password = _text(_decode(auth, "AnyTLS password"), "AnyTLS password")
    options = _compact(_query(parts.query, _ANYTLS_OPTIONS))
    proxy = {"type": "anytls", "server": server, "port": port, "password": password,
             "udp": True}
    if "sni" in options:
        options["sni"] = proxy["sni"] = _hostname(options["sni"])
    if _flag(options, "insecure", "allowInsecure"):
        proxy["skip-cert-verify"] = True
        options["insecure"] = "1"
    if "alpn" in options:
        proxy["alpn"] = _alpn_list(options["alpn"])
    if "fp" in options:
        if options["fp"] not in _FINGERPRINTS:
            raise FormatError("Unsupported TLS client fingerprint.")
        proxy["client-fingerprint"] = options["fp"]
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("anytls", name, server, port,
                   _link("anytls", password, server, port, options, name), proxy)


def _wg_key(value: str, label: str) -> str:
    _text(value, label)
    if len(_b64_bytes(value, label)) != 32:
        raise FormatError("WireGuard keys must be 32-byte Base64.")
    return base64.b64encode(_b64_bytes(value, label)).decode("ascii")


def _parse_wireguard(uri: str) -> dict:
    # v2rayN percent-encodes the Base64 key before "@"; tolerate raw "/" and "+" too.
    match = _WG_USERINFO.match(uri)
    if match:
        uri = match[1] + quote(unquote(match[2]), safe="") + uri[match.end() - 1:]
    parts, auth, server, port = _split_uri(uri)
    if auth is None:
        raise FormatError("WireGuard links require the private key before @.")
    private_key = _wg_key(_decode(auth, "WireGuard private key"), "WireGuard private key")
    options = _compact(_query(parts.query, _WIREGUARD_OPTIONS))
    if any(key in options for key in ("wnoise", "wnoisecount", "wpayloadsize", "wnoisedelay")):
        raise FormatError("WireGuard noise options cannot be converted to Mihomo.")
    public_key = _wg_key(options.get("publickey", ""), "WireGuard public key")
    proxy = {"type": "wireguard", "server": server, "port": port,
             "private-key": private_key, "public-key": public_key, "udp": True}
    options["publickey"] = public_key
    if "presharedkey" in options:
        options["presharedkey"] = proxy["pre-shared-key"] = _wg_key(
            options["presharedkey"], "WireGuard pre-shared key")
    addresses = {}
    for item in options.get("address", "").split(","):
        try:
            interface = ipaddress.ip_interface(item) if item else None
        except ValueError:
            interface = None
        if interface is None or interface.version in addresses:
            raise FormatError("WireGuard address must list one IPv4 and/or one IPv6 interface address.")
        addresses[interface.version] = (
            str(interface.ip) if interface.network.prefixlen == interface.max_prefixlen
            else str(interface)
        )
    if 4 in addresses:
        proxy["ip"] = addresses[4]
    if 6 in addresses:
        proxy["ipv6"] = addresses[6]
    options["address"] = ",".join(addresses[version] for version in sorted(addresses))
    if "reserved" in options:
        fields = options["reserved"].split(",")
        if len(fields) != 3 or not all(re.fullmatch(r"[0-9]{1,3}", field) and int(field) <= 255
                                       for field in fields):
            raise FormatError("WireGuard reserved must be three comma-separated bytes.")
        proxy["reserved"] = [int(field) for field in fields]
        options["reserved"] = ",".join(str(field) for field in proxy["reserved"])
    if "mtu" in options:
        proxy["mtu"] = _integer(options["mtu"], "WireGuard MTU", 576, 65535)
        options["mtu"] = str(proxy["mtu"])
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("wireguard", name, server, port,
                   _link("wireguard", private_key, server, port, options, name), proxy)


def _parse_mieru(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    username, password = _split_auth(auth, "Mieru username", "Mieru password")
    options = _compact(_query(parts.query, _MIERU_OPTIONS))
    if options.get("transport", "TCP").upper() != "TCP":
        raise FormatError("Mihomo Mieru only supports the TCP transport.")
    proxy = {"type": "mieru", "server": server, "port": port, "transport": "TCP",
             "username": username, "password": password}
    canonical = {}
    if "multiplexing" in options:
        if options["multiplexing"] not in _MIERU_MULTIPLEXING:
            raise FormatError("Mieru multiplexing must be MULTIPLEXING_OFF, LOW, MIDDLE, or HIGH.")
        canonical["multiplexing"] = proxy["multiplexing"] = options["multiplexing"]
    if "mtu" in options and _integer(options["mtu"], "Mieru MTU", 576, 65535) != 1400:
        raise FormatError("Mieru MTU other than the default 1400 cannot be converted to Mihomo.")
    fallback = _display_name(options.get("profile", ""), _authority(server, port))
    name = _display_name(_decode(parts.fragment, "Name"), fallback)
    return _record("mieru", name, server, port,
                   _link("mierus", None, server, port, canonical, name,
                         encoded_auth=_userinfo(username, password)), proxy)


def _parse_trojan_go(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    if auth is None:
        raise FormatError("Authentication is required.")
    password = _text(_decode(auth, "Trojan password"), "Trojan password")
    options = _compact(_query(parts.query, _TROJAN_GO_OPTIONS))
    if "plugin" in options:
        raise FormatError("Trojan-Go plugins cannot be converted to Mihomo.")
    kind = options.get("type", "original")
    if kind not in {"original", "ws"}:
        raise FormatError("Trojan-Go type must be original or ws.")
    proxy = {"type": "trojan", "server": server, "port": port, "password": password,
             "udp": True, "skip-cert-verify": False}
    if "sni" in options:
        options["sni"] = proxy["sni"] = _hostname(options["sni"])
    if kind == "ws":
        proxy["network"] = "ws"
        ws = {"path": _ws_path(options.get("path", "/"))}
        if "host" in options:
            ws["headers"] = {"Host": _http_host(options["host"])}
        proxy["ws-opts"] = ws
    elif "host" in options or "path" in options:
        raise FormatError("Transport options cannot be applied to plain TCP.")
    if "encryption" in options:
        fields = options["encryption"].split(";")
        if len(fields) != 3 or fields[0] != "ss" or fields[1].lower() not in _TROJAN_GO_CIPHERS or not fields[2]:
            raise FormatError("Trojan-Go encryption must be ss;method;password with an AEAD method.")
        proxy["ss-opts"] = {"enabled": True, "method": fields[1].lower(), "password": fields[2]}
        options["encryption"] = ";".join(("ss", fields[1].lower(), fields[2]))
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("trojan-go", name, server, port,
                   _link("trojan-go", password, server, port, options, name), proxy)


def _ssr_link(server: str, port: int, protocol: str, cipher: str, obfs: str,
              password: str, obfs_param: str, protocol_param: str, name: str) -> str:
    params = {"remarks": name}
    if obfs_param:
        params["obfsparam"] = obfs_param
    if protocol_param:
        params["protoparam"] = protocol_param
    query = "&".join(f"{key}={_b64_encode(value, urlsafe=True)}" for key, value in sorted(params.items()))
    main = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{_b64_encode(password, urlsafe=True)}"
    return "ssr://" + _b64_encode(main + "/?" + query, urlsafe=True)


def _parse_ssr(uri: str) -> dict:
    body, _, fragment = uri.partition("://")[2].partition("#")
    decoded = _b64_text(body, "SSR payload")
    main, _, params = decoded.partition("/?")
    fields = main.rsplit(":", 5)
    if len(fields) != 6 or not all(fields[:5]):
        raise FormatError("SSR payload must be host:port:protocol:method:obfs:password.")
    host, raw_port, protocol, cipher, obfs, raw_password = fields
    server = _hostname(host.strip("[]"))
    port = _integer(raw_port, "Port", 1, 65535)
    protocol, cipher, obfs = protocol.lower(), cipher.lower(), obfs.lower()
    if cipher not in _SSR_CIPHERS:
        raise FormatError("Unsupported SSR cipher.")
    if protocol not in _SSR_PROTOCOLS:
        raise FormatError("Unsupported SSR protocol.")
    if obfs not in _SSR_OBFS:
        raise FormatError("Unsupported SSR obfs.")
    password = _text(_b64_text(raw_password, "SSR password") if raw_password else "", "SSR password")
    extras = {}
    for position, pair in enumerate(filter(None, params.split("&")), 1):
        key, _, value = pair.partition("=")
        if key not in {"obfsparam", "protoparam", "remarks", "group"}:
            raise FormatError(f"Unsupported query option (query parameter {position}); "
                              "refusing lossy conversion.")
        if key in extras:
            raise FormatError("Repeated or conflicting query option.")
        extras[key] = _b64_text(value, "SSR option") if value else ""
    proxy = {"type": "ssr", "server": server, "port": port, "cipher": cipher,
             "password": password, "obfs": obfs, "protocol": protocol, "udp": True}
    if extras.get("obfsparam"):
        proxy["obfs-param"] = _text(extras["obfsparam"], "SSR option")
    if extras.get("protoparam"):
        proxy["protocol-param"] = _text(extras["protoparam"], "SSR option")
    fallback = _display_name(extras.get("remarks", ""), _authority(server, port))
    name = _display_name(_decode(fragment, "Name"), fallback)
    canonical = _ssr_link(server, port, protocol, cipher, obfs, password,
                          extras.get("obfsparam", ""), extras.get("protoparam", ""), name)
    return _record("ssr", name, server, port, canonical, proxy)


def _parse_ssh(uri: str) -> dict:
    parts, auth, server, port = _split_uri(uri)
    username, password = _split_auth(auth, "SSH username", "SSH password")
    _query(parts.query, set())
    proxy = {"type": "ssh", "server": server, "port": port, "username": username,
             "password": password}
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("ssh", name, server, port,
                   _link("ssh", None, server, port, {}, name,
                         encoded_auth=_userinfo(username, password)), proxy)


def _parse_http(uri: str, scheme: str) -> dict:
    try:
        if urlsplit(uri).path not in ("", "/"):
            raise FormatError("HTTP proxy links cannot contain a path; remote subscriptions are not fetched.")
    except ValueError:
        raise FormatError("Malformed URI authority or bracketed IPv6 address.") from None
    parts, auth, server, port = _split_uri(uri)
    options = _compact(_query(parts.query, _HTTP_OPTIONS))
    tls = scheme == "https"
    proxy = {"type": "http", "server": server, "port": port, "tls": tls}
    encoded_auth = None
    if auth is not None:
        username, password = _split_auth(auth, "HTTP proxy username", "HTTP proxy password")
        proxy.update(username=username, password=password)
        encoded_auth = _userinfo(username, password)
    if tls:
        if "sni" in options:
            options["sni"] = proxy["sni"] = _hostname(options["sni"])
        if _flag(options, "insecure", "allowInsecure"):
            proxy["skip-cert-verify"] = True
            options["insecure"] = "1"
    elif options:
        raise FormatError("TLS options require TLS; refusing to ignore them.")
    name = _display_name(_decode(parts.fragment, "Name"), _authority(server, port))
    return _record("http", name, server, port,
                   _link(scheme, None, server, port, options, name, encoded_auth=encoded_auth), proxy)


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
    if scheme in {"hysteria2", "hy2"}:
        return _parse_hysteria2(uri)
    if scheme == "hysteria":
        return _parse_hysteria(uri)
    if scheme == "tuic":
        return _parse_tuic(uri)
    if scheme == "anytls":
        return _parse_anytls(uri)
    if scheme == "wireguard":
        return _parse_wireguard(uri)
    if scheme == "mierus":
        return _parse_mieru(uri)
    if scheme == "trojan-go":
        return _parse_trojan_go(uri)
    if scheme == "ssr":
        return _parse_ssr(uri)
    if scheme == "ssh":
        return _parse_ssh(uri)
    if scheme in {"http", "https"}:
        return _parse_http(uri, scheme)
    raise FormatError("Unsupported share URI scheme.")


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
    if node["protocol"] not in _V2RAYN_PROTOCOLS:
        raise FormatError(f"{node['protocol']} nodes cannot be shared with v2rayN; use Clash export.")
    # Hysteria2/TUIC/AnyTLS links carry their own insecure flag; the Xray proposal
    # that removed allowInsecure only affects VLESS/VMess/Trojan/HTTP.
    if proxy.get("skip-cert-verify") and node["protocol"] not in {"hysteria2", "tuic", "anytls"}:
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
        elif node["protocol"] == "ssr":
            proxy = node["clash"]
            link = _ssr_link(proxy["server"], proxy["port"], proxy["protocol"], proxy["cipher"],
                             proxy["obfs"], proxy["password"], proxy.get("obfs-param", ""),
                             proxy.get("protocol-param", ""), node["name"])
        else:
            link = node["uri"].partition("#")[0] + "#" + quote(node["name"], safe="")
        if len(link) > MAX_URI_LENGTH:
            raise FormatError(f"Node {index}: renamed share URI is too long.")
        links.append(link)
    return _b64_encode("\n".join(links))
