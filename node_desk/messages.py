from __future__ import annotations

import re
from datetime import datetime

_MESSAGES = {
    "TCP connection succeeded only; proxy handshake and HTTP access were not tested.":
        "TCP 端口可达，尚未验证代理握手和网页访问。",
    "Proxy HTTP HEAD returned the expected status (204).":
        "代理请求成功，测试地址返回 HTTP 204。",
    "TCP connection refused; the endpoint is unreachable.":
        "连接被拒绝，节点端口不可达。",
    "TCP endpoint is unreachable.": "节点端口不可达。",
    "TCP endpoint hostname could not be resolved.": "无法解析节点服务器域名。",
    "TCP connection or hostname resolution timed out.": "TCP 连接或域名解析超时。",
    "Private controller authentication failed.": "临时测试内核认证失败。",
    "Proxy test timed out; handshake and target access were not verified.":
        "代理测试超时，尚未验证握手和目标访问。",
    "Proxy authentication was rejected.": "代理认证被拒绝，请检查节点凭据。",
    "Proxy or target TLS verification/handshake failed.": "节点或测试地址的 TLS 验证、握手失败。",
    "Proxy endpoint or target is unreachable.": "节点服务器或测试地址不可达。",
    "Proxy handshake or target request failed.": "代理握手或目标请求失败。",
    "Private controller returned an invalid or unsupported response.":
        "临时测试内核返回了不支持的响应。",
    "Node has an invalid server or port.": "节点服务器或端口无效。",
    "Node has an invalid server hostname.": "节点服务器域名无效。",
    "No usable Mihomo proxy definition is available.": "节点缺少可用的 Mihomo 配置。",
    "This proxy protocol is not supported by the isolated tester.": "测试内核暂不支持此协议。",
    "Node protocol does not match its proxy definition.": "节点协议与其配置不一致。",
    "Node endpoint does not match its proxy definition.": "节点地址与其配置不一致。",
    "Proxy chaining and interface overrides are not supported in isolated tests.":
        "独立测试不支持代理链和指定网络接口。",
    "This proxy plugin is not supported in isolated tests.": "独立测试不支持此代理插件。",
    "Proxy definition is invalid or too large.": "节点配置无效或过大。",
    "Private Mihomo process exited.": "临时测试内核已退出。",
    "Private controller response was too large.": "测试内核响应过大。",
    "Private controller returned malformed data.": "测试内核响应格式无效。",
    "Private controller request failed or timed out.": "测试内核请求失败或超时。",
    "Private core rejected the temporary configuration or exited during startup.":
        "测试内核无法加载此批节点配置，或在启动时退出。",
    "The isolated tester requires the bundled Mihomo v1.19.33.":
        "请使用随程序提供的 Mihomo v1.19.33 内核。",
    "Private Mihomo controller did not become ready in time.": "临时测试内核启动超时。",
    "TCP testing is unsupported for this UDP-based protocol or transport.":
        "此节点使用 UDP 协议，不能通过 TCP 端口测试判断。",
    "Private core did not report a valid proxy delay.": "内核未返回有效代理延迟。",
    "Core did not verify the target HTTP status; refusing an unverified result.":
        "内核未验证 HTTP 状态，不能确认节点可用。",
    "Target did not return the expected HTTP status (204); redirects are not accepted.":
        "测试地址未返回 HTTP 204，或返回了重定向。",
    "Core returned inconsistent target HTTP status verification.":
        "内核的 HTTP 状态验证结果不一致。",
    "Test cancelled.": "测试已取消。",
    "Test timed out.": "测试超时。",
    "Test could not be completed.": "测试未能完成。",
    "Bundled Mihomo core is unavailable; proxy testing was not performed.":
        "找不到内置 Mihomo 内核，未执行实际代理测试。",
    "Private Mihomo could not be started safely.": "无法安全启动独立测试内核。",
    "Private core exposed unexpected additional listeners.": "测试内核开启了非预期端口，已终止测试。",
}


def display_test_message(message: str | None) -> str:
    value = message or ""
    if value in _MESSAGES:
        return _MESSAGES[value]
    if "This core cannot distinguish authentication from target failures." in value:
        return "TCP 端口可达，但代理请求失败；无法区分认证失败与测试地址访问失败。"
    return value


# 导入/导出时 FormatError 的中文提示。formats.py 保持英文（测试与日志依赖），
# 界面展示前经 format_message() 翻译；未收录的消息原样返回。
_FORMAT_MESSAGES = {
    "A colon in a SOCKS username cannot be shared with v2rayN.": "SOCKS 用户名含有冒号，无法以 v2rayN 格式分享。",
    "ALPN must be a comma-separated list of nonempty ASCII tokens.": "ALPN 必须是用逗号分隔的非空 ASCII 值。",
    "An explicit obfs-host is required for portable plugin conversion.": "obfs 插件需要明确填写 obfs-host 才能可靠转换。",
    "An explicit port is required; IPv6 addresses must be bracketed.": "必须写明端口；IPv6 地址需用方括号括起。",
    "Authentication delimiters must be percent-encoded.": "认证信息中的分隔符必须进行百分号编码。",
    "Authentication is required.": "缺少认证信息（UUID 或密码）。",
    "Canonical share URI is too long.": "规范化后的分享链接过长。",
    "Current Xray/v2rayN cannot preserve allowInsecure; use verified TLS.": "当前 Xray/v2rayN 不支持 allowInsecure，请使用可验证的 TLS。",
    "Expected a supported share URI.": "不是可识别的分享链接。",
    "gRPC options cannot be applied to HTTP header obfuscation.": "HTTP 伪装不能携带 gRPC 参数。",
    "gRPC options cannot be applied to WebSocket.": "WebSocket 不能携带 gRPC 参数。",
    "HTTP header hosts must be a comma-separated list of nonempty values.": "HTTP 伪装的 host 必须是用逗号分隔的非空值。",
    "HTTP header obfuscation only applies to the TCP transport.": "HTTP 伪装只能用于 TCP 传输。",
    "HTTP header paths must be comma-separated escaped absolute paths.": "HTTP 伪装的 path 必须是用逗号分隔、以 / 开头的已编码路径。",
    "IPv6 must be bracketed and followed by an explicit port.": "IPv6 地址需用方括号括起并写明端口。",
    "Invalid HTTP host or authority.": "HTTP host 无效。",
    "Invalid Reality public key length.": "Reality 公钥长度无效。",
    "Invalid WebSocket path query.": "WebSocket 路径中的查询参数无效。",
    "Malformed Shadowsocks plugin escaping.": "Shadowsocks 插件参数的转义格式错误。",
    "Malformed URI authority or bracketed IPv6 address.": "链接的服务器地址部分格式错误（或 IPv6 括号不正确）。",
    "Malformed query or too many query options.": "查询参数格式错误或参数过多。",
    "Mihomo Trojan has no HTTP header obfuscation.": "Mihomo 的 Trojan 不支持 HTTP 伪装。",
    "Mihomo WebSocket does not preserve Reality security.": "Mihomo 的 WebSocket 不支持 Reality。",
    "Mihomo cannot set gRPC authority independently of SNI.": "Mihomo 无法单独设置与 SNI 不同的 gRPC authority。",
    "Mihomo fixes ALPN for this transport; requested ALPN would be lost.": "Mihomo 对此传输方式固定使用 ALPN，链接指定的 ALPN 会丢失。",
    "Nodes must be a list within the node count limit.": "节点数量超出上限。",
    "Only HTTP header obfuscation can be converted to Mihomo.": "伪装头类型（headerType）仅支持 http。",
    "Only VLESS encryption=none is supported by this adapter.": "VLESS 仅支持 encryption=none。",
    "Only VMess share JSON version 2 is supported.": "仅支持 VMess 分享格式版本 2。",
    "Only gRPC gun mode can be converted to Mihomo.": "gRPC 仅支持 gun 模式。",
    "Only v2ray-plugin WebSocket mode is supported.": "v2ray-plugin 仅支持 WebSocket 模式。",
    "Only xtls-rprx-vision over TLS/Reality TCP is supported.": "flow 仅支持 TLS/Reality TCP 下的 xtls-rprx-vision。",
    "Put transport paths in the path query option, not after the port.": "传输路径应写在 path 参数里，而不是端口后面。",
    "Query contains an invalid percent escape.": "查询参数中有无效的百分号编码。",
    "Reality cannot disable certificate authentication.": "Reality 不能关闭证书验证。",
    "Reality options require security=reality.": "pbk/sid 参数需要 security=reality。",
    "Reality pbk must be a 32-byte unpadded Base64URL key.": "Reality 公钥 pbk 必须是 32 字节的无填充 Base64URL。",
    "Reality sid must be even-length hex, at most 16 characters.": "Reality sid 必须是偶数长度的十六进制，最多 16 位。",
    "Repeated ALPN token.": "ALPN 中有重复值。",
    "Repeated VMess certificate verification flag.": "VMess 中重复出现了证书验证标志。",
    "Repeated WebSocket early-data option.": "WebSocket early-data 参数重复。",
    "Repeated or conflicting query option.": "查询参数重复或互相冲突。",
    "Repeated or malformed Shadowsocks plugin option.": "Shadowsocks 插件参数重复或格式错误。",
    "SIP002 requires percent-encoded, not Base64, SS2022 userinfo.": "SS2022 的 SIP002 链接需使用百分号编码（而非 Base64）的认证信息。",
    "SOCKS legacy payload cannot contain an inner fragment.": "旧式 SOCKS 链接内部不能包含 # 片段。",
    "SOCKS payload requires credentials and an endpoint.": "SOCKS 链接缺少认证信息或服务器地址。",
    "SOCKS username and password must each be 1-255 UTF-8 bytes.": "SOCKS 用户名和密码各需为 1-255 个 UTF-8 字节。",
    "SS2022 identity key chains require an AES cipher.": "SS2022 多重身份密钥需要 AES 加密方式。",
    "SS2022 key has the wrong size for its cipher.": "SS2022 密钥长度与加密方式不匹配。",
    "Server contains an invalid IDN hostname.": "服务器域名无效（IDN）。",
    "Server contains an invalid IP address.": "服务器 IP 地址无效。",
    "Server contains an invalid hostname.": "服务器域名无效。",
    "Server must be a hostname or an unscoped IP address.": "服务器必须是域名或不带区域标识的 IP 地址。",
    "Shadowsocks authentication is required.": "Shadowsocks 缺少认证信息。",
    "Shadowsocks legacy payload cannot contain an inner fragment.": "旧式 Shadowsocks 链接内部不能包含 # 片段。",
    "Shadowsocks obfs mode must be http or tls.": "Shadowsocks obfs 模式只能是 http 或 tls。",
    "Shadowsocks payload requires authentication and an endpoint.": "Shadowsocks 链接缺少认证信息或服务器地址。",
    "Shadowsocks plugin name is required.": "Shadowsocks 插件名称不能为空。",
    "Share URI contains an invalid percent escape.": "链接中有无效的百分号编码。",
    "Share URI contains unescaped whitespace.": "链接中含有未编码的空白字符。",
    "Share URI is required.": "链接不能为空。",
    "Stored clash settings disagree with the share URI; re-import the node.": "已保存的配置与链接不一致，请重新导入该节点。",
    "Stored endpoint fields disagree with the share URI; re-import the node.": "已保存的地址信息与链接不一致，请重新导入该节点。",
    "Subscription contains too many lines.": "订阅内容行数过多。",
    "Subscription must be text within the size limit.": "订阅内容必须是文本且不超过大小限制。",
    "TLS options require TLS; refusing to ignore them.": "sni/alpn/fp 等参数需要开启 TLS。",
    "Test URL must be a valid HTTP(S) URL without credentials or fragment.": "测试地址必须是不含凭据和片段的有效 HTTP(S) 网址。",
    "Transport options cannot be applied to plain TCP.": "普通 TCP 不能携带 host/path 等传输参数。",
    "UUID must use the 8-4-4-4-12 hexadecimal form.": "UUID 必须是 8-4-4-4-12 的十六进制格式。",
    "Unsupported Shadowsocks cipher; only AEAD/AEAD-2022 are supported.": "不支持的 Shadowsocks 加密方式，仅支持 AEAD / AEAD-2022。",
    "Unsupported Shadowsocks plugin; refusing to remove it.": "不支持的 Shadowsocks 插件，不会擅自去掉它。",
    "Unsupported TLS client fingerprint.": "不支持的 TLS 客户端指纹（fp）。",
    "Unsupported VMess JSON field; refusing lossy conversion.": "VMess 中含有不支持的字段，为避免丢失配置已拒绝。",
    "Unsupported VMess cipher.": "不支持的 VMess 加密方式。",
    "Unsupported obfs plugin option; refusing lossy conversion.": "obfs 插件含有不支持的参数，为避免丢失配置已拒绝。",
    "Unsupported protocol; expected VLESS, VMess, SOCKS5, Trojan, or Shadowsocks.": "不支持的协议，仅支持 VLESS、VMess、SOCKS5、Trojan、Shadowsocks。",
    "Unsupported query option; refusing lossy conversion.": "链接含有不支持的参数，为避免丢失配置已拒绝。",
    "Unsupported security mode; Trojan requires TLS.": "不支持的 security 值（Trojan 必须使用 TLS）。",
    "Unsupported transport; only TCP, WebSocket, and gRPC are supported.": "不支持的传输方式，仅支持 TCP、WebSocket、gRPC。",
    "Unsupported v2ray-plugin option; refusing lossy conversion.": "v2ray-plugin 含有不支持的参数，为避免丢失配置已拒绝。",
    "Use serviceName/authority, not path/host, for gRPC.": "gRPC 请使用 serviceName/authority，而不是 path/host。",
    "VLESS ID must be a UUID or a custom string of at most 30 bytes.": "VLESS ID 必须是 UUID，或不超过 30 字节的自定义字符串。",
    "VMess JSON contains a non-finite number.": "VMess 内容包含无效数字。",
    "VMess JSON contains duplicate fields.": "VMess 内容包含重复字段。",
    "VMess payload must be a JSON object.": "VMess 内容必须是 JSON 对象。",
    "VMess payload must be valid JSON without duplicate fields.": "VMess 内容不是有效的 JSON。",
    "VMess requires the v2rayN Base64 JSON share format.": "VMess 链接必须是 v2rayN 的 Base64 JSON 分享格式。",
    "WebSocket path cannot contain a fragment.": "WebSocket 路径不能包含 # 片段。",
    "WebSocket path contains unescaped whitespace.": "WebSocket 路径含有未编码的空白字符。",
    "WebSocket path must be an escaped absolute path.": "WebSocket 路径必须是以 / 开头并已编码的绝对路径。",
    "renamed share URI is too long.": "重命名后的分享链接过长。",
    "v2ray-plugin tls must be a bare flag.": "v2ray-plugin 的 tls 参数不应带值。",
    "v2rayN cannot preserve this plugin escaping; use Clash export.": "v2rayN 无法保留此插件参数的转义，请使用 Clash 订阅。",
    "v2rayN cannot preserve v2ray-plugin mux; use Clash export.": "v2rayN 无法保留 v2ray-plugin 的 mux 设置，请使用 Clash 订阅。",
    "v2rayN does not preserve the obfs-local TLS plugin; use Clash export.": "v2rayN 不支持 obfs-local 的 TLS 模式，请使用 Clash 订阅。",
    "xtls-rprx-vision cannot be combined with HTTP header obfuscation.": "xtls-rprx-vision 不能与 HTTP 伪装同时使用。",
    "Unsupported share URI scheme.": "不支持的链接类型。支持：VLESS、VMess、Trojan、Trojan-Go、Shadowsocks、SSR、SOCKS5、HTTP、Hysteria2、Hysteria、TUIC、AnyTLS、WireGuard、Mieru、SSH。",
    "Hysteria2 obfs must be salamander with an obfs-password.": "Hysteria2 的 obfs 只能是 salamander，且必须带 obfs-password。",
    "Hysteria2 pinSHA256 must be a SHA-256 hex fingerprint.": "Hysteria2 的 pinSHA256 必须是 SHA-256 十六进制指纹。",
    "Bandwidth must be a number optionally followed by bps units.": "带宽必须是数字（可带 Mbps 等单位）。",
    "Port hopping ranges must be comma-separated ports or ranges.": "端口跳跃范围必须是用逗号分隔的端口或区间（如 20000-30000）。",
    "Hysteria v1 links carry credentials in the auth query option.": "Hysteria v1 链接的认证信息应放在 auth 参数里，而不是 @ 之前。",
    "Hysteria protocol must be udp, wechat-video, or faketcp.": "Hysteria 的 protocol 只能是 udp、wechat-video 或 faketcp。",
    "Hysteria obfs must be xplus with an obfsParam password.": "Hysteria 的 obfs 只能是 xplus，且必须带 obfsParam。",
    "TUIC links must use the v5 uuid:password form.": "TUIC 链接必须是 v5 的 uuid:password 形式。",
    "TUIC congestion control must be cubic, new_reno, or bbr.": "TUIC 拥塞控制只能是 cubic、new_reno 或 bbr。",
    "TUIC UDP relay mode must be native or quic.": "TUIC 的 udp_relay_mode 只能是 native 或 quic。",
    "WireGuard keys must be 32-byte Base64.": "WireGuard 密钥必须是 32 字节的 Base64。",
    "WireGuard links require the private key before @.": "WireGuard 链接需要在 @ 之前写私钥。",
    "WireGuard noise options cannot be converted to Mihomo.": "WireGuard 的 wnoise 等噪声参数无法转换到 Mihomo。",
    "WireGuard address must list one IPv4 and/or one IPv6 interface address.": "WireGuard 的 address 需要一个 IPv4 和/或一个 IPv6 接口地址。",
    "WireGuard reserved must be three comma-separated bytes.": "WireGuard 的 reserved 必须是用逗号分隔的三个字节值。",
    "Mihomo Mieru only supports the TCP transport.": "Mihomo 的 Mieru 目前只支持 TCP 传输。",
    "Mieru multiplexing must be MULTIPLEXING_OFF, LOW, MIDDLE, or HIGH.": "Mieru 的 multiplexing 只能是 MULTIPLEXING_OFF/LOW/MIDDLE/HIGH。",
    "Mieru MTU other than the default 1400 cannot be converted to Mihomo.": "Mihomo 无法设置 Mieru 的 MTU，仅接受默认值 1400。",
    "Trojan-Go plugins cannot be converted to Mihomo.": "Trojan-Go 的 plugin 无法转换到 Mihomo。",
    "Trojan-Go type must be original or ws.": "Trojan-Go 的 type 只能是 original 或 ws。",
    "Trojan-Go encryption must be ss;method;password with an AEAD method.": "Trojan-Go 的 encryption 必须是 ss;加密方式;密码，且加密方式为 AEAD。",
    "SSR payload must be host:port:protocol:method:obfs:password.": "SSR 链接内容必须是 服务器:端口:协议:加密:混淆:密码 的形式。",
    "Unsupported SSR cipher.": "不支持的 SSR 加密方式。",
    "Unsupported SSR protocol.": "不支持的 SSR 协议插件。",
    "Unsupported SSR obfs.": "不支持的 SSR 混淆插件。",
    "HTTP proxy links cannot contain a path; remote subscriptions are not fetched.": "HTTP 代理链接不能带路径；如果这是订阅地址，本程序不抓取远程订阅。",
    "At least one node is required for the sing-box export.": "sing-box 导出至少需要一个节点。",
    "Hysteria2 pinSHA256 certificate pinning cannot be expressed in sing-box; use the Clash subscription.": "sing-box 无法表达 Hysteria2 的 pinSHA256 证书固定，请使用 Clash 订阅。",
    "Trojan-Go SS encryption cannot be expressed in sing-box; use the Clash subscription.": "sing-box 无法表达 Trojan-Go 的 SS 加密，请使用 Clash 订阅。",
}

_FORMAT_LABELS = {
    "Authentication": "认证信息", "Certificate verification flag": "证书验证标志",
    "Cipher": "加密方式", "HTTP host": "HTTP host", "HTTP host port": "HTTP host 端口",
    "Name": "名称", "Password": "密码", "Port": "端口", "Query value": "参数值",
    "Reality public key": "Reality 公钥", "SOCKS authentication": "SOCKS 认证信息",
    "SOCKS password": "SOCKS 密码", "SOCKS payload": "SOCKS 链接内容",
    "SOCKS username": "SOCKS 用户名", "SS2022 key": "SS2022 密钥", "Server": "服务器",
    "Shadowsocks authentication": "Shadowsocks 认证信息",
    "Shadowsocks password": "Shadowsocks 密码", "Shadowsocks payload": "Shadowsocks 链接内容",
    "Share URI": "链接", "Subscription": "订阅内容", "Test URL": "测试地址",
    "Test URL port": "测试地址端口", "Trojan password": "Trojan 密码", "UUID": "UUID",
    "VLESS ID": "VLESS ID", "VMess alterId": "VMess alterId",
    "VMess certificate verification flag": "VMess 证书验证标志", "VMess field": "VMess 字段",
    "VMess payload": "VMess 内容", "WebSocket early data": "WebSocket early data",
    "WebSocket path": "WebSocket 路径",
    "Hysteria2 password": "Hysteria2 密码", "Hysteria upmbps": "Hysteria 上行带宽",
    "Hysteria downmbps": "Hysteria 下行带宽", "TUIC password": "TUIC 密码",
    "AnyTLS password": "AnyTLS 密码", "WireGuard private key": "WireGuard 私钥",
    "WireGuard public key": "WireGuard 公钥", "WireGuard pre-shared key": "WireGuard 预共享密钥",
    "WireGuard MTU": "WireGuard MTU", "Mieru username": "Mieru 用户名",
    "Mieru password": "Mieru 密码", "Mieru MTU": "Mieru MTU", "SSR payload": "SSR 链接内容",
    "SSR password": "SSR 密码", "SSR option": "SSR 参数", "SSH username": "SSH 用户名",
    "SSH password": "SSH 密码", "HTTP proxy username": "HTTP 代理用户名",
    "HTTP proxy password": "HTTP 代理密码", "VMess id": "VMess 的 id",
}

_FORMAT_PATTERNS = (
    (r"(\S+) nodes cannot be shared with v2rayN; use Clash export\.", "v2rayN 不支持 {0} 节点，请使用 Clash 订阅。"),
    (r"(\S+) nodes cannot be exported to sing-box; use the Clash subscription\.", "sing-box 不支持 {0} 节点，请使用 Clash 订阅。"),
    (r"Unsupported query option \(query parameter (\d+)\); refusing lossy conversion\.", "链接含有不支持的参数（? 后第 {0} 个），为避免丢失配置已拒绝。"),
    (r"(.+) and (.+) are both required before @\.", "@ 之前必须同时写 {label} 和 {label2}。"),
    (r"(.+) must be a UUID or a custom string of at most 30 bytes\.", "{label} 必须是 UUID，或不超过 30 字节的自定义字符串。"),
    (r"Node (\d+) must be a record\.", "第 {0} 个节点的记录格式无效。"),
    (r"Node (\d+) has invalid or inconsistent settings; re-import it\.", "第 {0} 个节点的设置无效或不一致，请重新导入。"),
    (r"Nonempty (\S+) cannot be faithfully converted to Mihomo\.", "参数 {0} 无法完整转换到 Mihomo，请去掉后重试。"),
    (r"The (\S+) option cannot be empty\.", "参数 {0} 不能为空。"),
    (r"(.+) contains an invalid percent escape\.", "{label}中有无效的百分号编码。"),
    (r"(.+) contains control characters or invalid Unicode\.", "{label}含有控制字符或无效字符。"),
    (r"(.+) has invalid Base64 padding\.", "{label}的 Base64 填充无效。"),
    (r"(.+) is not valid Base64\.", "{label}不是有效的 Base64。"),
    (r"(.+) is not valid UTF-8\.", "{label}不是有效的 UTF-8。"),
    (r"(.+) is required\.", "缺少{label}。"),
    (r"(.+) is too long\.", "{label}过长。"),
    (r"(.+) must be an integer\.", "{label}必须是整数。"),
    (r"(.+) must be an unsigned decimal integer\.", "{label}必须是非负整数。"),
    (r"(.+) must be between (\d+) and (\d+)\.", "{label}必须在 {1} 到 {2} 之间。"),
    (r"(.+) must be text\.", "{label}必须是文本。"),
    (r"(.+) must be true, false, 1, or 0\.", "{label}只能是 true/false/1/0。"),
    (r"(.+) must contain a username/method and password separator\.", "{label}缺少用户名/加密方式与密码之间的分隔符。"),
)


def format_message(message: str | None) -> str:
    """Translate a FormatError message for display; unknown text is returned as-is."""
    text = (message or "").strip()
    if text in _FORMAT_MESSAGES:
        return _FORMAT_MESSAGES[text]
    nested = re.fullmatch(r"Node (\d+): (.+)", text, re.DOTALL)
    if nested:
        return f"第 {nested[1]} 个节点：{format_message(nested[2])}"
    for pattern, template in _FORMAT_PATTERNS:
        match = re.fullmatch(pattern, text)
        if match:
            groups = match.groups()
            label = _FORMAT_LABELS.get(groups[0], groups[0])
            label2 = _FORMAT_LABELS.get(groups[1], groups[1]) if len(groups) > 1 else ""
            return template.format(*groups, label=label, label2=label2)
    return text


def local_stamp(value: object, fallback: str = "-") -> str:
    """Best-effort display format for a stored ISO timestamp."""
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).astimezone().strftime("%m-%d %H:%M:%S")
    except (ValueError, AttributeError, TypeError):
        return fallback
