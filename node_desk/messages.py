from __future__ import annotations

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


def test_message(message: str | None) -> str:
    value = message or ""
    if value in _MESSAGES:
        return _MESSAGES[value]
    if "This core cannot distinguish authentication from target failures." in value:
        return "TCP 端口可达，但代理请求失败；无法区分认证失败与测试地址访问失败。"
    return value


def local_stamp(value: object, fallback: str = "-") -> str:
    """Best-effort display format for a stored ISO timestamp."""
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).astimezone().strftime("%m-%d %H:%M:%S")
    except (ValueError, AttributeError, TypeError):
        return fallback
