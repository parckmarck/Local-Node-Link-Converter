"""sing-box configuration export coverage for 1.6.0."""

from __future__ import annotations

import base64
import json
import unittest
from urllib.parse import quote, urlencode

from node_desk.formats import FormatError, parse_uri
from node_desk.rules import RuleError, new_rule
from node_desk.singbox import export_singbox

UUID = "12345678-1234-4234-8234-123456789abc"
PBK = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode("ascii")
WG_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
WG_KEY2 = base64.b64encode(bytes(range(32, 64))).decode("ascii")


def link(scheme, auth, options=None, *, host="example.com", port=443, name="Node"):
    userinfo = auth + "@" if auth is not None else ""
    query = "?" + urlencode(options, quote_via=quote) if options else ""
    return f"{scheme}://{userinfo}{host}:{port}{query}#{quote(name, safe='')}"


def vmess(name="VM", **fields):
    body = {"v": "2", "ps": name, "add": "example.com", "port": "443", "id": UUID,
            "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "host": "",
            "path": "", "tls": ""}
    body.update(fields)
    return "vmess://" + base64.b64encode(json.dumps(body).encode()).decode()


def build(*uris, rules=None, test_url=None):
    nodes = [parse_uri(uri) for uri in uris]
    kwargs = {"rules": rules}
    if test_url is not None:
        kwargs["test_url"] = test_url
    return json.loads(export_singbox(nodes, **kwargs))


def outbound(config, tag):
    for entry in config["outbounds"]:
        if entry["tag"] == tag:
            return entry
    raise AssertionError(f"missing outbound {tag}")


class ProfileShapeTests(unittest.TestCase):
    def test_complete_profile_shape(self):
        config = build("socks5://a:b@127.0.0.1:1080#Alpha", "socks5://c:d@127.0.0.1:1081#Beta")
        self.assertEqual(config["log"]["level"], "info")
        self.assertEqual(config["inbounds"],
                         [{"type": "mixed", "tag": "mixed-in",
                           "listen": "127.0.0.1", "listen_port": 7890}])
        self.assertEqual(config["dns"]["final"], "remote")
        self.assertEqual([server["tag"] for server in config["dns"]["servers"]],
                         ["remote", "local"])
        selector = outbound(config, "PROXY")
        self.assertEqual(selector["outbounds"], ["AUTO", "Alpha", "Beta", "DIRECT"])
        self.assertEqual(selector["default"], "AUTO")
        auto = outbound(config, "AUTO")
        self.assertEqual(auto["type"], "urltest")
        self.assertEqual(auto["outbounds"], ["Alpha", "Beta"])
        self.assertEqual(auto["url"], "https://www.gstatic.com/generate_204")
        self.assertEqual(outbound(config, "DIRECT")["type"], "direct")
        self.assertEqual(config["route"]["rules"], [{"action": "sniff"}])
        self.assertEqual(config["route"]["final"], "PROXY")
        self.assertTrue(config["route"]["auto_detect_interface"])
        self.assertEqual(config["route"]["default_domain_resolver"], {"server": "local"})
        self.assertNotIn("rule_set", config["route"])
        self.assertNotIn("endpoints", config)
        self.assertEqual(outbound(config, "Alpha")["type"], "socks")

    def test_custom_test_url_and_unicode_names(self):
        config = build("socks5://127.0.0.1:1080#节点一", test_url="https://example.org/204")
        self.assertEqual(outbound(config, "AUTO")["url"], "https://example.org/204")
        self.assertEqual(outbound(config, "节点一")["tag"], "节点一")

    def test_reserved_and_duplicate_names_are_unique(self):
        config = build("socks5://127.0.0.1:1080#PROXY", "socks5://127.0.0.1:1081#DIRECT",
                       "socks5://127.0.0.1:1082#PROXY")
        tags = [entry["tag"] for entry in config["outbounds"]]
        self.assertIn("PROXY (2)", tags)
        self.assertIn("DIRECT (2)", tags)
        self.assertEqual(outbound(config, "PROXY")["outbounds"][-1], "DIRECT")

    def test_empty_nodes_and_bad_test_url_are_rejected(self):
        with self.assertRaisesRegex(FormatError, "At least one node is required"):
            export_singbox([])
        with self.assertRaisesRegex(FormatError, "Test URL must be a valid"):
            export_singbox([parse_uri("socks5://127.0.0.1:1080#A")], test_url="ftp://x")
        with self.assertRaises(FormatError):
            export_singbox([parse_uri("socks5://127.0.0.1:1080#A")], test_url="https://u:p@x/y")


class ProtocolMappingTests(unittest.TestCase):
    def test_vless_reality(self):
        uri = link("vless", UUID, {"security": "reality", "sni": "www.microsoft.com",
                                   "fp": "chrome", "pbk": PBK, "sid": "ab12",
                                   "type": "tcp", "flow": "xtls-rprx-vision"}, name="R")
        entry = outbound(build(uri), "R")
        self.assertEqual(entry["uuid"], UUID)
        self.assertEqual(entry["flow"], "xtls-rprx-vision")
        self.assertEqual(entry["tls"]["server_name"], "www.microsoft.com")
        self.assertEqual(entry["tls"]["utls"], {"enabled": True, "fingerprint": "chrome"})
        self.assertEqual(entry["tls"]["reality"],
                         {"enabled": True, "public_key": PBK, "short_id": "ab12"})
        self.assertNotIn("transport", entry)

    def test_vless_custom_id_maps_like_xray(self):
        entry = outbound(build(link("vless", "example", {"type": "tcp"}, name="C")), "C")
        self.assertEqual(entry["uuid"], "feb54431-301b-52bb-a6dd-e1e93e81bb9e")

    def test_vless_ws_early_data(self):
        uri = link("vless", UUID, {"security": "tls", "sni": "x.com", "type": "ws",
                                   "path": "/ws?ed=2048&mode=x", "host": "x.com"})
        transport = outbound(build(uri), "Node")["transport"]
        self.assertEqual(transport["type"], "ws")
        self.assertEqual(transport["path"], "/ws?mode=x")
        self.assertEqual(transport["max_early_data"], 2048)
        self.assertEqual(transport["early_data_header_name"], "Sec-WebSocket-Protocol")
        self.assertEqual(transport["headers"], {"Host": "x.com"})

    def test_vless_grpc_and_http_obfuscation(self):
        grpc = outbound(build(link("vless", UUID, {"security": "tls", "sni": "x.com",
                                                   "type": "grpc", "serviceName": "svc",
                                                   "mode": "gun"})), "Node")
        self.assertEqual(grpc["transport"], {"type": "grpc", "service_name": "svc"})
        obfs = outbound(build(link("vless", UUID, {"type": "tcp", "headerType": "http",
                                                   "host": "bing.com",
                                                   "path": "/,/index"})), "Node")
        self.assertEqual(obfs["transport"],
                         {"type": "http", "method": "GET", "path": ["/", "/index"],
                          "host": ["bing.com"]})
        self.assertNotIn("tls", obfs)

    def test_vmess_fields(self):
        entry = outbound(build(vmess(aid="1", scy="aes-128-gcm", net="ws",
                                     host="x.com", path="/ws", tls="tls", sni="x.com")), "VM")
        self.assertEqual(entry["alter_id"], 1)
        self.assertEqual(entry["security"], "aes-128-gcm")
        self.assertEqual(entry["tls"]["server_name"], "x.com")
        self.assertEqual(entry["transport"]["type"], "ws")
        plain = outbound(build(vmess()), "VM")
        self.assertNotIn("alter_id", plain)
        self.assertNotIn("security", plain)
        self.assertNotIn("tls", plain)

    def test_trojan_and_trojan_go(self):
        entry = outbound(build(link("trojan", "pass", {"sni": "x.com", "type": "ws",
                                                       "path": "/t"}, name="T")), "T")
        self.assertEqual(entry["password"], "pass")
        self.assertEqual(entry["tls"]["server_name"], "x.com")
        self.assertEqual(entry["transport"], {"type": "ws", "path": "/t"})
        go = outbound(build(link("trojan-go", "pass", {"sni": "x.com", "type": "ws",
                                                       "path": "/t"}, name="G")), "G")
        self.assertEqual(go["type"], "trojan")
        with self.assertRaisesRegex(FormatError, "Trojan-Go SS encryption"):
            build(link("trojan-go", "pass", {"sni": "x.com",
                                             "encryption": "ss;aes-128-gcm;secret"}))

    def test_shadowsocks_plugins(self):
        uri = "ss://" + base64.urlsafe_b64encode(
            b"aes-256-gcm:pw").decode().rstrip("=") + "@example.com:8388?" + urlencode(
            {"plugin": "obfs-local;obfs=http;obfs-host=bing.com"}) + "#O"
        entry = outbound(build(uri), "O")
        self.assertEqual(entry["method"], "aes-256-gcm")
        self.assertEqual(entry["plugin"], "obfs-local")
        self.assertEqual(entry["plugin_opts"], "obfs-local;obfs=http;obfs-host=bing.com")
        uri = "ss://" + base64.urlsafe_b64encode(
            b"aes-256-gcm:pw").decode().rstrip("=") + "@example.com:8388?" + urlencode(
            {"plugin": "v2ray-plugin;mode=websocket;host=x.com;path=/ws;tls;mux=0"}) + "#V"
        entry = outbound(build(uri), "V")
        self.assertEqual(entry["plugin"], "v2ray-plugin")
        self.assertEqual(entry["plugin_opts"],
                         "v2ray-plugin;host=x.com;mode=websocket;mux=0;path=/ws;tls")

    def test_hysteria2_port_hopping_obfs_bandwidth(self):
        uri = link("hysteria2", "pass", {"sni": "x.com", "obfs": "salamander",
                                         "obfs-password": "op", "up": "100",
                                         "down": "200", "ports": "20000-30000,31000"},
                   name="H2")
        entry = outbound(build(uri), "H2")
        self.assertEqual(entry["server_ports"], ["20000:30000", "31000"])
        self.assertNotIn("server_port", entry)
        self.assertEqual(entry["obfs"], {"type": "salamander", "password": "op"})
        self.assertEqual(entry["up_mbps"], 100)
        self.assertEqual(entry["down_mbps"], 200)
        plain = outbound(build(link("hysteria2", "pass", {"sni": "x.com"})), "Node")
        self.assertEqual(plain["server_port"], 443)
        self.assertNotIn("server_ports", plain)

    def test_hysteria2_pin_is_rejected(self):
        uri = link("hysteria2", "pass", {"pinSHA256": "ab" * 32})
        with self.assertRaisesRegex(FormatError, "pinSHA256 certificate pinning"):
            build(uri)

    def test_tuic_fields(self):
        uri = link("tuic", f"{UUID}:pass", {"congestion_control": "bbr",
                                            "udp_relay_mode": "quic", "sni": "x.com",
                                            "disable_sni": "1"}, name="T")
        entry = outbound(build(uri), "T")
        self.assertEqual(entry["uuid"], UUID)
        self.assertEqual(entry["password"], "pass")
        self.assertEqual(entry["congestion_control"], "bbr")
        self.assertEqual(entry["udp_relay_mode"], "quic")
        self.assertTrue(entry["tls"]["disable_sni"])
        self.assertEqual(entry["tls"]["alpn"], ["h3"])

    def test_anytls_ssh_http(self):
        entry = outbound(build(link("anytls", "pass", {"sni": "x.com", "insecure": "1"})), "Node")
        self.assertEqual(entry["password"], "pass")
        self.assertTrue(entry["tls"]["insecure"])
        entry = outbound(build("ssh://root:pass@example.com:22#S"), "S")
        self.assertEqual((entry["user"], entry["password"], entry["server_port"]),
                         ("root", "pass", 22))
        entry = outbound(build("https://u:p@example.com:8443?sni=x.com&insecure=1#H"), "H")
        self.assertEqual((entry["username"], entry["password"]), ("u", "p"))
        self.assertEqual(entry["tls"], {"enabled": True, "server_name": "x.com",
                                        "insecure": True})

    def test_wireguard_becomes_endpoint(self):
        uri = link("wireguard", WG_KEY, {"publickey": WG_KEY2, "address": "10.0.0.2/32,fd00::2/128",
                                         "reserved": "1,2,3", "mtu": "1380"}, port=2408, name="WG")
        config = build(uri)
        self.assertNotIn("WG", [entry["tag"] for entry in config["outbounds"]])
        endpoint = next(e for e in config["endpoints"] if e["tag"] == "WG")
        self.assertEqual(endpoint["type"], "wireguard")
        self.assertEqual(endpoint["address"], ["10.0.0.2/32", "fd00::2/128"])
        self.assertEqual(endpoint["private_key"], WG_KEY)
        self.assertEqual(endpoint["mtu"], 1380)
        peer = endpoint["peers"][0]
        self.assertEqual(peer["address"], "example.com")
        self.assertEqual(peer["port"], 2408)
        self.assertEqual(peer["public_key"], WG_KEY2)
        self.assertNotIn("pre_shared_key", peer)
        self.assertEqual(peer["reserved"], [1, 2, 3])
        self.assertEqual(peer["allowed_ips"], ["0.0.0.0/0", "::/0"])
        self.assertIn("WG", outbound(config, "PROXY")["outbounds"])

    def test_unsupported_protocols_are_rejected(self):
        ssr = "ssr://" + base64.urlsafe_b64encode(
            ("example.com:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:"
             + base64.urlsafe_b64encode(b"pass").decode().rstrip("=")).encode()
        ).decode().rstrip("=")
        for uri in ("hysteria://example.com:443?auth=cred#H",
                    "mierus://u:p@example.com:9000#M",
                    ssr):
            with self.subTest(uri=uri):
                with self.assertRaisesRegex(FormatError, "cannot be exported to sing-box"):
                    build(uri)


class RuleConversionTests(unittest.TestCase):
    def rules(self):
        return [
            new_rule("IP-CIDR", "10.0.0.0/8", "DIRECT", no_resolve=True),
            new_rule("GEOSITE", "category-ads-all", "REJECT"),
            new_rule("GEOIP", "CN", "DIRECT"),
            new_rule("DOMAIN-SUFFIX", "t.me", "PROXY"),
            new_rule("DOMAIN-KEYWORD", "google", "AUTO"),
            new_rule("PROCESS-NAME", "Telegram.exe", "PROXY"),
        ]

    def test_rule_conversion_and_rule_sets(self):
        config = build("socks5://127.0.0.1:1080#A", rules=self.rules())
        rules = config["route"]["rules"]
        self.assertEqual(rules[0], {"action": "sniff"})
        self.assertEqual(rules[1], {"action": "route", "outbound": "DIRECT",
                                    "ip_cidr": ["10.0.0.0/8"]})
        self.assertEqual(rules[2], {"action": "reject",
                                    "rule_set": ["geosite-category-ads-all"]})
        self.assertEqual(rules[3], {"action": "route", "outbound": "DIRECT",
                                    "rule_set": ["geoip-cn"]})
        self.assertEqual(rules[4], {"action": "route", "outbound": "PROXY",
                                    "domain_suffix": ["t.me"]})
        self.assertEqual(rules[5], {"action": "route", "outbound": "AUTO",
                                    "domain_keyword": ["google"]})
        self.assertEqual(rules[6], {"action": "route", "outbound": "PROXY",
                                    "process_name": ["Telegram.exe"]})
        sets = config["route"]["rule_set"]
        self.assertEqual([entry["tag"] for entry in sets],
                         ["geosite-category-ads-all", "geoip-cn"])
        self.assertTrue(sets[0]["url"].endswith("/geosite-category-ads-all.srs"))
        self.assertTrue(sets[1]["url"].endswith("/geoip-cn.srs"))
        self.assertEqual(sets[0]["download_detour"], "PROXY")
        self.assertEqual(sets[0]["format"], "binary")

    def test_duplicate_sets_and_disabled_rules(self):
        rules = self.rules()
        rules.append(new_rule("GEOSITE", "cn", "DIRECT"))
        rules.append(new_rule("GEOSITE", "cn", "REJECT", enabled=False))
        rules.append(new_rule("GEOIP", "cn", "PROXY"))
        config = build("socks5://127.0.0.1:1080#A", rules=rules)
        tags = [entry["tag"] for entry in config["route"]["rule_set"]]
        self.assertEqual(tags.count("geosite-cn"), 1)
        self.assertEqual(tags.count("geoip-cn"), 1)
        converted = config["route"]["rules"]
        self.assertEqual(len(converted), 1 + len(rules) - 1)

    def test_invalid_rule_reports_position(self):
        with self.assertRaisesRegex(RuleError, "第 2 条规则无效"):
            build("socks5://127.0.0.1:1080#A",
                  rules=[new_rule("DOMAIN", "a.com", "PROXY"),
                         {"type": "DOMAIN", "value": "bad value", "action": "PROXY"}])


if __name__ == "__main__":
    unittest.main()
