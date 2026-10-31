"""Share-link coverage for the protocols added in 1.5.0."""

from __future__ import annotations

import base64
import unittest
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import yaml

from node_desk.formats import (
    PROTOCOLS,
    FormatError,
    export_clash,
    export_v2ray,
    parse_batch,
    parse_uri,
)

UUID = "12345678-1234-4234-8234-123456789abc"
KEY = base64.b64encode(bytes(range(32))).decode("ascii")
KEY2 = base64.b64encode(bytes(range(32, 64))).decode("ascii")
# 0xfb 0xff 0xbf encodes to "+/+/": exercises raw "+" and "/" inside the userinfo.
RAW_KEY = base64.b64encode(bytes([0xFB, 0xFF, 0xBF]) * 10 + bytes([0xFB, 0xFF])).decode("ascii")
PIN = "ab:" * 31 + "cd"


def link(scheme, auth, options=None, *, host="example.com", port=443, name="Node"):
    userinfo = auth + "@" if auth is not None else ""
    query = "?" + urlencode(options, quote_via=quote) if options else ""
    return f"{scheme}://{userinfo}{host}:{port}{query}#{quote(name, safe='')}"


def b64url(value):
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def ssr(main="example.com:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:" + b64url("pass"),
        params=None):
    if params is None:
        params = {"obfsparam": b64url("cdn.example"), "remarks": b64url("SSR Node")}
    query = "&".join(f"{key}={value}" for key, value in params.items())
    return "ssr://" + b64url(main + ("/?" + query if query else ""))


def clash_proxy(node):
    return yaml.safe_load(export_clash([node]))["proxies"][0]


def round_trip(test, node):
    test.assertEqual(parse_uri(node["uri"]), node)
    test.assertIn(node["protocol"], PROTOCOLS)


def v2ray_round_trip(test, node):
    batch = parse_batch(export_v2ray([node]))
    test.assertEqual(batch["errors"], [])
    test.assertEqual(batch["nodes"], [node])


class Hysteria2Tests(unittest.TestCase):
    def test_full_options_and_round_trips(self):
        options = {"sni": "TLS.example", "insecure": "1", "obfs": "salamander",
                   "obfs-password": "ob", "alpn": "h3", "up": "100 Mbps", "down": "50",
                   "mport": "20000-30000,40000", "pinSHA256": PIN}
        node = parse_uri(link("hysteria2", "p%40ss", options))
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "hysteria2")
        self.assertEqual(proxy["password"], "p@ss")
        self.assertEqual(proxy["sni"], "tls.example")
        self.assertTrue(proxy["skip-cert-verify"])
        self.assertEqual((proxy["obfs"], proxy["obfs-password"]), ("salamander", "ob"))
        self.assertEqual(proxy["alpn"], ["h3"])
        self.assertEqual((proxy["up"], proxy["down"]), ("100 Mbps", "50"))
        self.assertEqual(proxy["ports"], "20000-30000,40000")
        self.assertEqual(proxy["fingerprint"], PIN)
        round_trip(self, node)
        v2ray_round_trip(self, node)
        self.assertEqual(parse_qs(urlsplit(node["uri"]).query)["insecure"], ["1"])

    def test_hy2_alias_and_minimal_link_are_the_same_node(self):
        full = parse_uri(link("hysteria2", "pw"))
        alias = parse_uri(link("hy2", "pw"))
        self.assertEqual(full, alias)
        self.assertEqual(full["protocol"], "hysteria2")
        self.assertNotIn("skip-cert-verify", full["clash"])
        batch = parse_batch(link("hysteria2", "pw") + "\n" + link("hy2", "pw", name="Other"))
        self.assertEqual((len(batch["nodes"]), batch["duplicates"]), (1, 1))

    def test_rejections(self):
        for auth, options in (
            (None, {}), ("pw", {"obfs": "salamander"}), ("pw", {"obfs-password": "x"}),
            ("pw", {"obfs": "none", "obfs-password": "x"}), ("pw", {"pinSHA256": "abc"}),
            ("pw", {"up": "fast"}), ("pw", {"mport": "30000-20000"}), ("pw", {"mport": "0-10"}),
            ("pw", {"fp": "chrome"}), ("pw", {"insecure": "maybe"}),
            ("pw", {"mport": "1000", "ports": "2000"}), ("pw", {"alpn": "h3,h3"}),
        ):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("hysteria2", auth, options))


class HysteriaV1Tests(unittest.TestCase):
    def test_options_and_clash_mapping(self):
        options = {"protocol": "udp", "auth": "secret", "peer": "tls.example", "insecure": "1",
                   "upmbps": "100", "downmbps": "200", "alpn": "h3", "obfs": "xplus", "obfsParam": "ob"}
        node = parse_uri(link("hysteria", None, options))
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "hysteria")
        self.assertEqual(proxy["auth-str"], "secret")
        self.assertEqual(proxy["sni"], "tls.example")
        self.assertEqual((proxy["up"], proxy["down"]), ("100", "200"))
        self.assertEqual(proxy["obfs"], "ob")
        self.assertTrue(proxy["skip-cert-verify"])
        round_trip(self, node)
        with self.assertRaises(FormatError):
            export_v2ray([node])

    def test_rejections(self):
        for auth, options in (
            ("pw", {}), (None, {"protocol": "quic"}), (None, {"obfs": "xplus"}),
            (None, {"obfs": "other", "obfsParam": "x"}), (None, {"upmbps": "0"}),
        ):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("hysteria", auth, options))


class TuicTests(unittest.TestCase):
    def test_v5_options_defaults_and_round_trips(self):
        node = parse_uri(link("tuic", f"{UUID}:pa%3Ass", {
            "congestion_control": "bbr", "udp_relay_mode": "quic", "alpn": "h3,h2",
            "sni": "tls.example", "allow_insecure": "1", "disable_sni": "1",
        }))
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "tuic")
        self.assertEqual((proxy["uuid"], proxy["password"]), (UUID, "pa:ss"))
        self.assertEqual((proxy["congestion-controller"], proxy["udp-relay-mode"]), ("bbr", "quic"))
        self.assertEqual(proxy["alpn"], ["h3", "h2"])
        self.assertTrue(proxy["skip-cert-verify"] and proxy["disable-sni"])
        self.assertIn(f"{UUID}:pa%3Ass@example.com:443", node["uri"])
        round_trip(self, node)
        v2ray_round_trip(self, node)
        plain = parse_uri(link("tuic", f"{UUID}:pw"))
        self.assertEqual((plain["clash"]["congestion-controller"], plain["clash"]["udp-relay-mode"],
                          plain["clash"]["alpn"]), ("cubic", "native", ["h3"]))
        self.assertNotIn("skip-cert-verify", plain["clash"])
        dashless = parse_uri(link("tuic", f"{UUID.replace('-', '')}:pw"))
        self.assertEqual(dashless["clash"]["uuid"], UUID)

    def test_rejections(self):
        for auth, options in (
            ("token", {}), (None, {}), (f"{UUID}:", {}),
            (f"{UUID}:pw", {"congestion_control": "fast"}), (f"{UUID}:pw", {"udp_relay_mode": "tcp"}),
            (f"{UUID}:pw", {"insecure": "1", "allow_insecure": "0"}), (f"{UUID}:pw", {"fp": "chrome"}),
        ):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("tuic", auth, options))


class AnyTlsTests(unittest.TestCase):
    def test_options_and_round_trips(self):
        node = parse_uri(link("anytls", "pw", {"sni": "tls.example", "allowInsecure": "1",
                                                "alpn": "h2,http/1.1", "fp": "firefox"}))
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "anytls")
        self.assertEqual((proxy["password"], proxy["sni"], proxy["client-fingerprint"]),
                         ("pw", "tls.example", "firefox"))
        self.assertEqual(proxy["alpn"], ["h2", "http/1.1"])
        self.assertTrue(proxy["skip-cert-verify"] and proxy["udp"])
        round_trip(self, node)
        v2ray_round_trip(self, node)
        for auth, options in ((None, {}), ("pw", {"fp": "nope"}), ("pw", {"type": "ws"})):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("anytls", auth, options))


class WireGuardTests(unittest.TestCase):
    def test_encoded_and_raw_keys_addresses_and_reserved(self):
        options = {"publickey": KEY2, "presharedkey": KEY, "address": "172.16.0.2/32,2606:4700::1/128",
                   "reserved": "1,2,3", "mtu": "1420"}
        node = parse_uri(link("wireguard", quote(RAW_KEY, safe=""), options, port=51820))
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "wireguard")
        self.assertEqual((proxy["private-key"], proxy["public-key"], proxy["pre-shared-key"]),
                         (RAW_KEY, KEY2, KEY))
        self.assertEqual((proxy["ip"], proxy["ipv6"]), ("172.16.0.2", "2606:4700::1"))
        self.assertEqual((proxy["reserved"], proxy["mtu"]), ([1, 2, 3], 1420))
        self.assertTrue(proxy["udp"])
        round_trip(self, node)
        v2ray_round_trip(self, node)
        raw = parse_uri(f"wireguard://{RAW_KEY}@example.com:51820?publickey={quote(KEY2, safe='')}"
                        "&address=10.0.0.0%2F24#Node")
        self.assertEqual(raw["clash"]["private-key"], RAW_KEY)
        self.assertEqual(raw["clash"]["ip"], "10.0.0.0/24")
        self.assertNotIn("ipv6", raw["clash"])
        self.assertNotIn("+", urlsplit(raw["uri"]).netloc)

    def test_rejections(self):
        for auth, options in (
            (None, {"publickey": KEY2, "address": "10.0.0.2"}),
            (quote(KEY), {"address": "10.0.0.2"}),
            (quote(KEY), {"publickey": "short", "address": "10.0.0.2"}),
            (quote(KEY), {"publickey": KEY2}),
            (quote(KEY), {"publickey": KEY2, "address": "10.0.0.2,10.0.0.3"}),
            (quote(KEY), {"publickey": KEY2, "address": "nope"}),
            (quote(KEY), {"publickey": KEY2, "address": "10.0.0.2", "reserved": "1,2"}),
            (quote(KEY), {"publickey": KEY2, "address": "10.0.0.2", "reserved": "1,2,300"}),
            (quote(KEY), {"publickey": KEY2, "address": "10.0.0.2", "mtu": "100"}),
            (quote(KEY), {"publickey": KEY2, "address": "10.0.0.2", "wnoise": "quic"}),
        ):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("wireguard", auth, options, port=51820))


class MieruTests(unittest.TestCase):
    def test_options_profile_fallback_and_rejections(self):
        node = parse_uri(link("mierus", "user:p%40ss", {"multiplexing": "MULTIPLEXING_HIGH",
                                                         "profile": "Home", "mtu": "1400",
                                                         "transport": "TCP"}, port=2000))
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "mieru")
        self.assertEqual((proxy["username"], proxy["password"], proxy["transport"],
                          proxy["multiplexing"]), ("user", "p@ss", "TCP", "MULTIPLEXING_HIGH"))
        self.assertEqual(node["name"], "Node")
        round_trip(self, node)
        unnamed = parse_uri(f"mierus://u:p@example.com:2000?profile=Home")
        self.assertEqual(unnamed["name"], "Home")
        self.assertNotIn("multiplexing", unnamed["clash"])
        with self.assertRaises(FormatError):
            export_v2ray([node])
        for auth, options in (
            ("useronly", {}), (None, {}), ("u:p", {"transport": "UDP"}), ("u:p", {"mtu": "1300"}),
            ("u:p", {"multiplexing": "HIGH"}), ("u:p", {"port-range": "1-2"}),
        ):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("mierus", auth, options, port=2000))


class TrojanGoTests(unittest.TestCase):
    def test_original_websocket_and_shadowsocks_layer(self):
        node = parse_uri(link("trojan-go", "pw", {"sni": "tls.example",
                                                   "encryption": "ss;AES-128-GCM;sspass"}))
        proxy = clash_proxy(node)
        self.assertEqual(node["protocol"], "trojan-go")
        self.assertEqual(proxy["type"], "trojan")
        self.assertEqual(proxy["ss-opts"], {"enabled": True, "method": "aes-128-gcm", "password": "sspass"})
        self.assertEqual(proxy["sni"], "tls.example")
        self.assertFalse(proxy["skip-cert-verify"])
        self.assertNotIn("network", proxy)
        round_trip(self, node)
        websocket = parse_uri(link("trojan-go", "pw", {"type": "ws", "host": "cdn.example", "path": "/tg"}))
        self.assertEqual(websocket["clash"]["network"], "ws")
        self.assertEqual(websocket["clash"]["ws-opts"], {"path": "/tg", "headers": {"Host": "cdn.example"}})
        round_trip(self, websocket)
        with self.assertRaises(FormatError):
            export_v2ray([node])

    def test_rejections(self):
        for options in ({"plugin": "shadowsocks"}, {"type": "grpc"}, {"path": "/x"},
                        {"encryption": "ss;rc4-md5;pw"}, {"encryption": "aes-128-gcm;pw"},
                        {"encryption": "ss;aes-128-gcm;"}, {"security": "tls"}):
            with self.subTest(options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("trojan-go", "pw", options))


class SsrTests(unittest.TestCase):
    def test_fields_name_round_trip_and_rename_on_export(self):
        node = parse_uri(ssr())
        proxy = clash_proxy(node)
        self.assertEqual(proxy["type"], "ssr")
        self.assertEqual((proxy["server"], proxy["port"], proxy["protocol"], proxy["cipher"],
                          proxy["obfs"], proxy["password"], proxy["obfs-param"]),
                         ("example.com", 8388, "auth_aes128_md5", "aes-256-cfb",
                          "tls1.2_ticket_auth", "pass", "cdn.example"))
        self.assertNotIn("protocol-param", proxy)
        self.assertEqual(node["name"], "SSR Node")
        round_trip(self, node)
        renamed = dict(node, name="Renamed")
        exported = parse_batch(export_v2ray([renamed]))["nodes"]
        self.assertEqual(exported[0]["name"], "Renamed")
        self.assertEqual(exported[0]["clash"]["password"], "pass")
        bare = parse_uri(ssr(params={}))
        self.assertEqual(bare["name"], "example.com:8388")

    def test_rejections(self):
        for uri in (
            ssr(main="example.com:8388:origin:aes-256-cfb:plain"),
            ssr(main="example.com:8388:origin:rc4:plain:" + b64url("p")),
            ssr(main="example.com:8388:magic:aes-256-cfb:plain:" + b64url("p")),
            ssr(main="example.com:8388:origin:aes-256-cfb:magic:" + b64url("p")),
            ssr(params={"group": b64url("g"), "remarks": b64url("r"), "extra": b64url("x")}),
            "ssr://%%%", "ssr://" + b64url("example.com:0:origin:aes-256-cfb:plain:" + b64url("p")),
        ):
            with self.subTest(uri=uri):
                with self.assertRaises(FormatError):
                    parse_uri(uri)


class SshAndHttpTests(unittest.TestCase):
    def test_ssh_requires_user_and_password(self):
        node = parse_uri(link("ssh", "root:p%3Aw", port=22))
        proxy = clash_proxy(node)
        self.assertEqual((proxy["type"], proxy["username"], proxy["password"], proxy["port"]),
                         ("ssh", "root", "p:w", 22))
        round_trip(self, node)
        with self.assertRaises(FormatError):
            export_v2ray([node])
        for auth, options in (("root", {}), (None, {}), ("root:pw", {"private-key": "x"})):
            with self.subTest(auth=auth, options=options):
                with self.assertRaises(FormatError):
                    parse_uri(link("ssh", auth, options, port=22))

    def test_http_and_https_proxies(self):
        plain = parse_uri(link("http", "user:pass", port=8080))
        self.assertEqual(plain["protocol"], "http")
        self.assertEqual(plain["clash"], {"name": "Node", "type": "http", "server": "example.com",
                                          "port": 8080, "tls": False, "username": "user",
                                          "password": "pass"})
        round_trip(self, plain)
        v2ray_round_trip(self, plain)
        secure = parse_uri(link("https", None, {"sni": "tls.example", "insecure": "1"}))
        self.assertTrue(secure["clash"]["tls"] and secure["clash"]["skip-cert-verify"])
        self.assertEqual(secure["clash"]["sni"], "tls.example")
        self.assertNotIn("username", secure["clash"])
        round_trip(self, secure)
        for uri in ("https://example.com/sub", "http://example.com:8080/path",
                    link("http", None, {"sni": "tls.example"}), link("http", "useronly", port=8080)):
            with self.subTest(uri=uri):
                with self.assertRaises(FormatError):
                    parse_uri(uri)


class ProtocolCatalogTests(unittest.TestCase):
    def test_every_protocol_can_be_imported_in_one_batch(self):
        links = [
            link("hysteria2", "pw"), link("hysteria", None, {"auth": "a"}),
            link("tuic", f"{UUID}:pw"), link("anytls", "pw"),
            link("wireguard", quote(KEY), {"publickey": KEY2, "address": "10.0.0.2"}, port=51820),
            link("mierus", "u:p", port=2000), link("trojan-go", "pw"), ssr(),
            link("ssh", "u:p", port=22), link("http", None, port=8080),
        ]
        batch = parse_batch("\n".join(links))
        self.assertEqual(batch["errors"], [])
        self.assertEqual(len(batch["nodes"]), len(links))
        self.assertEqual({node["protocol"] for node in batch["nodes"]} - set(PROTOCOLS), set())
        config = yaml.safe_load(export_clash(batch["nodes"]))
        self.assertEqual(len(config["proxies"]), len(links))
        with self.assertRaises(FormatError):
            export_v2ray(batch["nodes"])


if __name__ == "__main__":
    unittest.main()
