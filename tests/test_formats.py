"""Synthetic, offline protocol conversion tests; no supplied nodes or secrets."""

import base64
import copy
import json
import random
import socket
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import yaml

from node_desk.formats import (
    MAX_BATCH_LENGTH,
    MAX_BATCH_LINES,
    MAX_NAME_LENGTH,
    MAX_URI_LENGTH,
    FormatError,
    export_clash,
    export_v2ray,
    parse_batch,
    parse_uri,
)


UUID = "12345678-1234-4234-8234-123456789abc"
PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
UNICODE_NAME = "\u8282\u70b9 \u6d4b\u8bd5"


def b64(value, urlsafe=False, padding=True):
    raw = value.encode("utf-8") if isinstance(value, str) else value
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    result = encoder(raw).decode("ascii")
    return result if padding else result.rstrip("=")


def vless(options=None, name="Example", server="example.com", port=443):
    query = "?" + urlencode(options, quote_via=quote) if options else ""
    return f"vless://{UUID}@{server}:{port}{query}#{quote(name, safe='')}"


def trojan(options=None, name="Example", password="test-only"):
    query = "?" + urlencode(options, quote_via=quote) if options else ""
    return f"trojan://{quote(password, safe='')}@example.com:443{query}#{quote(name, safe='')}"


def vmess(**updates):
    data = {"v": "2", "ps": "Example", "add": "example.com", "port": "443",
            "id": UUID, "aid": "0", "net": "tcp", "type": "none",
            "host": "", "path": "", "tls": "", "scy": "auto"}
    data.update(updates)
    return "vmess://" + b64(json.dumps(data, ensure_ascii=False))


def ss(password="test-only", cipher="aes-128-gcm", plugin=None, name="Example",
       encoded=True, server="example.com", port=8388):
    auth = b64(f"{cipher}:{password}", urlsafe=True, padding=False) if encoded else (
        quote(cipher, safe="") + ":" + quote(password, safe="")
    )
    query = "/?" + urlencode({"plugin": plugin}, quote_via=quote) if plugin is not None else ""
    return f"ss://{auth}@{server}:{port}{query}#{quote(name, safe='')}"


def without_name(node):
    return {key: value for key, value in node["clash"].items() if key != "name"}


class UriValidationTests(unittest.TestCase):
    def test_exact_public_record_shape_and_integer_port(self):
        for uri, protocol in [
            (vless(), "vless"), (vmess(), "vmess"),
            ("socks5://example.com:1080", "socks5"),
            (trojan(), "trojan"), (ss(), "ss"),
        ]:
            with self.subTest(protocol=protocol):
                node = parse_uri(uri)
                self.assertEqual(set(node), {"name", "protocol", "server", "port", "uri", "clash"})
                self.assertEqual(node["protocol"], protocol)
                self.assertIs(type(node["port"]), int)
                self.assertEqual(node["name"], node["clash"]["name"])
                self.assertEqual(node["server"], node["clash"]["server"])
                self.assertEqual(node["port"], node["clash"]["port"])
                self.assertEqual(parse_uri(node["uri"]), node)

    def test_format_error_is_value_error(self):
        self.assertTrue(issubclass(FormatError, ValueError))

    def test_invalid_input_types_and_lengths(self):
        for value in (None, 123, {}, b"vless://", "", " ", "x" * (MAX_URI_LENGTH + 1)):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(FormatError):
                    parse_uri(value)

    def test_invalid_ports(self):
        for port in ("", "0", "65536", "-1", "+80", "1.5", "443x", "0x50", "\uff14\uff14\uff13"):
            with self.subTest(port=port):
                with self.assertRaises(FormatError):
                    parse_uri(f"socks5://example.com:{port}")

    def test_port_bounds_and_leading_zeroes(self):
        for port in ("1", "65535", "001080"):
            with self.subTest(port=port):
                node = parse_uri(f"socks5://example.com:{port}")
                self.assertEqual(node["port"], int(port))
                self.assertEqual(parse_uri(node["uri"])["port"], int(port))

    def test_port_must_be_explicit_for_all_authority_protocols(self):
        for prefix in (f"vless://{UUID}@", "trojan://test-only@", "socks5://", "ss://YWVzLTEyOC1nY206cHc@"):
            with self.subTest(prefix=prefix):
                with self.assertRaises(FormatError):
                    parse_uri(prefix + "example.com")

    def test_host_validation(self):
        for host in ("", "999.2.3.4", "example..com", "-example.com", "example-.com",
                     "a" * 64 + ".com", "example_com", "example%2ecom", "[::gg]",
                     "[fe80::1%25eth0]", "[::1]suffix"):
            with self.subTest(host=host):
                with self.assertRaises(FormatError):
                    parse_uri(f"socks5://{host}:1080")

    def test_hostname_idna_and_case_canonicalization(self):
        node = parse_uri("SOCKS5://B\u00dcCHER.Example:1080")
        self.assertEqual(node["server"], "xn--bcher-kva.example")
        self.assertTrue(node["uri"].startswith("socks://xn--bcher-kva.example:1080"))

    def test_ipv6_is_bracketed_only_in_uri(self):
        for uri in (
            vless(server="[2001:0DB8:0:0::1]"),
            "socks5://user:test-only@[2001:0DB8:0:0::1]:1080",
            "trojan://test-only@[2001:0DB8:0:0::1]:443",
            ss(server="[2001:0DB8:0:0::1]"),
        ):
            with self.subTest(uri=uri):
                node = parse_uri(uri)
                self.assertEqual(node["server"], "2001:db8::1")
                self.assertIn("@[2001:db8::1]:", node["uri"])
                self.assertEqual(parse_uri(node["uri"]), node)
        with self.assertRaises(FormatError):
            parse_uri("socks5://2001:db8::1:1080")

    def test_invalid_and_nonstandard_uuids(self):
        for identifier in ("", "not-a-uuid", UUID.replace("-", ""), "{" + UUID + "}",
                           UUID[:-1] + "g", "urn:uuid:" + UUID):
            with self.subTest(identifier=identifier):
                with self.assertRaises(FormatError):
                    parse_uri(f"vless://{quote(identifier, safe='')}@example.com:443")
                with self.assertRaises(FormatError):
                    parse_uri(vmess(id=identifier))

    def test_encoded_uuid_is_decoded_once_and_normalized(self):
        encoded = UUID.upper().replace("-", "%2D")
        node = parse_uri(f"VLESS://{encoded}@EXAMPLE.COM:443")
        self.assertEqual(node["clash"]["uuid"], UUID)
        self.assertIn(UUID + "@example.com:443", node["uri"])

    def test_name_unicode_plus_hash_and_percent_round_trip(self):
        name = UNICODE_NAME + " + # %41"
        node = parse_uri(vless(name=name))
        self.assertEqual(node["name"], name)
        self.assertIn("%2B", node["uri"])
        self.assertIn("%2541", node["uri"])
        self.assertEqual(parse_uri(node["uri"])["name"], name)
        self.assertEqual(parse_uri(vless().partition("#")[0] + "#A+B")["name"], "A+B")

    def test_missing_name_has_deterministic_fallback(self):
        node = parse_uri(f"vless://{UUID}@example.com:443")
        self.assertEqual(node["name"], "example.com:443")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_name_length_and_long_hostname_fallback(self):
        with self.assertRaises(FormatError):
            parse_uri(vless(name="x" * (MAX_NAME_LENGTH + 1)))
        host = ".".join(["a" * 63] * 3 + ["b" * 61])
        node = parse_uri(f"socks5://{host}:65535")
        self.assertLessEqual(len(node["name"]), MAX_NAME_LENGTH)
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_percent_decoding_rejects_bad_escapes_and_utf8(self):
        for bad in ("%", "%0", "%GG", "%ff", "%C3%28", "%ED%A0%80"):
            with self.subTest(bad=bad):
                with self.assertRaises(FormatError):
                    parse_uri(vless().partition("#")[0] + "#" + bad)

    def test_controls_are_not_silently_stripped_by_urllib(self):
        for char in ("\x00", "\t", "\n", "\r", "\x7f", "\x85", "\u2028", "\ud800"):
            with self.subTest(char=repr(char)):
                with self.assertRaises(FormatError):
                    parse_uri(vless() + char)
        for encoded in ("%00", "%0a", "%0D", "%09", "%7F"):
            with self.subTest(encoded=encoded):
                with self.assertRaises(FormatError):
                    parse_uri(trojan(password="test").replace("test@", "test" + encoded + "@"))

    def test_unsupported_schemes_and_authority_paths(self):
        for uri in ("https://example.com/sub", "ssr://example", "hy2://pw@example.com:443",
                    f"vless://{UUID}@example.com:443/ws", "socks5://example.com:1080/path",
                    "trojan://u:p@ss@example.com:443"):
            with self.subTest(uri=uri):
                with self.assertRaises(FormatError):
                    parse_uri(uri)

    def test_query_allowlist_duplicate_and_alias_collisions(self):
        for query in (
            "server=evil.example", "port=1", "name=override", "uuid=override",
            "dialer-proxy=DIRECT", "udp=false", "type=ws&type=tcp",
            "security=tls&security=none", "security=tls&Security=none",
            "sni=example.com&serverName=other.example", "insecure=1&allowInsecure=0",
            "headerType", "type=tcp&", "type=",
            "security=", "encryption=", "fp=", "alpn=", "sni=",
        ):
            with self.subTest(query=query):
                with self.assertRaises(FormatError):
                    parse_uri(f"vless://{UUID}@example.com:443?{query}")

    def test_query_limit_is_bounded(self):
        with self.assertRaises(FormatError):
            parse_uri(vless().partition("#")[0] + "?" + "&".join(["host=x"] * 65))


class VlessTests(unittest.TestCase):
    def test_plain_tcp(self):
        node = parse_uri(vless({"encryption": "none"}))
        self.assertEqual(node["clash"]["network"], "tcp")
        self.assertFalse(node["clash"]["tls"])
        self.assertNotIn("reality-opts", node["clash"])

    def test_tls_options_are_preserved(self):
        options = {"security": "tls", "sni": "tls.example", "fp": "firefox",
                   "alpn": "h2,http/1.1", "allowInsecure": "false", "encryption": "none"}
        node = parse_uri(vless(options))
        self.assertEqual(node["clash"]["servername"], "tls.example")
        self.assertEqual(node["clash"]["client-fingerprint"], "firefox")
        self.assertEqual(node["clash"]["alpn"], ["h2", "http/1.1"])
        self.assertFalse(node["clash"]["skip-cert-verify"])
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertEqual(parse_qs(urlsplit(node["uri"]).query)["allowInsecure"], ["0"])

    def test_tls_defaults_are_explicit_and_secure(self):
        node = parse_uri(vless({"security": "tls"}))
        self.assertEqual(node["clash"]["servername"], "example.com")
        self.assertEqual(node["clash"]["client-fingerprint"], "chrome")
        self.assertFalse(node["clash"]["skip-cert-verify"])

    def test_websocket_tls_and_early_data(self):
        options = {"security": "tls", "type": "ws", "host": "cdn.example",
                   "path": "/ws%2Fescaped?ed=2048&token=%2541",
                   "sni": "tls.example", "alpn": "http/1.1", "fp": "chrome"}
        node = parse_uri(vless(options))
        self.assertEqual(node["clash"]["ws-opts"],
                         {"path": options["path"], "headers": {"Host": "cdn.example"}})
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertEqual(parse_qs(urlsplit(node["uri"]).query)["path"], [options["path"]])

    def test_plain_websocket_does_not_get_random_host(self):
        node = parse_uri(vless({"type": "ws"}))
        self.assertEqual(node["clash"]["ws-opts"],
                         {"path": "/", "headers": {"Host": "example.com:443"}})

    def test_grpc_tls_and_matching_authority(self):
        options = {"type": "grpc", "security": "tls", "serviceName": "my.Service/test",
                   "authority": "tls.example", "sni": "tls.example", "mode": "gun", "alpn": "h2"}
        node = parse_uri(vless(options))
        self.assertEqual(node["clash"]["grpc-opts"]["grpc-service-name"], "my.Service/test")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_grpc_plain_and_empty_authority(self):
        node = parse_uri(vless({"type": "grpc", "serviceName": "test", "authority": ""}))
        self.assertFalse(node["clash"]["tls"])
        self.assertEqual(node["clash"]["grpc-opts"], {"grpc-service-name": "test"})

    def test_reality_vision(self):
        node = parse_uri(vless({"security": "reality", "pbk": PUBLIC_KEY, "sid": "A0B1",
                                "sni": "tls.example", "fp": "chrome", "flow": "xtls-rprx-vision"}))
        self.assertTrue(node["clash"]["tls"])
        self.assertEqual(node["clash"]["flow"], "xtls-rprx-vision")
        self.assertEqual(node["clash"]["reality-opts"],
                         {"public-key": PUBLIC_KEY, "short-id": "a0b1"})
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_reality_grpc_with_empty_short_id(self):
        node = parse_uri(vless({"type": "grpc", "security": "reality", "pbk": PUBLIC_KEY,
                               "sid": "", "fp": "chrome", "serviceName": "test"}))
        self.assertEqual(node["clash"]["reality-opts"]["short-id"], "")
        self.assertEqual(node["clash"]["grpc-opts"]["grpc-service-name"], "test")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_reality_validation(self):
        for update in (
            {"pbk": ""}, {"pbk": "not-a-key"}, {"pbk": PUBLIC_KEY + "="},
            {"sid": "a"}, {"sid": "gg"}, {"sid": "00" * 9},
            {"type": "ws"}, {"allowInsecure": "1"}, {"spx": "/spider"},
            {"pqv": "not-supported"},
        ):
            with self.subTest(update=update):
                options = {"security": "reality", "pbk": PUBLIC_KEY, "fp": "chrome", **update}
                with self.assertRaises(FormatError):
                    parse_uri(vless(options))

    def test_unsupported_or_inapplicable_options_fail_instead_of_downgrading(self):
        for options in (
            {"security": "xtls"}, {"encryption": "mlkem768x25519plus.native.0rtt.test"},
            {"type": "kcp"}, {"type": "quic"}, {"type": "httpupgrade"}, {"type": "xhttp"},
            {"headerType": "http"}, {"path": "/"}, {"host": "cdn.example"},
            {"security": "none", "sni": "tls.example"}, {"fp": "chrome"},
            {"pbk": PUBLIC_KEY}, {"sid": ""}, {"allowInsecure": "yes"},
            {"security": "tls", "fp": "not-a-fingerprint"},
            {"security": "tls", "alpn": "h2, http/1.1"},
            {"security": "tls", "alpn": "h2,h2"},
            {"security": "tls", "alpn": "h2,"},
            {"security": "tls", "flow": "xtls-rprx-vision-udp443"},
            {"flow": "xtls-rprx-vision"},
            {"security": "tls", "type": "ws", "flow": "xtls-rprx-vision"},
            {"type": "grpc", "mode": "multi"}, {"type": "grpc", "mode": "guna"},
            {"type": "grpc", "authority": "other.example"},
            {"type": "grpc", "path": "/test"},
            {"type": "ws", "serviceName": "test"},
            {"type": "ws", "security": "tls", "alpn": "h2,http/1.1"},
            {"type": "grpc", "security": "tls", "alpn": "http/1.1"},
            {"security": "tls", "ech": "AA=="}, {"security": "tls", "pcs": "pin"},
            {"security": "tls", "vcn": "cert.example"}, {"fm": "{}"},
        ):
            with self.subTest(options=options):
                with self.assertRaises(FormatError):
                    parse_uri(vless(options))

    def test_websocket_path_validation(self):
        for path in ("", "relative", "//elsewhere/path", "/has space", "/bad%",
                     "/x#fragment", "/x#", "/ws?ed=bad", "/ws?ed=-1",
                     "/ws?ed=65536", "/ws?ed=1&ed=2"):
            with self.subTest(path=path):
                with self.assertRaises(FormatError):
                    parse_uri(vless({"type": "ws", "path": path}))

    def test_query_plus_is_not_decoded_as_a_form_space(self):
        uri = f"vless://{UUID}@example.com:443?type=ws&path=%2Fws%3Ftoken%3Da+b"
        node = parse_uri(uri)
        self.assertEqual(node["clash"]["ws-opts"]["path"], "/ws?token=a+b")
        self.assertIn("%2B", node["uri"])
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_http_hosts_do_not_accept_hidden_url_components(self):
        for host in ("example.com#", "example.com?", "example.com:", "example.com/path",
                     "user@example.com", "example.com:0", "example.com:65536"):
            with self.subTest(host=host):
                with self.assertRaises(FormatError):
                    parse_uri(vless({"type": "ws", "host": host}))


class VmessTests(unittest.TestCase):
    def test_json_numbers_uuid_and_name(self):
        node = parse_uri(vmess(v=2, port=8443, aid=0, id=UUID.upper(), ps=UNICODE_NAME))
        self.assertEqual(node["name"], UNICODE_NAME)
        self.assertEqual(node["clash"]["uuid"], UUID)
        self.assertEqual(node["clash"]["alterId"], 0)
        self.assertEqual(node["clash"]["cipher"], "auto")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_json_tls_websocket(self):
        node = parse_uri(vmess(net="ws", host="cdn.example", path="/ws?ed=2048", tls="tls",
                               sni="tls.example", alpn="http/1.1", fp="firefox", scy="aes-128-gcm"))
        self.assertEqual(node["clash"]["ws-opts"]["headers"], {"Host": "cdn.example"})
        self.assertEqual(node["clash"]["ws-opts"]["path"], "/ws?ed=2048")
        self.assertEqual(node["clash"]["servername"], "tls.example")
        self.assertEqual(node["clash"]["cipher"], "aes-128-gcm")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_json_grpc_uses_path_and_host_fields(self):
        node = parse_uri(vmess(net="grpc", type="gun", path="Service", host="tls.example",
                               tls="tls", sni="tls.example", alpn="h2"))
        self.assertEqual(node["clash"]["grpc-opts"], {"grpc-service-name": "Service"})
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_default_grpc_mode_is_gun(self):
        node = parse_uri(vmess(net="grpc", path="Service"))
        self.assertEqual(node["clash"]["grpc-opts"], {"grpc-service-name": "Service"})

    def test_optional_null_and_empty_insecure_fields_are_unset(self):
        node = parse_uri(vmess(ps=None, net=None, type=None, host=None, path=None,
                               scy=None, tls=None, sni=None, alpn=None, fp=None,
                               vcn=None, pcs=None, insecure=None))
        self.assertEqual(node["name"], "example.com:443")
        self.assertFalse(node["clash"]["tls"])
        self.assertEqual(node["clash"]["cipher"], "auto")
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertFalse(parse_uri(vmess(tls="tls", insecure=""))["clash"]["skip-cert-verify"])

    def test_base64_standard_urlsafe_and_unpadded(self):
        body = json.dumps({"v": 2, "add": "example.com", "port": 443, "id": UUID,
                           "ps": UNICODE_NAME})
        for urlsafe in (False, True):
            for padding in (False, True):
                with self.subTest(urlsafe=urlsafe, padding=padding):
                    node = parse_uri("vmess://" + b64(body, urlsafe, padding))
                    self.assertEqual(node["name"], UNICODE_NAME)

    def test_fragment_overrides_json_display_name(self):
        node = parse_uri(vmess() + "#" + quote(UNICODE_NAME))
        self.assertEqual(node["name"], UNICODE_NAME)
        self.assertEqual(parse_uri(node["uri"])["name"], UNICODE_NAME)

    def test_ipv6_in_json_is_unbracketed(self):
        node = parse_uri(vmess(add="2001:db8::1"))
        self.assertEqual(node["server"], "2001:db8::1")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_invalid_json_shapes_types_and_options(self):
        for updates in (
            {"port": True}, {"port": 1.5}, {"port": []}, {"aid": -1}, {"aid": 65536},
            {"v": "1"}, {"ps": {}}, {"host": []}, {"tls": True}, {"add": None},
            {"extra": {"something": "sensitive"}}, {"net": "kcp"}, {"net": "h2"},
            {"net": "tcp", "type": "http"}, {"scy": "wrong"}, {"tls": "reality"},
            {"net": "grpc", "type": "multi"},
            {"net": "grpc", "host": "different.example", "tls": "tls"},
            {"insecure": "yes"}, {"insecure": "1", "allowInsecure": "1"},
            {"tls": "tls", "vcn": "pin"}, {"tls": "tls", "pcs": "pin"},
            {"net": "ws", "tls": "tls", "alpn": "h2"},
        ):
            with self.subTest(updates=updates):
                with self.assertRaises(FormatError):
                    parse_uri(vmess(**updates))

    def test_invalid_json_duplicate_fields_and_nonfinite_numbers(self):
        for payload in ("[]", "null", "123", '{"id":1,"id":2}', '{"port":NaN}',
                        '{"port":Infinity}', "{bad json", "[" * 1200 + "]" * 1200):
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(FormatError):
                    parse_uri("vmess://" + b64(payload))

    def test_malformed_base64_does_not_use_replacement_decoding(self):
        for token in ("", "A", "!!!!", "abcd===", "YQ=", "YWJj$A==", b64(b"\xff\xfe")):
            with self.subTest(token=token):
                with self.assertRaises(FormatError):
                    parse_uri("vmess://" + token)

    def test_standard_uuid_vmess_links_are_explicitly_unsupported(self):
        with self.assertRaisesRegex(FormatError, "Base64 JSON"):
            parse_uri(f"vmess://{UUID}@example.com:443?security=tls")

    def test_allow_insecure_is_honored_for_clash_not_silently_exported_to_xray(self):
        node = parse_uri(vmess(tls="tls", insecure="1"))
        self.assertTrue(node["clash"]["skip-cert-verify"])
        self.assertTrue(yaml.safe_load(export_clash([node]))["proxies"][0]["skip-cert-verify"])
        with self.assertRaisesRegex(FormatError, "allowInsecure"):
            export_v2ray([node])


class SocksTests(unittest.TestCase):
    def test_no_auth_and_explicit_empty_auth(self):
        for uri in ("socks5://example.com:1080", "socks://example.com:1080",
                    "socks://Og==@example.com:1080", "socks5://:@example.com:1080"):
            with self.subTest(uri=uri):
                node = parse_uri(uri)
                self.assertEqual(node["protocol"], "socks5")
                self.assertTrue(node["uri"].startswith("socks://example.com:1080#"))
                self.assertNotIn("username", node["clash"])
                self.assertEqual(parse_uri(node["uri"]), node)

    def test_v2rayn_base64_userinfo(self):
        for urlsafe in (False, True):
            for padding in (False, True):
                auth = b64("test-user:p:a@s/s#%41+", urlsafe, padding)
                node = parse_uri(f"socks://{quote(auth, safe='')}@example.com:1080#Demo")
                self.assertEqual(node["clash"]["username"], "test-user")
                self.assertEqual(node["clash"]["password"], "p:a@s/s#%41+")
                self.assertEqual(parse_uri(node["uri"]), node)

    def test_v2rayn_legacy_whole_payload_with_ipv6(self):
        node = parse_uri("socks://" + b64("user:pass@word@[2001:db8::1]:1080") + "#Demo")
        self.assertEqual(node["server"], "2001:db8::1")
        self.assertEqual(node["clash"]["password"], "pass@word")
        self.assertIn("@[2001:db8::1]:1080", node["uri"])
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_plain_alias_credentials_are_decoded_exactly_once(self):
        node = parse_uri("socks5://user%40name:p%3Aa%40s%2Fs%23%2541%2B@example.com:1080")
        self.assertEqual(node["clash"]["username"], "user@name")
        self.assertEqual(node["clash"]["password"], "p:a@s/s#%41+")
        self.assertTrue(node["uri"].startswith("socks://"))
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_socks_unicode_auth_round_trip(self):
        node = parse_uri("socks5://" + quote("\u7528\u6237") + ":" + quote("\u5bc6\u7801") + "@example.com:1080")
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_socks_invalid_auth_security_and_lengths(self):
        for uri in (
            "socks5://user:@example.com:1080", "socks5://:pass@example.com:1080",
            "socks5://user%3Aname:pass@example.com:1080",
            "socks://" + b64("no-colon") + "@example.com:1080",
            "socks5://" + "u" * 256 + ":pass@example.com:1080",
            "socks5://user:" + quote("\u5bc6" * 86) + "@example.com:1080",
            "socks5://example.com:1080?tls=true",
            "socks5://example.com:1080?udp=false",
            "socks://" + b64("user:pass@example.com:1080#lost"),
            "socks://" + b64("user:pass@example.com:1080?security=tls"),
        ):
            with self.subTest(uri=uri[:60]):
                with self.assertRaises(FormatError):
                    parse_uri(uri)

    def test_legacy_and_new_socks_deduplicate(self):
        result = parse_batch("\n".join((
            "socks://" + b64("user:pass@example.com:1080") + "#one",
            "socks://" + b64("user:pass") + "@example.com:1080#two",
            "socks5://user:pass@example.com:1080#three",
        )))
        self.assertFalse(result["errors"])
        self.assertEqual(result["duplicates"], 2)
        self.assertEqual(len(result["nodes"]), 1)


class TrojanAndShadowsocksTests(unittest.TestCase):
    def test_trojan_password_tls_and_sni(self):
        node = parse_uri(trojan({"sni": "tls.example", "alpn": "h2,http/1.1"},
                               password="p:a@s/s#%41+"))
        self.assertEqual(node["clash"]["password"], "p:a@s/s#%41+")
        self.assertEqual(node["clash"]["sni"], "tls.example")
        self.assertNotIn("servername", node["clash"])
        self.assertNotIn("tls", node["clash"])
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_trojan_websocket_and_grpc(self):
        for options in (
            {"type": "ws", "path": "/trojan", "host": "cdn.example"},
            {"type": "grpc", "serviceName": "Service", "alpn": "h2"},
        ):
            with self.subTest(options=options):
                node = parse_uri(trojan(options))
                self.assertEqual(parse_uri(node["uri"]), node)
                self.assertEqual(len(parse_batch(export_v2ray([node]))["nodes"]), 1)

    def test_trojan_refuses_unsupported_security_and_flow(self):
        for options in ({"security": "none"}, {"security": "reality"},
                        {"flow": "xtls-rprx-vision"}, {"encryption": "none"}):
            with self.subTest(options=options):
                with self.assertRaises(FormatError):
                    parse_uri(trojan(options))
        with self.assertRaises(FormatError):
            parse_uri("trojan://@example.com:443")

    def test_ss_sip002_encoded_plain_and_legacy(self):
        password = "p:a@s/s#%41+"
        uris = [
            ss(password=password),
            ss(password=password, encoded=False),
            "ss://" + b64(f"aes-128-gcm:{password}@[2001:db8::1]:8388") + "#Demo",
        ]
        for uri in uris:
            with self.subTest(uri=uri):
                node = parse_uri(uri)
                self.assertEqual(node["clash"]["password"], password)
                self.assertEqual(node["clash"]["cipher"], "aes-128-gcm")
                self.assertEqual(parse_uri(node["uri"]), node)

    def test_ss_cipher_allowlist_and_empty_password(self):
        for cipher in ("bogus", "aes-256-cfb", "rc4-md5", "none", "AES-128-GCM"):
            with self.subTest(cipher=cipher):
                with self.assertRaises(FormatError):
                    parse_uri(ss(cipher=cipher))
        with self.assertRaises(FormatError):
            parse_uri(ss(password=""))

    def test_ss2022_key_sizes_and_plain_userinfo(self):
        for cipher, size in (
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
            ("2022-blake3-chacha20-poly1305", 32),
        ):
            with self.subTest(cipher=cipher):
                password = b64(bytes(range(size)))
                node = parse_uri(ss(password=password, cipher=cipher, encoded=False))
                self.assertTrue(node["uri"].startswith("ss://" + cipher + ":"))
                self.assertEqual(node["clash"]["password"], password)
                self.assertEqual(parse_uri(node["uri"]), node)
                with self.assertRaises(FormatError):
                    parse_uri(ss(password=b64(b"short"), cipher=cipher, encoded=False))
                with self.assertRaises(FormatError):
                    parse_uri(ss(password=password, cipher=cipher, encoded=True))
                with self.assertRaises(FormatError):
                    parse_uri("ss://" + b64(f"{cipher}:{password}@example.com:8388"))

    def test_ss2022_identity_key_chain(self):
        password = b64(bytes(range(16))) + ":" + b64(bytes(range(16, 32)))
        node = parse_uri(ss(password=password, cipher="2022-blake3-aes-128-gcm", encoded=False))
        self.assertEqual(parse_uri(node["uri"]), node)

    def test_ss2022_chacha_identity_key_chains_are_rejected(self):
        password = b64(bytes(range(32))) + ":" + b64(bytes(range(32, 64)))
        with self.assertRaisesRegex(FormatError, "AES"):
            parse_uri(ss(password=password, cipher="2022-blake3-chacha20-poly1305", encoded=False))

    def test_ss2022_keys_are_normalized_for_the_core(self):
        key = b"\xff" * 32
        node = parse_uri(ss(password=b64(key, urlsafe=True, padding=False),
                            cipher="2022-blake3-aes-256-gcm", encoded=False))
        self.assertEqual(node["clash"]["password"], b64(key))
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertEqual(parse_batch(export_v2ray([node]))["nodes"], [node])

    def test_obfs_plugin_maps_and_retains_options(self):
        node = parse_uri(ss(plugin="simple-obfs;obfs=http;obfs-host=cdn.example"))
        self.assertEqual(node["clash"]["plugin"], "obfs")
        self.assertEqual(node["clash"]["plugin-opts"], {"mode": "http", "host": "cdn.example"})
        self.assertIn("obfs-local", parse_qs(urlsplit(node["uri"]).query)["plugin"][0])
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertEqual(len(parse_batch(export_v2ray([node]))["nodes"]), 1)

    def test_obfs_tls_is_clash_only_and_v2ray_export_reports_it(self):
        node = parse_uri(ss(plugin="obfs-local;obfs=tls;obfs-host=cdn.example"))
        self.assertEqual(yaml.safe_load(export_clash([node]))["proxies"][0]["plugin-opts"]["mode"], "tls")
        with self.assertRaisesRegex(FormatError, "obfs-local TLS"):
            export_v2ray([node])

    def test_v2ray_plugin_websocket_tls_without_mux(self):
        node = parse_uri(ss(plugin="v2ray-plugin;mode=websocket;host=cdn.example;path=/ws;tls;mux=0"))
        self.assertEqual(node["clash"]["plugin-opts"],
                         {"mode": "websocket", "host": "cdn.example", "path": "/ws", "tls": True, "mux": False})
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertEqual(len(parse_batch(export_v2ray([node]))["nodes"]), 1)

    def test_v2ray_plugin_upstream_defaults_are_not_mihomo_defaults(self):
        node = parse_uri(ss(plugin="v2ray-plugin"))
        self.assertEqual(node["clash"]["plugin-opts"]["host"], "cloudfront.com")
        self.assertTrue(node["clash"]["plugin-opts"]["mux"])
        self.assertEqual(parse_uri(node["uri"]), node)
        with self.assertRaisesRegex(FormatError, "mux"):
            export_v2ray([node])

    def test_plugin_escaping_equals_and_comma(self):
        node = parse_uri(ss(plugin=r"v2ray-plugin;host=cdn.example;path=/ws?a\=b\,c;mux=0"))
        self.assertEqual(node["clash"]["plugin-opts"]["path"], "/ws?a=b,c")
        self.assertEqual(parse_uri(node["uri"]), node)
        self.assertEqual(len(parse_batch(export_v2ray([node]))["nodes"]), 1)

    def test_escaped_plugin_semicolon_and_colon_are_clash_only(self):
        for path, expected in ((r"/x\;y", "/x;y"), (r"/x\:y", "/x:y"), (r"/x\\y", r"/x\y")):
            with self.subTest(path=path):
                node = parse_uri(ss(plugin=f"v2ray-plugin;host=cdn.example;path={path};mux=0"))
                self.assertEqual(node["clash"]["plugin-opts"]["path"], expected)
                self.assertEqual(parse_uri(node["uri"]), node)
                with self.assertRaisesRegex(FormatError, "escaping"):
                    export_v2ray([node])

    def test_plugin_options_fail_closed(self):
        for plugin in (
            "", "unknown-plugin;tls", "obfs-local;obfs=http",
            "obfs-local;obfs=random;obfs-host=cdn.example",
            "obfs-local;obfs=http;obfs-host=cdn.example;extra=secret",
            "v2ray-plugin;server", "v2ray-plugin;mode=quic",
            "v2ray-plugin;cert=/not/to/be/read.pem",
            "v2ray-plugin;certRaw=secret", "v2ray-plugin;tls=false",
            "v2ray-plugin;mux=2", "v2ray-plugin;mux=-1",
            "v2ray-plugin;host=a;host=b", "v2ray-plugin;path=/x\\",
        ):
            with self.subTest(plugin=plugin):
                with self.assertRaises(FormatError):
                    parse_uri(ss(plugin=plugin))
        with self.assertRaises(FormatError):
            parse_uri(ss().partition("#")[0] + "?unsupported=something")


class BatchTests(unittest.TestCase):
    def test_partial_errors_preserve_physical_line_numbers(self):
        text = "# comment\n\n" + vless(name="kept") + "\r\nnot a share URI\n" + vmess() + "\nssr://bad\n"
        result = parse_batch(text)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual([error["line"] for error in result["errors"]], [4, 6])
        self.assertEqual(set(result), {"nodes", "errors", "duplicates"})
        self.assertTrue(all(set(error) == {"line", "message"} for error in result["errors"]))

    def test_base64_subscription_utf8_wrapping_missing_padding_and_bom(self):
        source = "\ufeff" + vless(name=UNICODE_NAME) + "\ninvalid line\n" + vmess()
        for urlsafe in (False, True):
            for padding in (False, True):
                encoded = b64(source, urlsafe, padding)
                wrapped = "\ufeff\n  " + "\r\n".join(encoded[i:i + 37] for i in range(0, len(encoded), 37))
                with self.subTest(urlsafe=urlsafe, padding=padding):
                    result = parse_batch(wrapped)
                    self.assertEqual(len(result["nodes"]), 2)
                    self.assertEqual(result["nodes"][0]["name"], UNICODE_NAME)
                    self.assertEqual(result["errors"][0]["line"], 2)

    def test_identity_ignores_names_and_query_and_json_key_order(self):
        first = vless({"type": "ws", "host": "cdn.example", "path": "/ws"}, name="first")
        second = vless({"path": "/ws", "host": "cdn.example", "type": "ws"}, name="second")
        vmess_one = vmess(ps="one")
        data = json.loads(base64.b64decode(vmess_one.partition("://")[2]))
        data = dict(reversed(list(data.items())))
        data["ps"] = "two"
        result = parse_batch("\n".join([first, second, vmess_one, "vmess://" + b64(json.dumps(data))]))
        self.assertEqual(result["duplicates"], 2)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(result["nodes"][0]["name"], "first")

    def test_identity_includes_transport_and_security_requirements(self):
        inputs = [
            vless(), vless({"security": "tls"}), vless({"type": "ws", "path": "/a"}),
            vless({"type": "ws", "path": "/b"}), vless({"type": "ws", "path": "/a", "host": "cdn.example"}),
            vmess(scy="auto"), vmess(scy="none"), ss(password="first"), ss(password="second"),
        ]
        result = parse_batch("\n".join(inputs))
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["nodes"]), len(inputs))
        self.assertEqual(result["duplicates"], 0)

    def test_two_invalid_plain_lines_remain_two_errors(self):
        result = parse_batch("bad\ninvalid")
        self.assertEqual([error["line"] for error in result["errors"]], [1, 2])

    def test_input_and_resource_limits(self):
        for value in (None, b"abc", {}, "x" * (MAX_BATCH_LENGTH + 1), "\n" * MAX_BATCH_LINES + "bad"):
            with self.subTest(kind=type(value).__name__):
                result = parse_batch(value)
                self.assertFalse(result["nodes"])
                self.assertTrue(result["errors"])
        result = parse_batch(vless() + "\n" + "x" * (MAX_URI_LENGTH + 1))
        self.assertEqual(len(result["nodes"]), 1)
        self.assertEqual(result["errors"][0]["line"], 2)

    def test_empty_and_comment_only_subscriptions(self):
        for value in ("", " \r\n\t", "\ufeff", "# heading\n\n# comment", b64(" \n")):
            with self.subTest(value=value):
                self.assertEqual(parse_batch(value), {"nodes": [], "errors": [], "duplicates": 0})

    def test_bad_utf8_and_nested_base64_do_not_get_silently_accepted(self):
        result = parse_batch(b64(b"\xff\xfe"))
        self.assertIn("UTF-8", result["errors"][0]["message"])
        result = parse_batch(b64(b64(vless())))
        self.assertFalse(result["nodes"])
        self.assertTrue(result["errors"])

    def test_errors_never_echo_credentials_uris_or_unknown_fields(self):
        secret = "SYNTHETIC-DO-NOT-ECHO"
        result = parse_batch(
            f"trojan://{secret}@example.com:bad\n"
            f"trojan://{secret}@example.com:443?{secret}=x\n"
            "vmess://" + b64(json.dumps({"secret": secret}))
        )
        self.assertEqual(len(result["errors"]), 3)
        self.assertNotIn(secret, json.dumps(result["errors"]))
        self.assertNotIn("trojan://", json.dumps(result["errors"]))


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            parse_uri(vless({"security": "tls"}, name="First")),
            parse_uri(vmess(ps="Second")),
            parse_uri("socks5://test-user:test-pass@example.com:1080#Third"),
            parse_uri(trojan(name="Fourth")),
            parse_uri(ss(name="Fifth")),
        ]

    def test_clash_is_a_complete_yaml_profile(self):
        config = yaml.safe_load(export_clash(self.nodes))
        self.assertEqual(config["mode"], "rule")
        self.assertEqual(config["mixed-port"], 7890)
        self.assertEqual(config["rules"], ["MATCH,PROXY"])
        self.assertEqual(len(config["proxies"]), 5)
        select, automatic = config["proxy-groups"]
        self.assertEqual(select["type"], "select")
        self.assertEqual(automatic["type"], "url-test")
        self.assertEqual(automatic["url"], "https://www.gstatic.com/generate_204")
        self.assertGreater(automatic["interval"], 0)
        available = {proxy["name"] for proxy in config["proxies"]}
        available.update(group["name"] for group in config["proxy-groups"])
        available.update({"DIRECT", "REJECT"})
        for group in config["proxy-groups"]:
            self.assertTrue(set(group["proxies"]) <= available)

    def test_clash_never_enables_lan_controller_tun_or_system_proxy(self):
        config = yaml.safe_load(export_clash(self.nodes))
        self.assertIs(config["allow-lan"], False)
        self.assertEqual(config["bind-address"], "127.0.0.1")
        for forbidden in ("external-controller", "external-controller-tls", "external-ui",
                          "secret", "tun", "system-proxy", "proxy-providers", "rule-providers"):
            self.assertNotIn(forbidden, config)

    def test_empty_exports_are_valid_and_do_not_automatically_go_direct(self):
        self.assertEqual(export_v2ray([]), "")
        config = yaml.safe_load(export_clash([]))
        self.assertEqual(config["proxies"], [])
        self.assertEqual(config["proxy-groups"][0]["proxies"][0], "AUTO")
        self.assertEqual(config["proxy-groups"][1]["proxies"], ["REJECT"])

    def test_custom_test_url_validation(self):
        url = "https://example.com/check?token=test-only"
        self.assertEqual(yaml.safe_load(export_clash([], url))["proxy-groups"][1]["url"], url)
        for invalid in ("file:///x", "ftp://example.com", "https://user:pass@example.com",
                        "https://example.com#fragment", "https://example.com:99999", "https://",
                        "https://example.com/\n", "https://example.com/a b", "https://example.com/%zz"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(FormatError):
                    export_clash([], invalid)

    def test_duplicate_and_reserved_names_are_unique_without_mutating_store(self):
        names = ["Same", "Same", "Same (2)", "PROXY", "AUTO", "DIRECT", "GLOBAL", "REJECT"]
        nodes = [parse_uri(vless(name=name, port=443 + index)) for index, name in enumerate(names)]
        before = copy.deepcopy(nodes)
        config = yaml.safe_load(export_clash(nodes))
        exported_names = [proxy["name"] for proxy in config["proxies"]]
        self.assertEqual(len(exported_names), len(set(exported_names)))
        self.assertEqual(exported_names[:3], ["Same", "Same (3)", "Same (2)"])
        self.assertFalse(set(exported_names) & {"PROXY", "AUTO", "DIRECT", "GLOBAL", "REJECT"})
        self.assertEqual(nodes, before)

    def test_long_duplicate_names_stay_within_limit(self):
        nodes = [parse_uri(vless(name="n" * MAX_NAME_LENGTH, port=443 + i)) for i in range(12)]
        names = [p["name"] for p in yaml.safe_load(export_clash(nodes))["proxies"]]
        self.assertEqual(len(set(names)), 12)
        self.assertTrue(all(len(name) <= MAX_NAME_LENGTH for name in names))

    def test_yaml_quoting_cannot_inject_configuration(self):
        name = "yes: [DIRECT] # !python/object"
        node = parse_uri(trojan(name=name, password="false: {a: b} # test-only"))
        config = yaml.safe_load(export_clash([node]))
        self.assertEqual(config["proxies"][0]["name"], name)
        self.assertEqual(config["proxies"][0]["password"], "false: {a: b} # test-only")
        self.assertNotIn("!python", export_clash([node]).splitlines()[0])

    def test_export_does_not_filter_enabled_or_group(self):
        for node in self.nodes:
            node["enabled"] = False
            node["group"] = "unselected"
        self.assertEqual(len(yaml.safe_load(export_clash(self.nodes))["proxies"]), len(self.nodes))
        self.assertEqual(len(parse_batch(export_v2ray(self.nodes))["nodes"]), len(self.nodes))

    def test_v2ray_export_is_utf8_base64_and_recognized_schemes(self):
        decoded = base64.b64decode(export_v2ray(self.nodes), validate=True).decode("utf-8")
        links = decoded.splitlines()
        self.assertEqual(len(links), len(self.nodes))
        self.assertEqual([uri.partition("://")[0] for uri in links],
                         ["vless", "vmess", "socks", "trojan", "ss"])
        self.assertFalse(decoded.endswith("\n"))
        result = parse_batch(decoded)
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["nodes"]), len(self.nodes))

    def test_current_names_are_used_in_both_exports_without_mutation(self):
        for index, node in enumerate(self.nodes):
            node["name"] = UNICODE_NAME + f" {index} + %41"
        before = copy.deepcopy(self.nodes)
        config = yaml.safe_load(export_clash(self.nodes))
        self.assertEqual([p["name"] for p in config["proxies"]], [n["name"] for n in self.nodes])
        result = parse_batch(export_v2ray(self.nodes))
        self.assertFalse(result["errors"])
        self.assertEqual([n["name"] for n in result["nodes"]], [n["name"] for n in self.nodes])
        self.assertEqual([without_name(n) for n in result["nodes"]], [without_name(n) for n in self.nodes])
        self.assertEqual(self.nodes, before)

    def test_vmess_name_is_rewritten_inside_json_not_as_a_fragment(self):
        node = parse_uri(vmess())
        node["name"] = UNICODE_NAME
        uri = base64.b64decode(export_v2ray([node])).decode()
        self.assertNotIn("#", uri)
        data = json.loads(base64.b64decode(uri.partition("://")[2]))
        self.assertEqual(data["ps"], UNICODE_NAME)

    def test_socks_export_uses_v2rayn_base64_credentials(self):
        node = parse_uri("socks5://test-user:p%3Aa%40ss@example.com:1080")
        uri = base64.b64decode(export_v2ray([node])).decode()
        auth = unquote(urlsplit(uri).netloc.split("@", 1)[0])
        auth += "=" * (-len(auth) % 4)
        self.assertEqual(base64.urlsafe_b64decode(auth).decode(), "test-user:p:a@ss")

    def test_export_preserves_reality_and_websocket_query_options(self):
        nodes = [
            parse_uri(vless({"security": "reality", "pbk": PUBLIC_KEY, "sid": "aabb",
                             "flow": "xtls-rprx-vision", "fp": "chrome"})),
            parse_uri(vless({"type": "ws", "path": "/a%2Fb?ed=2048&v=%2541",
                             "host": "cdn.example", "security": "tls", "alpn": "http/1.1"})),
        ]
        result = parse_batch(export_v2ray(nodes))
        self.assertFalse(result["errors"])
        self.assertEqual([without_name(n) for n in result["nodes"]], [without_name(n) for n in nodes])

    def test_export_rejects_invalid_or_stale_records(self):
        stale = copy.deepcopy(self.nodes[0])
        stale["clash"]["tls"] = False
        for nodes in (None, {}, [None], [{}], [{"uri": "https://example.com"}],
                      [stale], [{**self.nodes[0], "clash": None}],
                      [{**self.nodes[0], "port": 444}],
                      [{**self.nodes[0], "server": "another.example"}],
                      [{**self.nodes[0], "protocol": "trojan"}],
                      [{**self.nodes[0], "name": "bad\nname"}],
                      [{**self.nodes[0], "name": "x" * (MAX_NAME_LENGTH + 1)}]):
            with self.subTest(kind=type(nodes).__name__):
                with self.assertRaises(FormatError):
                    export_clash(nodes)
                with self.assertRaises(FormatError):
                    export_v2ray(nodes)

    def test_one_unexportable_node_prevents_partial_subscription(self):
        nodes = self.nodes + [parse_uri(ss(plugin="v2ray-plugin"))]
        with self.assertRaisesRegex(FormatError, "Node 6"):
            export_v2ray(nodes)

    def test_all_format_functions_are_offline(self):
        with patch.object(socket, "create_connection", side_effect=AssertionError("network call")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS call")):
            parse_uri(vless())
            parse_batch("\n".join(node["uri"] for node in self.nodes))
            export_clash(self.nodes)
            export_v2ray(self.nodes)


class MutationTests(unittest.TestCase):
    def test_deterministic_uri_mutations_never_escape_format_errors(self):
        rng = random.Random(20261028)
        seeds = [
            vless({"security": "tls", "type": "ws", "host": "cdn.example", "path": "/ws"}),
            vless({"security": "reality", "pbk": PUBLIC_KEY, "sid": "aabb", "fp": "chrome"}),
            vmess(net="grpc", path="Service", tls="tls"),
            "socks5://user:p%40ss@example.com:1080#Demo",
            "socks://" + b64("user:pass@example.com:1080"),
            ss(plugin="v2ray-plugin;host=cdn.example;path=/ws;mux=0"),
            trojan(password="test-only"),
        ]
        alphabet = "abcXYZ09%:/?#@=&+_-[] \t\n\\" + "\u8282"
        for index in range(1200):
            original = rng.choice(seeds)
            position = rng.randrange(len(original) + 1)
            mutation = rng.choice(alphabet)
            candidate = original[:position] + mutation + original[position + (index % 2):]
            with self.subTest(index=index):
                try:
                    node = parse_uri(candidate)
                except FormatError:
                    continue
                self.assertEqual(parse_uri(node["uri"]), node)
                self.assertEqual(yaml.safe_load(export_clash([node]))["proxies"][0]["server"],
                                 node["server"])


if __name__ == "__main__":
    unittest.main()
