"""Synthetic local-only tests for the on-demand testing slice."""

from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
import io
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import yaml

import node_desk.testing as testing
from node_desk.testing import NodeTester


ROOT = Path(__file__).resolve().parents[1]
CORE = Path(os.environ.get("NODE_DESK_TEST_CORE", ROOT / "vendor" / "mihomo.exe"))
USERNAME = "synthetic-test-user"
PASSWORD = "synthetic-test-password-not-a-real-secret"


def node(port=1080, identifier="node-1", name="Example", protocol="socks5", **updates):
    proxy = {"name": name, "type": protocol, "server": "127.0.0.1", "port": port}
    record = {
        "id": identifier, "name": name, "protocol": protocol,
        "server": "127.0.0.1", "port": port, "clash": proxy,
        "uri": "socks5://synthetic-share-link-must-not-be-returned",
        "extra": {"source": "test-only"},
    }
    record.update(updates)
    return record


def closed_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def eventually(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("Timed out waiting for the local test condition.")


def alive(pid):
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = testing._bind(
            kernel, "OpenProcess", wintypes.HANDLE,
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
        )
        handle = open_process(0x100000, False, pid)
        if not handle:
            return False
        try:
            return testing._wait_handle(handle, 0) == 258
        finally:
            testing._close_handle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class LocalServer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True

    def handle_error(self, request, client_address):
        self.errors.append(type(sys.exc_info()[1]).__name__)


@contextmanager
def serve(handler, **attributes):
    server = LocalServer(("127.0.0.1", 0), handler)
    server.stop = threading.Event()
    server.accepted = threading.Event()
    server.lock = threading.Lock()
    server.errors = []
    server.requests = []
    server.active = server.peak = 0
    server.authenticated = 0
    server.auth_rejected = threading.Event()
    server.status = 204
    server.delay = 0
    server.username = server.password = None
    server.__dict__.update(attributes)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.025),
        name="testing-local-server",
    )
    thread.start()
    try:
        yield server
    finally:
        server.stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if thread.is_alive():
            raise AssertionError("Local fixture server did not stop.")
        if server.errors:
            raise AssertionError(f"Unexpected fixture errors: {server.errors}")


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.accepted.set()
        self.request.settimeout(0.05)
        while not self.server.stop.is_set():
            try:
                if not self.request.recv(1024):
                    break
            except socket.timeout:
                continue
            except OSError:
                break


class HttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self):
        with self.server.lock:
            self.server.requests.append((self.command, self.path))
            self.server.active += 1
            self.server.peak = max(self.server.peak, self.server.active)
        try:
            self.server.accepted.set()
            self.server.stop.wait(self.server.delay)
            self.send_response(self.server.status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            if 300 <= self.server.status < 400:
                self.send_header("Location", "/must-not-follow")
            self.end_headers()
        except OSError:
            pass
        finally:
            with self.server.lock:
                self.server.active -= 1

    def log_message(self, *args):
        pass


class SocksHandler(socketserver.StreamRequestHandler):
    def read_exact(self, count):
        value = self.rfile.read(count)
        if len(value) != count:
            raise EOFError
        return value

    def handle(self):
        self.server.accepted.set()
        self.request.settimeout(0.3)
        try:
            version, count = self.read_exact(2)
            methods = self.read_exact(count)
            if version != 5:
                return
            authenticate = self.server.username is not None
            method = 2 if authenticate else 0
            if method not in methods:
                self.request.sendall(b"\x05\xff")
                return
            self.request.sendall(bytes((5, method)))
            if authenticate:
                version, size = self.read_exact(2)
                username = self.read_exact(size).decode("utf-8")
                password = self.read_exact(self.read_exact(1)[0]).decode("utf-8")
                if version != 1 or (username, password) != (self.server.username, self.server.password):
                    self.server.auth_rejected.set()
                    self.request.sendall(b"\x01\x01")
                    return
                self.request.sendall(b"\x01\x00")
            with self.server.lock:
                self.server.authenticated += 1
            version, command, _, kind = self.read_exact(4)
            if kind == 1:
                host = socket.inet_ntop(socket.AF_INET, self.read_exact(4))
            elif kind == 3:
                host = self.read_exact(self.read_exact(1)[0]).decode("ascii")
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, self.read_exact(16))
            else:
                return
            port = int.from_bytes(self.read_exact(2), "big")
            with self.server.lock:
                self.server.requests.append((host, port))
            if version != 5 or command != 1 or (host, port) != self.server.target:
                self.request.sendall(b"\x05\x02\x00\x01" + b"\0" * 6)
                return
            with socket.create_connection(self.server.target, timeout=0.5) as upstream:
                self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                while not self.server.stop.is_set():
                    readable, _, _ = select.select([self.request, upstream], [], [], 0.025)
                    for source in readable:
                        data = source.recv(16_384)
                        if not data:
                            return
                        destination = upstream if source is self.request else self.request
                        destination.sendall(data)
        except (EOFError, OSError):
            pass


@contextmanager
def background(tester, nodes, mode="proxy", callback=None):
    result = {"results": None, "error": None}

    def run():
        try:
            result["results"] = tester.run(nodes, mode=mode, on_result=callback)
        except BaseException as error:
            result["error"] = error

    thread = threading.Thread(target=run, name="testing-run-caller")
    thread.start()
    try:
        yield thread, result
    finally:
        if thread.is_alive():
            tester.cancel()
        thread.join(timeout=5)
        if thread.is_alive():
            raise AssertionError("Tester worker did not stop after cancellation.")


class TestingUnitTests(unittest.TestCase):
    def tearDown(self):
        self.assertFalse([thread.name for thread in threading.enumerate()
                          if thread.name.startswith("node-tester")])

    def test_constructor_and_call_validation(self):
        for timeout in (0, -1, 32768, True, 1.5):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                NodeTester(None, timeout_ms=timeout)
        for concurrency in (0, -1, 33, True, 1.5):
            with self.subTest(concurrency=concurrency), self.assertRaises(ValueError):
                NodeTester(None, concurrency=concurrency)
        for url in ("file:///tmp/a", "ftp://example.com", "", None, 2,
                    "https://user:secret@example.com", "https://example.com/#fragment",
                    "http://localhost:0", "https://example.com/\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                NodeTester(None, test_url=url)
        tester = NodeTester(None)
        with self.assertRaises(ValueError):
            tester.run([], mode="ping")
        with self.assertRaises(TypeError):
            tester.run([None])
        with self.assertRaises(TypeError):
            tester.run([], on_result=1)
        self.assertEqual(tester.run([]), [])

    def test_tcp_success_is_only_tcp_and_result_has_exact_public_shape(self):
        with serve(TcpHandler) as server:
            record = node(server.server_address[1])
            before = copy.deepcopy(record)
            result = NodeTester(None).run([record], mode="tcp")[0]
        self.assertEqual(record, before)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["mode"], "tcp")
        self.assertIn("only", result["message"])
        self.assertIn("not tested", result["message"])
        self.assertIs(type(result["latency_ms"]), int)
        self.assertEqual(set(result), {
            "node_id", "name", "mode", "status", "latency_ms", "message", "checked_at",
        })
        checked = datetime.fromisoformat(result["checked_at"])
        self.assertEqual(checked.utcoffset(), timezone.utc.utcoffset(checked))
        self.assertNotIn(record["uri"], json.dumps(result))

    def test_tcp_closed_port_and_invalid_endpoint(self):
        result = NodeTester(None, timeout_ms=300).run([node(closed_port())], mode="tcp")[0]
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["latency_ms"])
        self.assertIn("TCP", result["message"])
        for updates in ({"port": 0}, {"port": True}, {"server": "user:password@host"},
                        {"server": "\0"}, {"server": "bad host"}):
            result = NodeTester(None).run([node(**updates)], mode="tcp")[0]
            self.assertEqual(result["status"], "failed")

    def test_tcp_hostname_and_ipv6_loopback(self):
        with serve(TcpHandler) as server:
            record = node(server.server_address[1], server="localhost")
            result = NodeTester(None, timeout_ms=1500).run([record], mode="tcp")[0]
            self.assertEqual(result["status"], "ok")
        if socket.has_ipv6:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
                try:
                    listener.bind(("::1", 0))
                except OSError:
                    self.skipTest("IPv6 loopback is unavailable.")
                listener.listen()
                record = node(listener.getsockname()[1], server="::1")
                result = NodeTester(None).run([record], mode="tcp")[0]
                self.assertEqual(result["status"], "ok")

    def test_udp_tcp_mode_is_unsupported_without_connecting(self):
        with patch.object(testing, "_tcp_connect", side_effect=AssertionError("must not connect")):
            for protocol in ("hysteria", "hysteria2", "hy2", "tuic", "wireguard"):
                result = NodeTester(None).run([node(protocol=protocol)], mode="tcp")[0]
                self.assertEqual(result["status"], "unsupported")
                self.assertIn("TCP", result["message"])
            record = node(protocol="vmess")
            record["clash"]["network"] = "quic"
            self.assertEqual(NodeTester(None).run([record], mode="tcp")[0]["status"], "unsupported")

    def test_missing_core_has_no_tcp_fallback_and_leaves_no_files(self):
        with tempfile.TemporaryDirectory() as root:
            tester = NodeTester(Path(root) / "absent.exe", temp_root=root)
            with patch.object(testing, "_tcp_connect", side_effect=AssertionError("must not connect")):
                result = tester.run([node()])[0]
            self.assertEqual(result["status"], "unsupported")
            self.assertEqual(result["mode"], "proxy")
            self.assertEqual(list(Path(root).iterdir()), [])
            self.assertIsNone(tester.process_pid)

    def test_cancel_before_start_and_reuse(self):
        tester = NodeTester(None)
        tester.cancel()
        results = tester.run([node(), node(identifier="2")], mode="tcp")
        self.assertEqual([result["status"] for result in results], ["cancelled", "cancelled"])
        with serve(TcpHandler) as server:
            result = tester.run([node(server.server_address[1])], mode="tcp")[0]
            self.assertEqual(result["status"], "ok")

    def test_callback_thread_copies_order_and_once(self):
        with serve(TcpHandler) as server:
            records = [node(server.server_address[1], identifier=str(index)) for index in range(12)]
            seen = []
            caller = threading.get_ident()

            def callback(result):
                self.assertEqual(threading.get_ident(), caller)
                seen.append(result["node_id"])
                result["status"] = "modified-by-callback"

            results = NodeTester(None, concurrency=3).run(records, mode="tcp", on_result=callback)
        self.assertEqual([result["node_id"] for result in results], list(map(str, range(12))))
        self.assertCountEqual(seen, list(map(str, range(12))))
        self.assertTrue(all(result["status"] == "ok" for result in results))

    def test_bounded_submission_cancellation_and_concurrent_run_rejected(self):
        started = threading.Event()
        tester = NodeTester(None, concurrency=2)
        active = []

        def block(record, deadline, cancel):
            active.append(record["id"])
            if len(active) == 2:
                started.set()
            cancel.wait(2)
            testing._check_cancel(cancel)
            raise AssertionError("Cancellation did not reach TCP worker.")

        with patch.object(testing, "_tcp_connect", side_effect=block):
            with background(tester, [node(identifier=str(index)) for index in range(30)], "tcp") as (thread, state):
                self.assertTrue(started.wait(2))
                with self.assertRaises(RuntimeError):
                    tester.run([], mode="tcp")
                start = time.monotonic()
                tester.cancel()
                thread.join(timeout=2)
                self.assertLess(time.monotonic() - start, 1)
                self.assertIsNone(state["error"])
                self.assertEqual(len(active), 2)
                self.assertEqual(len(state["results"]), 30)
                self.assertTrue(all(result["status"] == "cancelled" for result in state["results"]))

    def test_callback_failure_cancels_pending_workers_and_is_sanitized(self):
        with serve(TcpHandler) as server:
            tester = NodeTester(None, concurrency=2)

            def callback(result):
                raise RuntimeError(PASSWORD)

            with self.assertRaisesRegex(RuntimeError, "^Result callback failed.$"):
                tester.run([node(server.server_address[1])] * 20, mode="tcp", on_result=callback)
            self.assertFalse(tester._cancel.is_set())
            self.assertEqual(tester.run([], mode="tcp"), [])

    def test_core_environment_does_not_mutate_parent(self):
        injected = {
            "CLASH_CONFIG_STRING": PASSWORD, "CLASH_POST_UP": PASSWORD,
            "CLASH_POST_DOWN": PASSWORD, "MIHOMO_TEST": PASSWORD,
            "HTTPS_PROXY": PASSWORD, "http_proxy": PASSWORD, "ALL_PROXY": PASSWORD,
            "NO_PROXY": PASSWORD, "SSLKEYLOGFILE": PASSWORD,
        }
        with patch.dict(os.environ, injected):
            environment = testing._core_environment()
            for key in injected:
                self.assertNotIn(key, environment)
                self.assertEqual(os.environ[key], PASSWORD)

    def test_private_configuration_is_inbound_free_and_names_are_unique(self):
        tester = NodeTester(None)
        record = node(name="name /? # %")
        before = copy.deepcopy(record)
        first = tester._prepare_proxy(record, 0)
        second = tester._prepare_proxy(record, 1)
        self.assertNotEqual(first["name"], second["name"])
        self.assertNotIn(record["name"], first["name"])
        self.assertEqual(record, before)
        config = testing._configuration([first, second], PASSWORD)
        for key in ("port", "socks-port", "mixed-port", "redir-port", "tproxy-port"):
            self.assertEqual(config[key], 0)
        self.assertEqual(config["external-controller"], "127.0.0.1:0")
        for key in ("dns", "tun", "sniffer", "ntp", "tuic-server"):
            self.assertFalse(config[key]["enable"])
        self.assertEqual(config["rules"], ["MATCH,REJECT"])
        self.assertEqual(config["proxy-providers"], {})
        self.assertFalse(config["geo-auto-update"])
        self.assertEqual(config["external-controller-pipe"], "")
        self.assertEqual(config["external-controller-unix"], "")
        self.assertNotIn("uri:", yaml.safe_dump(config))

    def test_dangerous_or_mismatched_proxy_definitions_fail_closed(self):
        records = []
        for field, value in (("type", "direct"), ("dialer-proxy", "user-group"),
                             ("interface-name", "Ethernet"), ("routing-mark", 3),
                             ("plugin", "external-command"), ("port", 1234)):
            record = node()
            record["clash"][field] = value
            records.append(record)
        results = NodeTester(None).run(records)
        self.assertTrue(all(result["status"] in {"failed", "unsupported"} for result in results))

    def test_error_categories_never_include_raw_credentials(self):
        for code, text, category in (
            (503, "authentication failed", "authentication"),
            (503, "x509 certificate error", "TLS"),
            (503, "connection refused", "unreachable"),
            (504, "private token", "timed out"),
            (401, "unauthorized", "controller"),
            (503, "An error occurred in the delay test", "handshake"),
        ):
            error = testing._api_error(code, (text + " " + PASSWORD).encode())
            self.assertIn(category, str(error))
            self.assertNotIn(PASSWORD, str(error))
        result = NodeTester(None).run([node(name="socks5://user:secret@example.com")])[0]
        self.assertEqual(result["name"], "Node")

    def test_http_status_verification_fails_closed(self):
        tester = NodeTester(None, test_url="http://127.0.0.1:1/204")
        cases = [
            ({"delay": 12}, {"extra": {tester.test_url: {"alive": True, "history": [{"delay": 12}]}}}, "ok"),
            ({"delay": 12}, {"extra": {tester.test_url: {"alive": False, "history": [{"delay": 0}]}}}, "failed"),
            ({"delay": 12}, {"alive": True, "history": [{"delay": 12}]}, "failed"),
            ({"delay": 12}, {"extra": {tester.test_url: {"alive": True, "history": [{"delay": 13}]}}}, "failed"),
            ({"delay": 0}, {}, "failed"),
            ({"delay": True}, {}, "failed"),
        ]
        for delay, detail, expected in cases:
            with self.subTest(expected=expected, delay=delay):
                with patch.object(tester, "_request", side_effect=[delay, detail]) as request:
                    result = tester._test_one(node(), "proxy", "safe-name")
                    self.assertEqual(result["status"], expected)
                    query = parse_qs(urlsplit(request.call_args_list[0].args[0]).query)
                    self.assertEqual(query["expected"], ["204"])

    def test_controller_redirect_is_never_followed(self):
        handler = testing._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "", {}, "http://example.com"))

    @unittest.skipUnless(os.name == "nt", "Windows DNS cancellation")
    def test_windows_dns_cancellation_completes_and_frees_native_query(self):
        cancel = threading.Event()
        captured = {}
        set_event = testing._bind(testing._kernel, "SetEvent", ctypes.c_int, ctypes.c_void_p)

        def pending(host, service, namespace, provider, hints, result, timeout, overlapped, callback, handle):
            captured["event"] = overlapped._obj.event
            cancel.set()
            return 997

        def complete(handle):
            set_event(captured["event"])
            return 0

        start = time.monotonic()
        with patch.object(testing, "_get_addr_info", side_effect=pending):
            with patch.object(testing, "_cancel_addr_info", side_effect=complete) as cancelled:
                with self.assertRaises(testing._Cancelled):
                    testing._resolve_windows("synthetic.invalid", 443, time.monotonic() + 2, cancel)
                cancelled.assert_called_once()
        self.assertLess(time.monotonic() - start, 0.5)


@unittest.skipUnless(CORE.is_file(), "Local pinned Mihomo core is not available.")
class MihomoIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.pids = []

    def tearDown(self):
        if self.root.exists():
            self.assertEqual(list(self.root.iterdir()), [], "Private temporary home was not removed.")
        for pid in self.pids:
            self.assertFalse(alive(pid), "Private Mihomo process outlived the test.")
        self.assertFalse([thread.name for thread in threading.enumerate()
                          if thread.name.startswith("node-tester")])

    def make_tester(self, target, **kwargs):
        return NodeTester(
            CORE, temp_root=self.root,
            test_url=f"http://127.0.0.1:{target.server_address[1]}/generate_204", **kwargs,
        )

    def capture(self, tester):
        def callback(result):
            pid = tester.process_pid
            if pid is not None:
                self.pids.append(pid)
        return callback

    def authenticated_node(self, server, **updates):
        record = node(server.server_address[1], **updates)
        record["clash"].update(username=USERNAME, password=PASSWORD)
        return record

    def test_authenticated_socks_success_real_head_and_cleanup(self):
        with serve(HttpHandler) as target:
            with serve(SocksHandler, target=target.server_address, username=USERNAME, password=PASSWORD) as socks:
                record = self.authenticated_node(socks, name="Duplicate / ? # %")
                before = copy.deepcopy(record)
                tester = self.make_tester(target, timeout_ms=2000)
                results = tester.run([record, record], on_result=self.capture(tester))
                self.assertEqual([result["status"] for result in results], ["ok", "ok"])
                self.assertEqual(record, before)
                self.assertEqual(socks.authenticated, 2)
                self.assertEqual(len(socks.requests), 2)
                self.assertEqual(target.requests, [("HEAD", "/generate_204")] * 2)
                self.assertNotIn(PASSWORD, json.dumps(results))
                self.assertIsNone(tester.process_pid)
                self.assertTrue(self.pids)

    def test_bad_socks_auth_never_counts_as_success(self):
        with serve(HttpHandler) as target:
            with serve(SocksHandler, target=target.server_address, username=USERNAME, password=PASSWORD) as socks:
                record = self.authenticated_node(socks)
                record["clash"]["password"] = "incorrect-synthetic-password"
                tester = self.make_tester(target, timeout_ms=1500)
                result = tester.run([record], on_result=self.capture(tester))[0]
                self.assertEqual(result["status"], "failed")
                self.assertTrue(socks.auth_rejected.is_set())
                self.assertEqual(target.requests, [])
                self.assertIn("authentication", result["message"].lower())
                self.assertIn("cannot distinguish", result["message"])
                self.assertNotIn("incorrect-synthetic-password", json.dumps(result))

    def test_closed_socks_port_identifies_unreachable_endpoint(self):
        with serve(HttpHandler) as target:
            tester = self.make_tester(target, timeout_ms=1500)
            result = tester.run([node(closed_port())], on_result=self.capture(tester))[0]
            self.assertEqual(result["status"], "failed")
            # A closed loopback port is normally refused immediately; some
            # security suites drop loopback SYNs instead, surfacing the
            # timeout message. Both identify the endpoint as not reachable.
            self.assertTrue(
                "unreachable" in result["message"] or "timed out" in result["message"],
                result["message"],
            )
            self.assertEqual(target.requests, [])

    def test_wrong_target_status_and_redirect_are_not_success(self):
        for status in (200, 301, 404, 500):
            with self.subTest(status=status), serve(HttpHandler, status=status) as target:
                with serve(SocksHandler, target=target.server_address) as socks:
                    tester = self.make_tester(target, timeout_ms=1500)
                    result = tester.run([node(socks.server_address[1])], on_result=self.capture(tester))[0]
                    self.assertEqual(result["status"], "failed")
                    self.assertIn("expected HTTP status (204)", result["message"])
                    self.assertEqual(target.requests, [("HEAD", "/generate_204")])
                    self.assertEqual(list(self.root.iterdir()), [])

    def test_tcp_only_acceptor_is_not_a_working_proxy(self):
        with serve(HttpHandler) as target, serve(TcpHandler) as endpoint:
            tester = self.make_tester(target, timeout_ms=250)
            record = node(endpoint.server_address[1])
            self.assertEqual(tester.run([record], mode="tcp")[0]["status"], "ok")
            start = time.monotonic()
            result = tester.run([record], on_result=self.capture(tester))[0]
            self.assertEqual(result["status"], "failed")
            self.assertLess(time.monotonic() - start, 3)
            self.assertEqual(target.requests, [])

    def test_cancel_active_core_and_queued_nodes_joins_everything(self):
        with serve(HttpHandler, delay=3) as target:
            with serve(SocksHandler, target=target.server_address) as socks:
                tester = self.make_tester(target, timeout_ms=8000, concurrency=2)
                records = [node(socks.server_address[1], identifier=str(index)) for index in range(12)]
                with background(tester, records) as (thread, state):
                    self.assertTrue(target.accepted.wait(3))
                    self.pids.append(tester.process_pid)
                    start = time.monotonic()
                    tester.cancel()
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())
                    self.assertLess(time.monotonic() - start, 1.5)
                    self.assertIsNone(state["error"])
                    self.assertEqual(len(state["results"]), 12)
                    self.assertTrue(all(result["status"] == "cancelled" for result in state["results"]))
                    self.assertIsNone(tester.process_pid)

    def test_cancel_during_controller_startup(self):
        with serve(HttpHandler) as target:
            tester = self.make_tester(target)
            with patch.object(testing, "_controller_port", return_value=None):
                with background(tester, [node()]) as (thread, state):
                    self.pids.append(eventually(lambda: tester.process_pid))
                    tester.cancel()
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())
                    self.assertIsNone(state["error"])
                    self.assertEqual(state["results"][0]["status"], "cancelled")

    def test_callback_exception_reaps_real_core(self):
        with serve(HttpHandler) as target:
            with serve(SocksHandler, target=target.server_address) as socks:
                tester = self.make_tester(target, concurrency=1, timeout_ms=1000)

                def fail(result):
                    self.pids.append(tester.process_pid)
                    raise ValueError(PASSWORD)

                with self.assertRaisesRegex(RuntimeError, "^Result callback failed.$"):
                    tester.run([node(socks.server_address[1])] * 4, on_result=fail)
                self.assertIsNone(tester.process_pid)

    def test_concurrency_cap_with_real_proxy_requests(self):
        with serve(HttpHandler, delay=0.12) as target:
            with serve(SocksHandler, target=target.server_address) as socks:
                tester = self.make_tester(target, concurrency=2, timeout_ms=1500)
                results = tester.run(
                    [node(socks.server_address[1], identifier=str(index)) for index in range(7)],
                    on_result=self.capture(tester),
                )
                self.assertTrue(all(result["status"] == "ok" for result in results))
                self.assertLessEqual(target.peak, 2)
                self.assertEqual(target.peak, 2)

    def test_environment_proxy_and_clash_overrides_are_ignored(self):
        injected = {
            "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "",
            "CLASH_CONFIG_STRING": "not-base64",
            "CLASH_OVERRIDE_SECRET": "wrong-private-controller-secret",
            "CLASH_POST_UP": "exit 73", "CLASH_POST_DOWN": "exit 73",
        }
        with serve(HttpHandler) as target:
            with serve(SocksHandler, target=target.server_address) as socks:
                tester = self.make_tester(target, timeout_ms=1500)
                with patch.dict(os.environ, injected):
                    with patch("urllib.request.getproxies", side_effect=AssertionError("must not detect proxies")):
                        result = tester.run([node(socks.server_address[1])], on_result=self.capture(tester))[0]
                    self.assertEqual(os.environ["CLASH_CONFIG_STRING"], "not-base64")
                self.assertEqual(result["status"], "ok")

    def test_core_config_error_is_sanitized_and_reaped(self):
        with serve(HttpHandler) as target:
            tester = self.make_tester(target, timeout_ms=1000)
            record = node(protocol="ss")
            record["clash"].update(cipher="invalid-synthetic-cipher", password=PASSWORD)
            result = tester.run([record])[0]
            self.assertEqual(result["status"], "failed")
            self.assertIn("configuration", result["message"])
            self.assertNotIn(PASSWORD, json.dumps(result))
            self.assertIsNone(tester.process_pid)

    def test_controller_ownership_no_other_process_is_terminated(self):
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        sentinel = subprocess.Popen(
            [sys.executable, "-B", "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags,
        )
        try:
            with serve(HttpHandler) as target:
                with serve(SocksHandler, target=target.server_address) as socks:
                    tester = self.make_tester(target, timeout_ms=1000)

                    def inspect(result):
                        pid = tester.process_pid
                        self.pids.append(pid)
                        self.assertNotEqual(pid, sentinel.pid)
                        self.assertEqual(testing._controller_port(pid), urlsplit(tester._controller).port)
                        self.assertIsNone(testing._controller_port(sentinel.pid))
                        self.assertIsNone(sentinel.poll())

                    result = tester.run([node(socks.server_address[1])], on_result=inspect)[0]
                    self.assertEqual(result["status"], "ok")
                    self.assertIsNone(sentinel.poll())
        finally:
            sentinel.terminate()
            sentinel.wait(timeout=3)

    @unittest.skipUnless(os.name == "nt", "Windows atomic Job Object")
    def test_windows_job_setup_failure_does_not_launch_unprotected_core(self):
        with serve(HttpHandler) as target:
            tester = self.make_tester(target)
            with patch.object(testing, "_update_attributes", return_value=False):
                with patch.object(testing, "_create_process") as create_process:
                    result = tester.run([node()])[0]
                    self.assertEqual(result["status"], "failed")
                    create_process.assert_not_called()
                    self.assertIsNone(tester.process_pid)

    @unittest.skipUnless(os.name == "nt", "Windows kill-on-parent-crash")
    def test_parent_crash_kills_job_and_deletes_credential_input(self):
        with serve(HttpHandler) as target:
            with serve(SocksHandler, target=target.server_address, username=USERNAME, password=PASSWORD) as socks:
                record = self.authenticated_node(socks)
                # This child intentionally bypasses Python finally/atexit handlers.
                script = (
                    "import json,os,sys\n"
                    "from node_desk.testing import NodeTester\n"
                    "tester=NodeTester(sys.argv[1],temp_root=sys.argv[2],test_url=sys.argv[3])\n"
                    "def crash(result):\n"
                    " print(tester.process_pid,flush=True)\n"
                    " os._exit(0 if result['status']=='ok' else 7)\n"
                    "tester.run([json.loads(sys.argv[4])],on_result=crash)\n"
                )
                child = subprocess.Popen(
                    [sys.executable, "-B", "-c", script, str(CORE), str(self.root),
                     f"http://127.0.0.1:{target.server_address[1]}/generate_204", json.dumps(record)],
                    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                try:
                    output, error = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, 0, "Crash fixture could not complete its local proxy test.")
                    self.assertEqual(error, b"")
                    pid = int(output.strip())
                    self.pids.append(pid)
                    eventually(lambda: not alive(pid))
                    for file in self.root.rglob("*"):
                        if file.is_file():
                            content = file.read_bytes()
                            self.assertNotIn(PASSWORD.encode(), content)
                            self.assertNotIn(b"external-controller:", content)
                            self.assertNotIn(b"secret:", content)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=3)
                    # A hard crash may leave a noncredential cache/home. This
                    # fixture owns and normally removes the enclosing directory.
                    self.temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
