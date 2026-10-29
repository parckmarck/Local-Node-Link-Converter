"""On-demand TCP checks and isolated Mihomo HTTP checks, without a Qt dependency.

``run`` is blocking. Call it on a worker thread, marshal callbacks to the UI,
and call ``cancel`` followed by joining that worker when closing the window.
No user controller, system proxy, or installed proxy configuration is used.
"""

from __future__ import annotations

import ctypes as ct
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import yaml

__all__ = ["NodeTester"]

_CORE_VERSION = "v1.19.33"
_STARTUP_SECONDS = 5.0
_TICK = 0.025
_MAX_RESPONSE = 65_536
_PROXY_TYPES = {
    "ss", "ssr", "vmess", "vless", "trojan", "socks5", "http",
    "hysteria", "hysteria2", "tuic", "anytls", "snell",
}
_UDP_TYPES = {"hysteria", "hysteria2", "hy2", "tuic", "wireguard", "quic", "masque"}
_CONNECT_PENDING = {
    errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
    10035, 10036, 10037,
}


class _Cancelled(Exception):
    pass


class _Failure(Exception):
    def __init__(self, message: str, status: str = "failed"):
        super().__init__(message)
        self.status = status


class _ApiFailure(_Failure):
    def __init__(self, message: str, *, diagnostic: bool = False):
        super().__init__(message)
        self.diagnostic = diagnostic


def _check_cancel(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise _Cancelled


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _core_environment() -> dict[str, str]:
    # CLASH_CONFIG_STRING and CLASH_POST_UP would otherwise override isolation.
    return {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith(("CLASH_", "MIHOMO_"))
        and not key.upper().endswith("_PROXY")
        and key.upper() not in {"SSLKEYLOGFILE", "KEYLOGFILE"}
    }


if os.name == "nt":
    import msvcrt
    from ctypes import wintypes as wt

    _kernel = ct.WinDLL("kernel32", use_last_error=True)

    def _bind(dll, name, result, *arguments):
        function = getattr(dll, name)
        function.restype = result
        function.argtypes = arguments
        return function

    _close_handle = _bind(_kernel, "CloseHandle", wt.BOOL, wt.HANDLE)
    _wait_handle = _bind(_kernel, "WaitForSingleObject", wt.DWORD, wt.HANDLE, wt.DWORD)
    _create_event = _bind(
        _kernel, "CreateEventW", wt.HANDLE, ct.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR
    )

    class _JobBasic(ct.Structure):
        _fields_ = [
            ("process_time", ct.c_int64), ("job_time", ct.c_int64),
            ("flags", wt.DWORD), ("min_working_set", ct.c_size_t),
            ("max_working_set", ct.c_size_t), ("active_processes", wt.DWORD),
            ("affinity", ct.c_size_t), ("priority", wt.DWORD),
            ("scheduling", wt.DWORD),
        ]

    class _JobLimits(ct.Structure):
        _fields_ = [
            ("basic", _JobBasic), ("io_counters", ct.c_uint64 * 6),
            ("process_memory", ct.c_size_t), ("job_memory", ct.c_size_t),
            ("peak_process_memory", ct.c_size_t), ("peak_job_memory", ct.c_size_t),
        ]

    class _StartupInfo(ct.Structure):
        _fields_ = [
            ("cb", wt.DWORD), ("reserved", wt.LPWSTR), ("desktop", wt.LPWSTR),
            ("title", wt.LPWSTR), ("x", wt.DWORD), ("y", wt.DWORD),
            ("x_size", wt.DWORD), ("y_size", wt.DWORD),
            ("x_chars", wt.DWORD), ("y_chars", wt.DWORD),
            ("fill", wt.DWORD), ("flags", wt.DWORD),
            ("show", wt.WORD), ("reserved_size", wt.WORD),
            ("reserved_bytes", ct.c_void_p), ("stdin", wt.HANDLE),
            ("stdout", wt.HANDLE), ("stderr", wt.HANDLE),
        ]

    class _StartupInfoEx(ct.Structure):
        _fields_ = [("startup", _StartupInfo), ("attributes", ct.c_void_p)]

    class _ProcessInfo(ct.Structure):
        _fields_ = [
            ("process", wt.HANDLE), ("thread", wt.HANDLE),
            ("pid", wt.DWORD), ("tid", wt.DWORD),
        ]

    _create_job = _bind(_kernel, "CreateJobObjectW", wt.HANDLE, ct.c_void_p, wt.LPCWSTR)
    _set_job = _bind(
        _kernel, "SetInformationJobObject", wt.BOOL,
        wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD,
    )
    _terminate_job = _bind(_kernel, "TerminateJobObject", wt.BOOL, wt.HANDLE, wt.UINT)
    _init_attributes = _bind(
        _kernel, "InitializeProcThreadAttributeList", wt.BOOL,
        ct.c_void_p, wt.DWORD, wt.DWORD, ct.POINTER(ct.c_size_t),
    )
    _update_attributes = _bind(
        _kernel, "UpdateProcThreadAttribute", wt.BOOL,
        ct.c_void_p, wt.DWORD, ct.c_size_t, ct.c_void_p, ct.c_size_t,
        ct.c_void_p, ct.c_void_p,
    )
    _delete_attributes = _bind(
        _kernel, "DeleteProcThreadAttributeList", None, ct.c_void_p
    )
    _create_process = _bind(
        _kernel, "CreateProcessW", wt.BOOL, wt.LPCWSTR, wt.LPWSTR,
        ct.c_void_p, ct.c_void_p, wt.BOOL, wt.DWORD, ct.c_void_p,
        wt.LPCWSTR, ct.POINTER(_StartupInfoEx), ct.POINTER(_ProcessInfo),
    )
    _get_exit_code = _bind(
        _kernel, "GetExitCodeProcess", wt.BOOL, wt.HANDLE, ct.POINTER(wt.DWORD)
    )

    class _WindowsProcess:
        """Create inside a kill-on-close job atomically (Windows 10 or later)."""

        def __init__(self, args, cwd, stdin, env):
            self._job = _create_job(None, None)
            self._process = None
            if not self._job:
                raise ct.WinError(ct.get_last_error())
            attributes = None
            initialized = False
            try:
                limits = _JobLimits()
                limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                if not _set_job(self._job, 9, ct.byref(limits), ct.sizeof(limits)):
                    raise ct.WinError(ct.get_last_error())
                size = ct.c_size_t()
                _init_attributes(None, 2, 0, ct.byref(size))
                attributes = ct.create_string_buffer(size.value)
                if not _init_attributes(attributes, 2, 0, ct.byref(size)):
                    raise ct.WinError(ct.get_last_error())
                initialized = True
                jobs = (wt.HANDLE * 1)(self._job)
                if not _update_attributes(
                    attributes, 0, 0x2000D, jobs, ct.sizeof(jobs), None, None
                ):
                    raise ct.WinError(ct.get_last_error())
                with open(os.devnull, "wb") as output:
                    handles = (wt.HANDLE * 2)(
                        msvcrt.get_osfhandle(stdin.fileno()),
                        msvcrt.get_osfhandle(output.fileno()),
                    )
                    old_flags = [os.get_handle_inheritable(handle) for handle in handles]
                    try:
                        for handle in handles:
                            os.set_handle_inheritable(handle, True)
                        if not _update_attributes(
                            attributes, 0, 0x20002, handles, ct.sizeof(handles), None, None
                        ):
                            raise ct.WinError(ct.get_last_error())
                        startup = _StartupInfoEx()
                        startup.startup.cb = ct.sizeof(startup)
                        startup.startup.flags = 0x100  # STARTF_USESTDHANDLES
                        startup.startup.stdin = handles[0]
                        startup.startup.stdout = startup.startup.stderr = handles[1]
                        startup.attributes = ct.addressof(attributes)
                        info = _ProcessInfo()
                        command = ct.create_unicode_buffer(subprocess.list2cmdline(args))
                        environment = ct.create_unicode_buffer(
                            "\0".join(f"{key}={env[key]}" for key in sorted(env, key=str.upper))
                            + "\0"
                        )
                        if not _create_process(
                            args[0], command, None, None, True,
                            0x08000000 | 0x00080000 | 0x00000400,
                            environment, str(cwd), ct.byref(startup), ct.byref(info),
                        ):
                            raise ct.WinError(ct.get_last_error())
                        self._process, self.pid = info.process, info.pid
                        _close_handle(info.thread)
                    finally:
                        for handle, flag in zip(handles, old_flags):
                            os.set_handle_inheritable(handle, flag)
            except BaseException:
                self.close()
                raise
            finally:
                if initialized:
                    _delete_attributes(attributes)

        def poll(self):
            if _wait_handle(self._process, 0) == 258:
                return None
            code = wt.DWORD()
            if not _get_exit_code(self._process, ct.byref(code)):
                raise ct.WinError(ct.get_last_error())
            return code.value

        def terminate(self):
            if self.poll() is None and not _terminate_job(self._job, 1):
                if self.poll() is None:
                    raise ct.WinError(ct.get_last_error())

        kill = terminate

        def wait(self, timeout):
            if _wait_handle(self._process, max(1, int(timeout * 1000))) == 258:
                raise subprocess.TimeoutExpired("private Mihomo", timeout)
            return self.poll()

        def close(self):
            if self._job:
                _close_handle(self._job)
                self._job = None
            if self._process:
                _close_handle(self._process)
                self._process = None

    class _AddrInfo(ct.Structure):
        pass

    _AddrInfo._fields_ = [
        ("flags", ct.c_int), ("family", ct.c_int), ("socktype", ct.c_int),
        ("protocol", ct.c_int), ("addrlen", ct.c_size_t),
        ("canonname", wt.LPWSTR), ("addr", ct.c_void_p),
        ("blob", ct.c_void_p), ("bloblen", ct.c_size_t),
        ("provider", ct.c_void_p), ("next", ct.POINTER(_AddrInfo)),
    ]

    class _Overlapped(ct.Structure):
        _fields_ = [
            ("internal", ct.c_size_t), ("internal_high", ct.c_size_t),
            ("offset", wt.DWORD), ("offset_high", wt.DWORD), ("event", wt.HANDLE),
        ]

    class _Timeval(ct.Structure):
        _fields_ = [("seconds", ct.c_long), ("microseconds", ct.c_long)]

    _winsock = ct.WinDLL("ws2_32", use_last_error=True)
    _get_addr_info = _bind(
        _winsock, "GetAddrInfoExW", ct.c_int, wt.LPCWSTR, wt.LPCWSTR,
        wt.DWORD, ct.c_void_p, ct.POINTER(_AddrInfo),
        ct.POINTER(ct.POINTER(_AddrInfo)), ct.POINTER(_Timeval),
        ct.POINTER(_Overlapped), ct.c_void_p, ct.POINTER(wt.HANDLE),
    )
    _cancel_addr_info = _bind(
        _winsock, "GetAddrInfoExCancel", ct.c_int, ct.POINTER(wt.HANDLE)
    )
    _addr_info_result = _bind(
        _winsock, "GetAddrInfoExOverlappedResult", ct.c_int, ct.POINTER(_Overlapped)
    )
    _free_addr_info = _bind(
        _winsock, "FreeAddrInfoExW", None, ct.POINTER(_AddrInfo)
    )
    _tcp_table = _bind(
        ct.WinDLL("iphlpapi"), "GetExtendedTcpTable", wt.DWORD,
        ct.c_void_p, ct.POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ct.c_int, wt.ULONG,
    )


def _private_directory(path: str) -> None:
    if os.name != "nt":
        os.chmod(path, 0o700)
        return
    security = ct.WinDLL("advapi32", use_last_error=True)
    convert = _bind(
        security, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        wt.BOOL, wt.LPCWSTR, wt.DWORD, ct.POINTER(ct.c_void_p), ct.c_void_p,
    )
    set_security = _bind(
        security, "SetFileSecurityW", wt.BOOL, wt.LPCWSTR, wt.DWORD, ct.c_void_p
    )
    free = _bind(_kernel, "LocalFree", ct.c_void_p, ct.c_void_p)
    descriptor = ct.c_void_p()
    # Only the owner and SYSTEM; children inherit these protected permissions.
    if not convert("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)", 1, ct.byref(descriptor), None):
        raise ct.WinError(ct.get_last_error())
    try:
        if not set_security(path, 0x80000004, descriptor):
            raise ct.WinError(ct.get_last_error())
    finally:
        free(descriptor)


def _controller_port(pid: int) -> int | None:
    """Only return an IPv4 loopback listener owned by the child process."""
    ports = []
    if os.name == "nt":
        size = wt.DWORD()
        _tcp_table(None, ct.byref(size), False, socket.AF_INET, 3, 0)
        for _ in range(3):
            table = ct.create_string_buffer(size.value)
            code = _tcp_table(table, ct.byref(size), False, socket.AF_INET, 3, 0)
            if code == 122:
                continue
            if code:
                raise OSError("Cannot inspect private controller ownership.")
            count = struct.unpack_from("<I", table)[0]
            for index in range(count):
                _, address, port, _, _, owner = struct.unpack_from(
                    "<6I", table, 4 + 24 * index
                )
                # Table class 3 already selects listeners. Some Windows
                # providers return zero in the otherwise redundant state field.
                if owner == pid and address == 0x0100007F:
                    ports.append(socket.ntohs(port & 0xFFFF))
            break
    elif sys.platform.startswith("linux"):
        try:
            sockets = {
                os.readlink(item) for item in Path(f"/proc/{pid}/fd").iterdir()
            }
            with open("/proc/net/tcp", encoding="ascii") as table:
                for line in table:
                    fields = line.split()
                    if len(fields) > 9 and fields[3] == "0A":
                        address, port = fields[1].split(":")
                        if address == "0100007F" and f"socket:[{fields[9]}]" in sockets:
                            ports.append(int(port, 16))
        except FileNotFoundError:
            return None
    else:
        raise _Failure("Private controller discovery requires Windows or Linux.", "unsupported")
    if len(ports) > 1:
        raise _Failure("Private core exposed unexpected additional listeners.")
    return ports[0] if ports else None


def _resolve_windows(host, port, deadline, cancel):
    event = _create_event(None, True, False, None)
    if not event:
        raise OSError("Cannot create DNS completion event.")
    result = ct.POINTER(_AddrInfo)()
    overlapped = _Overlapped()
    overlapped.event = event
    handle = wt.HANDLE()
    hints = _AddrInfo()
    hints.socktype, hints.protocol = socket.SOCK_STREAM, socket.IPPROTO_TCP
    remaining = _remaining(deadline)
    timeout = _Timeval(int(remaining), int(remaining % 1 * 1_000_000))
    try:
        code = _get_addr_info(
            host, str(port), 12, None, ct.byref(hints), ct.byref(result),
            ct.byref(timeout), ct.byref(overlapped), None, ct.byref(handle),
        )
        if code == 997:  # WSA_IO_PENDING
            while _wait_handle(event, 25) == 258:
                if cancel.is_set() or time.monotonic() >= deadline:
                    _cancel_addr_info(ct.byref(handle))
                    # Winsock requires completion before freeing OVERLAPPED/results.
                    _wait_handle(event, 0xFFFFFFFF)
                    _check_cancel(cancel)
                    raise TimeoutError
            code = _addr_info_result(ct.byref(overlapped))
        _check_cancel(cancel)
        if code:
            raise socket.gaierror(code, "DNS lookup failed.")
        addresses = []
        current = result
        while current and len(addresses) < 16:
            item = current.contents
            raw = ct.string_at(item.addr, item.addrlen)
            if item.family == socket.AF_INET and len(raw) >= 16:
                addresses.append((item.family, (socket.inet_ntop(item.family, raw[4:8]), port)))
            elif item.family == socket.AF_INET6 and len(raw) >= 28:
                addresses.append((item.family, (
                    socket.inet_ntop(item.family, raw[8:24]), port, 0,
                    int.from_bytes(raw[24:28], "little"),
                )))
            current = item.next
        return addresses
    finally:
        if result:
            _free_addr_info(result)
        _close_handle(event)


def _resolve(host, port, deadline, cancel):
    _check_cancel(cancel)
    if host.lower().rstrip(".") == "localhost":
        return [(socket.AF_INET, ("127.0.0.1", port)),
                (socket.AF_INET6, ("::1", port, 0, 0))]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if os.name == "nt":
            return _resolve_windows(host, port, deadline, cancel)
    else:
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        return [(family, (str(address), port))]
    # A disposable resolver process avoids uncancellable getaddrinfo worker threads
    # on non-Windows development hosts. Windows uses the native cancellable API.
    script = (
        "import json,socket,sys;"
        "print(json.dumps([(int(x[0]),x[4]) for x in "
        "socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)][:16]))"
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", script, host, str(port)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        while True:
            _check_cancel(cancel)
            try:
                output, _ = process.communicate(timeout=min(_TICK, _remaining(deadline)))
                if process.returncode:
                    raise socket.gaierror("DNS lookup failed.")
                return [(family, tuple(address)) for family, address in json.loads(output)]
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=1)


def _endpoint(node: dict) -> tuple[str, int]:
    host, port = node.get("server"), node.get("port")
    if (
        not isinstance(host, str) or not host or len(host) > 253
        or any(char.isspace() or ord(char) < 32 for char in host)
        or any(char in host for char in "/\\@?#%\0")
        or type(port) is not int or not 1 <= port <= 65535
    ):
        raise _Failure("Node has an invalid server or port.")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise _Failure("Node has an invalid server hostname.") from None
        if ":" in host or not re.fullmatch(r"[A-Za-z0-9_.-]+", host):
            raise _Failure("Node has an invalid server hostname.")
    return host, port


def _tcp_supported(node: dict) -> bool:
    clash = node.get("clash")
    clash = clash if isinstance(clash, dict) else {}
    return (
        node.get("protocol") not in _UDP_TYPES
        and clash.get("type") not in _UDP_TYPES
        and clash.get("network") not in {"quic", "kcp"}
    )


def _tcp_connect(node: dict, deadline: float, cancel: threading.Event) -> int:
    start = time.monotonic()
    try:
        host, port = _endpoint(node)
        addresses = _resolve(host, port, deadline, cancel)
        last_error = None
        for index, (family, address) in enumerate(addresses):
            _check_cancel(cancel)
            attempt_deadline = time.monotonic() + _remaining(deadline) / (len(addresses) - index)
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.setblocking(False)
                error = connection.connect_ex(address)
                if error not in _CONNECT_PENDING and error:
                    last_error = error
                    continue
                while error:
                    _check_cancel(cancel)
                    remaining = attempt_deadline - time.monotonic()
                    if remaining <= 0:
                        last_error = errno.ETIMEDOUT
                        break
                    _, ready, exceptional = select.select(
                        [], [connection], [connection], min(_TICK, remaining)
                    )
                    if ready or exceptional:
                        error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if error:
                            last_error = error
                        break
                if error == 0:
                    _check_cancel(cancel)
                    return max(1, round((time.monotonic() - start) * 1000))
        if last_error in {errno.ETIMEDOUT, 10060}:
            raise TimeoutError
        if last_error in {errno.ECONNREFUSED, 10061}:
            raise _Failure("TCP connection refused; the endpoint is unreachable.")
        raise _Failure("TCP endpoint is unreachable.")
    except socket.gaierror:
        raise _Failure("TCP endpoint hostname could not be resolved.") from None
    except TimeoutError:
        raise _Failure("TCP connection or hostname resolution timed out.") from None
    except OSError:
        _check_cancel(cancel)
        raise _Failure("TCP endpoint is unreachable.") from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def _api_error(code: int, body: bytes) -> _ApiFailure:
    if code == 401:
        return _ApiFailure("Private controller authentication failed.")
    if code == 504:
        return _ApiFailure("Proxy test timed out; handshake and target access were not verified.")
    # Inspect a bounded body for categories only. Never interpolate upstream text.
    text = body.decode("utf-8", errors="replace").lower()
    if any(word in text for word in ("authentication failed", "auth failed", "invalid password", "unauthorized")):
        return _ApiFailure("Proxy authentication was rejected.")
    if any(word in text for word in ("certificate", "x509", "tls handshake")):
        return _ApiFailure("Proxy or target TLS verification/handshake failed.")
    if any(word in text for word in ("connection refused", "network is unreachable", "no such host")):
        return _ApiFailure("Proxy endpoint or target is unreachable.")
    if code == 503:
        return _ApiFailure("Proxy handshake or target request failed.", diagnostic=True)
    return _ApiFailure("Private controller returned an invalid or unsupported response.")


def _configuration(proxies: list[dict], secret: str) -> dict:
    return {
        "mixed-port": 0, "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0,
        "allow-lan": False, "bind-address": "127.0.0.1", "ipv6": True,
        "external-controller": "127.0.0.1:0",
        "external-controller-tls": "", "external-controller-unix": "",
        "external-controller-pipe": "", "external-doh-server": "",
        "external-controller-cors": {"allow-origins": [], "allow-private-network": False},
        "external-ui": "", "external-ui-url": "", "secret": secret,
        "mode": "rule", "log-level": "silent", "unified-delay": False,
        "find-process-mode": "off", "geo-auto-update": False,
        "geox-url": {"geoip": "", "geosite": "", "mmdb": "", "asn": ""},
        "dns": {"enable": False, "listen": "", "fallback-filter": {"geoip": False}},
        "tun": {"enable": False, "auto-route": False, "auto-detect-interface": False},
        "sniffer": {"enable": False}, "ntp": {"enable": False, "write-to-system": False},
        "profile": {"store-selected": False, "store-fake-ip": False},
        "tuic-server": {"enable": False}, "ss-config": "", "vmess-config": "",
        "listeners": [], "tunnels": [], "proxy-providers": {}, "rule-providers": {},
        "proxy-groups": [], "rules": ["MATCH,REJECT"], "proxies": proxies,
    }


class NodeTester:
    """Reusable, single-run-at-a-time tester with joined, bounded worker threads.

    Results retain input order; callbacks run serially on the thread calling
    ``run`` in completion order and receive a separate result dictionary.
    Cancellation applies to the active/next run and resets when that run ends.
    ``timeout_ms`` is a per-node budget (1..32767); core startup has a separate
    five-second budget. Custom test URLs must also return HTTP 204 to HEAD.
    """

    def __init__(
        self, core_path: str | Path | None, timeout_ms: int = 8000,
        concurrency: int = 4, test_url: str = "https://www.gstatic.com/generate_204",
        temp_root: str | Path | None = None,
    ):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 32767:
            raise ValueError("timeout_ms must be an integer between 1 and 32767.")
        if type(concurrency) is not int or not 1 <= concurrency <= 32:
            raise ValueError("concurrency must be an integer between 1 and 32.")
        try:
            if not isinstance(test_url, str):
                raise ValueError
            parsed = urlsplit(test_url)
            valid_url = (
                parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not parsed.fragment and parsed.port != 0
                and len(test_url) <= 4096
                and not any(char.isspace() or ord(char) < 32 for char in test_url)
            )
        except (TypeError, ValueError):
            valid_url = False
        if not valid_url:
            raise ValueError("test_url must be an HTTP(S) URL without userinfo or a fragment.")
        self.core_path = Path(core_path).resolve() if core_path is not None else None
        self.timeout_ms, self.concurrency, self.test_url = timeout_ms, concurrency, test_url
        self.temp_root = Path(temp_root).resolve() if temp_root is not None else None
        self._cancel = threading.Event()
        self._run_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._process = None
        self._controller = ""
        self._secret = ""

    @property
    def process_pid(self) -> int | None:
        with self._state_lock:
            if self._process is not None and self._process.poll() is None:
                return self._process.pid
        return None

    def cancel(self) -> None:
        """Signal cancellation and terminate only this tester's private core."""
        self._cancel.set()
        with self._state_lock:
            if self._process is not None:
                try:
                    self._process.terminate()
                except OSError:
                    pass  # The run's finally block still waits/kills/closes the job.

    def _stop_core(self) -> None:
        with self._state_lock:
            process, self._process = self._process, None
            self._controller = self._secret = ""
            if process is None:
                return
            try:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            finally:
                if os.name == "nt":
                    process.close()

    @staticmethod
    def _result(node, mode, status, message, latency=None):
        name = node.get("name", "")
        name = name if isinstance(name, str) else ""
        if "://" in name:
            name = "Node"
        return {
            "node_id": node.get("id"), "name": name, "mode": mode,
            "status": status, "latency_ms": latency if status == "ok" else None,
            "message": message,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }

    def _prepare_proxy(self, node, index):
        host, port = _endpoint(node)
        proxy = node.get("clash")
        if not isinstance(proxy, dict):
            raise _Failure("No usable Mihomo proxy definition is available.", "unsupported")
        kind = proxy.get("type")
        if not isinstance(kind, str) or kind not in _PROXY_TYPES:
            raise _Failure("This proxy protocol is not supported by the isolated tester.", "unsupported")
        if node.get("protocol") != kind and not (kind == "hysteria2" and node.get("protocol") == "hy2"):
            raise _Failure("Node protocol does not match its proxy definition.")
        if proxy.get("server") != node.get("server") or proxy.get("port") != port:
            raise _Failure("Node endpoint does not match its proxy definition.")
        if any(key in proxy for key in ("dialer-proxy", "interface-name", "routing-mark")):
            raise _Failure("Proxy chaining and interface overrides are not supported in isolated tests.", "unsupported")
        if proxy.get("plugin") not in (None, "", "obfs", "v2ray-plugin"):
            raise _Failure("This proxy plugin is not supported in isolated tests.", "unsupported")
        try:
            encoded = json.dumps(proxy, allow_nan=False)
            if len(encoded) > 131_072:
                raise ValueError
            proxy = json.loads(encoded)
        except (ValueError, TypeError, RecursionError):
            raise _Failure("Proxy definition is invalid or too large.") from None
        token = hashlib.sha256(str(node.get("id", index)).encode("utf-8")).hexdigest()[:20]
        proxy.update(name=f"node-{token}-{index}", server=host)
        return proxy

    def _request(self, path: str, deadline: float):
        _check_cancel(self._cancel)
        with self._state_lock:
            if self._process is None or self._process.poll() is not None:
                raise _Failure("Private Mihomo process exited.")
            url, secret = self._controller + path, self._secret
        request = Request(url, headers={"Authorization": f"Bearer {secret}", "Connection": "close"})
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(request, timeout=_remaining(deadline)) as response:
                body = response.read(_MAX_RESPONSE + 1)
                if len(body) > _MAX_RESPONSE:
                    raise _Failure("Private controller response was too large.")
                result = json.loads(body)
                if not isinstance(result, dict):
                    raise ValueError
                _check_cancel(self._cancel)
                return result
        except HTTPError as error:
            with error:
                body = error.read(4096)
            _check_cancel(self._cancel)
            raise _api_error(error.code, body) from None
        except (ValueError, UnicodeError):
            raise _Failure("Private controller returned malformed data.") from None
        except (URLError, OSError):
            _check_cancel(self._cancel)
            raise _Failure("Private controller request failed or timed out.") from None

    def _start_core(self, directory, config_file, proxies):
        self._secret = secrets.token_urlsafe(32)
        configuration = _configuration(proxies, self._secret)
        config_file.write(yaml.safe_dump(configuration, sort_keys=False).encode("utf-8"))
        config_file.flush()
        config_file.seek(0)
        _check_cancel(self._cancel)
        args = [str(self.core_path), "-d", directory, "-f", "-"]
        if os.name == "nt":
            process = _WindowsProcess(args, directory, config_file, _core_environment())
        else:
            process = subprocess.Popen(
                args, cwd=directory, stdin=config_file,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=_core_environment(), close_fds=True,
            )
        with self._state_lock:
            self._process = process
        _check_cancel(self._cancel)
        deadline = time.monotonic() + _STARTUP_SECONDS
        while time.monotonic() < deadline:
            _check_cancel(self._cancel)
            if process.poll() is not None:
                raise _Failure("Private core rejected the temporary configuration or exited during startup.")
            port = _controller_port(process.pid)
            if port:
                self._controller = f"http://127.0.0.1:{port}"
                version = self._request("/version", deadline)
                if version.get("meta") is not True or version.get("version") != _CORE_VERSION:
                    raise _Failure("The isolated tester requires the bundled Mihomo v1.19.33.")
                return
            self._cancel.wait(_TICK)
        raise _Failure("Private Mihomo controller did not become ready in time.")

    def _test_one(self, node, mode, proxy_name=None):
        deadline = time.monotonic() + self.timeout_ms / 1000
        try:
            _check_cancel(self._cancel)
            if mode == "tcp":
                if not _tcp_supported(node):
                    raise _Failure("TCP testing is unsupported for this UDP-based protocol or transport.", "unsupported")
                latency = _tcp_connect(node, deadline, self._cancel)
                message = "TCP connection succeeded only; proxy handshake and HTTP access were not tested."
            else:
                path = "/proxies/" + quote(proxy_name, safe="")
                query = urlencode({
                    "url": self.test_url, "timeout": self.timeout_ms, "expected": "204",
                })
                try:
                    delay = self._request(path + "/delay?" + query, deadline)
                except _ApiFailure as error:
                    if error.diagnostic and _tcp_supported(node) and deadline - time.monotonic() > _TICK:
                        _tcp_connect(node, deadline, self._cancel)
                        raise _Failure(
                            "Proxy handshake or target request failed; endpoint TCP is reachable. "
                            "This core cannot distinguish authentication from target failures."
                        ) from None
                    raise
                latency = delay.get("delay")
                if type(latency) is not int or not 0 < latency <= 65535:
                    raise _Failure("Private core did not report a valid proxy delay.")
                detail = self._request(path, deadline)
                # v1.19.33 returns a delay even for the wrong HTTP status. Only
                # extra[url] records whether URLTest's expected range matched.
                extra = detail.get("extra")
                state = extra.get(self.test_url) if isinstance(extra, dict) else None
                history = state.get("history") if isinstance(state, dict) else None
                if not history or not isinstance(history, list) or not isinstance(history[-1], dict):
                    raise _Failure("Core did not verify the target HTTP status; refusing an unverified result.")
                if state.get("alive") is False or history[-1].get("delay") == 0:
                    raise _Failure("Target did not return the expected HTTP status (204); redirects are not accepted.")
                if state.get("alive") is not True or history[-1].get("delay") != latency:
                    raise _Failure("Core returned inconsistent target HTTP status verification.")
                message = "Proxy HTTP HEAD returned the expected status (204)."
            _check_cancel(self._cancel)
            return self._result(node, mode, "ok", message, latency)
        except _Cancelled:
            return self._result(node, mode, "cancelled", "Test cancelled.")
        except _Failure as error:
            if self._cancel.is_set():
                return self._result(node, mode, "cancelled", "Test cancelled.")
            return self._result(node, mode, error.status, str(error))
        except TimeoutError:
            return self._result(node, mode, "failed", "Test timed out.")
        except Exception:
            return self._result(node, mode, "failed", "Test could not be completed.")

    def _run_workers(self, nodes, mode, eligible, names, emit):
        executor = ThreadPoolExecutor(
            max_workers=min(self.concurrency, len(eligible)), thread_name_prefix="node-tester"
        )
        pending = {}
        todo = iter(eligible)
        try:
            while True:
                while len(pending) < self.concurrency and not self._cancel.is_set():
                    index = next(todo, None)
                    if index is None:
                        break
                    pending[executor.submit(self._test_one, nodes[index], mode, names.get(index))] = index
                if not pending:
                    break
                finished, _ = wait(pending, timeout=_TICK, return_when=FIRST_COMPLETED)
                for future in finished:
                    index = pending.pop(future)
                    emit(index, future.result())
        finally:
            if pending:
                self.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

    def run(self, nodes: list[dict], mode: str = "proxy", on_result: Callable | None = None) -> list[dict]:
        if mode not in {"proxy", "tcp"}:
            raise ValueError("mode must be 'proxy' or 'tcp'.")
        if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
            raise TypeError("nodes must be a list of dictionaries.")
        if on_result is not None and not callable(on_result):
            raise TypeError("on_result must be callable.")
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("This tester already has an active run.")
        nodes = [dict(node) for node in nodes]
        results = [None] * len(nodes)

        def emit(index, result):
            if self._cancel.is_set():
                result = self._result(nodes[index], mode, "cancelled", "Test cancelled.")
            results[index] = result
            if on_result is not None:
                try:
                    on_result(dict(result))
                except Exception:
                    raise RuntimeError("Result callback failed.") from None

        try:
            eligible, proxies, names = [], [], {}
            for index, node in enumerate(nodes):
                if self._cancel.is_set():
                    break
                try:
                    if mode == "proxy":
                        proxy = self._prepare_proxy(node, index)
                        proxies.append(proxy)
                        names[index] = proxy["name"]
                    eligible.append(index)
                except _Failure as error:
                    emit(index, self._result(node, mode, error.status, str(error)))
            if eligible and not self._cancel.is_set():
                if mode == "tcp":
                    self._run_workers(nodes, mode, eligible, names, emit)
                elif self.core_path is None or not self.core_path.is_file():
                    for index in eligible:
                        emit(index, self._result(nodes[index], mode, "unsupported", "Bundled Mihomo core is unavailable; proxy testing was not performed."))
                else:
                    with tempfile.TemporaryDirectory(prefix="node-desk-test-", dir=self.temp_root) as directory:
                        _private_directory(directory)
                        # Windows uses O_TEMPORARY (delete-on-last-close); POSIX
                        # unlinks immediately. The core inherits stdin, not a path.
                        with tempfile.TemporaryFile(mode="w+b", dir=directory) as config_file:
                            try:
                                try:
                                    self._start_core(directory, config_file, proxies)
                                except _Cancelled:
                                    pass
                                except (_Failure, OSError, ValueError) as error:
                                    message = str(error) if isinstance(error, _Failure) else "Private Mihomo could not be started safely."
                                    for index in eligible:
                                        emit(index, self._result(nodes[index], mode, "failed", message))
                                else:
                                    self._run_workers(nodes, mode, eligible, names, emit)
                            finally:
                                self._stop_core()
            for index, result in enumerate(results):
                if result is None:
                    emit(index, self._result(nodes[index], mode, "cancelled", "Test cancelled."))
            return results
        finally:
            try:
                self._stop_core()
            finally:
                self._cancel.clear()
                self._run_lock.release()
