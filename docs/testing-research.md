# On-Demand Connectivity Tests

Research date: October 28, 2026. Target: Windows 10/11, Python 3.12,
PyYAML, and the parent's separately verified official Mihomo v1.19.33 bundle.
The tester never downloads a core, a dashboard, a rule provider, or geodata.

## Primary Evidence

The narrow implementation question was how to test a node through its real
protocol while isolating process lifetime, controller ownership, credentials,
and HTTP-status validation. Research used GitHub CLI/raw tagged upstream
source and Microsoft/Python documentation. No additional research agent was
needed for this single-core API boundary. No protocol engine code was copied.

- Mihomo's tagged
  [proxy routes](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/route/proxies.go)
  accept `GET /proxies/{name}/delay?url=...&timeout=...&expected=204`.
  Timeout parsing uses a signed 16-bit integer, so this API cannot accept more
  than 32767 ms. Many handshake errors are deliberately reduced to generic
  HTTP 503 responses.
- The tagged
  [URLTest implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/adapter.go)
  uses an HTTP **HEAD** request over the chosen outbound, verifies HTTPS using
  its TLS client, and does not follow redirects. Crucially, an unexpected
  HTTP status does **not** make URLTest return an error or zero delay:
  it records `alive: false` and zero history delay in `extra[test_url]`.
  Therefore accepting the delay response alone is a false-positive bug.
  This runner also queries `/proxies/{name}` and checks that URL-specific
  status/history. Missing verification fails closed.
- The tagged
  [controller](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/route/server.go)
  supports bearer authentication and an ordinary loopback TCP listener.
  [Main](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/main.go) accepts
  `-d` for a private home and `-f -` for stdin YAML. It also reads environment
  overrides including `CLASH_CONFIG_STRING`, controller addresses/secrets,
  and post-up/down commands; these must not be inherited.
- The tagged
  [configuration defaults](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/config/config.go)
  were inspected to disable listeners, TUN, DNS serving, geodata updates,
  profile persistence, external UI, NTP, sniffing, providers, and process
  discovery explicitly. Only a non-geographic `MATCH,REJECT` rule is present;
  the delay API dials the selected outbound directly.
- Python's
  [urllib documentation](https://docs.python.org/3/library/urllib.request.html)
  specifies that `ProxyHandler({})` disables automatically detected proxies.
  A private opener uses that handler and rejects controller redirects. It
  neither installs an opener globally nor reads a user controller setting.
- Microsoft's
  [job object documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
  [job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information),
  and [process attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
  establish kill-on-last-job-handle-close behavior and Windows 10's
  `PROC_THREAD_ATTRIBUTE_JOB_LIST`. The latter assigns job membership during
  process creation, avoiding the create-then-assign parent-crash race.
- Microsoft's
  [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
  and [TCP owner rows](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid)
  let the runner discover the OS-assigned controller port belonging to its
  child PID. It never probes guessed/free-then-released controller ports.
- Microsoft's
  [GetAddrInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw)
  and [GetAddrInfoExCancel](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexcancel)
  provide cancellable DNS resolution without leaving Python resolver threads
  running. Native query completion is awaited before freeing overlapped
  memory, as required by Winsock.

## Contract And Isolation

- `NodeTester.run()` is synchronous. Use a UI worker and marshal callbacks to
  Qt signals. Call `cancel()`, then wait for the worker on window close.
- Results preserve input order. Callbacks are serial, on the `run` caller's
  thread, in completion order, once per result, and receive copies.
  A callback exception aborts the run with a generic exception after cleanup.
- One tester cannot run overlapping batches. It can be reused after a run.
  A cancellation just before the worker starts cancels that upcoming run;
  the cancellation flag resets when the run has finished.
- Concurrency is bounded to 1..32, default 4, with only that many submitted
  node jobs at once. Per-node deadlines include the actual delay request,
  status verification, and any failure diagnostic. Startup is separately
  bounded to five seconds and shutdown has bounded terminate/kill waits.
- TCP results mean **TCP connection only**, including DNS resolution time.
  They do not establish authentication or proxy/HTTP functionality. UDP-based
  protocols (including Hysteria2/TUIC/WireGuard) and QUIC/KCP transports return
  `unsupported` in TCP mode.
- Proxy mode starts a fresh core for the batch. Proxy names are hashes of
  node IDs plus input indices, so duplicate names and duplicate IDs do not
  collide. Caller dictionaries and extra metadata are not put into YAML.
- The controller binds `127.0.0.1:0`, has a new random bearer secret, and is
  located by the private child's PID. All proxy data ports are zero.
  No user configurations, controller endpoints, system proxy, or TUN settings
  are read or changed.
- The home is a fresh owner/SYSTEM-only directory on Windows. YAML is passed
  through a delete-on-close temporary stdin file, not command-line arguments
  or a durable `config.yaml`. The Windows child inherits only that input and
  the null output handle. Job membership is atomic and mandatory; a job
  creation/assignment failure does not fall back to an unprotected process.
- The job is unnamed and its handle is not inherited. Parent process death
  closes it and terminates only that job's child processes. The temporary
  credential file is then deleted on last handle close. A hard crash can
  leave an empty/private home or noncredential core cache artifacts, but
  there is no persistent YAML credential file.
- No log readers, telemetry streams, or monitoring threads exist. Core output
  is discarded. Controller errors are bounded and categorized, never copied
  into results. Share-link metadata is excluded; share links used as display
  names are replaced with `Node`.

## Failure Boundaries

The required successful target status is 204, including for custom test URLs.
Redirects, HTTP 200, HTTP 404, missing URL-specific state, inconsistent history,
zero delays, and unexpected core versions cannot produce success.

When the core gives a useful error, the runner categorizes authentication,
TLS, or endpoint/target reachability without returning raw text. A generic
503 may trigger a deadline-bounded TCP diagnostic for a TCP-based node:
connection refusal/DNS failure can identify an unreachable endpoint; a
successful TCP connection still cannot identify whether authentication or
the final target caused the proxy failure. The result states that ambiguity.
It would be incorrect to infer bad credentials from every generic 503.

This deliberately trusts the parent's pinned and SHA256-verified executable.
It does not sandbox an arbitrary malicious executable. Protocol conversions
belong to `formats.py`; unsupported/chained/interface-bound definitions are
rejected rather than silently changed. Core-level invalid YAML proxy options
can reject the entire temporary batch; the run reports startup failure and
cleans up rather than using a user configuration as fallback.

The production platform is Windows 10/11. A Linux development path discovers
child listeners via `/proc` and uses disposable, joined resolver processes
instead of uncancellable DNS threads. Other platforms fail closed for proxy
controller discovery.

## Verification

Focused tests live in `tests/test_testing.py` and use only synthetic records
and controlled loopback TCP, HTTP, and SOCKS5 servers. Core integration tests
use `vendor/mihomo.exe` when present, or `NODE_DESK_TEST_CORE` for an explicitly
selected local executable, and never download one.

Run only this slice with:

```powershell
python -B -m pytest -q -p no:cacheprovider tests/test_testing.py
```
