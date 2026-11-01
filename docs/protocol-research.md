# Subscription Format Research

Checked on 2026-10-28 for the independent Windows / Python 3.12 / PySide6
format-conversion slice. Only `node_desk/formats.py`, `tests/test_formats.py`,
`requirements-protocols.txt`, and this document belong to this slice.

## Scope and Research Method

The problem is offline conversion of user-supplied share links into useful
records, complete Mihomo YAML profiles, and v2rayN Base64 subscriptions. It is
not implementing proxy transports, dialing servers, fetching subscriptions,
setting a system proxy, or reading existing user configurations.

PavedPath research used primary upstream sources: `gh search repos` with
`subscription parser language:Python` and `vless parser language:Python`,
repository metadata, formatter source, upstream regression tests, and protocol
specifications. Web search cross-checked the upstream projects and Mihomo docs.
A targeted merged-PR search for v2rayN query decoding returned no matches;
the maintained source and `ShareUriQueryTests.cs` provided direct evidence.
No additional subagents were used: this was already an independently assigned,
narrow slice in a shared workspace.

Shell research used a process-local `HTTPS_PROXY` for the explicitly supplied
loopback proxy. No global proxy setting was changed. No credentials, real node
lists, tokens, or private repositories were read or included in research.

## Candidates

Repository statistics are discovery-time signals, not compatibility guarantees.

| Project | Observed Maturity | License / Language | Decision |
| --- | --- | --- | --- |
| [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo/tree/Meta) | 35,279 stars, 4,675 forks; repository activity 2026-10-28 | Inspected `Meta` source: Go, GPL-3.0 | Authoritative output schema and transport behavior. Its native converter is not an embeddable Python dependency and often skips invalid inputs. Use its configuration interface, not copied Go code. |
| [2dust/v2rayN](https://github.com/2dust/v2rayN) | 119,324 stars, 16,189 forks; repository activity 2026-10-27 | C#, GPL-3.0 | Authoritative target-client share formats. Reusing its application/service assembly would add a second runtime to this Python slice. |
| [tindy2013/subconverter](https://github.com/tindy2013/subconverter) | 17,108 stars, 3,839 forks; last observed push 2026-07-09 | C++, GPL-3.0 | Mature separate converter application, but integrating a native backend, lifecycle and packaging is excessive for this bounded offline API. Its popularity alone does not establish fidelity for new Reality options. |
| [arminmokri/v2ray2json](https://github.com/arminmokri/v2ray2json) | 117 stars, 15 forks; last observed push 2025-08-09 | Python, MIT | Closest Python candidate, but produces full Xray configurations. Inspected code sets `allowInsecure = True`, discards unknown VMess fields, and uses UTF-8 `errors="ignore"`. Those behaviors conflict with this slice's fail-closed contract. Adapting them would amount to replacing its core conversion policy. |
| [The-Saman/V2rayURI](https://github.com/The-Saman/V2rayURI) | Appeared in web search; direct repository lookup did not resolve | Not verified | Search-index evidence alone is insufficient to establish maintenance, licensing, or a dependable dependency. Not selected. |

The Mihomo default-branch metadata returned a Python/MIT description unrelated
to the inspected proxy implementation. Its `Meta` tree, Go source, and
[`Meta` LICENSE](https://github.com/MetaCubeX/mihomo/blob/Meta/LICENSE) were checked
explicitly instead of trusting that metadata.

Observed branch heads:

- v2rayN `master`: `57f17d5939e88c8e643ab49b90869d637765e75a` (commit date 2026-10-20).
- Mihomo `Meta`: `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` (commit date 2026-10-21).
- v2ray2json `main`: `b4131fe4dd7515be06fcb7108d5630a089bab478` (commit date 2025-08-09).

These are inspected branch references, not claims about the latest stable
release of any client.

## Selected Reuse

Use Python's structured standard-library parsers for the substrate:
[`urllib.parse`](https://docs.python.org/3/library/urllib.parse.html),
[`base64`](https://docs.python.org/3/library/base64.html),
[`json`](https://docs.python.org/3/library/json.html),
[`ipaddress`](https://docs.python.org/3/library/ipaddress.html), and
[`uuid`](https://docs.python.org/3/library/uuid.html).
[`shlex`](https://docs.python.org/3/library/shlex.html) supplies escape-aware
SIP003 tokenization with shell quote processing disabled. No custom URI, JSON,
Base64, TLS, WebSocket, gRPC, SOCKS, or encryption engine is introduced.

[`PyYAML`](https://github.com/yaml/pyyaml) supplies `safe_dump`; configuration is
assembled from validated ordinary Python values. It is the only additional
format dependency: `PyYAML>=6.0.2,<7`. Verification used PyYAML 6.0.2.

Small local adapters validate and translate fields, reject ambiguity, normalize
supported share formats, and implement the application's error/record/export
contract. `parse_qsl` receives literal plus signs escaped first because upstream
share links use RFC3986 percent decoding, not HTML form space conversion.
Credentials and query values are decoded exactly once.

## Primary Evidence

- [Xray VMessAEAD / VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716):
  explicit ports, bracketed IPv6, case-sensitive options, no repeated fields,
  transport/security separation, Reality fields, and current certificate policy.
  The 2026 updates include new encryption/finalmask/certificate fields; this
  adapter explicitly rejects unsupported nonempty requirements.
- [v2rayN BaseFmt](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/BaseFmt.cs),
  [Utils](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Common/Utils.cs),
  and [ShareUriQueryTests](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib.Tests/Fmt/ShareUriQueryTests.cs):
  query values are decoded once, split on the first `=`, and URI fragments are
  escaped. The local parser is intentionally stricter about duplicate and
  unknown options than the target's permissive import path.
- [v2rayN SocksFmt](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/SocksFmt.cs):
  both whole-payload legacy Base64 and Base64 userinfo are supported. Export uses
  canonical `socks://` with encoded authentication, not the `socks5://` alias.
- [v2rayN VmessFmt](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/VmessFmt.cs):
  JSON share payloads use `ps` for the display name; gRPC uses `path` for the
  service, `host` for authority and `type` for mode. Renames update JSON `ps`.
- [Mihomo VLESS](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outbound/vless.go),
  [VMess](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outbound/vmess.go),
  [Trojan](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outbound/trojan.go),
  and [SOCKS5](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outbound/socks5.go):
  exact output fields and transport constraints. In particular, gRPC authority
  is coupled to SNI; VLESS/VMess WebSocket fixes ALPN to HTTP/1.1; gRPC fixes it
  to h2. VLESS WebSocket does not apply Reality's TLS configuration.
- [Mihomo WebSocket transport](https://github.com/MetaCubeX/mihomo/blob/Meta/transport/vmess/websocket.go):
  recognizes `?ed=` in the path, sets early-data behavior and retains the other
  query values. Paths are preserved rather than reconstructed or double-decoded.
- [Shadowsocks SIP002](https://github.com/shadowsocks/shadowsocks-org/blob/master/docs/doc/sip002.md):
  AEAD userinfo may be Base64URL or separately percent-encoded method/password;
  AEAD-2022 must use the latter. Plugin arguments have escaping requirements.
- [v2ray-plugin options](https://github.com/shadowsocks/v2ray-plugin/blob/master/args.go)
  and [defaults](https://github.com/shadowsocks/v2ray-plugin/blob/master/main.go),
  [Mihomo Shadowsocks adapter](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outbound/shadowsocks.go),
  and [v2rayN ShadowsocksFmt](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/ShadowsocksFmt.cs):
  plugin defaults and fields must be mapped explicitly. Upstream v2ray-plugin
  defaults to host `cloudfront.com` and enabled mux, unlike Mihomo's host default.
  v2rayN handles HTTP obfs and non-multiplexed WebSocket plugins but cannot
  faithfully preserve all otherwise valid SIP003 combinations.
- [sing-vmess client](https://github.com/MetaCubeX/sing-vmess/blob/for-meta/client.go)
  confirms accepted VMess cipher names, including `zero`.
  [sing-shadowsocks2 SS2022 protocol](https://github.com/MetaCubeX/sing-shadowsocks2/blob/dev/shadowaead_2022/protocol.go)
  explicitly limits extendable identity headers to AES ciphers. The adapter
  rejects ChaCha20 identity-key chains and normalizes accepted keys to padded
  standard Base64 for the core.

## Compatibility Contract

| Format | Accepted Subset |
| --- | --- |
| VLESS | Standard UUID forms (dashed, unbraced, braced, or URN) canonicalized to dashed, or an Xray custom ID of at most 30 bytes; explicit port, `encryption=none`; TCP (optionally with HTTP header obfuscation; a missing host keeps Mihomo's server-address default) / WS / gRPC gun; TLS or Reality; SNI, portable fingerprint, compatible ALPN, WS Host/path/early data, gRPC service, and matching/default authority. Vision requires TLS/Reality TCP without header obfuscation. |
| VMess | v2rayN Base64 JSON v2, standard UUID forms canonicalized to dashed (custom IDs of at most 30 bytes are mapped like VLESS, matching Mihomo's UUIDMap) and strict numeric fields; TCP (optionally with HTTP header obfuscation; a missing host keeps Mihomo's server-address default) / WS / gRPC gun; TLS, cipher, alterId, SNI, fingerprint, compatible ALPN. Optional null fields mean unset; required endpoint/UUID fields cannot be null. JSON field order does not affect identity. |
| SOCKS5 | `socks://` whole-payload Base64, Base64 userinfo, and `socks5://username:password@host:port`; unauthenticated endpoints; encoded authentication and bracketed IPv6. Canonical export is `socks://`. |
| Trojan | TLS TCP / WS / gRPC gun, encoded password, SNI/fingerprint/compatible ALPN and supported transport fields. |
| Shadowsocks | AES-128/256-GCM and ChaCha20-IETF-Poly1305; legacy whole-payload and SIP002; the three listed AEAD-2022 ciphers with cipher-sized Base64 keys and separately encoded userinfo (identity key chains require AES); obfs-local/simple-obfs and WebSocket v2ray-plugin within the documented subset. |
| Trojan-Go (1.5.0) | `trojan-go://password@host:port` with `sni`, `type=original|ws`, WS `host`/`path`, and `encryption=ss;<aead>;<password>` (Mihomo `ss-opts`); `plugin` is rejected. Exported to Clash only. |
| SSR (1.5.0) | `ssr://` Base64URL payload `host:port:protocol:method:obfs:base64(password)/?obfsparam&protoparam&remarks&group`; common stream ciphers, `auth_*` protocols and `http_simple`/`tls1.2_ticket_auth`-style obfs; remarks become the name and are rewritten on export. |
| HTTP (1.5.0) | `http://`/`https://[user:pass@]host:port`; `https` accepts `sni` and `insecure`. Paths are rejected so remote subscription URLs are not mistaken for proxies. |
| Hysteria2 (1.5.0) | `hysteria2://`/`hy2://password@host:port` with `sni`, `insecure` (also `allowInsecure`/`allow_insecure`; identical duplicate spellings are accepted because older v2rayN releases emitted both), `obfs=salamander`+`obfs-password`, `pinSHA256`, `alpn`, `up`/`down`, and `mport`/`ports` port hopping (Mihomo `ports`). |
| Hysteria v1 (1.5.0) | `hysteria://host:port` with `protocol`, `auth`, `peer`, `insecure`, `upmbps`/`downmbps`, `alpn`, `obfs=xplus`+`obfsParam`. Clash export only. |
| TUIC (1.5.0) | v5 `tuic://uuid:password@host:port` with `congestion_control`, `udp_relay_mode`, `alpn` (default h3), `sni`, `allow_insecure`, `disable_sni`; v4 token links are rejected. |
| AnyTLS (1.5.0) | `anytls://password@host:port` with `sni`, `insecure`, `alpn`, `fp`. |
| WireGuard (1.5.0) | v2rayN `wireguard://privatekey@host:port?publickey&presharedkey&address&reserved&mtu`; 32-byte keys, one IPv4 and/or one IPv6 interface address, three reserved bytes; `wnoise*` is rejected. |
| Mieru (1.5.0) | `mierus://username:password@host:port` with `multiplexing`, optional `profile` (name fallback) and `mtu` (default 1400 only); TCP transport only, matching Mihomo. Clash export only. |
| SSH (1.5.0) | `ssh://username:password@host:port`; key-based authentication has no link form. Clash export only. |

Intentional errors, rather than silently weakened or incomplete output:

- Unknown/repeated URI options and JSON fields, unsupported transports, non-HTTP
  header obfuscation (HTTP obfuscation is rejected for Trojan or together with
  Vision), non-`none` VLESS encryption,
  non-gun gRPC, distinct gRPC authority,
  incompatible forced ALPN, Vision on WS/gRPC, Reality over WS, and nonempty
  `spx`, `pqv`, `ech`, `pcs`, `vcn`, or unimplemented finalmask requirements.
- Unscoped, syntactically valid IP addresses and DNS/IDNA hostnames only. IPv6
  zones, VMess JSON v1, and standard UUID-style VMess URLs are not accepted by
  this slice; custom non-UUID IDs are accepted for VLESS only. Hysteria2 is
  intentionally deferred.
- SOCKS username/password must both be absent or both have 1-255 UTF-8 bytes.
  A colon inside a username is not representable in v2rayN's shared userinfo.
- Deprecated Shadowsocks stream ciphers and unknown plugins are rejected.
  Obfs requires an explicit host to avoid different client defaults.
  External plugin binaries, certificate paths, embedded certificates, server
  flags, QUIC plugins, and mux concurrency greater than one are not supported.
- TLS verification remains enabled by default. Legacy verification-disable
  options can be imported and honored in Mihomo, but v2rayN export rejects them:
  current Xray's proposal explicitly removes `allowInsecure`. This prevents
  silently claiming equivalent behavior in a client that cannot honor it.
- HTTP obfs and WebSocket v2ray-plugin with `mux=0` are exportable to v2rayN.
  TLS obfs, enabled/default mux, and plugin values containing escaped
  semicolons/backslashes/colons remain available for Clash export but cause an
  explicit whole-export error for v2rayN. No partially truncated subscription
  is returned.

The adapter is deliberately stricter than general-purpose clients. It does
not claim that all legal protocol configurations fit this supported subset.
In particular, retaining a share string while dropping a field from `clash`
would not satisfy the import contract.

## API and Export Behavior

`parse_uri` returns exactly `name`, `protocol`, `server`, integer `port`,
canonical `uri`, and a Mihomo `clash` mapping including `name`. Protocol values
are `vless`, `vmess`, `socks5`, `trojan`, and `ss`.

`parse_batch` accepts newline/CRLF lists and one Base64 UTF-8 envelope, including
wrapped and unpadded variants. Blank lines and `#` comments are ignored; errors
have one-based physical line numbers, or decoded line numbers for envelopes.
Deduplication keeps the first display name and compares recursively sorted
proxy mappings without their top-level name. Errors never include raw URIs,
credentials, decoded payloads, or untrusted option names.

Bounds are 16,384 characters per incoming and canonical URI, 256 characters per
display name, 4 Mi characters per batch, 10,000 batch lines/exported records,
and 64 outer query fields. Base64/UTF-8/JSON errors are explicit. Parsing is not
recursive across Base64 envelopes.

Exports reparse the URI, validate stored endpoint and `clash` consistency, and
apply the current record name. `enabled` and `group` are caller-owned metadata:
neither exporter filters them or mutates input records. Export names are made
unique around existing names, built-ins, and group names only in YAML.

Clash output includes a loopback-bound mixed port, proxies, PROXY select and
AUTO url-test groups, `mode: rule`, and `MATCH,PROXY`. There is no controller,
TUN, provider fetching, LAN exposure, or system-proxy setting. The empty profile
defaults to REJECT through AUTO rather than silently connecting directly.
The caller-provided test URL is serialized, never fetched by this module.

v2rayN output is Base64 of UTF-8, newline-separated canonical share URLs,
without a trailing newline. VMess names are rewritten inside JSON and other
names in URI fragments. Empty input yields an empty Base64 string.

## sing-box Export (added in 1.6.0)

`export_singbox(nodes, test_url, rules)` produces a complete sing-box JSON
profile targeting the stable configuration format of sing-box 1.12–1.14
(current stable 1.14.4 at research time). The 1.13.0 removals (legacy
`block`/`dns` special outbounds, legacy WireGuard outbound) and the 1.14.0
removal (legacy DNS server formats) are avoided by emitting only current
syntax; clients older than 1.11 are not targeted. Export only: NodeDesk never
parses sing-box profiles.

Structure: loopback-only `mixed` inbound on 127.0.0.1:7890; DNS with a remote
DoH server detoured through PROXY and a local UDP server detoured through
DIRECT (`final: remote`), plus `route.default_domain_resolver` pointing at the
local server so proxy-server domains never resolve through the proxy; node
outbounds plus selector `PROXY` (default `AUTO`), urltest `AUTO`, and
`direct`. Subscription rules are converted in display order with the current
action syntax (`action: route`/`reject`, `final: PROXY`); GEOIP/GEOSITE rules
reference remote binary rule sets from SagerNet/sing-geoip and
SagerNet/sing-geosite, downloaded by the client with `download_detour:
PROXY`. `no_resolve` hints are dropped: sing-box matches IP rules against the
actual destination without forcing resolution. WireGuard nodes are emitted as
top-level `endpoints` entries (`allowed_ips` derived from the interface
address families). Xray custom VLESS/VMess IDs (≤30 bytes) are mapped to
their UUIDv5 form with a nil namespace (XTLS/Xray-core issue #158) because
sing-box parses strict UUIDs; the `?ed=` WebSocket convention becomes
`max_early_data` with `early_data_header_name: Sec-WebSocket-Protocol`.

Intentional whole-export errors: Hysteria v1, Mieru, and SSR are not
implemented by current sing-box (SSR remains a parse-only stub that aborts
startup); Trojan-Go `encryption=ss` has no sing-box field; Hysteria2
`pinSHA256` pins a certificate fingerprint while sing-box pins public-key
hashes, so dropping it would silently weaken TLS verification.

## Licensing and Verification

No upstream formatter or protocol-engine source was copied. GPL projects are
interoperability references, not bundled/linkable dependencies. License
notices for any separately distributed core remain that packaging slice's
responsibility.
[PyYAML's MIT license](https://github.com/yaml/pyyaml/blob/main/LICENSE) was read
directly. Python's standard library is provided by the Python runtime under its
own [license](https://docs.python.org/3/license.html). These are dependency/source
provenance notes, not a licensing opinion on the complete application.

The focused suite uses only `unittest`, the Python standard library, and
PyYAML. All fixtures are synthetic. It covers protocol round trips, escaped
credentials/Unicode, malformed and duplicate options, TLS/Reality and transport
boundaries, plugin fidelity, subscription envelopes, name-independent identity,
safe complete YAML, edited names, stale records, and offline operation.
Deterministic URI mutations additionally check that accepted inputs reparse
to the same canonical record and produce valid YAML.

Run from the workspace root:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -p test_formats.py -v
```

Verified on 2026-10-28 with Python 3.12.2 and PyYAML 6.0.2:

- `python -m unittest discover -s tests -p test_formats.py -q`: 95 tests passed.
- `python -m pytest tests/test_formats.py -q -p no:cacheprovider`: 95 tests and
  1,478 subtests passed, including 1,200 deterministic URI mutations. Pytest is
  optional for this suite; `unittest` is sufficient.

Actual proxy connectivity and installed-client/core execution are not covered:
no real nodes or running cores were supplied. End-to-end client compatibility
should be smoke-tested against the packaged core versions when that separate
packaging slice is ready.
