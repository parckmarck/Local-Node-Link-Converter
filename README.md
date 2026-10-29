# Node Desk · 节点维护

一个按需启动的 Windows 桌面程序。节点保存在本机，用于管理分享链接，
生成本地 Clash Verge / v2rayN 订阅，并执行连接测试。

## 直接运行

发布包解压后，双击 `NodeDesk.exe`。保留它旁边的 `_internal` 文件夹，
不要单独移动 EXE。不需要安装 Python，不需要管理员权限。

本项目目录中也可以双击 `启动程序.cmd`，打开已构建的发布版。
适用平台：Windows 10/11 64 位。

也可以使用安装版：运行 `dist\NodeDesk-<版本>-setup.exe`，按向导安装后，从开始菜单
或桌面快捷方式启动。安装版默认装到当前用户目录、不需要管理员权限，可在 Windows
“设置 → 应用”中正常卸载（卸载不会删除本地数据）。安装版与便携版读取同一份本地
数据（`%LOCALAPPDATA%\NodeDesk`），两者不要同时运行。

## 日常操作

1. 点击“导入节点”，粘贴一个或多个链接，点击“检查链接”，再确认导入。
   可读取 UTF-8 文本或 Base64 订阅内容，也可在“添加 SOCKS5”里填写服务器和认证。
2. 在节点列表中搜索、分组、修改名称和链接。重复节点会自动跳过。
   “订阅”开关只决定是否加入输出，不会删除节点。
3. 打开“本地订阅”，按需要选择分组，复制对应客户端的链接。
4. （可选）打开“订阅规则”，检查随 Clash 订阅一起下发的流量规则。默认包含
   局域网直连、广告拦截、国内直连，以及 Telegram、常见流媒体的分流；可以在这里
   增删规则、调整顺序和启用状态，客户端刷新订阅后生效（v2rayN 为纯节点列表，不含规则）。
5. 在 Clash Verge 的订阅页添加远程订阅，粘贴 Clash 地址后导入。
   在 v2rayN 的订阅分组设置中添加 v2rayN 地址，再执行“不通过代理”更新订阅。
   客户端的菜单名称可能随版本不同。
6. 维护完毕关闭窗口或点击“退出程序”。下次刷新订阅前再打开程序。

**不需要一直运行。** 客户端已导入的节点保存在客户端中，关闭本程序不影响
这些节点继续使用；但客户端无法在本程序关闭或服务暂停时刷新此本地订阅。
如果客户端设置了自动更新，关闭本程序期间会出现订阅更新失败提示。

本地订阅地址仅供同一台电脑使用，不是可分享给手机或其他电脑的公网链接。
只有“设置 → 随程序启动服务”控制打开本程序时是否启动订阅服务；
它不等于 Windows 开机自启。

## 节点与格式

| 类型 | 已支持的常用配置 |
| --- | --- |
| VLESS | UUID、TCP / WebSocket / gRPC gun、TLS、Reality、Vision 的适用组合 |
| VMess | Base64 JSON 分享格式、TCP / WebSocket / gRPC gun、TLS |
| SOCKS5 | `socks5://`、`socks://`、可选用户名密码、Base64 认证、IPv6 |
| Trojan | TLS、TCP / WebSocket / gRPC gun |
| Shadowsocks | 常用 AEAD、AEAD-2022、部分 obfs / v2ray-plugin 配置 |

Clash 输出是完整 Mihomo YAML，含手动选择、自动测速分组、订阅规则和 `MATCH` 兜底规则。
v2rayN 输出为 Base64 节点列表；SOCKS5 转为客户端识别的 `socks://` 格式。
不同客户端不能完整表达的配置会明确报错，不会悄悄省略安全或传输参数。

当前未覆盖：Hysteria2、TUIC、SSR、XHTTP、KCP、部分旧 VMess 分享格式、
自定义非 UUID 的 VLESS ID、新式 VLESS 加密以及所有厂商私有参数。
完整边界见 [协议兼容说明](docs/protocol-research.md)。
本程序不抓取远程订阅地址，不把节点发送到在线转换网站。

## 订阅规则

Clash 订阅会带上“订阅规则”页面里管理的规则，按列表顺序写入 `rules:`，
最先匹配的生效；最后的兜底规则固定为“其余流量 → 走代理 (PROXY)”，不可删除。

默认规则覆盖：局域网与私有地址直连、广告及跟踪域名拦截（`GEOSITE,category-ads-all`）、
中国大陆流量直连（`GEOSITE,cn` + `GEOIP,CN`）、Telegram 与常见流媒体走代理。
其中 GeoSite / GeoIP 数据由客户端提供，Clash Verge、Mihomo Party 等主流客户端
会自动下载。规则可在界面中添加、编辑、启用、停用、排序或删除；
误删后可用“恢复默认规则”一键还原，“导出备份”会一并保存规则。

## 可用性测试

- **实际代理**：临时启动独立 Mihomo，通过指定节点向测试地址发出 HTTP HEAD，
  并核验 HTTP 204。只有请求和状态验证均通过才标记“代理可用”。
- **TCP 端口**：只检查域名解析、TCP 连接与耗时，不验证代理密码或最终网站访问。
  “TCP 可达”不等于“代理可用”。
- 测试可取消，有超时和并发限制。测试结束、取消或程序退出会关闭自己启动的内核。
- 每次测试在“测试记录”里只生成一条汇总记录（测试方式、节点总数、成功/失败数量）；
  双击记录（或点击行末的眼睛按钮）可查看这一次测试中每个节点的结果，最多保留最近 50 次。
- 默认使用内置、固定版本的 Mihomo v1.19.33，不使用或修改你已有客户端的内核配置。
- 测试地址须能对 HEAD 返回 204。失败也可能来自该地址不可达，不一定是节点失效。
  可以更换另一个 204 地址复测。HTTPS 目标会验证证书。
- 延迟是这一次测试请求的测量结果，不是下载速度或带宽承诺。

## 数据与隐私

- 数据目录：`%LOCALAPPDATA%\NodeDesk`。可在“设置”中打开。
- 节点名称、地址、凭据、备注和订阅令牌均以当前 Windows 用户的 DPAPI 加密后
  保存在 SQLite 数据库中。该数据库不能直接复制给其他 Windows 用户使用。
- 跨电脑迁移请使用“导出备份 / 恢复备份”。备份、导出的订阅和剪贴板链接
  包含明文凭据，请妥善保管；导出备份前程序会再次提醒。
- 订阅服务仅监听 `127.0.0.1`，默认为 `17890`，URL 含随机访问令牌。
  服务没有远程管理 API。重置令牌后旧订阅地址立即失效。
- 不注册 Windows 服务、计划任务、托盘后台或开机启动项。
  不修改系统代理、TUN、防火墙或现有 Clash Verge / v2rayN 配置。
- 真实测试时，节点和测试网站会看到正常的代理连接。程序自身没有遥测、广告或云同步。
- DPAPI 不阻止同一 Windows 账户下有权限的程序访问你的数据。

## 常见情况

- **端口被占用**：在设置中换一个端口并保存，然后重新复制订阅地址。
  程序不会接管已有端口或终止其他软件。
- **更新订阅失败**：确认程序窗口已打开、左下角服务已开启、客户端直连
  `127.0.0.1`，且链接令牌与端口没有变更。
- **没有启用节点**：服务返回明确错误，不生成可能误导客户端的空配置。
- **链接检查失败**：查看具体行号；可只导入检查通过的项目。
  不支持的参数需在来源处确认，不建议直接删除安全参数。
- **复制链接后改名**：请在客户端重新刷新订阅以更新名称。
- **Windows 提示未签名**：此本地构建没有商业代码签名。不要关闭安全软件；
  可检查源码、发布校验文件并自行构建。程序不需要提升权限。

## 源码运行与维护

源码按职责拆分：

```text
main.py                   Windows 入口与单实例锁
node_desk/formats.py       分享格式解析与订阅输出
node_desk/rules.py         订阅规则模型与默认规则
node_desk/store.py         节点、设置、规则与备份
node_desk/security.py      Windows DPAPI
node_desk/service.py       本地只读订阅 HTTP 服务
node_desk/testing.py       临时测试内核与进程生命周期
node_desk/ui.py            桌面视图与操作
node_desk/dialogs.py       导入、编辑、预览
node_desk/table.py         节点模型、筛选与绘制
node_desk/theme.py         配色、字体与图标
packaging/NodeDesk.iss    安装包（Inno Setup）脚本
tests/                    格式、存储、安全、服务、内核、界面检查
```

在项目目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe scripts\fetch_vendor.py
.\.venv\Scripts\python.exe main.py
```

依赖下载可以显式传入自己的代理，例如
`python scripts\fetch_vendor.py --proxy http://127.0.0.1:端口`。
这只用于构建下载，不修改系统设置。发布包已经附带内核和图标，
正常启动不下载组件。

```powershell
python -m pytest tests -q
python -m scripts.visual_check
python scripts\build_windows.py     # 或直接双击项目根目录的「重新打包.cmd」
```

打包会生成三类产物（都在 `dist`）：

- `dist\NodeDesk`：便携版程序目录，配合「启动程序.cmd」使用，方式与以前完全一样；
- `dist\NodeDesk-<版本>-windows-x64.zip`：便携发布包（内含源码包）；
- `dist\NodeDesk-<版本>-setup.exe`：安装版，由 [Inno Setup 6](https://jrsoftware.org/isdl.php)
  编译。首次打包时若未安装 Inno Setup，脚本会询问是否用 winget 自动安装
  （仅打包工具，不随程序分发）；安装后也可双击「生成安装包.cmd」单独生成。
  安装向导默认为英文（Inno Setup 默认不附带中文语言文件）；从 Inno Setup 官网
  翻译页（jrsoftware.org/files/istrans）下载 ChineseSimplified.isl 放入 `packaging`
  文件夹，脚本会自动改用中文向导，编译失败时也会自动回退英文重试。
  只想要便携版时可运行 `python scripts\build_windows.py --no-installer`。

打包开始时会先清理旧的发布目录：上次强制退出程序残留的测试内核进程（mihomo.exe）
会被自动结束，只读或暂时被扫描的文件会自动重试；确实删不掉时会给出文件与操作提示。
打包成功后脚本会自动清理 `build` 等中间产物，只保留成品与源码；
打包失败时会保留现场便于排查。用 `python main.py --data-dir .qa\manual --no-service`
启动独立测试配置，不要用真实数据库跑测试。源码无需 Node.js 或前端开发服务器。

内核版本固定，是因为测试依赖已验证的 HTTP 状态历史语义。
更新内核时同步检查 `testing.py`、下载校验值、许可证和
`tests/test_testing.py`，不要只替换 EXE 就假定测试语义兼容。

## 验证范围

自动化使用合成节点及受控本地 TCP / SOCKS5 / HTTP 服务器，
不读取已有客户端节点。包括订阅生成、认证失败、状态码错误、
取消、程序退出、临时凭据文件和内核进程清理。

没有提供真实远程节点，所以不承诺你的节点均可用。
Clash 配置通过真实内核验证；v2rayN 格式根据上游导入实现及往返测试验证，
未改动已安装客户端的配置来试导入。

## 开源依赖

项目自编写代码的许可见 `LICENSE`。Mihomo、Qt/PySide6、PyYAML、
Python、PyInstaller 与 Lucide 保持各自许可。对应文本、版本及源码获取方式
见 `licenses`、`THIRD_PARTY_NOTICES.md` 和 `vendor/manifest.json`。
生成安装包时用到 Inno Setup，它只参与打包过程，不随程序分发。
