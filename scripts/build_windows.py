from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from node_desk import __version__  # noqa: E402 - resolved from the project root


def make_icon():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QByteArray, QRectF, Qt
    from PySide6.QtGui import QColor, QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    source = (ROOT / "assets" / "icons" / "network.svg").read_bytes()
    svg = QSvgRenderer(QByteArray(source.replace(b"currentColor", b"#ffffff")))
    image = QImage(256, 256, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#087f6d"))
    painter.drawRoundedRect(QRectF(8, 8, 240, 240), 40, 40)
    svg.render(painter, QRectF(53, 53, 150, 150))
    painter.end()
    if not image.save(str(ROOT / "assets" / "app.ico"), "ICO"):
        raise RuntimeError("Qt could not create the Windows app icon.")


def source_files():
    roots = ["node_desk", "scripts", "tests", "docs", "assets", "licenses", "packaging"]
    standalone = [
        "main.py", "NodeDesk.spec", "README.md", "THIRD_PARTY_NOTICES.md",
        "LICENSE", "requirements.txt", "requirements-dev.txt",
        "requirements-protocols.txt", "vendor/manifest.json",
        "启动程序.cmd", "重新打包.cmd", "生成安装包.cmd",
    ]
    for relative in standalone:
        yield ROOT / relative
    for folder in roots:
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                yield path


def ensure_dist_not_locked(distribution: Path) -> None:
    """若旧的 NodeDesk.exe 仍被占用（程序还在运行），提前给出清晰提示。"""
    exe = distribution / "NodeDesk.exe"
    if not exe.exists():
        return
    try:
        with open(exe, "ab"):
            pass
    except OSError:
        print()
        print("检测到 dist\\NodeDesk\\NodeDesk.exe 正在被占用，多半是 NodeDesk 程序还在运行。")
        print("请先关闭 NodeDesk 窗口（任务栏找不到窗口时，按 Ctrl+Shift+Esc 打开任务管理器，")
        print("找到 NodeDesk.exe 并结束任务），然后重新双击「重新打包.cmd」。")
        raise SystemExit(1)


def _remove_tree_collect_errors(path: Path) -> list[Path]:
    """删除目录树；返回删不掉的路径（只读属性会被清除后重试一次）。"""
    failures: list[Path] = []
    if not path.exists():
        return failures

    def handle(function, failing, _error):
        failing = Path(failing)
        try:  # 只读属性会阻止删除；在现有权限上补写位后重试一次。
            os.chmod(failing, os.stat(failing).st_mode | stat.S_IWRITE)
        except OSError:
            pass
        if function in (os.unlink, os.rmdir):
            try:
                function(failing)
                return
            except OSError:
                pass
        failures.append(failing)

    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=handle)
        else:
            shutil.rmtree(path, onerror=handle)
    except FileNotFoundError:
        pass
    except Exception:
        failures.append(path)
    return failures


def _image_path(pid: int) -> str:
    """进程映像完整路径；查询失败（如权限不足）时返回空字符串。"""
    if os.name != "nt":
        return ""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_ssize_t
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = (
        ctypes.c_ssize_t, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.CloseHandle.argtypes = (ctypes.c_ssize_t,)
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        kernel32.CloseHandle(handle)


def _terminate_process(pid: int) -> bool:
    """结束进程并等待其退出；无权限（例如对方以管理员身份运行）时返回 False。"""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_ssize_t
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = (ctypes.c_ssize_t, wintypes.UINT)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = (ctypes.c_ssize_t, wintypes.DWORD)
    kernel32.CloseHandle.argtypes = (ctypes.c_ssize_t,)
    handle = kernel32.OpenProcess(0x00100000 | 0x0001, False, pid)  # SYNCHRONIZE | TERMINATE
    if not handle:
        return False
    try:
        if not kernel32.TerminateProcess(handle, 1):
            return False
        return kernel32.WaitForSingleObject(handle, 5000) == 0
    finally:
        kernel32.CloseHandle(handle)


def _kernel_processes(distribution: Path) -> list[int]:
    """正从本发布目录运行的测试内核进程 PID；不会碰你其它客户端自己的 mihomo。"""
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_ssize_t
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = (ctypes.c_ssize_t, ctypes.POINTER(ProcessEntry))
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = (ctypes.c_ssize_t, ctypes.POINTER(ProcessEntry))
    kernel32.CloseHandle.argtypes = (ctypes.c_ssize_t,)

    target = os.path.normcase(os.path.abspath(str(distribution / "_internal" / "vendor" / "mihomo.exe")))
    pids: list[int] = []
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot == -1:
        return pids
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(ProcessEntry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            if entry.szExeFile.lower() == "mihomo.exe":
                pid = int(entry.th32ProcessID)
                if os.path.normcase(_image_path(pid)) == target:
                    pids.append(pid)
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return pids


def _file_lockers(path: Path) -> list[tuple[int, str, str]]:
    """用 Windows 重启管理器查询占用文件的进程，返回 (PID, 程序名, 映像路径)。"""
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    class UniqueProcess(ctypes.Structure):
        _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]

    class ProcessInfo(ctypes.Structure):
        _fields_ = [
            ("Process", UniqueProcess),
            ("strAppName", wintypes.WCHAR * 256),
            ("strServiceShortName", wintypes.WCHAR * 64),
            ("ApplicationType", wintypes.DWORD),
            ("AppStatus", wintypes.ULONG),
            ("TSSessionId", wintypes.DWORD),
            ("bRestartable", wintypes.BOOL),
        ]

    manager = ctypes.WinDLL("rstrtmgr", use_last_error=True)
    manager.RmStartSession.argtypes = (ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.LPWSTR)
    manager.RmStartSession.restype = wintypes.DWORD
    manager.RmRegisterResources.argtypes = (
        wintypes.DWORD, wintypes.UINT, ctypes.POINTER(wintypes.LPCWSTR),
        wintypes.UINT, ctypes.c_void_p, wintypes.UINT, ctypes.c_void_p,
    )
    manager.RmRegisterResources.restype = wintypes.DWORD
    manager.RmGetList.argtypes = (
        wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(ProcessInfo), ctypes.POINTER(wintypes.DWORD),
    )
    manager.RmGetList.restype = wintypes.DWORD
    manager.RmEndSession.argtypes = (wintypes.DWORD,)
    manager.RmEndSession.restype = wintypes.DWORD

    session = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(33)
    if manager.RmStartSession(ctypes.byref(session), 0, key) != 0:
        return []
    try:
        files = (wintypes.LPCWSTR * 1)(str(path))
        if manager.RmRegisterResources(session.value, 1, files, 0, None, 0, None) != 0:
            return []
        needed, count = wintypes.UINT(0), wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        code = manager.RmGetList(session.value, ctypes.byref(needed), ctypes.byref(count), None,
                                 ctypes.byref(reasons))
        if needed.value == 0 or code not in (0, 234):  # 234 = ERROR_MORE_DATA
            return []
        infos = (ProcessInfo * needed.value)()
        count = wintypes.UINT(needed.value)
        if manager.RmGetList(session.value, ctypes.byref(needed), ctypes.byref(count), infos,
                             ctypes.byref(reasons)) != 0:
            return []
        lockers = []
        for info in infos[: count.value]:
            pid = int(info.Process.dwProcessId)
            lockers.append((pid, info.strAppName, _image_path(pid)))
        return lockers
    finally:
        manager.RmEndSession(session.value)


def _describe_process(pid: int, name: str, image: str) -> str:
    return f"  PID {pid}  {image or name or '(未知程序)'}"


def remove_old_distribution(distribution: Path) -> None:
    """删除旧发布目录：自动结束残留测试内核、等待安全软件扫描结束，其余占用给出可操作提示。"""
    ensure_dist_not_locked(distribution)  # 也拦住“打包开始后用户又打开了程序”的情况
    failures = _remove_tree_collect_errors(distribution)
    if not failures:
        return
    kernel_path = os.path.normcase(
        os.path.abspath(str(distribution / "_internal" / "vendor" / "mihomo.exe"))
    )
    attempts = 8
    for attempt in range(1, attempts + 1):
        locked = failures[0]
        try:
            lockers = _file_lockers(locked)
        except Exception:
            lockers = []
        kernels = {pid for pid, _, image in lockers if image and os.path.normcase(image) == kernel_path}
        if locked.name.lower() == "mihomo.exe":
            try:
                kernels.update(_kernel_processes(distribution))
            except Exception:
                pass
        apps = [
            (pid, name, image) for pid, name, image in lockers if pid not in kernels
            and (Path(image).name if image else name).lower() in ("nodedesk.exe", "node desk")
        ]
        if apps:
            print()
            print("NodeDesk 程序正在运行，占用了旧发布目录中的文件：")
            for item in apps:
                print(_describe_process(*item))
            print("请先关闭 NodeDesk 窗口（包括已安装版本的窗口），然后重新双击「重新打包.cmd」。")
            raise SystemExit(1)
        if kernels:
            ended = [pid for pid in sorted(kernels) if _terminate_process(pid)]
            stuck = sorted(kernels - set(ended))
            if ended:
                listed = "、".join(f"PID {pid}" for pid in ended)
                print(f"检测到上次运行残留的测试内核进程（mihomo.exe，{listed}），已自动结束。")
            if stuck:
                print()
                listed = "、".join(f"PID {pid}" for pid in stuck)
                print(f"发现残留的测试内核进程（mihomo.exe，{listed}），但没有权限结束它，")
                print("它可能以管理员身份启动。请在任务管理器（Ctrl+Shift+Esc）→「详细信息」中")
                print("结束 mihomo.exe 后，重新双击「重新打包.cmd」。")
                raise SystemExit(1)
            time.sleep(0.5)
        else:
            others = sorted({
                (Path(image).name if image else name) or f"PID {pid}"
                for pid, name, image in lockers
            })
            who = "、".join(others) if others else "安全软件或系统"
            print(f"旧发布目录中的 {locked.name} 正被 {who} 占用（通常是后台扫描），"
                  f"等待后重试（{attempt}/{attempts}）……")
            time.sleep(2.5)
        failures = _remove_tree_collect_errors(distribution)
        if not failures:
            print("占用已解除，继续打包。")
            return
    locked = failures[0]
    print()
    print(f"无法删除旧的发布目录，文件仍被占用：{locked}")
    try:
        lockers = _file_lockers(locked)
    except Exception:
        lockers = []
    if lockers:
        print("当前占用它的程序：")
        for item in lockers:
            print(_describe_process(*item))
        print("请关闭或结束上述程序后重试；若是安全软件，请把「节点维护」文件夹加入其信任（排除）列表。")
    else:
        print("没有查到占用它的程序，一般是安全软件在后台扫描：请稍等一两分钟后再双击「重新打包.cmd」；")
        print("反复出现时，把「节点维护」文件夹加入安全软件的信任（排除）列表，或重启电脑后再试。")
    raise SystemExit(1)


def install_core(distribution: Path) -> None:
    """把经过校验的测试内核写入发布目录（带重试，避开安全软件的瞬时拦截）。"""
    source = ROOT / "vendor" / "mihomo.exe"
    target = distribution / "_internal" / "vendor" / "mihomo.exe"
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    last_problem = "未知原因"
    for attempt in range(1, 7):
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(data)
            if hashlib.sha256(target.read_bytes()).hexdigest() == digest:
                return
            last_problem = "写入后校验不一致"
        except OSError as error:
            last_problem = str(error)
        if attempt < 6:
            print(f"测试内核写入被临时拒绝（{last_problem}），5 秒后自动重试（第 {attempt} 次）……")
            time.sleep(5)
    print()
    print(f"无法把测试内核写入发布目录：{target}")
    print(f"最后的问题：{last_problem}")
    print("这通常是安全软件（Windows 安全中心或第三方杀毒）拦截了 mihomo.exe 的写入。")
    print("请打开「Windows 安全中心 → 保护历史记录」或第三方安全软件的拦截日志确认，")
    print("把整个「节点维护」文件夹加入信任/排除项（或临时关闭防护）后重新打包；")
    print("仍然失败时，重启电脑后再双击「重新打包.cmd」试试。")
    raise SystemExit(1)


def find_iscc() -> Path | None:
    candidates = []
    override = os.environ.get("NODEDESK_ISCC")
    if override:
        candidates.append(Path(override))
    local_appdata = os.environ.get("LOCALAPPDATA")
    for base in (
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramFiles"),
        os.path.join(local_appdata, "Programs") if local_appdata else None,
        local_appdata,
    ):
        if base:
            candidates.append(Path(base) / "Inno Setup 6" / "ISCC.exe")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("ISCC")
    return Path(found) if found else None


def _offer_inno_setup_install() -> None:
    print()
    print("生成安装包需要免费工具 Inno Setup 6（仅打包时使用，不随程序分发）。")
    print("  方式一（推荐，自动）：按提示输入 y，脚本会调用 winget 自动安装；")
    print("                        如弹出管理员授权（UAC）窗口请选择“是”。")
    print("  方式二（手动）：访问 https://jrsoftware.org/isdl.php 下载并安装 Inno Setup 6，")
    print("                  安装时一路默认下一步即可，然后双击「生成安装包.cmd」重试。")
    if not (sys.stdin and sys.stdin.isatty()):
        return
    try:
        answer = input("是否现在自动安装 Inno Setup 6？需要联网 [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in {"y", "yes", "是"}:
        return
    try:
        completed = subprocess.run([
            "winget", "install", "-e", "--id", "JRSoftware.InnoSetup",
            "--accept-source-agreements", "--accept-package-agreements",
            "--disable-interactivity",
        ])
    except OSError:
        print("未能启动 winget（系统可能缺少“应用安装程序”），请改用方式二手动安装。")
        return
    if completed.returncode != 0:
        print("winget 安装未成功，请改用方式二手动安装后重试。")


def build_installer() -> tuple[str, object]:
    """用 Inno Setup 编译安装包；返回 ("ok"|"skipped"|"failed", 详情)。"""
    distribution = ROOT / "dist" / "NodeDesk"
    if not (distribution / "NodeDesk.exe").is_file():
        return "failed", "未找到 dist\\NodeDesk（请先运行「重新打包.cmd」生成程序本体）。"
    if not (distribution / "_internal" / "vendor" / "mihomo.exe").is_file():
        return "failed", "dist\\NodeDesk 中缺少测试内核 mihomo.exe，请先运行「重新打包.cmd」重新生成。"
    if not (ROOT / "assets" / "app.ico").is_file():
        make_icon()
    iscc = find_iscc()
    if iscc is None:
        _offer_inno_setup_install()
        iscc = find_iscc()
    if iscc is None:
        return "skipped", "未安装 Inno Setup 6，已跳过安装包生成。"
    chinese_isl = None
    for candidate in (
        iscc.parent / "Languages" / "ChineseSimplified.isl",  # 编译器自带（部分安装方式附带）
        ROOT / "packaging" / "ChineseSimplified.isl",        # 随项目附带的副本
    ):
        if candidate.is_file():
            chinese_isl = candidate
            break
    for stale in (ROOT / "dist").glob("NodeDesk-*-setup.exe"):
        stale.unlink()
    print("正在生成安装包（Inno Setup 编译，约 1-3 分钟）……")

    def compile_once(isl_path: Path | None):
        command = [
            str(iscc), "/Qp",
            f"/DAppVersion={__version__}",
            f"/DSourceDir={distribution}",
            f"/DOutputDir={ROOT / 'dist'}",
            f"/DProjectRoot={ROOT}",
        ]
        if isl_path is not None:
            command.append(f"/DChineseIsl={isl_path}")
        command.append(str(ROOT / "packaging" / "NodeDesk.iss"))
        return subprocess.run(command, cwd=ROOT, check=False)

    completed = compile_once(chinese_isl)
    if completed.returncode != 0 and chinese_isl is not None:
        print()
        print(f"中文安装向导未能编译通过（语言文件：{chinese_isl}）。")
        print("已自动改用英文安装向导重试一次，安装包功能不受影响。")
        completed = compile_once(None)
    setup = ROOT / "dist" / f"NodeDesk-{__version__}-setup.exe"
    if completed.returncode != 0:
        return "failed", f"Inno Setup 编译失败（退出码 {completed.returncode}），请把上方输出发给协助排查的人。"
    if not setup.is_file():
        return "failed", f"编译完成但未找到 {setup.name}，请检查安装包脚本的输出文件名设置。"
    return "ok", setup


def write_checksums() -> None:
    dist = ROOT / "dist"
    files = []
    exe = dist / "NodeDesk" / "NodeDesk.exe"
    if exe.is_file():
        files.append(exe)
    files.extend(sorted(dist.glob("NodeDesk-*.zip")))
    files.extend(sorted(dist.glob("NodeDesk-*-setup.exe")))
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(dist).as_posix()}\n"
        for path in files
    ]
    (dist / "SHA256SUMS.txt").write_text("".join(lines), encoding="ascii", newline="\n")


def clean_intermediates():
    """深度清理打包过程的中间产物，只保留 dist 成品与源码。"""
    targets = [
        ROOT / "build",
        ROOT / "__pycache__",
        ROOT / ".pytest_cache",
        ROOT / ".qa",
        ROOT / "_removed_icu_strays",
    ]
    targets += [ROOT / folder / "__pycache__" for folder in ("node_desk", "scripts", "tests")]
    for target in targets:
        shutil.rmtree(target, ignore_errors=True)


def build_portable() -> Path:
    if os.name != "nt" or sys.maxsize < 2**32:
        raise RuntimeError("Build this distribution with 64-bit Python on Windows.")
    core = ROOT / "vendor" / "mihomo.exe"
    manifest = json.loads((ROOT / "vendor" / "manifest.json").read_text(encoding="utf-8"))
    if hashlib.sha256(core.read_bytes()).hexdigest() != manifest["mihomo"]["executable_sha256"]:
        raise RuntimeError("Bundled core checksum changed. Fetch the pinned vendor inputs first.")
    make_icon()
    child_env = os.environ.copy()
    child_env.pop("QT_QPA_PLATFORM", None)
    distribution = ROOT / "dist" / "NodeDesk"
    # 先移除旧的发布目录（被占用时给出针对性提示，并自动清理残留的测试内核）。
    remove_old_distribution(distribution)
    try:
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--noconfirm", str(ROOT / "NodeDesk.spec")],
            cwd=ROOT, env=child_env, check=True,
        )
    except subprocess.CalledProcessError as error:
        print()
        print("打包没有完成（详细输出在上方）。若错误与“拒绝访问 / PermissionError”有关，")
        print("通常是 NodeDesk 程序或测试内核还在运行：请在任务管理器中结束 NodeDesk.exe")
        print("与 mihomo.exe 进程，然后重新双击「重新打包.cmd」再试一次。")
        raise SystemExit(1) from error
    install_core(distribution)
    for stale in (ROOT / "dist").glob("NodeDesk-*.zip"):
        stale.unlink()
    for name in ("README.md", "THIRD_PARTY_NOTICES.md", "LICENSE"):
        shutil.copyfile(ROOT / name, distribution / name)
    source_zip = ROOT / "dist" / f"NodeDesk-{__version__}-source.zip"
    with zipfile.ZipFile(source_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=8) as output:
        for path in source_files():
            output.write(path, "NodeDesk-source/" + path.relative_to(ROOT).as_posix())
    portable = ROOT / "dist" / f"NodeDesk-{__version__}-windows-x64.zip"
    with zipfile.ZipFile(portable, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in distribution.rglob("*"):
            if path.is_file():
                output.write(path, "NodeDesk/" + path.relative_to(distribution).as_posix())
        output.write(source_zip, f"NodeDesk/NodeDesk-{__version__}-source.zip")
    return portable


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Node Desk distributions.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--installer-only", action="store_true",
                       help="跳过便携版打包，仅用现有 dist 生成安装包")
    group.add_argument("--no-installer", action="store_true",
                       help="只生成便携版，不生成安装包")
    args = parser.parse_args()

    if args.installer_only:
        print(f"NodeDesk {__version__} 安装包生成（使用现有 dist\\NodeDesk 目录；如需最新版本请先运行「重新打包.cmd」）……")
        state, detail = build_installer()
        if state == "ok":
            write_checksums()
            print(f"安装包已生成：{detail}")
            return 0
        print(detail)
        if state == "skipped":
            print("安装 Inno Setup 6 后，重新双击「生成安装包.cmd」即可。")
        return 1

    print(f"NodeDesk {__version__} 打包开始，请保持窗口打开（便携版约 1-3 分钟，含安装包会更久）……")
    portable = build_portable()
    print(f"便携版已生成：{portable}")
    exit_code = 0
    if args.no_installer:
        print("已按 --no-installer 跳过安装包生成。")
    else:
        state, detail = build_installer()
        if state == "ok":
            print(f"安装包已生成：{detail}")
        elif state == "skipped":
            print(detail)
            print("安装 Inno Setup 6 后，双击「生成安装包.cmd」即可快速补齐安装包（无需重新打包便携版）。")
        else:
            print(f"安装包未能生成：{detail}")
            exit_code = 1
    write_checksums()
    clean_intermediates()
    print("中间产物已清理：build/、__pycache__、.pytest_cache、.qa。")
    print("便携版可双击「启动程序.cmd」运行；发布文件都在 dist 目录。")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
