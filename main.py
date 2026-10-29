from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtCore import QLockFile
from PySide6.QtWidgets import QApplication

from node_desk.dialogs import error_dialog
from node_desk.paths import default_data_dir
from node_desk.service import SubscriptionService
from node_desk.store import Store
from node_desk.theme import apply_theme
from node_desk.ui import MainWindow


def main() -> int:
    parser = argparse.ArgumentParser(description="Node Desk local desktop manager")
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--no-service", action="store_true")
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("Node Desk")
    app.setOrganizationName("NodeDesk")
    app.setQuitOnLastWindowClosed(True)
    apply_theme(app)
    directory = (args.data_dir or default_data_dir()).resolve()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        error_dialog(None, "无法打开数据目录", "请检查本地数据目录的写入权限。")
        return 1
    lock = QLockFile(str(directory / "app.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        error_dialog(None, "程序已在运行", "此数据目录已经由另一个 Node Desk 窗口打开。")
        return 1
    store = None
    service = None
    try:
        store = Store(directory)
        service = SubscriptionService(store)
        window = MainWindow(store, service, start_service=not args.no_service)
        window.show()
        return app.exec()
    except Exception as error:
        # Never write node credentials, subscription URLs, or full tracebacks to logs.
        error_dialog(None, "程序无法启动", f"本地数据或程序组件无法读取（{type(error).__name__}）。请保留原数据并检查程序文件是否完整。")
        return 1
    finally:
        if service:
            service.stop()
        if store:
            store.close()
        lock.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
