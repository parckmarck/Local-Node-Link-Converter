"""Launch an isolated QA profile; never touches the user's normal library."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from node_desk.formats import parse_uri
from node_desk.store import Store


def main():
    root = Path(__file__).resolve().parent.parent
    profile = root / ".qa" / "native-profile"
    store = Store(profile)
    store.update_settings({"port": 17892, "start_service": True})
    store.add_nodes(
        [parse_uri("socks5://demo:synthetic-password@127.0.0.1:49180#Local%20QA%20SOCKS5")],
        "\u6d4b\u8bd5\u5206\u7ec4",
    )
    store.add_nodes(
        [parse_uri("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp#Reserved%20domain%20fixture")],
        "\u683c\u5f0f\u68c0\u67e5",
    )
    store.close()
    executable = root / "dist" / "NodeDesk" / "NodeDesk.exe"
    command = [str(executable)] if executable.is_file() else [sys.executable, str(root / "main.py")]
    process = subprocess.Popen(
        [*command, "--data-dir", str(profile)], cwd=root,
        creationflags=subprocess.CREATE_NO_WINDOW,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"QA_PID={process.pid}")
    print(f"QA_PROFILE={profile}")
    print("QA_PORT=17892")


if __name__ == "__main__":
    main()
