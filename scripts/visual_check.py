from __future__ import annotations

import base64
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from node_desk.formats import parse_uri
from node_desk.service import SubscriptionService
from node_desk.store import Store
from node_desk.theme import apply_theme
from node_desk.ui import MainWindow
from node_desk.dialogs import ImportDialog


def main():
    root = Path(__file__).resolve().parent.parent
    output = root / ".qa" / "screenshots"
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    apply_theme(app)
    store = Store(root / ".qa" / "visual-profile", protected=False)
    vmess = base64.b64encode(json.dumps({
        "v": "2", "ps": "Tokyo / Transit 01", "add": "jp-01.example.com", "port": "443",
        "id": "11111111-1111-4111-8111-111111111111", "aid": "0",
        "net": "ws", "type": "none", "host": "jp-01.example.com", "path": "/ws", "tls": "tls",
    }).encode()).decode()
    examples = [
        ("vless://11111111-1111-4111-8111-111111111111@hk-01.example.com:443?security=tls&type=tcp#Hong%20Kong%20%2F%20Premium%2001", "主力节点"),
        ("vless://22222222-2222-4222-8222-222222222222@sg-01.example.com:443?security=tls&type=ws&path=%2Fws#Singapore%20%2F%20Edge%2001", "主力节点"),
        ("vmess://" + vmess, "备用节点"),
        ("trojan://sample-password@us-01.example.com:443?sni=us-01.example.com#Los%20Angeles%20%2F%20Transit", "备用节点"),
        ("socks5://demo:sample-password@127.0.0.1:1080#Local%20%2F%20SOCKS5", "本地"),
        ("vless://33333333-3333-4333-8333-333333333333@de-01.example.com:443?security=tls&type=grpc&serviceName=grpc#Frankfurt%20%2F%20Edge%2002", "备用节点"),
        ("ss://YWVzLTI1Ni1nY206c2FtcGxlLXBhc3N3b3Jk@tw-01.example.com:8388#Taipei%20%2F%20Direct", "主力节点"),
    ]
    for uri, group in examples:
        store.add_nodes([parse_uri(uri)], group)
    # These reserved-domain records are visual fixtures, not real connectivity claims.
    nodes = list(reversed(store.list_nodes()))
    for index, node in enumerate(nodes[:5]):
        mode = "tcp" if node["protocol"] == "socks5" else "proxy"
        store.save_test_result({
            "node_id": node["id"], "name": node["name"], "mode": mode,
            "status": "failed" if index == 3 else "ok",
            "latency_ms": None if index == 3 else [42, 67, 98, 180, 1][index],
            "message": "Synthetic visual fixture; not a real node test.",
            "checked_at": "2026-10-28T10:30:00Z",
        })
    store.update_node(nodes[-1]["id"], enabled=False)
    service = SubscriptionService(store)
    window = MainWindow(store, service, start_service=False)
    for width, height in ((1320, 860), (1080, 690)):
        window.resize(width, height)
        window.show()
        for index, page in enumerate(("nodes", "subscriptions", "rules", "history", "settings")):
            window.navigate(index)
            app.processEvents()
            window.grab().save(str(output / f"{page}-{width}.png"))
    window.resize(1320, 860)
    window.navigate(0)
    dialog = ImportDialog(window.groups(), window)
    dialog.text.setPlainText("\n".join(uri for uri, _ in examples[:3]))
    dialog.check()
    dialog.show()
    app.processEvents()
    dialog.grab().save(str(output / "import.png"))
    dialog.close()
    window.close()
    app.processEvents()
    store.close()
    print(str(output))


if __name__ == "__main__":
    main()
