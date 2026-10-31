from __future__ import annotations

import os
import socket
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from node_desk.dialogs import EditDialog, ImportDialog
from node_desk.formats import parse_uri
from node_desk.service import SubscriptionService
from node_desk.store import Store
from node_desk.theme import apply_theme
from node_desk.ui import MainWindow
from node_desk.table import node_test_state, proxy_tested
from node_desk.messages import display_test_message


@pytest.fixture(scope="module")
def app():
    value = QApplication.instance() or QApplication([])
    apply_theme(value)
    return value


@pytest.fixture
def window(app, tmp_path):
    store = Store(tmp_path, protected=False)
    service = SubscriptionService(store)
    value = MainWindow(store, service, start_service=False)
    value.show()
    app.processEvents()
    yield value
    value.close()
    app.processEvents()
    service.stop()
    store.close()


def populate(window):
    window.store.add_nodes([parse_uri("socks5://127.0.0.1:1080#First")], "Group A")
    window.store.add_nodes([parse_uri("socks5://127.0.0.1:1081#Second")], "Group B")
    window.refresh()


def test_initial_state_is_empty_and_service_off(window):
    assert window.model.rowCount() == 0
    assert window.table_stack.currentIndex() == 1
    assert not window.service.running
    assert not window.test_button.isEnabled()


def test_import_dialog_partial_validation(app):
    dialog = ImportDialog(["Group A"])
    dialog.text.setPlainText("socks5://127.0.0.1:1080#One\nsocks5://127.0.0.1:1081#Two\ninvalid")
    dialog.check()
    assert len(dialog.parsed_nodes) == 2
    assert dialog.import_button.isEnabled()
    assert "3" in dialog.errors.toPlainText()
    dialog.text.setPlainText("changed")
    assert not dialog.import_button.isEnabled()


def test_manual_socks_dialog(app):
    dialog = ImportDialog([])
    dialog.tabs.setCurrentIndex(1)
    dialog.socks_host.setText("::1")
    dialog.socks_name.setText("IPv6")
    dialog.socks_auth.setChecked(True)
    dialog.socks_user.setText("user")
    dialog.socks_password.setText("a@b:c")
    dialog.check()
    assert len(dialog.parsed_nodes) == 1
    assert dialog.parsed_nodes[0]["server"] == "::1"
    assert dialog.parsed_nodes[0]["clash"]["password"] == "a@b:c"


def test_search_groups_and_selection(window):
    populate(window)
    assert window.proxy.rowCount() == 2
    window.search.setText("First")
    assert window.proxy.rowCount() == 1
    window.select_visible(True)
    assert len(window.model.checked) == 1
    window.set_selected_enabled(False)
    assert sum(node["enabled"] for node in window.model.nodes) == 1
    window.reset_filters()
    assert window.proxy.rowCount() == 2
    index = window.group_filter.findData("Group B")
    window.group_filter.setCurrentIndex(index)
    assert window.proxy.rowCount() == 1


def test_subscription_views_populate_and_empty_scope_disables_actions(window):
    populate(window)
    window.navigate(1)
    assert len(window._export_cache) == 3
    assert window.client_widgets["clash"]["copy"].isEnabled()
    assert window.client_widgets["singbox"]["copy"].isEnabled()
    ids = [node["id"] for node in window.model.nodes]
    window.store.set_enabled(ids, False)
    window.refresh()
    assert window._export_cache == {}
    assert not window.client_widgets["clash"]["copy"].isEnabled()
    assert not window.client_widgets["singbox"]["copy"].isEnabled()


def test_edit_metadata_and_export(window):
    populate(window)
    node = window.model.nodes[0]
    dialog = EditDialog(node, window.groups())
    dialog.name.setText("Renamed")
    dialog.group.setCurrentText("Renamed group")
    window.store.update_node(node["id"], **dialog.changes())
    window.refresh()
    window.navigate(1)
    assert "Renamed" in window._export_cache["clash"]
    assert '"tag": "Renamed"' in window._export_cache["singbox"]


def test_native_background_test_completes_without_blocking_ui(window, app):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    window.store.add_nodes([parse_uri(f"socks5://127.0.0.1:{port}#Controlled")])
    window.refresh()
    window.run_tests(mode="tcp")
    deadline = time.monotonic() + 5
    while window.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    listener.close()
    assert window.worker is None
    result = window.store.list_nodes()[0]["tests"]["tcp"]
    assert result["status"] == "ok"
    sessions = window.store.list_test_sessions()
    assert len(sessions) == 1
    assert sessions[0]["mode"] == "tcp"
    assert sessions[0]["counts"]["ok"] == 1
    assert sessions[0]["finished_at"]
    assert window.test_button.isVisible()
    assert not window.service.running


def test_minimum_window_keeps_toolbar_inside_page(window, app):
    populate(window)
    window.resize(1080, 690)
    app.processEvents()
    for control in (window.import_button, window.test_button, window.mode_combo, window.search):
        assert control.width() > 0
        assert control.geometry().right() < window.node_page.width()


def test_cancelled_proxy_remains_untested():
    node = {"tests": {"proxy": {"status": "cancelled"}}}
    assert not proxy_tested(node)
    assert node_test_state(node)[2] == "untested"


def test_engine_messages_are_readable_in_chinese():
    assert display_test_message("Test cancelled.") == "\u6d4b\u8bd5\u5df2\u53d6\u6d88\u3002"
    assert "204" in display_test_message("Proxy HTTP HEAD returned the expected status (204).")
    assert display_test_message("custom diagnostic") == "custom diagnostic"


def test_close_during_test_flushes_results_and_releases_service(window, app):
    window.store.add_nodes([
        parse_uri(f"socks5://127.0.0.1:{port}#Fixture") for port in range(49180, 49188)
    ])
    window.refresh()
    window.service.start(0)
    port = window.service.port
    window.run_tests(mode="tcp")
    window.close()
    assert window._closing
    assert not window.service.running
    deadline = time.monotonic() + 5
    while window.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert window.worker is None
    assert not window.isVisible()
    assert all("tcp" in item["tests"] for item in window.store.list_nodes())
    sessions = window.store.list_test_sessions()
    assert len(sessions) == 1
    assert sessions[0]["cancelled"] is True
    assert sessions[0]["tested"] == 8
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=0.1)
