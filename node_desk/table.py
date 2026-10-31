from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel, QEvent, QModelIndex, QRect, QRectF, QSize, QSortFilterProxyModel,
    Qt, Signal,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QStyle, QStyledItemDelegate

from .messages import display_test_message
from .theme import ACCENT, AMBER, BLUE, GREEN, INK, MUTED, RED, icon

NODE_ROLE = int(Qt.ItemDataRole.UserRole) + 1
SORT_ROLE = int(Qt.ItemDataRole.UserRole) + 2


def node_test_state(node: dict, testing=False) -> tuple[str, str, str, int | None]:
    if testing:
        return "测试中", BLUE, "testing", None
    tests = node.get("tests", {})
    proxy = tests.get("proxy")
    if proxy and proxy["status"] != "cancelled":
        if proxy["status"] == "ok":
            return "代理可用", GREEN, "ok", proxy.get("latency_ms")
        if proxy["status"] == "failed":
            return "代理失败", RED, "failed", None
        return "不支持", AMBER, "unsupported", None
    tcp = tests.get("tcp")
    if tcp and tcp["status"] != "cancelled":
        if tcp["status"] == "ok":
            return "TCP 可达", BLUE, "tcp", tcp.get("latency_ms")
        if tcp["status"] == "failed":
            return "TCP 失败", RED, "failed", None
        return "不支持 TCP", AMBER, "unsupported", None
    if proxy and proxy["status"] == "cancelled":
        return "已取消", MUTED, "untested", None
    return "未测试", MUTED, "untested", None


def proxy_tested(node: dict) -> bool:
    return node.get("tests", {}).get("proxy", {}).get("status") in ("ok", "failed", "unsupported")


class NodeModel(QAbstractTableModel):
    selection_changed = Signal()
    enabled_changed = Signal(str, bool)
    HEADERS = ["", "节点", "协议", "分组", "连接状态", "延迟", "订阅", ""]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes: list[dict] = []
        self.checked: set[str] = set()
        self.testing: set[str] = set()

    def replace(self, nodes: list[dict]):
        self.beginResetModel()
        self.nodes = nodes
        self.checked.intersection_update(node["id"] for node in nodes)
        self.endResetModel()
        self.selection_changed.emit()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.nodes)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.nodes):
            return None
        node, column = self.nodes[index.row()], index.column()
        state, color, status, delay = node_test_state(node, node["id"] in self.testing)
        if role == NODE_ROLE:
            return node
        if role == Qt.ItemDataRole.CheckStateRole and column == 0:
            return Qt.CheckState.Checked if node["id"] in self.checked else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.SizeHintRole:
            return QSize(70, 64)
        if role == Qt.ItemDataRole.ToolTipRole:
            if column == 1:
                return f"{node['name']}\n{node['server']}:{node['port']}"
            if column == 3:
                return node["group"] or "未分组"
            if column in (4, 5):
                latest = node.get("tests", {}).get("proxy") or node.get("tests", {}).get("tcp")
                return display_test_message((latest or {}).get("message", "尚无测试结果"))
            if column == 6:
                return "从订阅中移除" if node["enabled"] else "加入订阅"
        if role in (Qt.ItemDataRole.DisplayRole, SORT_ROLE):
            values = [
                "", node["name"], node["protocol"].upper(), node["group"] or "未分组",
                state, delay if delay is not None else 2**31,
                "已启用" if node["enabled"] else "已停用", "",
            ]
            if column == 5 and role == Qt.ItemDataRole.DisplayRole:
                return f"{delay} ms" if delay is not None else "-"
            return values[column]
        if role == Qt.ItemDataRole.ForegroundRole:
            return QColor(color if column == 4 else INK)
        return None

    def flags(self, index):
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if role == Qt.ItemDataRole.CheckStateRole and index.column() == 0:
            node_id = self.nodes[index.row()]["id"]
            if value == Qt.CheckState.Checked or value == Qt.CheckState.Checked.value:
                self.checked.add(node_id)
            else:
                self.checked.discard(node_id)
            self.dataChanged.emit(index, index, [role])
            self.selection_changed.emit()
            return True
        return False

    def set_checked(self, node_ids: list[str], checked: bool):
        if checked:
            self.checked.update(node_ids)
        else:
            self.checked.difference_update(node_ids)
        if self.nodes:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.nodes) - 1, 0))
        self.selection_changed.emit()


class NodeFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.search = ""
        self.protocol = ""
        self.group: str | None = None
        self.status = ""
        self.setSortRole(SORT_ROLE)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def update_filters(self, *, search="", protocol="", group=None, status=""):
        self.beginFilterChange()
        self.search, self.protocol, self.group, self.status = (
            search.casefold().strip(), protocol, group, status
        )
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(self, source_row, source_parent):
        node = self.sourceModel().nodes[source_row]
        if self.search not in " ".join(
            [node["name"], node["server"], node["group"], node.get("note", "")]
        ).casefold():
            return False
        if self.protocol and self.protocol != node["protocol"]:
            return False
        if self.group is not None and self.group != node["group"]:
            return False
        state = node_test_state(node)[2]
        return not self.status or (
            (self.status == "untested" and not proxy_tested(node))
            or (self.status == "ok" and state == "ok")
            or (self.status == "failed" and state in ("failed", "unsupported"))
        )


class NodeDelegate(QStyledItemDelegate):
    edit_requested = Signal(str)
    menu_requested = Signal(str)
    toggle_requested = Signal(str, bool)

    def paint(self, painter: QPainter, option, index):
        node = index.data(NODE_ROLE)
        column = index.column()
        if column == 0:
            super().paint(painter, option, index)
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = option.rect
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(rect, QColor("#edf6f2"))
        elif option.state & QStyle.StateFlag.State_MouseOver:
            painter.fillRect(rect, QColor("#fafcfb"))
        painter.setPen(QColor("#edf0f4"))
        painter.drawLine(rect.bottomLeft(), rect.bottomRight())
        font = QFont(option.font)
        font.setPixelSize(12)
        painter.setFont(font)
        painter.setPen(QColor(INK))
        text_rect = rect.adjusted(8, 0, -8, 0)
        if column == 1:
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            painter.drawText(
                text_rect.adjusted(0, 10, 0, -29),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                painter.fontMetrics().elidedText(node["name"], Qt.TextElideMode.ElideRight, text_rect.width()),
            )
            font.setWeight(QFont.Weight.Normal)
            font.setPixelSize(11)
            painter.setFont(font)
            painter.setPen(QColor("#939caa"))
            host = f"[{node['server']}]" if ":" in node["server"] else node["server"]
            text = f"{host}:{node['port']}"
            painter.drawText(
                text_rect.adjusted(0, 30, 0, -8),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                painter.fontMetrics().elidedText(text, Qt.TextElideMode.ElideMiddle, text_rect.width()),
            )
        elif column == 2:
            protocol = node["protocol"]
            color, background = {
                "vless": (ACCENT, "#e9f5ef"), "vmess": (BLUE, "#edf3fc"),
                "socks5": ("#8c6c28", "#faf4e7"), "trojan": ("#b06372", "#fbf0f3"),
                "ss": ("#5e6b79", "#eef1f5"),
            }.get(protocol, (MUTED, "#f0f2f5"))
            title = protocol.upper()
            font.setPixelSize(10)
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            width = min(painter.fontMetrics().horizontalAdvance(title) + 16, text_rect.width())
            badge = QRectF(text_rect.left(), rect.center().y() - 11, width, 22)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(background))
            painter.drawRoundedRect(badge, 4, 4)
            painter.setPen(QColor(color))
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, title)
        elif column == 4:
            title = index.data(Qt.ItemDataRole.DisplayRole)
            color = index.data(Qt.ItemDataRole.ForegroundRole)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawEllipse(QRectF(text_rect.left() + 1, rect.center().y() - 3, 6, 6))
            painter.setPen(color)
            painter.drawText(text_rect.adjusted(16, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter, title)
        elif column == 6:
            width, height = 30, 17
            track = QRectF(rect.center().x() - width / 2, rect.center().y() - height / 2, width, height)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(ACCENT if node["enabled"] else "#d3d9e1"))
            painter.drawRoundedRect(track, 8.5, 8.5)
            painter.setBrush(QColor("#ffffff"))
            painter.drawEllipse(QRectF(track.left() + (16 if node["enabled"] else 3), track.top() + 3, 11, 11))
        elif column == 7:
            y = rect.center().y() - 9
            icon("pencil", MUTED, 16).paint(painter, QRect(rect.left() + 12, y, 18, 18))
            icon("ellipsis", MUTED, 18).paint(painter, QRect(rect.left() + 46, y, 18, 18))
        else:
            text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
            if column == 3:
                painter.setPen(QColor("#808999"))
            if column == 5:
                font.setFamily("Segoe UI")
                painter.setFont(font)
                painter.setPen(QColor("#606d80"))
            painter.drawText(
                text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                painter.fontMetrics().elidedText(text, Qt.TextElideMode.ElideRight, text_rect.width()),
            )
        painter.restore()

    def editorEvent(self, event, model, option, index):
        if event.type() == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton:
            node = index.data(NODE_ROLE)
            if index.column() == 6:
                self.toggle_requested.emit(node["id"], not node["enabled"])
                return True
            if index.column() == 7:
                if event.position().x() - option.rect.left() < 41:
                    self.edit_requested.emit(node["id"])
                else:
                    self.menu_requested.emit(node["id"])
                return True
        return super().editorEvent(event, model, option, index)
