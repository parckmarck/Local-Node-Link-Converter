from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QFileDialog,
    QFormLayout, QHeaderView, QHBoxLayout, QLineEdit, QMessageBox, QPlainTextEdit,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from .formats import MAX_BATCH_LENGTH, FormatError, parse_batch, parse_uri
from .messages import local_stamp, test_message
from .rules import NO_RESOLVE_TYPES, RULE_ACTIONS, RULE_HINTS, RULE_TYPES, RuleError, render_rule, validate_rule
from .theme import GREEN, MUTED, RED
from .widgets import button, divider, icon_button, label


def error_dialog(parent, title: str, message: str):
    dialog = QMessageBox(parent)
    dialog.setWindowTitle(title)
    dialog.setIcon(QMessageBox.Icon.Warning)
    dialog.setTextFormat(Qt.TextFormat.PlainText)
    dialog.setText(message)
    dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
    dialog.button(QMessageBox.StandardButton.Ok).setText("确定")
    dialog.exec()


def confirm(parent, title: str, message: str, action="确认") -> bool:
    dialog = QMessageBox(parent)
    dialog.setWindowTitle(title)
    dialog.setIcon(QMessageBox.Icon.Question)
    dialog.setTextFormat(Qt.TextFormat.PlainText)
    dialog.setText(message)
    accept = dialog.addButton(action, QMessageBox.ButtonRole.AcceptRole)
    cancel = dialog.addButton("取消", QMessageBox.ButtonRole.RejectRole)
    dialog.setDefaultButton(cancel)
    dialog.exec()
    return dialog.clickedButton() == accept


def group_input(groups: list[str], current: str = "") -> QComboBox:
    combo = QComboBox()
    combo.setEditable(True)
    combo.addItem("")
    combo.addItems(sorted({group for group in groups if group}))
    combo.setCurrentText(current)
    combo.lineEdit().setPlaceholderText("未分组")
    combo.lineEdit().setMaxLength(80)
    return combo


class ImportDialog(QDialog):
    def __init__(self, groups: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("导入节点")
        self.resize(700, 650)
        self.setMinimumSize(580, 560)
        self.parsed_nodes: list[dict] = []
        self.duplicate_count = 0
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 22)
        layout.setSpacing(16)
        layout.addWidget(label("导入节点", "sectionTitle"))
        layout.addWidget(label("VLESS  /  VMess  /  SOCKS5  /  Trojan  /  Shadowsocks", "small"))
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        link_page = QWidget()
        links = QVBoxLayout(link_page)
        links.setContentsMargins(0, 8, 0, 0)
        action_row = QHBoxLayout()
        action_row.addWidget(label("节点链接", "muted"))
        action_row.addStretch()
        paste = button("粘贴", "copy")
        read_file = button("读取文件", "folder-open")
        paste.clicked.connect(self.paste)
        read_file.clicked.connect(self.read_file)
        action_row.addWidget(paste)
        action_row.addWidget(read_file)
        links.addLayout(action_row)
        self.text = QPlainTextEdit()
        self.text.setObjectName("importText")
        self.text.setAccessibleName("节点链接")
        self.text.setPlaceholderText("vless://...\nvmess://...\nsocks5://...")
        self.text.setMinimumHeight(155)
        self.text.textChanged.connect(self.invalidate)
        links.addWidget(self.text, 1)
        self.tabs.addTab(link_page, "链接导入")
        socks_page = QWidget()
        socks = QFormLayout(socks_page)
        socks.setContentsMargins(0, 18, 0, 12)
        socks.setVerticalSpacing(14)
        self.socks_name = QLineEdit()
        self.socks_name.setMaxLength(256)
        self.socks_name.setPlaceholderText("SOCKS5")
        self.socks_host = QLineEdit()
        self.socks_host.setPlaceholderText("127.0.0.1")
        self.socks_host.setAccessibleName("SOCKS5 服务器")
        self.socks_port = QSpinBox()
        self.socks_port.setRange(1, 65535)
        self.socks_port.setValue(1080)
        self.socks_auth = QCheckBox("身份验证")
        self.socks_user = QLineEdit()
        self.socks_password = QLineEdit()
        self.socks_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.socks_user.setEnabled(False)
        self.socks_password.setEnabled(False)
        self.socks_auth.toggled.connect(self.socks_user.setEnabled)
        self.socks_auth.toggled.connect(self.socks_password.setEnabled)
        for title, widget in (
            ("名称", self.socks_name), ("服务器", self.socks_host), ("端口", self.socks_port),
            ("", self.socks_auth), ("用户名", self.socks_user), ("密码", self.socks_password),
        ):
            socks.addRow(title, widget)
        self.tabs.addTab(socks_page, "添加 SOCKS5")
        for widget in (self.socks_name, self.socks_host, self.socks_user, self.socks_password):
            widget.textChanged.connect(self.invalidate)
        self.socks_port.valueChanged.connect(self.invalidate)
        self.socks_auth.toggled.connect(self.invalidate)
        self.tabs.currentChanged.connect(self.invalidate)
        form = QFormLayout()
        self.group = group_input(groups)
        form.addRow("分组", self.group)
        layout.addLayout(form)
        self.summary = label("尚未检查", "muted")
        layout.addWidget(self.summary)
        self.errors = QPlainTextEdit()
        self.errors.setReadOnly(True)
        self.errors.setMaximumHeight(95)
        self.errors.setVisible(False)
        layout.addWidget(self.errors)
        layout.addWidget(divider())
        actions = QHBoxLayout()
        self.check_button = button("检查链接", "check-check")
        self.check_button.clicked.connect(self.check)
        actions.addWidget(self.check_button)
        actions.addStretch()
        cancel = button("取消")
        cancel.clicked.connect(self.reject)
        self.import_button = button("导入", "plus", primary=True)
        self.import_button.setEnabled(False)
        self.import_button.clicked.connect(self.accept)
        actions.addWidget(cancel)
        actions.addWidget(self.import_button)
        layout.addLayout(actions)

    def invalidate(self, *_):
        self.parsed_nodes = []
        self.import_button.setEnabled(False)
        self.import_button.setText("导入")
        self.summary.setText("尚未检查")
        self.errors.hide()

    def paste(self):
        self.text.setPlainText(QApplication.clipboard().text())

    def read_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "读取节点链接", "", "文本文件 (*.txt *.list);;所有文件 (*)")
        if not path:
            return
        try:
            source = Path(path)
            if source.stat().st_size > MAX_BATCH_LENGTH:
                raise ValueError("文件过大，最大 4 MB。")
            self.text.setPlainText(source.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, ValueError) as error:
            error_dialog(self, "读取失败", str(error))

    def check(self):
        try:
            if self.tabs.currentIndex() == 0:
                text = self.text.toPlainText()
            else:
                host = self.socks_host.text().strip().strip("[]")
                endpoint = f"[{host}]" if ":" in host else host
                auth = ""
                if self.socks_auth.isChecked():
                    user, password = self.socks_user.text(), self.socks_password.text()
                    if not user or not password:
                        raise FormatError("用户名和密码均不能为空。")
                    auth = f"{quote(user, safe='')}:{quote(password, safe='')}@"
                name = self.socks_name.text().strip() or "SOCKS5"
                text = f"socks5://{auth}{endpoint}:{self.socks_port.value()}#{quote(name, safe='')}"
            if not text.strip():
                raise FormatError("请填写节点链接。")
            batch = parse_batch(text)
            self.parsed_nodes = batch["nodes"]
            self.duplicate_count = batch["duplicates"]
            failures = batch["errors"]
            count = len(self.parsed_nodes)
            self.summary.setText(
                f"{count} 个可导入  ·  {self.duplicate_count} 个重复  ·  {len(failures)} 个错误"
            )
            self.errors.setPlainText("\n".join(
                f"第 {item['line']} 行：{item['message']}" for item in failures
            ))
            self.errors.setVisible(bool(failures))
            self.import_button.setEnabled(count > 0)
            self.import_button.setText(f"导入 {count} 个节点" if count else "导入")
        except (ValueError, TypeError) as error:
            self.summary.setText("检查未通过")
            self.errors.setPlainText(str(error))
            self.errors.show()
            self.import_button.setEnabled(False)


class EditDialog(QDialog):
    def __init__(self, node: dict, groups: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("编辑节点")
        self.resize(660, 570)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(18)
        layout.addWidget(label("编辑节点", "sectionTitle"))
        form = QFormLayout()
        form.setVerticalSpacing(14)
        self.name = QLineEdit(node["name"])
        self.name.setMaxLength(256)
        self.name.setAccessibleName("节点名称")
        self.group = group_input(groups, node["group"])
        self.enabled = QCheckBox("加入订阅")
        self.enabled.setChecked(node["enabled"])
        self.uri = QPlainTextEdit(node["uri"])
        self.uri.setAccessibleName("原始节点链接")
        self.uri.setMinimumHeight(105)
        self.uri.setMaximumHeight(145)
        self.note = QPlainTextEdit(node.get("note", ""))
        self.note.setMaximumHeight(80)
        form.addRow("名称", self.name)
        form.addRow("分组", self.group)
        form.addRow("链接", self.uri)
        form.addRow("备注", self.note)
        form.addRow("", self.enabled)
        layout.addLayout(form, 1)
        layout.addWidget(divider())
        actions = QHBoxLayout()
        actions.addStretch()
        cancel = button("取消")
        cancel.clicked.connect(self.reject)
        save = button("保存更改", "check", primary=True)
        save.clicked.connect(self.validate)
        actions.addWidget(cancel)
        actions.addWidget(save)
        layout.addLayout(actions)

    def validate(self):
        try:
            if not self.name.text().strip():
                raise ValueError("节点名称不能为空。")
            parse_uri(self.uri.toPlainText().strip())
            if len(self.note.toPlainText()) > 2000:
                raise ValueError("备注不能超过 2000 字。")
            self.accept()
        except ValueError as error:
            error_dialog(self, "无法保存", str(error))

    def changes(self) -> dict:
        return {
            "name": self.name.text().strip(), "group": self.group.currentText().strip(),
            "uri": self.uri.toPlainText().strip(), "note": self.note.toPlainText().strip(),
            "enabled": self.enabled.isChecked(),
        }


class PreviewDialog(QDialog):
    def __init__(self, title: str, content: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 620)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        layout.addWidget(label(title, "sectionTitle"))
        text = QPlainTextEdit(content)
        text.setReadOnly(True)
        text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        text.setFont(QFont("Cascadia Mono", 10))
        layout.addWidget(text, 1)
        actions = QHBoxLayout()
        actions.addStretch()
        copy = button("复制", "copy")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(content))
        done = button("关闭")
        done.clicked.connect(self.accept)
        actions.addWidget(copy)
        actions.addWidget(done)
        layout.addLayout(actions)


class RuleDialog(QDialog):
    """添加或编辑一条订阅规则。"""

    def __init__(self, rule: dict | None = None, parent=None):
        super().__init__(parent)
        editing = rule is not None
        self.setWindowTitle("编辑规则" if editing else "添加规则")
        self.resize(560, 420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(16)
        layout.addWidget(label("编辑规则" if editing else "添加规则", "sectionTitle"))
        form = QFormLayout()
        form.setVerticalSpacing(14)
        self.type = QComboBox()
        for code, title in RULE_TYPES.items():
            self.type.addItem(title, code)
        self.value = QLineEdit()
        self.value.setMaxLength(260)
        self.value.setAccessibleName("匹配内容")
        self.action = QComboBox()
        for code, title in RULE_ACTIONS.items():
            self.action.addItem(title, code)
        self.no_resolve = QCheckBox("不对域名做本地解析（no-resolve）")
        self.no_resolve.setToolTip("仅 IP 网段 / 国家代码规则可用；可避免为匹配规则做额外的 DNS 解析。")
        form.addRow("类型", self.type)
        form.addRow("匹配内容", self.value)
        form.addRow("动作", self.action)
        form.addRow("", self.no_resolve)
        if editing:
            index = self.type.findData(rule.get("type"))
            if index >= 0:
                self.type.setCurrentIndex(index)
            self.value.setText(str(rule.get("value", "")))
            index = self.action.findData(rule.get("action"))
            if index >= 0:
                self.action.setCurrentIndex(index)
            self.no_resolve.setChecked(bool(rule.get("no_resolve")))
        layout.addLayout(form, 1)
        self.preview = label("", "muted")
        self.preview.setWordWrap(True)
        layout.addWidget(self.preview)
        layout.addWidget(divider())
        actions = QHBoxLayout()
        actions.addStretch()
        cancel = button("取消")
        cancel.clicked.connect(self.reject)
        save = button("保存规则", "check", primary=True)
        save.clicked.connect(self.save)
        actions.addWidget(cancel)
        actions.addWidget(save)
        layout.addLayout(actions)
        self.type.currentIndexChanged.connect(self.type_changed)
        self.value.textChanged.connect(self.refresh_preview)
        self.action.currentIndexChanged.connect(self.refresh_preview)
        self.no_resolve.toggled.connect(self.refresh_preview)
        self.type_changed()

    def type_changed(self):
        rule_type = self.type.currentData()
        self.value.setPlaceholderText(RULE_HINTS.get(rule_type, ""))
        allowed = rule_type in NO_RESOLVE_TYPES
        self.no_resolve.setEnabled(allowed)
        if not allowed:
            self.no_resolve.setChecked(False)
        self.refresh_preview()

    def refresh_preview(self, *_):
        try:
            self.preview.setText("将生成：" + render_rule(self.rule()))
        except RuleError:
            self.preview.setText("将生成：（填写匹配内容后预览）")

    def rule(self) -> dict:
        return {
            "type": self.type.currentData(),
            "value": self.value.text().strip(),
            "action": self.action.currentData(),
            "no_resolve": self.no_resolve.isChecked() and self.no_resolve.isEnabled(),
        }

    def save(self):
        try:
            validate_rule(self.rule())
            self.accept()
        except RuleError as error:
            error_dialog(self, "无法保存", str(error))


class TestDetailDialog(QDialog):
    """显示一次测试中每个节点的结果；失败/异常节点排在最前。"""

    def __init__(self, session: dict, parent=None):
        super().__init__(parent)
        mode = "实际代理" if session.get("mode") == "proxy" else "TCP 端口"
        stamp = local_stamp(session.get("started_at"))
        self.setWindowTitle("测试详情")
        self.resize(780, 580)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label(f"测试详情 · {stamp} · {mode}", "sectionTitle"))
        items = list(session.get("items") or [])
        total = int(session.get("total") or len(items))
        ok = sum(item.get("status") == "ok" for item in items)
        failed = sum(item.get("status") == "failed" for item in items)
        rest = max(0, total - ok - failed)
        parts = [f"共 {total} 个节点", f"成功 {ok}", f"失败 {failed}"]
        if rest:
            parts.append(f"其他 {rest}")
        if session.get("cancelled"):
            parts.append("本次测试已取消")
        layout.addWidget(label(" · ".join(parts), "muted"))
        table = QTableWidget(0, 5)
        table.setAccessibleName("本次测试的节点结果")
        table.setHorizontalHeaderLabels(["节点", "结果", "延迟", "完成时间", "详情"])
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(44)
        table.setShowGrid(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 190), (1, 76), (2, 76), (3, 150)):
            table.setColumnWidth(column, width)
        rank = {"failed": 0, "unsupported": 1, "cancelled": 2, "ok": 3}
        items.sort(key=lambda item: (rank.get(item.get("status"), 2), str(item.get("name", ""))))
        table.setRowCount(len(items))
        labels = {"ok": "成功", "failed": "失败", "unsupported": "不支持", "cancelled": "已取消"}
        for row, item in enumerate(items):
            status = item.get("status")
            delay = item.get("latency_ms")
            message = test_message(item.get("message", ""))
            values = [
                str(item.get("name", "")), labels.get(status, "未知"),
                f"{delay} ms" if delay is not None else "-",
                local_stamp(item.get("checked_at")), message,
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                if column == 1:
                    cell.setForeground(QColor(
                        GREEN if status == "ok" else RED if status == "failed" else MUTED
                    ))
                table.setItem(row, column, cell)
        layout.addWidget(table, 1)
        actions = QHBoxLayout()
        actions.addStretch()
        close = button("关闭")
        close.clicked.connect(self.accept)
        actions.addWidget(close)
        layout.addLayout(actions)
