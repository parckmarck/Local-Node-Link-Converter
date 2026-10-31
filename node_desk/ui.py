from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Qt, QUrl, Signal, QSize
from PySide6.QtGui import QAction, QColor, QCursor, QDesktopServices, QFont, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog,
    QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMenu, QProgressBar, QScrollArea, QSizePolicy,
    QSpinBox, QStackedWidget, QTableView, QTableWidget, QTableWidgetItem,
    QToolButton, QVBoxLayout, QWidget,
)

from . import __version__
from .dialogs import EditDialog, ImportDialog, PreviewDialog, RuleDialog, TestDetailDialog, confirm, error_dialog
from .formats import PROTOCOLS, export_clash, export_v2ray
from .messages import local_stamp, test_message
from .paths import bundled_core, resource_root
from .rules import RULE_ACTIONS, RULE_TYPES
from .service import SubscriptionService
from .store import MAX_BACKUP_BYTES, Store
from .table import NODE_ROLE, NodeDelegate, NodeFilter, NodeModel, proxy_tested, test_state
from .theme import ACCENT, AMBER, BLUE, GREEN, INK, MUTED, RED, icon
from .widgets import Metric, Switch, button, divider, icon_button, label


class TestWorker(QThread):
    result_ready = Signal(dict)
    failed = Signal(str)

    def __init__(self, tester, nodes, mode, parent=None):
        super().__init__(parent)
        self.tester, self.nodes, self.mode = tester, nodes, mode
        self.error = False

    def run(self):
        try:
            self.tester.run(self.nodes, mode=self.mode, on_result=self.result_ready.emit)
        except Exception:
            self.error = True
            self.failed.emit("测试未能完成，请检查内核文件、测试地址和超时设置。")


class MainWindow(QMainWindow):
    def __init__(self, store: Store, service: SubscriptionService, *, start_service=True):
        super().__init__()
        self.store, self.service = store, service
        self.worker: TestWorker | None = None
        self._closing = False
        self._test_done = 0
        self._test_total = 0
        self._export_cache: dict[str, str] = {}
        self._rule_ids: list[str] = []
        self._history_ids: list[str] = []
        self._test_session_id: str | None = None
        self._test_cancelled = False
        self.setWindowTitle("Node Desk · 节点维护")
        self.setWindowIcon(icon("network", ACCENT, 32))
        self.resize(1320, 860)
        self.setMinimumSize(1080, 690)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.build_sidebar())
        self.pages = QStackedWidget()
        self.node_page = self.build_nodes()
        self.subscription_page = self.build_subscriptions()
        self.rules_page = self.build_rules()
        self.history_page = self.build_history()
        self.settings_page = self.build_settings()
        for page in (self.node_page, self.subscription_page, self.rules_page,
                     self.history_page, self.settings_page):
            self.pages.addWidget(page)
        layout.addWidget(self.pages, 1)
        self.status_label = label("数据保存在本机", "small")
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(label(f"Node Desk {__version__}", "small"))
        self.statusBar().setSizeGripEnabled(True)
        self.bind_shortcuts()
        self.refresh()
        self.nav_buttons[0].setChecked(True)
        if start_service and self.store.settings()["start_service"]:
            QTimer.singleShot(0, self.start_service)
        else:
            self.update_service_state()

    def build_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(196)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 27, 14, 15)
        layout.setSpacing(8)
        brand_row = QHBoxLayout()
        brand_row.setSpacing(11)
        brand_icon = QLabel()
        brand_icon.setPixmap(icon("network", "#ffffff", 23).pixmap(23, 23))
        brand_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand_icon.setFixedSize(36, 36)
        brand_icon.setStyleSheet("background: #087f6d; border-radius: 7px;")
        brand_row.addWidget(brand_icon)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)
        brand_text.addWidget(label("Node Desk", "brand"))
        brand_text.addWidget(label("本地工作区", "brandSub"))
        brand_row.addLayout(brand_text)
        layout.addLayout(brand_row)
        layout.addSpacing(34)
        workspace = label("工作区", "navLabel")
        workspace.setContentsMargins(14, 0, 0, 7)
        layout.addWidget(workspace)
        self.nav_buttons = []
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for index, (title, symbol) in enumerate((
            ("节点管理", "server"), ("本地订阅", "link"),
            ("订阅规则", "filter"), ("测试记录", "activity"),
        )):
            nav = self.nav_button(title, symbol, index)
            layout.addWidget(nav)
        layout.addStretch(1)
        settings = self.nav_button("设置", "settings-2", 4)
        layout.addWidget(settings)
        layout.addSpacing(8)
        layout.addWidget(divider())
        layout.addSpacing(9)
        service_row = QHBoxLayout()
        service_row.setContentsMargins(8, 0, 6, 0)
        service_row.addWidget(label("订阅服务", "muted"))
        service_row.addStretch()
        self.service_switch = Switch("开启或暂停本地订阅服务")
        self.service_switch.clicked.connect(self.toggle_service)
        service_row.addWidget(self.service_switch)
        layout.addLayout(service_row)
        self.service_detail = label("已暂停", "small")
        self.service_detail.setContentsMargins(8, 0, 0, 0)
        layout.addWidget(self.service_detail)
        layout.addSpacing(12)
        exit_button = button("退出程序", "power")
        exit_button.setObjectName("exitButton")
        exit_button.clicked.connect(self.close)
        layout.addWidget(exit_button)
        return sidebar

    def nav_button(self, title, symbol, index):
        nav = QToolButton()
        nav.setObjectName("nav")
        nav.setText(title)
        nav.setIcon(icon(symbol, MUTED, 18))
        nav.setIconSize(QSize(18, 18))
        nav.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        nav.setCheckable(True)
        nav.setFixedHeight(43)
        nav.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        nav.setCursor(Qt.CursorShape.PointingHandCursor)
        nav.setAccessibleName(title)
        nav.clicked.connect(lambda checked=False, i=index: self.navigate(i))
        self.nav_group.addButton(nav, index)
        self.nav_buttons.append(nav)
        return nav

    def page_shell(self, title: str):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 27, 32, 20)
        layout.setSpacing(18)
        layout.addWidget(label(f"工作区  /  {title}", "crumb"))
        header = QHBoxLayout()
        header.setSpacing(12)
        header.addWidget(label(title, "pageTitle"))
        header.addStretch()
        layout.addLayout(header)
        return page, layout, header

    def build_nodes(self):
        page, layout, header = self.page_shell("节点管理")
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("实际代理", "proxy")
        self.mode_combo.addItem("TCP 端口", "tcp")
        self.mode_combo.setFixedWidth(115)
        self.mode_combo.setAccessibleName("测试方式")
        self.mode_combo.setToolTip("实际代理会向测试地址发起请求；TCP 仅检查端口")
        header.addWidget(self.mode_combo)
        self.test_button = button("测试节点", "play")
        self.test_button.clicked.connect(lambda: self.run_tests())
        header.addWidget(self.test_button)
        self.cancel_test_button = button("取消测试", "square")
        self.cancel_test_button.clicked.connect(self.cancel_tests)
        self.cancel_test_button.hide()
        header.addWidget(self.cancel_test_button)
        self.import_button = button("导入节点", "plus", primary=True)
        self.import_button.clicked.connect(self.import_nodes)
        header.addWidget(self.import_button)
        metrics = QHBoxLayout()
        metrics.setSpacing(0)
        self.metrics = [
            Metric("全部节点", "server", BLUE),
            Metric("已启用", "check-check", ACCENT),
            Metric("代理可用", "activity", GREEN),
            Metric("未测代理", "globe", AMBER),
        ]
        for index, metric in enumerate(self.metrics):
            if index:
                line = QFrame()
                line.setObjectName("metricDivider")
                line.setFixedWidth(1)
                line.setFixedHeight(42)
                metrics.addWidget(line)
                metrics.addSpacing(24)
            metrics.addWidget(metric, 1)
        layout.addSpacing(0)
        layout.addLayout(metrics)
        layout.addWidget(divider())
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.status_group = QButtonGroup(self)
        self.status_group.setExclusive(True)
        self.status_filter = ""
        for index, (title, value) in enumerate((
            ("全部", ""), ("代理可用", "ok"), ("未测代理", "untested"), ("异常", "failed")
        )):
            toggle = QToolButton()
            toggle.setObjectName("segment")
            toggle.setText(title)
            toggle.setCheckable(True)
            toggle.clicked.connect(lambda checked=False, v=value: self.change_status_filter(v))
            self.status_group.addButton(toggle, index)
            filters.addWidget(toggle)
            if not index:
                toggle.setChecked(True)
        filters.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索名称、地址或分组")
        self.search.addAction(icon("search", MUTED, 16), QLineEdit.ActionPosition.LeadingPosition)
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(170)
        self.search.setMaximumWidth(280)
        self.search.setAccessibleName("搜索节点")
        self.search.textChanged.connect(self.apply_filters)
        filters.addWidget(self.search, 1)
        layout.addLayout(filters)
        secondary = QHBoxLayout()
        self.select_all = QCheckBox("全选")
        self.select_all.setAccessibleName("全选当前筛选节点")
        self.select_all.clicked.connect(self.select_visible)
        secondary.addWidget(self.select_all)
        secondary.addSpacing(10)
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItem("全部协议", "")
        for name in PROTOCOLS:
            self.protocol_filter.addItem(name.upper(), name)
        self.protocol_filter.setFixedWidth(130)
        self.protocol_filter.setAccessibleName("协议筛选")
        self.protocol_filter.currentIndexChanged.connect(self.apply_filters)
        secondary.addWidget(self.protocol_filter)
        self.group_filter = QComboBox()
        self.group_filter.setMinimumWidth(140)
        self.group_filter.setMaximumWidth(220)
        self.group_filter.setAccessibleName("分组筛选")
        self.group_filter.currentIndexChanged.connect(self.apply_filters)
        secondary.addWidget(self.group_filter)
        secondary.addStretch()
        self.batch_label = label("", "muted")
        secondary.addWidget(self.batch_label)
        self.enable_button = icon_button("check", "启用选中节点")
        self.enable_button.clicked.connect(lambda: self.set_selected_enabled(True))
        secondary.addWidget(self.enable_button)
        self.disable_button = icon_button("square", "停用选中节点")
        self.disable_button.clicked.connect(lambda: self.set_selected_enabled(False))
        secondary.addWidget(self.disable_button)
        self.delete_button = icon_button("trash-2", "删除选中节点", color=RED)
        self.delete_button.clicked.connect(self.delete_selected)
        secondary.addWidget(self.delete_button)
        layout.addLayout(secondary)
        self.model = NodeModel(self)
        self.model.selection_changed.connect(self.update_selection)
        self.proxy = NodeFilter(self)
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setObjectName("nodeTable")
        self.table.setAccessibleName("节点列表")
        self.table.setModel(self.proxy)
        self.table.setShowGrid(False)
        self.table.setMouseTracking(True)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(-1, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(64)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setMinimumSectionSize(36)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 36), (2, 87), (3, 104), (4, 116), (5, 82), (6, 57), (7, 80)):
            self.table.setColumnWidth(column, width)
        self.delegate = NodeDelegate(self.table)
        self.delegate.edit_requested.connect(self.edit_node)
        self.delegate.menu_requested.connect(self.show_node_menu)
        self.delegate.toggle_requested.connect(self.toggle_node)
        self.table.setItemDelegate(self.delegate)
        self.table.doubleClicked.connect(
            lambda index: self.edit_node(index.data(NODE_ROLE)["id"])
            if index.column() not in (0, 6, 7) else None
        )
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.context_menu)
        self.table_stack = QStackedWidget()
        self.table_stack.addWidget(self.table)
        empty = QWidget()
        empty_layout = QVBoxLayout(empty)
        empty_layout.addStretch()
        empty_image = QLabel()
        empty_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_image.setPixmap(icon("server", "#a4b8b0", 48).pixmap(48, 48))
        empty_layout.addWidget(empty_image)
        self.empty_title = label("暂无节点", "emptyTitle")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_title)
        empty_layout.addSpacing(10)
        empty_buttons = QHBoxLayout()
        empty_buttons.addStretch()
        self.empty_import = button("导入节点", "plus", primary=True)
        self.empty_import.clicked.connect(self.import_nodes)
        empty_buttons.addWidget(self.empty_import)
        self.empty_reset = button("重置筛选", "rotate-cw")
        self.empty_reset.clicked.connect(self.reset_filters)
        empty_buttons.addWidget(self.empty_reset)
        empty_buttons.addStretch()
        empty_layout.addLayout(empty_buttons)
        empty_layout.addStretch(2)
        self.table_stack.addWidget(empty)
        layout.addWidget(self.table_stack, 1)
        self.test_progress = QProgressBar()
        self.test_progress.setFixedHeight(4)
        self.test_progress.setTextVisible(False)
        self.test_progress.hide()
        layout.addWidget(self.test_progress)
        footer = QHBoxLayout()
        self.table_summary = label("", "small")
        footer.addWidget(self.table_summary)
        footer.addStretch()
        self.test_summary = label("", "small")
        footer.addWidget(self.test_summary)
        layout.addLayout(footer)
        return page

    def build_subscriptions(self):
        page, layout, header = self.page_shell("本地订阅")
        self.subscription_state = label("", "muted")
        header.addWidget(self.subscription_state)
        filters = QHBoxLayout()
        filters.addWidget(label("订阅范围", "muted"))
        self.subscription_group = QComboBox()
        self.subscription_group.setMinimumWidth(190)
        self.subscription_group.setMaximumWidth(260)
        self.subscription_group.setAccessibleName("订阅分组")
        self.subscription_group.currentIndexChanged.connect(self.update_subscriptions)
        filters.addWidget(self.subscription_group)
        filters.addStretch()
        self.subscription_count = label("", "muted")
        filters.addWidget(self.subscription_count)
        layout.addLayout(filters)
        self.client_widgets = {}
        for format, title, subtitle, symbol in (
            ("clash", "Clash Verge", "Mihomo YAML", "network"),
            ("v2ray", "v2rayN", "Base64 URI", "server"),
        ):
            card = QFrame()
            card.setObjectName("client")
            content = QVBoxLayout(card)
            content.setContentsMargins(22, 21, 22, 20)
            content.setSpacing(16)
            heading = QHBoxLayout()
            graphic = QLabel()
            graphic.setPixmap(icon(symbol, ACCENT if format == "clash" else BLUE, 25).pixmap(25, 25))
            graphic.setFixedWidth(38)
            heading.addWidget(graphic)
            names = QVBoxLayout()
            names.setSpacing(3)
            names.addWidget(label(title, "sectionTitle"))
            names.addWidget(label(subtitle, "small"))
            heading.addLayout(names)
            heading.addStretch()
            preview = icon_button("eye", "预览订阅内容")
            preview.clicked.connect(lambda checked=False, f=format: self.preview_subscription(f))
            heading.addWidget(preview)
            export = button("导出文件", "download")
            export.clicked.connect(lambda checked=False, f=format: self.save_subscription(f))
            heading.addWidget(export)
            content.addLayout(heading)
            address = QHBoxLayout()
            url = QLineEdit()
            url.setReadOnly(True)
            url.setAccessibleName(f"{title} 订阅地址")
            url.setMinimumHeight(36)
            url.setFont(QFont("Consolas", 10))
            url.setStyleSheet("QLineEdit { border: 1px solid #e3e8ef; padding: 9px 12px; background: #f7f9fb; }")
            address.addWidget(url, 1)
            copy = button("复制链接", "copy")
            copy.clicked.connect(lambda checked=False, f=format: self.copy_subscription(f))
            address.addWidget(copy)
            content.addLayout(address)
            status = label("", "small")
            status.setWordWrap(True)
            content.addWidget(status)
            self.client_widgets[format] = {
                "url": url, "copy": copy, "export": export, "preview": preview, "status": status,
            }
            layout.addWidget(card)
        layout.addSpacing(10)
        layout.addWidget(divider())
        details = QHBoxLayout()
        for title, value in (("监听范围", "127.0.0.1"), ("访问控制", "随机令牌"), ("服务模式", "随窗口退出")):
            group = QVBoxLayout()
            group.setSpacing(7)
            group.addWidget(label(title, "small"))
            group.addWidget(label(value, "muted"))
            details.addLayout(group, 1)
        layout.addLayout(details)
        layout.addStretch()
        return page

    def build_rules(self):
        page, layout, header = self.page_shell("订阅规则")
        self.reset_rules_button = button("恢复默认规则", "rotate-cw")
        self.reset_rules_button.clicked.connect(self.reset_rules)
        header.addWidget(self.reset_rules_button)
        self.add_rule_button = button("添加规则", "plus", primary=True)
        self.add_rule_button.clicked.connect(self.add_rule)
        header.addWidget(self.add_rule_button)
        layout.addWidget(label(
            "规则按列表顺序写入 Clash 订阅，先匹配先生效；未匹配的流量由固定的兜底规则处理。",
            "muted", wrap=True,
        ))
        self.rules_table = QTableWidget(0, 5)
        self.rules_table.setAccessibleName("订阅规则列表")
        self.rules_table.setHorizontalHeaderLabels(["启用", "类型", "匹配内容", "动作", "操作"])
        self.rules_table.verticalHeader().hide()
        self.rules_table.verticalHeader().setDefaultSectionSize(48)
        self.rules_table.setShowGrid(False)
        self.rules_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.rules_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.rules_table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 64), (1, 128), (3, 150), (4, 182)):
            self.rules_table.setColumnWidth(column, width)
        self.rules_table.doubleClicked.connect(self.edit_rule_row)
        layout.addWidget(self.rules_table, 1)
        footer = QHBoxLayout()
        self.rules_summary = label("", "small")
        footer.addWidget(self.rules_summary)
        footer.addStretch()
        footer.addWidget(label("兜底：其余所有流量 → 走代理（PROXY）", "muted"))
        layout.addLayout(footer)
        return page

    def build_history(self):
        page, layout, header = self.page_shell("测试记录")
        self.retest_button = button("复测异常", "refresh-cw")
        self.retest_button.clicked.connect(self.retest_failed)
        header.addWidget(self.retest_button)
        self.history_summary = label("", "muted")
        layout.addWidget(self.history_summary)
        self.history_table = QTableWidget(0, 7)
        self.history_table.setAccessibleName("测试批次记录")
        self.history_table.setHorizontalHeaderLabels(
            ["时间", "测试方式", "节点", "成功", "失败", "其他", "操作"]
        )
        self.history_table.verticalHeader().hide()
        self.history_table.verticalHeader().setDefaultSectionSize(50)
        self.history_table.setShowGrid(False)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.history_table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.history_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 168), (1, 92), (2, 62), (3, 62), (4, 62), (5, 62)):
            self.history_table.setColumnWidth(column, width)
        self.history_table.doubleClicked.connect(self.history_detail_row)
        layout.addWidget(self.history_table, 1)
        return page

    def build_settings(self):
        page, outer, header = self.page_shell("设置")
        self.save_settings_button = button("保存设置", "check", primary=True)
        self.save_settings_button.clicked.connect(self.save_settings)
        header.addWidget(self.save_settings_button)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 5, 10, 20)
        layout.setSpacing(19)
        layout.addWidget(label("订阅服务", "sectionTitle"))
        form = QFormLayout()
        form.setVerticalSpacing(16)
        form.setHorizontalSpacing(28)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setMaximumWidth(180)
        self.port_input.setAccessibleName("本地服务端口")
        self.auto_service = Switch("打开程序时启动订阅服务")
        self.rotate_button = button("重置订阅令牌", "rotate-cw")
        self.rotate_button.setMaximumWidth(180)
        self.rotate_button.clicked.connect(self.rotate_token)
        form.addRow("本地端口", self.port_input)
        form.addRow("随程序启动服务", self.auto_service)
        form.addRow("访问令牌", self.rotate_button)
        layout.addLayout(form)
        layout.addWidget(divider())
        layout.addWidget(label("连通性测试", "sectionTitle"))
        test_form = QFormLayout()
        test_form.setVerticalSpacing(16)
        test_form.setHorizontalSpacing(28)
        self.target_input = QComboBox()
        self.target_input.setEditable(True)
        self.target_input.addItems([
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "http://www.gstatic.com/generate_204",
        ])
        self.target_input.setAccessibleName("测试地址")
        self.target_input.setToolTip("返回 HTTP 204 的测试地址")
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 30)
        self.timeout_input.setSuffix(" 秒")
        self.timeout_input.setMaximumWidth(180)
        self.concurrency_input = QSpinBox()
        self.concurrency_input.setRange(1, 16)
        self.concurrency_input.setMaximumWidth(180)
        core_row = QHBoxLayout()
        self.core_input = QLineEdit()
        self.core_input.setPlaceholderText("内置 Mihomo v1.19.33")
        self.core_input.setReadOnly(True)
        browse = icon_button("folder-open", "选择其他 Mihomo 内核")
        browse.clicked.connect(self.choose_core)
        reset = icon_button("rotate-cw", "使用内置内核")
        reset.clicked.connect(self.core_input.clear)
        core_row.addWidget(self.core_input, 1)
        core_row.addWidget(browse)
        core_row.addWidget(reset)
        test_form.addRow("测试地址", self.target_input)
        test_form.addRow("单节点超时", self.timeout_input)
        test_form.addRow("并发数", self.concurrency_input)
        test_form.addRow("测试内核", core_row)
        layout.addLayout(test_form)
        layout.addWidget(divider())
        layout.addWidget(label("本地数据", "sectionTitle"))
        data_row = QHBoxLayout()
        location = QLineEdit(str(self.store.data_dir))
        location.setReadOnly(True)
        location.setAccessibleName("本地数据目录")
        open_data = icon_button("folder-open", "打开本地数据目录")
        open_data.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.store.data_dir))))
        data_row.addWidget(location, 1)
        data_row.addWidget(open_data)
        layout.addLayout(data_row)
        backup_row = QHBoxLayout()
        backup = button("导出备份", "download")
        backup.clicked.connect(self.export_backup)
        self.restore_button = button("恢复备份", "upload")
        self.restore_button.clicked.connect(self.restore_backup)
        backup_row.addWidget(backup)
        backup_row.addWidget(self.restore_button)
        backup_row.addStretch()
        licenses = button("开源许可", "file-text")
        licenses.clicked.connect(self.show_licenses)
        backup_row.addWidget(licenses)
        layout.addLayout(backup_row)
        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)
        self.load_settings()
        return page

    def bind_shortcuts(self):
        for key, slot in (
            ("Ctrl+N", self.import_nodes), ("Ctrl+F", self.focus_search),
            ("Ctrl+Q", self.close), ("Delete", self.delete_selected),
        ):
            action = QAction(self)
            action.setShortcut(QKeySequence(key))
            action.triggered.connect(slot)
            self.addAction(action)

    def focus_search(self):
        self.navigate(0)
        self.search.setFocus()
        self.search.selectAll()

    def navigate(self, index):
        self.pages.setCurrentIndex(index)
        self.nav_buttons[index].setChecked(True)
        if index == 1:
            self.update_subscriptions()
        elif index == 2:
            self.update_rules()
        elif index == 3:
            self.update_history()

    def busy(self):
        return self.worker is not None and self.worker.isRunning()

    def groups(self):
        return sorted({node["group"] for node in self.model.nodes})

    def refresh(self):
        self.model.replace(self.store.list_nodes())
        groups = self.groups()
        for combo in (self.group_filter, self.subscription_group):
            current = combo.currentData()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("全部分组", None)
            for group in groups:
                combo.addItem(group or "未分组", group)
            index = combo.findData(current)
            combo.setCurrentIndex(max(0, index))
            combo.blockSignals(False)
        self.apply_filters()
        self.update_metrics()
        if self.pages.currentIndex() == 1:
            self.update_subscriptions()
        if self.pages.currentIndex() == 2:
            self.update_rules()
        if self.pages.currentIndex() == 3:
            self.update_history()
        self.update_selection()

    def update_metrics(self):
        nodes = self.model.nodes
        values = (
            len(nodes),
            sum(bool(node["enabled"]) for node in nodes),
            sum(test_state(node)[2] == "ok" for node in nodes),
            sum(not proxy_tested(node) for node in nodes),
        )
        for metric, value in zip(self.metrics, values):
            metric.set_value(value)

    def apply_filters(self, *_):
        if not hasattr(self, "proxy"):
            return
        self.proxy.update_filters(
            search=self.search.text(), protocol=self.protocol_filter.currentData() or "",
            group=self.group_filter.currentData(), status=self.status_filter,
        )
        self.update_table_state()
        self.update_selection()

    def change_status_filter(self, value):
        self.status_filter = value
        self.apply_filters()

    def reset_filters(self):
        self.search.clear()
        self.protocol_filter.setCurrentIndex(0)
        self.group_filter.setCurrentIndex(0)
        self.status_group.button(0).setChecked(True)
        self.change_status_filter("")

    def update_table_state(self):
        count = self.proxy.rowCount()
        self.table_stack.setCurrentIndex(0 if count else 1)
        self.empty_title.setText("没有匹配的节点" if self.model.nodes else "暂无节点")
        self.empty_import.setVisible(not self.model.nodes)
        self.empty_reset.setVisible(bool(self.model.nodes))
        self.table_summary.setText(f"显示 {count} / {len(self.model.nodes)} 个节点")
        self.test_button.setEnabled(bool(count or self.model.checked) and not self.busy())

    def visible_ids(self):
        return [self.proxy.index(row, 0).data(NODE_ROLE)["id"] for row in range(self.proxy.rowCount())]

    def select_visible(self, checked):
        self.model.set_checked(self.visible_ids(), checked)

    def update_selection(self):
        if not hasattr(self, "proxy"):
            return
        count = len(self.model.checked)
        self.batch_label.setText(f"已选 {count} 项" if count else "")
        for control in (self.enable_button, self.disable_button, self.delete_button):
            control.setEnabled(count > 0 and not self.busy())
        visible = set(self.visible_ids())
        self.select_all.blockSignals(True)
        self.select_all.setChecked(bool(visible) and visible.issubset(self.model.checked))
        self.select_all.blockSignals(False)
        self.test_button.setText(f"测试选中 ({count})" if count else "测试节点")

    def import_nodes(self):
        if self.busy():
            return
        dialog = ImportDialog(self.groups(), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            added, duplicates = self.store.add_nodes(dialog.parsed_nodes, dialog.group.currentText())
            self.refresh()
            self.notice(f"已导入 {added} 个节点，跳过 {duplicates + dialog.duplicate_count} 个重复项")
        except ValueError as error:
            error_dialog(self, "导入失败", str(error))

    def edit_node(self, node_id):
        if self.busy():
            return
        try:
            dialog = EditDialog(self.store.get_node(node_id), self.groups(), self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.store.update_node(node_id, **dialog.changes())
                self.refresh()
                self.notice("节点已保存")
        except (ValueError, KeyError) as error:
            error_dialog(self, "保存失败", str(error))

    def toggle_node(self, node_id, enabled):
        if self.busy():
            return
        try:
            self.store.update_node(node_id, enabled=enabled)
            self.refresh()
            self.notice("节点已加入订阅" if enabled else "节点已从订阅中停用")
        except (ValueError, KeyError) as error:
            error_dialog(self, "操作失败", str(error))

    def set_selected_enabled(self, enabled):
        if self.busy():
            return
        count = self.store.set_enabled(list(self.model.checked), enabled)
        self.refresh()
        self.notice(f"已{'启用' if enabled else '停用'} {count} 个节点")

    def delete_selected(self):
        if self.busy() or self.pages.currentIndex() != 0:
            return
        self.delete_nodes(list(self.model.checked))

    def delete_nodes(self, node_ids):
        if self.busy() or not node_ids:
            return
        if not confirm(self, "删除节点", f"删除选中的 {len(node_ids)} 个节点？此操作不可撤销。", "删除"):
            return
        count = self.store.delete_nodes(node_ids)
        self.refresh()
        self.notice(f"已删除 {count} 个节点")

    def context_menu(self, position):
        index = self.table.indexAt(position)
        if index.isValid():
            self.show_node_menu(index.data(NODE_ROLE)["id"])

    def show_node_menu(self, node_id):
        try:
            node = self.store.get_node(node_id)
        except KeyError:
            return
        menu = QMenu(self)
        edit = menu.addAction(icon("pencil"), "编辑节点")
        edit.setEnabled(not self.busy())
        edit.triggered.connect(lambda: self.edit_node(node_id))
        copy = menu.addAction(icon("copy"), "复制原链接")
        copy.triggered.connect(lambda: self.copy_text(node["uri"], "原链接已复制"))
        test = menu.addAction(icon("play"), "实际代理测试")
        test.setEnabled(not self.busy())
        test.triggered.connect(lambda: self.run_tests([node_id], "proxy"))
        menu.addSeparator()
        toggle = menu.addAction(icon("square" if node["enabled"] else "check"),
                                "从订阅中停用" if node["enabled"] else "加入订阅")
        toggle.setEnabled(not self.busy())
        toggle.triggered.connect(lambda: self.toggle_node(node_id, not node["enabled"]))
        remove = menu.addAction(icon("trash-2", RED), "删除节点")
        remove.setEnabled(not self.busy())
        remove.triggered.connect(lambda: self.delete_nodes([node_id]))
        menu.exec(QCursor.pos())

    def start_service(self):
        try:
            self.service.start()
        except OSError:
            error_dialog(self, "订阅服务未启动", f"端口 {self.store.settings()['port']} 无法使用。请在设置中选择其他端口。")
        self.update_service_state()

    def toggle_service(self, checked):
        if checked:
            self.start_service()
        else:
            self.service.stop()
            self.update_service_state()
            self.notice("订阅服务已暂停")

    def update_service_state(self):
        self.service_switch.blockSignals(True)
        self.service_switch.setChecked(self.service.running)
        self.service_switch.blockSignals(False)
        self.service_detail.setText(f"127.0.0.1:{self.service.port}" if self.service.running else "已暂停")
        self.subscription_state.setText("服务运行中" if self.service.running else "服务已暂停")
        self.subscription_state.setStyleSheet(f"color: {GREEN if self.service.running else MUTED};")
        if self.pages.currentIndex() == 1:
            self.update_subscriptions()

    def subscription_nodes(self):
        group = self.subscription_group.currentData()
        return [
            node for node in self.model.nodes
            if node["enabled"] and (group is None or node["group"] == group)
        ]

    def update_subscriptions(self, *_):
        if not hasattr(self, "client_widgets") or not hasattr(self, "model"):
            return
        nodes = self.subscription_nodes()
        rules = self.store.list_rules()
        active_rules = sum(1 for rule in rules if rule["enabled"])
        self.subscription_count.setText(f"包含 {len(nodes)} 个已启用节点")
        self._export_cache.clear()
        for format, controls in self.client_widgets.items():
            url = self.service.url(format, self.subscription_group.currentData())
            controls["url"].setText(url)
            controls["url"].setCursorPosition(0)
            ready = bool(nodes)
            message = "已就绪" if nodes else "暂无已启用节点"
            if ready and format == "clash":
                message = f"已就绪 · 含 {active_rules} 条规则" if active_rules else "已就绪 · 仅兜底规则"
            try:
                if nodes:
                    self._export_cache[format] = (
                        export_clash(nodes, self.store.settings()["test_url"], rules=rules)
                        if format == "clash" else export_v2ray(nodes)
                    )
            except ValueError as error:
                message = f"导出受限：{error}"
                ready = False
            controls["status"].setText(message)
            controls["status"].setStyleSheet(f"color: {GREEN if ready else MUTED};")
            for control in ("copy", "export", "preview"):
                controls[control].setEnabled(ready)

    def copy_text(self, text, message):
        QApplication.clipboard().setText(text)
        self.notice(message)

    def copy_subscription(self, format):
        self.copy_text(
            self.service.url(format, self.subscription_group.currentData()),
            "订阅链接已复制" if self.service.running else "订阅链接已复制，服务当前已暂停",
        )

    def preview_subscription(self, format):
        content = self._export_cache.get(format, "")
        if format == "v2ray":
            content = base64.b64decode(content).decode("utf-8")
        PreviewDialog("Clash YAML" if format == "clash" else "v2rayN 节点列表", content, self).exec()

    def save_subscription(self, format):
        suffix = "yaml" if format == "clash" else "txt"
        name = "node-desk-clash.yaml" if format == "clash" else "node-desk-v2ray.txt"
        path, _ = QFileDialog.getSaveFileName(self, "导出订阅", name, f"订阅文件 (*.{suffix})")
        if path:
            try:
                Path(path).write_text(self._export_cache[format], encoding="utf-8")
                self.notice("订阅文件已导出")
            except OSError as error:
                error_dialog(self, "导出失败", str(error))

    def update_rules(self):
        if not hasattr(self, "rules_table"):
            return
        rules = self.store.list_rules()
        self._rule_ids = [rule["id"] for rule in rules]
        enabled_count = sum(1 for rule in rules if rule["enabled"])
        self.rules_summary.setText(f"共 {len(rules)} 条规则 · 启用 {enabled_count} 条")
        self.rules_table.setRowCount(len(rules))
        action_colors = {"PROXY": ACCENT, "AUTO": BLUE, "DIRECT": GREEN, "REJECT": RED}
        for row, rule in enumerate(rules):
            switch = Switch("启用该规则")
            switch.setChecked(rule["enabled"])
            switch.clicked.connect(
                lambda checked=False, rule_id=rule["id"]: self.toggle_rule(rule_id, checked)
            )
            holder = QWidget()
            holder_layout = QHBoxLayout(holder)
            holder_layout.setContentsMargins(14, 0, 0, 0)
            holder_layout.addWidget(switch)
            holder_layout.addStretch()
            self.rules_table.setCellWidget(row, 0, holder)
            type_item = QTableWidgetItem(RULE_TYPES.get(rule["type"], rule["type"]))
            value_item = QTableWidgetItem(rule["value"])
            value_item.setToolTip(rule["value"])
            action_item = QTableWidgetItem(RULE_ACTIONS.get(rule["action"], rule["action"]))
            action_item.setForeground(QColor(action_colors.get(rule["action"], INK)))
            for column, item in ((1, type_item), (2, value_item), (3, action_item)):
                if not rule["enabled"]:
                    item.setForeground(QColor(MUTED))
                self.rules_table.setItem(row, column, item)
            tools = QWidget()
            tools_layout = QHBoxLayout(tools)
            tools_layout.setContentsMargins(0, 0, 0, 0)
            tools_layout.setSpacing(2)
            up = icon_button("upload", "上移")
            up.setEnabled(row > 0)
            up.clicked.connect(
                lambda checked=False, rule_id=rule["id"]: self.move_rule(rule_id, -1)
            )
            down = icon_button("download", "下移")
            down.setEnabled(row < len(rules) - 1)
            down.clicked.connect(
                lambda checked=False, rule_id=rule["id"]: self.move_rule(rule_id, 1)
            )
            edit = icon_button("pencil", "编辑规则")
            edit.clicked.connect(
                lambda checked=False, rule_id=rule["id"]: self.edit_rule(rule_id)
            )
            remove = icon_button("trash-2", "删除规则", color=RED)
            remove.clicked.connect(
                lambda checked=False, rule_id=rule["id"]: self.delete_rule(rule_id)
            )
            for control in (up, down, edit, remove):
                tools_layout.addWidget(control)
            tools_layout.addStretch()
            self.rules_table.setCellWidget(row, 4, tools)

    def add_rule(self):
        dialog = RuleDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.store.add_rule(dialog.rule())
        except ValueError as error:
            error_dialog(self, "无法添加规则", str(error))
            return
        self.update_rules()
        self.notice("规则已添加")

    def edit_rule(self, rule_id):
        rule = next((item for item in self.store.list_rules() if item["id"] == rule_id), None)
        if rule is None:
            return
        dialog = RuleDialog(rule, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.store.update_rule(rule_id, **dialog.rule())
        except (ValueError, KeyError) as error:
            error_dialog(self, "无法保存规则", str(error))
            return
        # 延迟刷新：请求可能来自表格内的按钮，避免在信号处理中销毁发送者。
        QTimer.singleShot(0, self.update_rules)
        self.notice("规则已保存")

    def edit_rule_row(self, index):
        if 0 <= index.row() < len(self._rule_ids):
            self.edit_rule(self._rule_ids[index.row()])

    def toggle_rule(self, rule_id, enabled):
        try:
            self.store.update_rule(rule_id, enabled=enabled)
        except (ValueError, KeyError) as error:
            error_dialog(self, "操作失败", str(error))
        else:
            self.notice("规则已启用" if enabled else "规则已停用")
        QTimer.singleShot(0, self.update_rules)

    def move_rule(self, rule_id, delta):
        try:
            moved = self.store.move_rule(rule_id, delta)
        except (ValueError, KeyError) as error:
            error_dialog(self, "操作失败", str(error))
            moved = False
        if moved:
            QTimer.singleShot(0, self.update_rules)

    def delete_rule(self, rule_id):
        rule = next((item for item in self.store.list_rules() if item["id"] == rule_id), None)
        if rule is None:
            return
        if not confirm(self, "删除规则", f"删除规则“{rule['type']},{rule['value']}”？此操作不可撤销。", "删除"):
            return
        self.store.delete_rule(rule_id)
        QTimer.singleShot(0, self.update_rules)
        self.notice("规则已删除")

    def reset_rules(self):
        if not confirm(self, "恢复默认规则", "将使用内置默认规则替换当前全部规则，当前自定义内容会丢失。", "恢复默认"):
            return
        self.store.reset_rules()
        self.update_rules()
        self.notice("已恢复默认规则")

    def run_tests(self, node_ids=None, mode=None):
        if self.busy():
            return
        ids = set(node_ids if node_ids is not None else (self.model.checked or self.visible_ids()))
        nodes = [node for node in self.model.nodes if node["id"] in ids]
        if not nodes:
            return
        from .testing import NodeTester

        settings = self.store.settings()
        selected_mode = mode or self.mode_combo.currentData()
        core = Path(settings["core_path"]) if settings["core_path"] else bundled_core()
        if selected_mode == "proxy" and not core.is_file():
            error_dialog(self, "缺少测试内核", "未找到 Mihomo 内核。请保留程序的完整文件夹，或在设置中选择内核。")
            return
        try:
            tester = NodeTester(
                core_path=core, timeout_ms=settings["timeout_ms"],
                concurrency=settings["concurrency"], test_url=settings["test_url"],
                temp_root=self.store.data_dir,
            )
        except (ValueError, OSError):
            error_dialog(self, "无法开始测试", "请检查测试设置和数据目录权限。")
            return
        self.model.testing = ids
        self._test_done, self._test_total = 0, len(nodes)
        self.test_progress.setRange(0, len(nodes))
        self.test_progress.setValue(0)
        self.test_progress.show()
        self.test_summary.setText(f"已完成 0 / {len(nodes)}")
        self.worker = TestWorker(tester, nodes, selected_mode, self)
        self.worker.result_ready.connect(self.on_test_result)
        self.worker.failed.connect(lambda message: error_dialog(self, "测试未完成", message) if not self._closing else None)
        self.worker.finished.connect(self.on_tests_finished)
        self._test_cancelled = False
        self._test_session_id = self.store.start_test_session(selected_mode, len(nodes))
        self.worker.start()
        self.set_testing_state(True)
        self.table.viewport().update()

    def set_testing_state(self, active):
        self.import_button.setEnabled(not active)
        self.empty_import.setEnabled(not active)
        self.test_button.setVisible(not active)
        self.cancel_test_button.setVisible(active)
        self.mode_combo.setEnabled(not active)
        self.save_settings_button.setEnabled(not active)
        self.restore_button.setEnabled(not active)
        self.retest_button.setEnabled(not active)
        self.update_selection()

    def on_test_result(self, result):
        self.store.save_test_result(result)
        if self._test_session_id is not None:
            self.store.add_test_session_item(self._test_session_id, result)
        self.model.testing.discard(result["node_id"])
        for index, node in enumerate(self.model.nodes):
            if node["id"] == result["node_id"]:
                node.setdefault("tests", {})[result["mode"]] = result
                self.model.dataChanged.emit(self.model.index(index, 0), self.model.index(index, 7))
                break
        self._test_done += 1
        self.test_progress.setValue(self._test_done)
        self.test_summary.setText(f"已完成 {self._test_done} / {self._test_total}")
        self.update_metrics()

    def cancel_tests(self):
        if self.worker:
            self._test_cancelled = True
            self.worker.tester.cancel()
            self.cancel_test_button.setEnabled(False)
            self.test_summary.setText("正在结束测试")

    def on_tests_finished(self):
        if self._test_session_id is not None:
            self.store.finish_test_session(self._test_session_id, cancelled=self._test_cancelled)
            self._test_session_id = None
        self._test_cancelled = False
        worker = self.worker
        self.worker = None
        self.model.testing.clear()
        self.cancel_test_button.setEnabled(True)
        self.test_progress.hide()
        self.set_testing_state(False)
        self.refresh()
        if worker:
            if not worker.error:
                self.notice(f"测试结束，已记录 {self._test_done} 个结果")
            worker.deleteLater()
        if self._closing:
            QTimer.singleShot(0, self.close)

    def retest_failed(self):
        ids = [node["id"] for node in self.model.nodes if test_state(node)[2] in ("failed", "unsupported")]
        if not ids:
            self.notice("暂无异常节点")
            return
        self.navigate(0)
        self.run_tests(ids, "proxy")

    def update_history(self):
        sessions = self.store.list_test_sessions()
        self._history_ids = [session["id"] for session in sessions]
        self.history_table.setRowCount(len(sessions))
        ok_total = sum(session["counts"]["ok"] for session in sessions)
        failed_total = sum(session["counts"]["failed"] for session in sessions)
        self.history_summary.setText(
            f"每次测试保留一条记录 · 共 {len(sessions)} 次 · 成功 {ok_total} · 失败 {failed_total}"
            " · 双击记录（或点击眼睛按钮）查看当次全部节点"
        )
        for row, session in enumerate(sessions):
            counts = session["counts"]
            rest = max(0, int(session["total"]) - counts["ok"] - counts["failed"])
            stamp = local_stamp(session.get("started_at"))
            if session.get("cancelled"):
                stamp += "（已取消）"
            elif not session.get("finished_at"):
                stamp += "（未完成）"
            mode = "实际代理" if session.get("mode") == "proxy" else "TCP 端口"
            values = [
                stamp, mode, str(session["total"]),
                str(counts["ok"]), str(counts["failed"]), str(rest) if rest else "-",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 3:
                    item.setForeground(QColor(GREEN if counts["ok"] else MUTED))
                elif column == 4:
                    item.setForeground(QColor(RED if counts["failed"] else MUTED))
                elif column == 5:
                    item.setForeground(QColor(MUTED))
                self.history_table.setItem(row, column, item)
            detail = icon_button("eye", "查看该次测试的全部节点结果")
            detail.clicked.connect(
                lambda checked=False, session_id=session["id"]: self.show_test_session(session_id)
            )
            holder = QWidget()
            holder_layout = QHBoxLayout(holder)
            holder_layout.setContentsMargins(6, 0, 0, 0)
            holder_layout.addWidget(detail)
            holder_layout.addStretch()
            self.history_table.setCellWidget(row, 6, holder)
        self.retest_button.setEnabled(
            not self.busy()
            and any(test_state(node)[2] in ("failed", "unsupported") for node in self.model.nodes)
        )

    def history_detail_row(self, index):
        if 0 <= index.row() < len(self._history_ids):
            self.show_test_session(self._history_ids[index.row()])

    def show_test_session(self, session_id):
        try:
            session = self.store.get_test_session(session_id)
        except KeyError:
            self.update_history()
            return
        TestDetailDialog(session, self).exec()

    def load_settings(self):
        settings = self.store.settings()
        self.port_input.setValue(settings["port"])
        self.auto_service.setChecked(settings["start_service"])
        self.target_input.setCurrentText(settings["test_url"])
        self.timeout_input.setValue(settings["timeout_ms"] // 1000)
        self.concurrency_input.setValue(settings["concurrency"])
        self.core_input.setText(settings["core_path"])

    def save_settings(self):
        if self.busy():
            return
        old = self.store.settings()
        changes = {
            "port": self.port_input.value(), "start_service": self.auto_service.isChecked(),
            "test_url": self.target_input.currentText().strip(),
            "timeout_ms": self.timeout_input.value() * 1000,
            "concurrency": self.concurrency_input.value(), "core_path": self.core_input.text(),
        }
        if changes["core_path"] and not Path(changes["core_path"]).is_file():
            error_dialog(self, "无法保存", "所选内核文件不存在。")
            return
        try:
            self.store.update_settings(changes)
        except (ValueError, TypeError) as error:
            error_dialog(self, "无法保存", str(error))
            return
        if self.service.running and old["port"] != changes["port"]:
            self.service.stop()
            try:
                self.service.start()
            except OSError:
                self.store.update_settings({key: old[key] for key in changes})
                try:
                    self.service.start()
                except OSError:
                    pass
                self.load_settings()
                self.update_service_state()
                error_dialog(self, "端口不可用", "新端口无法使用，已还原原有设置。")
                return
        self.update_service_state()
        self.notice("设置已保存")

    def choose_core(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 Mihomo 内核", "", "Windows 程序 (*.exe)")
        if path:
            self.core_input.setText(path)

    def rotate_token(self):
        if confirm(self, "重置订阅令牌", "旧订阅地址将立即失效，客户端需要重新填写地址。", "重置"):
            self.store.rotate_token()
            self.update_subscriptions()
            self.notice("订阅令牌已重置")

    def export_backup(self):
        if not confirm(self, "导出备份", "备份文件包含明文节点密码和链接，请妥善保管。", "继续导出"):
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出备份", f"node-desk-backup-{datetime.now().strftime('%Y%m%d')}.json",
            "Node Desk 备份 (*.json)",
        )
        if path:
            try:
                Path(path).write_text(self.store.export_backup(), encoding="utf-8")
                self.notice("备份已导出")
            except OSError as error:
                error_dialog(self, "导出失败", str(error))

    def restore_backup(self):
        if self.busy():
            return
        path, _ = QFileDialog.getOpenFileName(self, "恢复备份", "", "Node Desk 备份 (*.json)")
        if not path:
            return
        if not confirm(self, "恢复备份", "将备份中的节点合并到当前列表，现有节点不会被覆盖。", "合并"):
            return
        try:
            source = Path(path)
            if source.stat().st_size > MAX_BACKUP_BYTES:
                raise ValueError("备份文件过大。")
            added, duplicates = self.store.import_backup(source.read_text(encoding="utf-8-sig"))
            self.refresh()
            self.notice(f"已恢复 {added} 个节点，跳过 {duplicates} 个重复项")
        except (ValueError, OSError, UnicodeError) as error:
            error_dialog(self, "恢复失败", str(error))

    def show_licenses(self):
        parts = [f"Node Desk {__version__}\n\n"]
        path = resource_root() / "licenses"
        for source in sorted(path.glob("*.txt")):
            parts.append(f"\n{source.name}\n\n{source.read_text(encoding='utf-8', errors='replace')}")
        PreviewDialog("开源许可", "\n".join(parts), self).exec()

    def notice(self, message):
        self.statusBar().showMessage(message, 6500)

    def closeEvent(self, event):
        self._closing = True
        self.service.stop()
        if self.worker is not None:
            self._test_cancelled = True
            self.worker.tester.cancel()
            self.setEnabled(False)
            event.ignore()
            self.notice("正在结束测试并退出")
            return
        event.accept()
