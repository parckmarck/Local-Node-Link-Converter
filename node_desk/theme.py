from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication

from .paths import resource_root

INK = "#242936"
MUTED = "#747d8c"
ACCENT = "#087f6d"
GREEN = "#16815d"
RED = "#c54b50"
BLUE = "#3d70bd"
AMBER = "#ad771a"


@lru_cache(maxsize=160)
def icon(name: str, color: str = MUTED, size: int = 20) -> QIcon:
    path = resource_root() / "assets" / "icons" / f"{name}.svg"
    if not path.exists():
        return QIcon()
    source = path.read_bytes().replace(b"currentColor", color.encode("ascii"))
    renderer = QSvgRenderer(QByteArray(source))
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return QIcon(pixmap)


def apply_theme(app: QApplication):
    app.setStyle("Fusion")
    if app.platformName() == "offscreen" and os.name == "nt":
        _load_test_fonts()
    palette = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, "#ffffff"), (QPalette.ColorRole.Base, "#ffffff"),
        (QPalette.ColorRole.Text, INK), (QPalette.ColorRole.WindowText, INK),
        (QPalette.ColorRole.Button, "#ffffff"), (QPalette.ColorRole.ButtonText, INK),
        (QPalette.ColorRole.Highlight, "#e1f0eb"), (QPalette.ColorRole.HighlightedText, INK),
        (QPalette.ColorRole.ToolTipBase, "#303846"), (QPalette.ColorRole.ToolTipText, "#ffffff"),
    ):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    font = QFont("Microsoft YaHei UI", 10)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)
    app.setStyleSheet(STYLESHEET)


@lru_cache(maxsize=1)
def _load_test_fonts():
    # Qt's offscreen platform does not enumerate the Windows system font database.
    fonts = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    for name in ("msyh.ttc", "msyhbd.ttc", "segoeui.ttf", "consola.ttf"):
        path = fonts / name
        if path.is_file():
            QFontDatabase.addApplicationFont(str(path))


STYLESHEET = """
QWidget {
    color: #242936; font-family: "Microsoft YaHei UI"; font-size: 13px;
}
QMainWindow, QDialog { background: #ffffff; }
QLabel { background: transparent; }
QFrame#sidebar { background: #f5f7fa; border-right: 1px solid #e6e9ef; }
QLabel#brand { font-size: 20px; font-weight: 700; color: #242936; }
QLabel#brandSub { font-size: 11px; color: #89919e; }
QLabel#navLabel { color: #929aa7; font-size: 11px; }
QToolButton#nav {
    text-align: left; padding: 11px 14px; border: none;
    border-radius: 6px; color: #737d8c; background: transparent; font-size: 13px;
}
QToolButton#nav:hover { background: #e9edf2; color: #242936; }
QToolButton#nav:checked { background: #e1f0eb; color: #087f6d; font-weight: 600; }
QLabel#crumb { font-size: 11px; color: #929aa7; }
QLabel#pageTitle { font-size: 26px; font-weight: 700; color: #242936; }
QLabel#muted { color: #747d8c; }
QLabel#small { color: #929aa7; font-size: 11px; }
QLabel#sectionTitle { font-size: 15px; font-weight: 600; }
QLabel#metricValue { font-size: 28px; font-weight: 600; }
QLabel#metricLabel { color: #7f8897; font-size: 12px; }
QFrame#divider { background: #e9ecf1; border: none; max-height: 1px; }
QFrame#metricDivider { background: #e9ecf1; border: none; max-width: 1px; }
QFrame#client { border: 1px solid #e4e8ef; border-radius: 6px; background: #ffffff; }
QFrame#client QWidget { border: none; }
QFrame#batchBar { background: #eff7f4; border-radius: 4px; }
QLabel#emptyTitle { font-size: 18px; font-weight: 600; color: #5e6878; }
QPushButton, QToolButton {
    border: 1px solid #dfe4ec; border-radius: 5px; padding: 8px 13px;
    background: #ffffff; color: #485364; font-size: 12px;
}
QPushButton:hover, QToolButton:hover { background: #f6f8fa; border-color: #c5ceda; }
QPushButton:pressed, QToolButton:pressed { background: #eaf0f4; }
QPushButton:disabled, QToolButton:disabled { color: #aeb5c0; background: #f8f9fb; border-color: #edf0f4; }
QPushButton#primary, QToolButton#primary { color: #ffffff; background: #087f6d; border-color: #087f6d; font-weight: 600; }
QPushButton#primary:hover, QToolButton#primary:hover { background: #066b5c; border-color: #066b5c; }
QPushButton#primary:disabled { background: #a3c9bf; border-color: #a3c9bf; color: #f1f7f5; }
QPushButton#danger { color: #be4750; border-color: #f0d8db; }
QPushButton#danger:hover { background: #fdf0f1; }
QToolButton#icon { border: none; padding: 7px; background: transparent; }
QToolButton#icon:hover { background: #edf2f5; }
QToolButton#segment { border: none; padding: 7px 13px; background: transparent; color: #828b99; }
QToolButton#segment:checked { color: #087f6d; background: #e9f4ef; font-weight: 600; }
QToolButton::menu-indicator { subcontrol-position: right center; right: 5px; }
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QComboBox {
    background: #ffffff; border: 1px solid #dfe4ec; border-radius: 5px;
    padding: 8px 10px; selection-background-color: #dcefe8; selection-color: #242936;
}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #399a87; }
QLineEdit:read-only { background: #f7f9fb; color: #5c687a; }
QComboBox { min-height: 18px; padding-right: 25px; }
QComboBox::drop-down { border: none; width: 23px; }
QComboBox QAbstractItemView { background: #ffffff; padding: 5px; border: 1px solid #dfe4ec; selection-background-color: #e9f4ef; }
QSpinBox::up-button, QSpinBox::down-button { width: 20px; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 15px; height: 15px; border: 1px solid #cad2dc; border-radius: 3px; background: #ffffff; }
QCheckBox::indicator:checked { background: #087f6d; border-color: #087f6d; }
QCheckBox:disabled { color: #9fa7b3; }
QTableView, QTableWidget {
    background: #ffffff; alternate-background-color: #ffffff; border: none;
    gridline-color: #edf0f4; selection-background-color: #f0f6f4;
    selection-color: #242936; outline: none;
}
QTableView::item { border-bottom: 1px solid #edf0f4; padding: 8px; }
QTableView::item:selected { background: #edf6f2; color: #242936; }
QHeaderView::section {
    background: #f7f9fb; color: #8a93a0; border: none;
    border-bottom: 1px solid #e7ebf1; padding: 12px 8px; font-size: 11px;
}
QTableCornerButton::section { background: #f7f9fb; border: none; }
QScrollBar:vertical { width: 8px; background: transparent; margin: 0; }
QScrollBar::handle:vertical { background: #d8dee6; min-height: 30px; border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal { height: 8px; background: transparent; margin: 0; }
QScrollBar::handle:horizontal { background: #d8dee6; min-width: 30px; border-radius: 4px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QProgressBar { border: none; background: #edf2f0; height: 4px; border-radius: 2px; color: transparent; }
QProgressBar::chunk { background: #1b967c; border-radius: 2px; }
QTabWidget::pane { border: none; border-top: 1px solid #e7ebf1; padding-top: 16px; }
QTabBar::tab { padding: 12px 18px; color: #7d8695; background: #ffffff; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #087f6d; border-bottom: 2px solid #087f6d; }
QMenu { background: #ffffff; padding: 5px; border: 1px solid #e0e5eb; border-radius: 5px; }
QMenu::item { padding: 9px 25px 9px 12px; border-radius: 3px; }
QMenu::item:selected { background: #ecf5f1; color: #087f6d; }
QMenu::separator { height: 1px; background: #e9edf2; margin: 5px 4px; }
QToolTip { color: #ffffff; background: #303846; border: none; padding: 6px 9px; font-size: 11px; }
QStatusBar { background: #ffffff; color: #8992a0; border-top: 1px solid #edf0f4; font-size: 11px; }
QStatusBar::item { border: none; }
QMessageBox QLabel { min-width: 300px; }
QScrollArea { border: none; background: #ffffff; }
"""
