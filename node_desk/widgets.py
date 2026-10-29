from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractButton, QFrame, QHBoxLayout, QLabel, QPushButton, QToolButton, QVBoxLayout,
)

from .theme import ACCENT, INK, MUTED, icon


def label(text: str, role: str = "", *, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    widget.setObjectName(role)
    widget.setWordWrap(wrap)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    return widget


def button(text: str, symbol: str | None = None, *, primary=False, danger=False) -> QPushButton:
    widget = QPushButton(text)
    widget.setMinimumHeight(36)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if primary:
        widget.setObjectName("primary")
    elif danger:
        widget.setObjectName("danger")
    if symbol:
        widget.setIcon(icon(symbol, "#ffffff" if primary else MUTED, 17))
        widget.setIconSize(QSize(17, 17))
    widget.setAccessibleName(text)
    return widget


def icon_button(symbol: str, title: str, *, color: str = MUTED) -> QToolButton:
    widget = QToolButton()
    widget.setObjectName("icon")
    widget.setIcon(icon(symbol, color, 18))
    widget.setIconSize(QSize(18, 18))
    widget.setFixedSize(34, 34)
    widget.setToolTip(title)
    widget.setAccessibleName(title)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget


def divider() -> QFrame:
    widget = QFrame()
    widget.setObjectName("divider")
    widget.setFixedHeight(1)
    return widget


class Switch(QAbstractButton):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(38, 23)
        self.setAccessibleName(title)
        self.setToolTip(title)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = ACCENT if self.isChecked() else "#c9d0db"
        if not self.isEnabled():
            color = "#e3e7ed"
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(color))
        painter.drawRoundedRect(QRectF(1, 3, 36, 19), 9.5, 9.5)
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(QRectF(20 if self.isChecked() else 4, 6, 13, 13))
        if self.hasFocus():
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor("#90c8b9"), 1))
            painter.drawRoundedRect(QRectF(0.5, 1, 37, 21), 10, 10)


class Metric(QFrame):
    def __init__(self, title: str, symbol: str, color: str = ACCENT):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 8, 20, 8)
        layout.setSpacing(14)
        image = QLabel()
        image.setFixedSize(38, 38)
        image.setPixmap(icon(symbol, color, 22).pixmap(22, 22))
        image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        image.setStyleSheet(f"background: {self._tint(color)}; border-radius: 6px;")
        layout.addWidget(image)
        values = QVBoxLayout()
        values.setSpacing(0)
        self.value = label("0", "metricValue")
        values.addWidget(self.value)
        values.addWidget(label(title, "metricLabel"))
        layout.addLayout(values)
        layout.addStretch()

    @staticmethod
    def _tint(color: str) -> str:
        return {
            ACCENT: "#e8f4ef", "#3d70bd": "#edf2fb",
            "#16815d": "#edf7ef", "#ad771a": "#fbf5e9",
        }.get(color, "#f1f3f7")

    def set_value(self, value: int):
        self.value.setText(str(value))
