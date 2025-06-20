# ── views/workflows_view.py ────────────────────────────────────────────
"""
Professional-looking, responsive card grid for Shuffle workflows.

• Cards are 320 × 240 px with a soft shadow so they “float” above the page.
• Column count recalculates on resize; the first card is always top-left.
• Design mirrors Guardian’s Dashboard / Alerts pages (colours, fonts, spacing).
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QScrollArea, QFrame, QLabel,
    QPushButton, QSizePolicy, QGridLayout, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont
from datetime import datetime


class WorkflowsView(QWidget):
    """SOAR workflows grid-view with large shadowed cards."""
    refresh_requested = pyqtSignal()

    CARD_W  = 320
    CARD_H  = 240
    GRID_SP = 24          # space between cards

    # ────────────────────────────────────────────────────────────────
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.controller = None
        self._build_ui()

    # router helper
    def set_controller(self, controller):
        self.controller = controller
        # ask controller for fresh data right after view initialises
        QTimer.singleShot(60, getattr(controller, "refresh_workflows", lambda: None))

    # ────────────────────────────────────────────────────────────────
    # UI setup
    def _build_ui(self):
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)

        self.setStyleSheet("""
            QLabel#title { font-size:22px; font-weight:bold; color:#2c3e50; }
            QPushButton  { background:#3498db; color:#fff; border:none;
                           border-radius:4px; padding:6px 16px; font-weight:bold; }
            QPushButton:hover   { background:#2980b9; }
            QPushButton:pressed { background:#1f6da9; }

            /* base card styling (shadow applied programmatically) */
            QFrame#card { background:#ffffff; border-radius:10px;
                          border:1px solid #e0e0e0; }
        """)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(18)

        # header
        header = QHBoxLayout()
        header.addWidget(QLabel("SOAR Workflows", objectName="title"))
        header.addStretch()
        self.refresh_btn = QPushButton("Refresh", clicked=self._on_refresh)
        header.addWidget(self.refresh_btn)
        outer.addLayout(header)

        # scroll-area + grid
        self.scroll = QScrollArea(frameShape=QFrame.Shape.NoFrame)
        self.scroll.setWidgetResizable(True)

        self._grid_host = QWidget()
        self.grid = QGridLayout(self._grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(self.GRID_SP)
        self.grid.setVerticalSpacing(self.GRID_SP)
        self.grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        self.scroll.setWidget(self._grid_host)
        outer.addWidget(self.scroll, 1)

    # ────────────────────────────────────────────────────────────────
    # Public API – called by controller
    def update_workflows(self, workflows: list[dict]) -> None:
        """Re-populate the grid with (possibly) new workflow data."""
        # clear old
        while self.grid.count():
            w = self.grid.takeAt(0).widget()
            w.deleteLater()

        if not workflows:
            return

        cols = self._cols_fit()
        for i, wf in enumerate(workflows):
            r, c = divmod(i, cols)
            self.grid.addWidget(self._make_card(wf), r, c)

        # push free space to the right so row looks full-width
        for c in range(cols):
            self.grid.setColumnStretch(c, 0)
        self.grid.setColumnStretch(cols, 1)

    # ────────────────────────────────────────────────────────────────
    # helpers
    def _cols_fit(self) -> int:
        vp_w = self.scroll.viewport().width() or self.width()
        return max(1, (vp_w + self.GRID_SP) // (self.CARD_W + self.GRID_SP))

    def _make_card(self, wf: dict) -> QFrame:
        """Return a styled card widget with drop-shadow."""
        card = QFrame(objectName="card")
        card.setFixedSize(self.CARD_W, self.CARD_H)

        # soft shadow
        shadow = QGraphicsDropShadowEffect(blurRadius=20, xOffset=0, yOffset=4,
                                           color=QColor(0, 0, 0, 35))
        card.setGraphicsEffect(shadow)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        # title
        ttl = QLabel(wf.get("name", "—"), alignment=Qt.AlignmentFlag.AlignCenter)
        f = QFont(); f.setBold(True); f.setPointSize(12)
        ttl.setFont(f)
        lay.addWidget(ttl)

        # status
        status_txt = (wf.get("status") or "—").title()
        status = QLabel(status_txt, alignment=Qt.AlignmentFlag.AlignCenter)
        status.setStyleSheet(f"color:{self._status_colour(status_txt)}; font-size:11px;")
        lay.addWidget(status)

        # ID (short)
        wid = wf.get("id", "—")[:8] + ("…" if wf.get("id") else "")
        id_lbl = QLabel(f"ID: {wid}", alignment=Qt.AlignmentFlag.AlignCenter)
        id_lbl.setStyleSheet("color:#7f8c8d; font-size:11px;")
        lay.addWidget(id_lbl)

        # last update
        raw = wf.get("updated", "—")
        nice = raw
        if isinstance(raw, (int, float)):
            nice = datetime.fromtimestamp(raw).strftime("%Y-%m-%d %H:%M")
        ts = QLabel(f"Last update: {nice}", alignment=Qt.AlignmentFlag.AlignCenter)
        ts.setStyleSheet("color:#95a5a6; font-size:11px;")
        lay.addWidget(ts)

        lay.addStretch(1)
        return card

    @staticmethod
    def _status_colour(txt: str) -> str:
        t = txt.lower()
        if t in ("active", "running"):      return "#2ecc71"
        if t in ("scheduled", "pending"):   return "#3498db"
        if t in ("failed", "error"):        return "#e74c3c"
        return "#95a5a6"

    # ────────────────────────────────────────────────────────────────
    # events
    def _on_refresh(self):
        if self.controller and hasattr(self.controller, "refresh_workflows"):
            self.controller.refresh_workflows()
        else:
            self.refresh_requested.emit()

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        if self.controller and hasattr(self.controller, "_fetch_once"):
            self.update_workflows(self.controller._fetch_once())
