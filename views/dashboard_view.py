# ── views/dashboard_view.py — fully rewritten ─────────────────────────────
"""Guardian – Security Dashboard view (2025‑06)

• 100 % contained charts (no bleeding outside their card)
• SOAR Automation status shows *real* data coming from controller
• “View Workflows” button switches view using the router

Drop‑in replacement for the previous file.  Nothing else in the code‑base
needs to change – as long as the Router injects itself via
```
    view.set_router(router)
```
right after instantiating the view.
"""

from __future__ import annotations

from datetime import datetime
import time

from PyQt6.QtCore import (Qt, QMargins, QThread, QTimer, pyqtSignal)
from PyQt6.QtGui import QColor, QFont, QPainter, QBrush
from PyQt6.QtWidgets import (
    QFrame, QLabel, QPushButton, QSizePolicy, QHBoxLayout, QVBoxLayout,
    QGridLayout, QWidget, QGraphicsDropShadowEffect
)
from PyQt6.QtCharts import (
    QChart, QChartView, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis,
    QPieSeries
)


class _StatCard(QFrame):
    """Small white card used in the 4‑tile statistics row."""
    def __init__(self, title: str, emoji: str, colour: str):
        super().__init__()
        self.setObjectName("statCard")
        self.setMinimumHeight(110)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Preferred)
        self.setStyleSheet("""
            #statCard { background:#fff;border:1px solid #e0e0e0;border-radius:8px; }
        """)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(14); shadow.setOffset(0, 2);
        shadow.setColor(QColor(0, 0, 0, 30)); self.setGraphicsEffect(shadow)

        lay = QVBoxLayout(self); lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(4)

        row = QHBoxLayout(); row.setSpacing(6)
        title_lbl = QLabel(title); title_lbl.setStyleSheet("color:#7f8c8d;font:600 14px;")
        row.addWidget(title_lbl); row.addStretch()
        icon_lbl = QLabel(emoji); icon_lbl.setStyleSheet("font:16px;")
        row.addWidget(icon_lbl)
        lay.addLayout(row)

        self.value_lbl = QLabel("0"); self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_lbl.setStyleSheet("font:700 28px;")
        lay.addWidget(self.value_lbl)
        lay.addStretch()
        self._colour = colour

    def update_value(self, val):
        self.value_lbl.setText(str(val))
        self.value_lbl.setStyleSheet(f"font:700 28px;color:{self._colour};")


class _ContainedChart(QChartView):
    """Base‑class for both charts – handles the *in‑card* look"""
    def __init__(self, min_h: int = 250):
        super().__init__()
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setBackgroundBrush(QBrush(QColor("transparent")))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumHeight(min_h)


class _AlertTrendChart(_ContainedChart):

    def __init__(self):
        super().__init__()
        self._build_chart()

    # ------------------------------------------------------------------ helpers
    def _build_chart(self) -> None:
        """Initialise the 7-day bar chart (same margins, visible Y labels)."""
        # ── chart shell ──────────────────────────────────────────────
        self.chart_obj = QChart()
        self.setChart(self.chart_obj)

        self.chart_obj.setTitle("Alert Trend (7 Days)")
        self.chart_obj.setTitleFont(QFont("Segoe UI", 12, QFont.Weight.Medium))
        self.chart_obj.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        self.chart_obj.setBackgroundVisible(False)
        self.chart_obj.setMargins(QMargins(0, 0, 0, 0))  # ← KEEP original zero margins

        # legend
        lgnd = self.chart_obj.legend()
        lgnd.setVisible(True)
        lgnd.setAlignment(Qt.AlignmentFlag.AlignBottom)
        lgnd.setFont(QFont("Segoe UI", 9))

        # ── axes ─────────────────────────────────────────────────────
        # X-axis
        self.categories = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        self.axis_x = QBarCategoryAxis()
        self.axis_x.append(self.categories)
        self.axis_x.setLabelsFont(QFont("Segoe UI", 9))
        self.chart_obj.addAxis(self.axis_x, Qt.AlignmentFlag.AlignBottom)

        # Y-axis  – shrunk font so digits fit inside 0-margin area
        self.axis_y = QValueAxis()
        small_font = QFont("Segoe UI", 7)  # ← smaller so “0/2/4/…” fit
        self.axis_y.setLabelsFont(small_font)
        self.axis_y.setLabelFormat("%d")
        self.axis_y.setGridLineColor(QColor("#e0e0e0"))
        self.axis_y.setRange(0, 10)  # default – will be stretched in update_data()
        self.axis_y.setTickCount(6)
        self.chart_obj.addAxis(self.axis_y, Qt.AlignmentFlag.AlignLeft)

        # ── colour palette (unchanged) ───────────────────────────────
        self._palette = {
            "critical": QColor("#e74c3c"),
            "high": QColor("#f39c12"),
            "medium": QColor("#3498db"),
            "low": QColor("#2ecc71"),
        }

        # prime chart with an empty dataset
        self.update_data({})

    # ---------------------------------------------------------------- public API
    def update_data(self, series: dict[int, dict]):
        """`series` → {weekday: {critical,high,medium,low}}"""
        self.chart_obj.removeAllSeries()
        s = QBarSeries(); s.setBarWidth(0.8)
        sets = {k: QBarSet(k.title()) for k in self._palette}
        for k, bar in sets.items():
            bar.setColor(self._palette[k]); bar.setLabelColor(QColor("white"))
        max_y = 1
        for i in range(7):
            vals = series.get(i, {})
            for sev in sets:
                val = vals.get(sev, 0)
                sets[sev].append(val)
            max_y = max(max_y, sum(vals.values()))
        for bar in sets.values():
            s.append(bar)
        self.chart_obj.addSeries(s)
        s.attachAxis(self.axis_x); s.attachAxis(self.axis_y)
        self.axis_y.setRange(0, max_y + 2)
        self.axis_y.setTickCount(min(8, max_y + 3))


class _SystemHealthChart(_ContainedChart):
    def __init__(self):
        super().__init__()
        self.chart_obj = QChart(); self.setChart(self.chart_obj)
        self.chart_obj.setTitle("System Health")
        self.chart_obj.setTitleFont(QFont("Segoe UI", 12, QFont.Weight.Medium))
        self.chart_obj.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        self.chart_obj.setBackgroundVisible(False)
        self.chart_obj.setMargins(QMargins(0, 0, 0, 0))
        self.chart_obj.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.chart_obj.legend().setFont(QFont("Segoe UI", 9))
        self.update_data({})

    def update_data(self, data: dict[str, int]):
        self.chart_obj.removeAllSeries()
        series = QPieSeries(); series.setLabelsVisible(False)
        if not data:
            slice = series.append("No data", 1); slice.setColor(QColor("#95a5a6"))
        else:
            pal = {"healthy": "#2ecc71", "warning": "#f39c12", "critical": "#e74c3c"}
            tot = sum(data.values()) or 1
            for name, value in data.items():
                if value <= 0: continue
                pct = value / tot * 100
                sl = series.append(f"{name} ({pct:.0f} %)", value)
                for k, col in pal.items():
                    if k in name.lower(): sl.setColor(QColor(col))
                if "critical" in name.lower(): sl.setExploded(True); sl.setExplodeDistanceFactor(0.08)
        self.chart_obj.addSeries(series)


class _Worker(QThread):
    update_ready = pyqtSignal(dict)
    def __init__(self, ctrl):
        super().__init__(); self.ctrl = ctrl; self.running = True
    def run(self):
        while self.running:
            if self.ctrl:
                self.update_ready.emit(self.ctrl.get_dashboard_data())
            for _ in range(30):
                if not self.running: break
                time.sleep(1)
    def stop(self): self.running = False


class DashboardView(QWidget):
    """Main dashboard – drop‑in replacement."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setStyleSheet("background:#fff;font-family:'Segoe UI',Arial,sans-serif;")
        self.controller = None; self.router = None
        self._cards: dict[str, _StatCard] = {}
        self._workflow_items: dict[str, tuple[QFrame, QLabel, QFrame]] = {}
        self._worker: _Worker | None = None
        self._build_ui(); self.show()

    # ---------------------------------------------------------------- router hook
    def set_router(self, router):
        self.router = router

    # ---------------------------------------------------------------- controller
    def set_controller(self, controller):
        self.controller = controller
        if not self._worker:
            self._worker = _Worker(controller)
            self._worker.update_ready.connect(self._update_from_data)
            self._worker.start()
        # immediate first paint
        self._update_from_data(controller.get_dashboard_data())

    # ---------------------------------------------------------------- UI layout
    def _build_ui(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(20, 20, 20, 20); outer.setSpacing(16)
        self._build_header(outer)
        self._build_stats_row(outer)
        self._build_charts_row(outer)
        self._build_soar_status(outer)
        outer.addStretch(1)

    def _build_header(self, lay):
        row = QHBoxLayout(); title = QLabel("Security Dashboard");
        title.setStyleSheet("font:700 24px;color:#333;"); row.addWidget(title); row.addStretch()
        ref_btn = QPushButton("Refresh"); ref_btn.clicked.connect(lambda: self._update_from_data(self.controller.get_dashboard_data()))
        ref_btn.setStyleSheet("""QPushButton{background:#3498db;border:none;color:#fff;padding:8px 16px;border-radius:4px;font-weight:600;}
                                QPushButton:hover{background:#2980b9;} QPushButton:pressed{background:#1f6da9;}""")
        row.addWidget(ref_btn); lay.addLayout(row)

    def _build_stats_row(self, lay):
        wrap = QFrame(); grid = QGridLayout(wrap); grid.setSpacing(20); grid.setContentsMargins(0, 0, 0, 0)
        cfg = [
            ("Active Threats", "🛡️", "#e74c3c"),
            ("System Status",  "⚡", "#2ecc71"),
            ("Total Alerts",  "🔔", "#f1c40f"),
            ("Last Scan",      "🔄", "#3498db"),
        ]
        for col, (title, emo, colr) in enumerate(cfg):
            card = _StatCard(title, emo, colr); self._cards[title] = card
            grid.addWidget(card, 0, col); grid.setColumnStretch(col, 1)
        lay.addWidget(wrap)

    def _build_charts_row(self, lay):
        row_fr = QFrame(); row_lay = QHBoxLayout(row_fr); row_lay.setSpacing(20); row_lay.setContentsMargins(0, 0, 0, 0)
        # wrappers keep the charts inside white rounded boxes
        def _wrapper(widget):
            f = QFrame(); f.setStyleSheet("background:#fff;border:1px solid #e0e0e0;border-radius:8px;")
            fl = QVBoxLayout(f); fl.setContentsMargins(12, 12, 12, 12); fl.addWidget(widget)
            return f
        self.alert_chart = _AlertTrendChart(); row_lay.addWidget(_wrapper(self.alert_chart), 1)
        self.health_chart = _SystemHealthChart(); row_lay.addWidget(_wrapper(self.health_chart), 1)
        lay.addWidget(row_fr, 1)

    def _build_soar_status(self, lay):
        self.soar_box = QFrame(); self.soar_box.setStyleSheet("background:#fff;border:1px solid #e0e0e0;border-radius:8px;")
        box_lay = QVBoxLayout(self.soar_box); box_lay.setContentsMargins(20, 20, 20, 20); box_lay.setSpacing(14)
        head = QHBoxLayout(); ttl = QLabel("SOAR Automation Status"); ttl.setStyleSheet("font:600 16px;color:#2c3e50;"); head.addWidget(ttl); head.addStretch()
        vw = QPushButton("View Workflows"); vw.setCursor(Qt.CursorShape.PointingHandCursor)
        vw.clicked.connect(lambda: self.router and self.router.show("workflows"))
        vw.setStyleSheet("""QPushButton{background:#3498db;color:#fff;border:none;border-radius:4px;padding:8px 16px;font-weight:600;}
                           QPushButton:hover{background:#2980b9;} QPushButton:pressed{background:#1f6da9;}""")
        head.addWidget(vw); box_lay.addLayout(head)
        # grid reused every update
        self.workflow_grid = QGridLayout(); self.workflow_grid.setHorizontalSpacing(18); self.workflow_grid.setVerticalSpacing(12)
        box_lay.addLayout(self.workflow_grid)
        lay.addWidget(self.soar_box)

    # ---------------------------------------------------------------- live update
    def _update_from_data(self, data: dict):
        # ① stat cards
        mapping = {
            "active_threats": "Active Threats",
            "system_status":  "System Status",
            "total_alerts":   "Total Alerts",
            "last_scan":      "Last Scan",
        }
        for key, title in mapping.items():
            if key in data and title in self._cards:
                self._cards[title].update_value(data[key])
        # ② charts
        self.alert_chart.update_data(data.get("alert_trend", {}))
        self.health_chart.update_data(data.get("system_health", {}))
        # ③ SOAR status grid
        self._rebuild_workflow_grid(data.get("workflows", {}))

    # ---------------------------------------------------------------- helpers
    def _rebuild_workflow_grid(self, workflows: dict):
        # clear old items
        while self.workflow_grid.count():
            w = self.workflow_grid.takeAt(0).widget()
            if w: w.deleteLater()
        self._workflow_items.clear()
        if not workflows:
            lbl = QLabel("No workflows configured"); lbl.setStyleSheet("color:#7f8c8d;font:12px;")
            self.workflow_grid.addWidget(lbl, 0, 0)
            return
        # add fresh
        for idx, (name, info) in enumerate(workflows.items()):
            row, col = divmod(idx, 2)
            frame = QFrame(); frame.setStyleSheet("background:#f8f9fa;border-radius:6px;")
            fr_lay = QHBoxLayout(frame); fr_lay.setContentsMargins(14, 10, 14, 10)
            dot = QFrame(); dot.setFixedSize(12, 12); fr_lay.addWidget(dot)
            nm = QLabel(name); nm.setStyleSheet("font-weight:500;"); fr_lay.addWidget(nm); fr_lay.addStretch()
            st = QLabel(); fr_lay.addWidget(st)
            self.workflow_grid.addWidget(frame, row, col)
            self._workflow_items[name] = (dot, st)
            self._update_workflow_item(name, info)
        for i in range(2):
            self.workflow_grid.setColumnStretch(i, 1)

    def _update_workflow_item(self, name: str, info: dict):
        dot, lbl = self._workflow_items[name]
        status = info.get("status", "Unknown")
        upd = info.get("updated")
        when = datetime.fromtimestamp(upd).strftime("%Y‑%m‑%d %H:%M") if isinstance(upd, (int, float)) else ""
        txt = f"{status}  {when}".strip()
        lbl.setText(txt)
        col = self._status_color(status)
        lbl.setStyleSheet(f"color:{col};font-weight:600;")
        dot.setStyleSheet(f"background:{col};border-radius:6px;")

    @staticmethod
    def _status_color(st: str) -> str:
        s = (st or "").lower()
        if st in ("active", "running", "enabled", "test"):
            return "#2ecc71"  # green
        if st in ("scheduled", "pending"):
            return "#3498db"  # blue
        if st in ("failed", "error"):
            return "#e74c3c"  # red
        return "#95a5a6"  # grey (idle / unknown)

    # ---------------------------------------------------------------- cleanup
    def closeEvent(self, ev):
        if self._worker and self._worker.isRunning():
            self._worker.stop(); self._worker.wait(800)
        super().closeEvent(ev)
