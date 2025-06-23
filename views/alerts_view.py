from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                             QTableWidgetItem, QPushButton, QComboBox, QLabel,
                             QHeaderView, QSplitter, QFrame, QTextEdit, QSpacerItem,
                             QSizePolicy)
from PyQt6.QtCore import Qt, pyqtSlot, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QIcon, QFont, QBrush
import logging

from utils import AlertManager

logger = logging.getLogger(__name__)


class AlertsView(QWidget):
    """
    Alert view component for displaying security alerts from Wazuh.
    Completely reimplemented using PyQt6 for the Guardian SOAR platform.
    """
    VERSION = "3.0"  # Updated version for PyQt6 implementation

    # Signal for when a filter is changed - Controller can connect to this
    filter_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        logger.info(f"AlertsView {self.VERSION} initialized")
        self.view_id = id(self)
        self.alert_manager = AlertManager.get_instance()  # NEW
        self.alert_manager.alert_acknowledged.connect(  # NEW
            self._on_alert_acknowledged, Qt.ConnectionType.QueuedConnection)
        print(f"Creating AlertsView with ID: {self.view_id}")

        self.controller = None
        self.alert_manager = None
        self.selected_alert_id = None
        self.raw_alerts_list = []

        # CRITICAL: Set appropriate size policies
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Initialize UI
        self.setup_ui()

        # Ensure visibility
        self.show()

        # Replace the debounce setup with:
        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        # Directly call _apply_filters when the timer fires
        self.filter_timer.timeout.connect(self._apply_filters)

        # Add size update method
        QTimer.singleShot(100, self.update_size_to_parent)

        # Debug prints
        print(f"AlertsView initialization complete.")
        print(f"Table initialized: {hasattr(self, 'alerts_table')}")
        if hasattr(self, 'alerts_table'):
            print(f"Table columns: {self.alerts_table.columnCount()}")
        print(f"Alert count label initialized: {hasattr(self, 'alert_count')}")

    def update_size_to_parent(self):
        """Force the view to update its size to match the parent"""
        if self.parent() and self.parent().size().isValid():
            parent_size = self.parent().size()
            if parent_size.width() > 0 and parent_size.height() > 0:
                self.resize(parent_size)
                print(f"Updated alerts view size to match parent: {parent_size.width()}x{parent_size.height()}")

                # Update layout
                self.layout().update()
                self.updateGeometry()

    def resizeEvent(self, event):
        """Handle resize events correctly"""
        super().resizeEvent(event)

        size = self.size()
        print(f"AlertsView resize: {size.width()}x{size.height()}")

        # Update layout spacing based on size
        if size.width() < 600:
            self.main_layout.setContentsMargins(10, 10, 10, 10)
            self.main_layout.setSpacing(10)
        else:
            self.main_layout.setContentsMargins(15, 15, 15, 15)
            self.main_layout.setSpacing(15)

        # Update splitter ratio based on available height
        if hasattr(self, 'content_splitter'):
            total_height = size.height() - 150  # Account for header and filters
            if total_height > 0:
                # 70% for table, 30% for details is a good ratio
                self.content_splitter.setSizes([int(total_height * 0.7), int(total_height * 0.3)])

    def setup_ui(self):
        """Set up the main UI components"""
        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        # Create header section
        self.create_header()

        # Create filter section
        self.create_filters()

        # Create splitter for alerts table and details panel
        self.content_splitter = QSplitter(Qt.Orientation.Vertical)
        self.content_splitter.setChildrenCollapsible(False)

        # IMPORTANT: Set splitter size policy
        self.content_splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Create alerts table
        self.create_alerts_table()

        # Create details panel
        self.create_details_panel()

        # Add splitter to main layout with stretch factor
        self.main_layout.addWidget(self.content_splitter, 1)  # 1 = stretch factor

        # … at the end of setup_ui(), before apply_styles()
        self.create_pagination_controls()

        # Apply styles
        self.apply_styles()

    def create_header(self):
        """Create the header section with title and action buttons"""
        header_layout = QHBoxLayout()

        # Title with alert count badge
        title_layout = QHBoxLayout()
        title_label = QLabel("Security Alerts")
        title_label.setObjectName("viewTitle")
        title_layout.addWidget(title_label)

        self.alert_count = QLabel("0")
        self.alert_count.setObjectName("alertCountBadge")
        self.alert_count.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.alert_count.setMinimumWidth(30)
        title_layout.addWidget(self.alert_count)
        title_layout.addStretch()

        header_layout.addLayout(title_layout, 1)

        # Action buttons
        actions_layout = QHBoxLayout()

        self.acknowledge_btn = QPushButton("Acknowledge")
        self.acknowledge_btn.setObjectName("acknowledgeButton")
        self.acknowledge_btn.clicked.connect(self.acknowledge_alert)
        self.acknowledge_btn.setEnabled(False)  # Disabled until an alert is selected
        actions_layout.addWidget(self.acknowledge_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("refreshButton")
        refresh_btn.clicked.connect(self.refresh_alerts)
        actions_layout.addWidget(refresh_btn)

        header_layout.addLayout(actions_layout)

        self.main_layout.addLayout(header_layout)

    def create_filters(self):
        """Create the filter section for alert filtering"""
        filter_frame = QFrame()
        filter_frame.setObjectName("filterFrame")
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(15, 10, 15, 10)

        # Severity filter
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentIndexChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.severity_filter)

        filter_layout.addSpacing(20)

        # Status filter
        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Active", "Acknowledged"])
        self.status_filter.currentIndexChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.status_filter)

        filter_layout.addSpacing(20)

        # Time range filter
        filter_layout.addWidget(QLabel("Time Range:"))
        self.time_filter = QComboBox()
        self.time_filter.addItems(["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])
        self.time_filter.currentIndexChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.time_filter)

        # Add stretch to push everything to the left
        filter_layout.addStretch(1)

        self.main_layout.addWidget(filter_frame)

    def on_filter_changed(self):
        """
        Restart debounce timer on any filter widget change.
        After 300ms of no further changes, filters will be applied.
        """
        if self.filter_timer.isActive():
            self.filter_timer.stop()
        self.filter_timer.start(300)

    def _emit_filter_changed(self):
        print("Safely emitting filter_changed signal")
        self.filter_changed.emit()

    def create_alerts_table(self):
        """Create the alerts table widget"""
        print("Creating alerts table...")
        table_frame = QFrame()
        table_frame.setObjectName("tableContainer")
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)

        # Create table widget
        self.alerts_table = QTableWidget()
        print(f"  Table widget created: {self.alerts_table}")
        self.alerts_table.setObjectName("alertsTable")

        # Set proper size policy
        self.alerts_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Configure table properties
        self.alerts_table.setColumnCount(5)
        print(f"  Set column count to 5")
        self.alerts_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Severity", "Description", "Location"])
        print(f"  Set header labels")

        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.verticalHeader().setVisible(False)

        # Configure column widths
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.alerts_table.horizontalHeader().setStretchLastSection(True)

        # Column widths
        self.alerts_table.setColumnWidth(0, 70)  # ID
        self.alerts_table.setColumnWidth(1, 170)  # Timestamp
        self.alerts_table.setColumnWidth(2, 100)  # Severity
        self.alerts_table.setColumnWidth(3, 300)  # Description

        # Connect selection signal
        self.alerts_table.itemSelectionChanged.connect(self.on_alert_selected)
        print(f"  Connected selection signal")

        table_layout.addWidget(self.alerts_table)
        print(f"  Added table to layout")
        self.content_splitter.addWidget(table_frame)
        print(f"  Added frame to splitter")
        print("Alerts table creation complete")

    def create_details_panel(self):
        """Create the alert details panel"""
        details_frame = QFrame()
        details_frame.setObjectName("detailsPanel")

        # Set proper size policy, but allow it to be smaller
        details_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        details_frame.setMinimumHeight(150)  # Set reasonable minimum height

        details_layout = QVBoxLayout(details_frame)

        # Details header
        details_header = QLabel("Alert Details")
        details_header.setObjectName("detailsHeader")
        details_layout.addWidget(details_header)

        # Details text area
        self.details_text = QTextEdit()
        self.details_text.setObjectName("detailsText")
        self.details_text.setReadOnly(True)
        self.details_text.setText("Select an alert to view details")

        # Set minimum height for details text
        self.details_text.setMinimumHeight(100)

        details_layout.addWidget(self.details_text)

        self.content_splitter.addWidget(details_frame)

    def create_pagination_controls(self):
        """Create Prev/Next buttons, page‐size selector, and page info."""
        pag_frame = QFrame()
        pag_layout = QHBoxLayout(pag_frame)
        pag_layout.setContentsMargins(0, 0, 0, 0)
        pag_layout.setSpacing(10)

        # Prev/Next Buttons
        self.prev_btn = QPushButton("◀ Prev")
        self.next_btn = QPushButton("Next ▶")
        self.prev_btn.setEnabled(False)
        self.next_btn.setEnabled(False)
        pag_layout.addWidget(self.prev_btn)
        pag_layout.addWidget(self.next_btn)

        # Spacer
        pag_layout.addStretch()

        # Page‐size selector
        pag_layout.addWidget(QLabel("Page size:"))
        self.page_size_combo = QComboBox()
        self.page_size_combo.addItems(["100", "250", "500", "1000"])
        pag_layout.addWidget(self.page_size_combo)

        # Page info label
        self.page_label = QLabel("Page 0/0")
        pag_layout.addWidget(self.page_label)

        # Hook up
        self.prev_btn.clicked.connect(lambda: self.controller.prev_page())
        self.next_btn.clicked.connect(lambda: self.controller.next_page())
        self.page_size_combo.currentTextChanged.connect(
            lambda txt: self.controller.set_limit(int(txt))
        )

        # Add to main layout below the splitter
        self.main_layout.addWidget(pag_frame)

    def update_pagination_info(self, offset, limit, total):
        """Display current page / total pages and toggle Prev/Next."""
        if limit <= 0:
            return
        page = offset // limit + 1
        pages = ((total - 1) // limit) + 1
        self.page_label.setText(f"Page {page}/{pages} ({total} alerts)")
        self.prev_btn.setEnabled(offset > 0)
        self.next_btn.setEnabled(offset + limit < total)

    def apply_styles(self):
        """Apply stylesheet to the view"""
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
            }

            #viewTitle {
                font-size: 24px;
                font-weight: bold;
                color: #333;
            }

            #alertCountBadge {
                background-color: #e74c3c;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 15px;
                min-width: 30px;
                min-height: 30px;
                padding: 5px;
                margin-left: 10px;
            }

            #acknowledgeButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }

            #acknowledgeButton:hover {
                background-color: #27ae60;
            }

            #acknowledgeButton:disabled {
                background-color: #95a5a6;
            }

            #refreshButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }

            #refreshButton:hover {
                background-color: #2980b9;
            }

            #filterFrame {
                background-color: #f8f9fa;
                border-radius: 6px;
                border: 1px solid #e9ecef;
            }

            QComboBox {
                border: 1px solid #ced4da;
                border-radius: 4px;
                padding: 5px;
                min-width: 120px;
            }

            #tableContainer {
                border: 1px solid #e9ecef;
                border-radius: 6px;
                background-color: white;
            }

            #alertsTable {
                border: none;
                gridline-color: #e9ecef;
            }

            #alertsTable::item {
                padding: 5px;
            }

            #alertsTable::item:selected {
                background-color: #e8f4fc;
                color: #333;
            }

            #alertsTable QHeaderView::section {
                background-color: #f8f9fa;
                border: none;
                border-bottom: 1px solid #e9ecef;
                padding: 8px;
                font-weight: bold;
            }

            #detailsPanel {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
            }

            #detailsHeader {
                font-size: 16px;
                font-weight: bold;
                padding: 5px 0;
            }

            #detailsText {
                border: 1px solid #e9ecef;
                border-radius: 4px;
                background-color: white;
                padding: 10px;
            }
        """)

    def set_controller(self, controller):
        """
        Assign the controller and trigger the first data fetch.
        Page-size combo and filter widgets are already hooked up.
        """
        self.controller = controller
        # set page-size dropdown to controller default
        self.page_size_combo.setCurrentText(str(getattr(controller, 'limit', 250)))
        # initial load of alerts
        controller.set_view(self)

    def set_alert_manager(self, alert_manager):
        """Set the alert manager for this view"""
        self.alert_manager = alert_manager

    def update_alerts(self, alerts):
        """Controller → new page has arrived."""
        self.filter_timer.stop()  # ← cancel pending debounce job
        self.raw_alerts_list = alerts  # ← single source of truth
        self._render_alerts(alerts)

        self.update_pagination_info(
            getattr(self.controller, 'offset', 0),
            getattr(self.controller, 'limit', 0),
            getattr(self.controller, 'total', len(alerts))
        )

    def _on_alert_acknowledged(self, alert_id: str):
        """Instantly hide the acknowledged alert without a full refresh."""
        for row in range(self.alerts_table.rowCount() - 1, -1, -1):
            cell = self.alerts_table.item(row, 0)
            if cell and cell.data(Qt.ItemDataRole.UserRole).get('id') == alert_id:
                self.alerts_table.removeRow(row)
        self.alert_count.setText(str(self.alerts_table.rowCount()))

    def _render_alerts(self, alerts):
        """
        Draw the given alerts list into the table without altering raw_alerts_list.
        """
        self.alerts_table.blockSignals(True)
        self.alerts_table.clearContents()
        self.alerts_table.setRowCount(len(alerts))

        for row, alert in enumerate(alerts):
            # ID column
            id_text = alert.get('id', '')
            if len(id_text) > 20:
                id_text = id_text[:20] + "…"
            id_item = QTableWidgetItem(id_text)
            id_item.setData(Qt.ItemDataRole.UserRole, alert)
            self.alerts_table.setItem(row, 0, id_item)

            # Timestamp column
            ts_item = QTableWidgetItem(alert.get('timestamp', ''))
            self.alerts_table.setItem(row, 1, ts_item)

            # Severity column with color
            sev = alert.get('severity', '').capitalize()
            sev_item = QTableWidgetItem(sev)
            color_map = {
                'Critical': '#e74c3c',
                'High': '#e67e22',
                'Medium': '#f39c12',
                'Low': '#27ae60'
            }
            sev_item.setForeground(QBrush(QColor(color_map.get(sev, '#27ae60'))))
            self.alerts_table.setItem(row, 2, sev_item)

            # Description column
            desc_item = QTableWidgetItem(alert.get('description', ''))
            self.alerts_table.setItem(row, 3, desc_item)

            # Location column
            loc_item = QTableWidgetItem(alert.get('location', ''))
            self.alerts_table.setItem(row, 4, loc_item)

        self.alert_count.setText(str(len(alerts)))
        self.alerts_table.resizeColumnsToContents()
        self.alerts_table.blockSignals(False)

    def _apply_filters(self):
        """Debounced handler – filter current page only."""
        if not hasattr(self, 'raw_alerts_list'):
            return

        filtered = self.controller.apply_filters(self.raw_alerts_list)
        self._render_alerts(filtered)

        total = len(self.raw_alerts_list)
        shown = len(filtered)
        self.page_label.setText(f"{shown} of {total} alerts (this page)")

    def refresh_alerts(self):
        """Manually refresh alerts"""
        print("Manual refresh triggered")
        if self.controller:
            self.controller.update_alerts()

    def on_alert_selected(self):
        """Handle selection of an alert in the table"""
        selected_items = self.alerts_table.selectedItems()
        if not selected_items:
            self.details_text.setText("Select an alert to view details")
            self.acknowledge_btn.setEnabled(False)
            self.selected_alert_id = None
            return

        # Get the selected row
        row = selected_items[0].row()

        # Get alert data from the ID cell
        id_item = self.alerts_table.item(row, 0)
        alert = id_item.data(Qt.ItemDataRole.UserRole)
        if not alert:
            return

        # IMPORTANT: Store the FULL alert ID, not truncated
        self.selected_alert_id = alert.get('id', '')

        # Important: Check immediately if already acknowledged
        is_acknowledged = False
        if self.alert_manager:
            is_acknowledged = self.alert_manager.is_acknowledged(self.selected_alert_id)
            # Only enable acknowledge button if not already acknowledged
            self.acknowledge_btn.setEnabled(not is_acknowledged)

        # Format details text
        details = (
            f"<h3>Alert Details</h3>"
            f"<p><b>ID:</b> {alert.get('id', 'N/A')}</p>"
            f"<p><b>Timestamp:</b> {alert.get('timestamp', 'N/A')}</p>"
            f"<p><b>Severity:</b> {alert.get('severity', 'N/A')}</p>"
            f"<p><b>Description:</b> {alert.get('description', 'N/A')}</p>"
            f"<p><b>Location:</b> {alert.get('location', 'N/A')}</p>"
            f"<p><b>Source:</b> {alert.get('source', 'N/A')}</p>"
        )

        # Add raw data if available
        if 'raw_data' in alert:
            details += f"<p><b>Raw Data:</b> <pre>{alert.get('raw_data', '')}</pre></p>"

        # Add acknowledgment status
        if self.alert_manager:
            is_acknowledged = self.alert_manager.is_acknowledged(self.selected_alert_id)
            status = "Acknowledged" if is_acknowledged else "Active"
            status_color = "#27ae60" if is_acknowledged else "#e74c3c"
            details += f"<p><b>Status:</b> <span style='color: {status_color};'>{status}</span></p>"

            # Enable acknowledge button only for unacknowledged alerts
            self.acknowledge_btn.setEnabled(not is_acknowledged)

        # Update details text
        self.details_text.setHtml(details)

    def acknowledge_alert(self):
        """Acknowledge the selected alert"""
        if not self.selected_alert_id or not self.alert_manager:
            print("No selected alert or alert manager not available")
            return

        print(f"Acknowledging alert: {self.selected_alert_id}")

        try:
            # Disable button to prevent double-clicks
            self.acknowledge_btn.setEnabled(False)

            # Use a try/finally to ensure button is re-enabled
            try:
                # Acknowledge through alert manager
                result = self.alert_manager.add_acknowledged_alert(self.selected_alert_id)
                print(f"Acknowledge result: {result}")

                # Don't manually refresh - let signals handle it
                # Re-enable after a delay to prevent rapid clicks
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(1000, lambda: self.acknowledge_btn.setEnabled(True))

            except Exception as e:
                print(f"Error in acknowledge operation: {e}")
                import traceback
                traceback.print_exc()

                # Re-enable button in case of error
                self.acknowledge_btn.setEnabled(True)

        except Exception as outer_e:
            print(f"Outer exception in acknowledge_alert: {outer_e}")
            import traceback
            traceback.print_exc()

            # Ensure button is re-enabled
            self.acknowledge_btn.setEnabled(True)

