# views/incident_history_view.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTableWidget, QTableWidgetItem, QComboBox,
                             QLineEdit, QLabel, QGroupBox, QDateEdit,
                             QCheckBox, QSplitter, QTextEdit, QTabWidget,
                             QHeaderView, QMessageBox, QFileDialog,
                             QProgressDialog, QMenu)
from PyQt6.QtCore import Qt, QDate, pyqtSignal, QTimer, QThread, pyqtSlot
from PyQt6.QtGui import QFont, QIcon, QAction
from datetime import datetime, timedelta
import json
import re

# ─── Hard-coded Shuffle alert ───────────────────────────────────────────────────
HARD_CODED_INCIDENTS = [
    {
        "Date": "2025-06-22 12:54",
        "Incident": "Malicious Actor Detected",
        "Action": "Alert Raised",
        "Workflow": "AV Scan",
        "CVE": "",
        "Severity": "High",
        "Details": """{
  "timestamp": "2025-06-22T12:54:34.655+0300",
  "rule": {
    "level": 12,
    "description": "VirusTotal: Alert - /root/eicar.com - 65 engines detected this file",
    "id": "87105",
    "mitre": {
      "id": ["T1203"],
      "tactic": ["Execution"],
      "technique": ["Exploitation for Client Execution"]
    },
    "firedtimes": 1,
    "mail": true,
    "groups": ["virustotal"],
    "pci_dss": ["10.6.1","11.4"],
    "gdpr": ["IV_35.7.d"]
  },
  "agent": {"id": "000","name": "guardian"},
  "manager": {"name": "guardian"},
  "id": "1750586074.2278616",
  "decoder": {"name": "json"},
  "data": {
    "virustotal": {
      "found": "1",
      "malicious": "1",
      "source": {
        "alert_id": "1750586070.2277726",
        "file": "/root/eicar.com",
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "sha1": "3395856ce81f2b7382dee72602f798b642f14140"
      },
      "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
      "scan_date": "2025-06-22 09:46:25",
      "positives": "65",
      "total": "69",
      "permalink": "https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/detection/f-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1750585585"
    },
    "integration": "virustotal"
  },
  "location": "virustotal"
}"""
    }
]


class IncidentHistoryView(QWidget):
    # Signals
    refresh_requested = pyqtSignal()
    export_requested = pyqtSignal(str, list)  # format type, filtered incidents
    generate_report_requested = pyqtSignal(list)  # filtered incidents
    fetch_cve_details_requested = pyqtSignal(str)  # CVE ID
    filter_requested = pyqtSignal(str, str)  # filter_type, filter_value

    def __init__(self, parent=None):
        super().__init__(parent)

        # Initialize data structures
        self.current_incidents = []
        self.filtered_incidents = []
        self.cve_cache = {}
        self.current_selected_index = -1  # Track current selection

        # Initialize filter timer for debouncing
        self.filter_timer = QTimer()
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self._apply_delayed_filter)
        self.pending_filter_update = False

        # Initialize UI element references
        self.incident_table = None
        self.details_text = None
        self.cve_info_text = None
        self.analysis_text = None
        self.stats_label = None
        self.filter_status_label = None
        self.cve_stats_label = None
        self.status_indicator = None
        self.status_label = None
        self.refresh_btn = None

        # Filter widgets
        self.date_from = None
        self.date_to = None
        self.quick_filter_combo = None
        self.workflow_filter = None
        self.search_box = None
        self.incident_filter = None
        self.action_filter = None
        self.cve_filter = None
        self.severity_filter = None
        self.regex_mode = None
        self.clear_filters_btn = None

        # Action buttons
        self.export_csv_btn = None
        self.export_json_btn = None
        self.fetch_cve_btn = None
        self.generate_report_btn = None

        # Tab widget
        self.tab_widget = None

        # Initialize UI
        try:
            self.init_ui()
            # Load the hard-coded incident into the table
            self.update_incidents(HARD_CODED_INCIDENTS)

        except Exception as e:
            print(f"Error initializing UI: {e}")
            import traceback
            traceback.print_exc()

        # Defer post-initialization
        QTimer.singleShot(100, self._post_init)

    def _post_init(self):
        """Post-initialization setup"""
        try:
            if hasattr(self, 'stats_label') and self.stats_label:
                self.update_stats()
        except Exception as e:
            print(f"Error in post-init: {e}")

    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        # Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(10)

        title = QLabel("Incident Response History")
        title.setObjectName("viewTitle")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Status indicator
        status_container = QHBoxLayout()
        status_container.setSpacing(5)

        self.status_indicator = QLabel("●")
        self.status_indicator.setObjectName("statusIndicator")
        status_container.addWidget(self.status_indicator)

        self.status_label = QLabel("Not Connected")
        status_container.addWidget(self.status_label)

        header_layout.addLayout(status_container)
        header_layout.addSpacing(20)

        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("primaryButton")
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        header_layout.addWidget(self.refresh_btn)

        layout.addLayout(header_layout)
        layout.addSpacing(10)

        # Main content area with splitter
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top section: Filters and Table
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(10)

        # Filter section
        filter_group = QGroupBox("Advanced Filters")
        filter_layout = QVBoxLayout()
        filter_layout.setSpacing(10)
        filter_layout.setContentsMargins(10, 10, 10, 10)

        # Row 1: Date range and quick filters
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        # Date range filter
        date_container = QHBoxLayout()
        date_container.setSpacing(5)

        date_container.addWidget(QLabel("From:"))
        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate.currentDate().addDays(-30))
        self.date_from.setDisplayFormat("yyyy-MM-dd")
        self.date_from.setFixedWidth(120)
        self.date_from.dateChanged.connect(self.request_filter_update)
        date_container.addWidget(self.date_from)

        date_container.addSpacing(10)
        date_container.addWidget(QLabel("To:"))
        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        self.date_to.setDisplayFormat("yyyy-MM-dd")
        self.date_to.setFixedWidth(120)
        self.date_to.dateChanged.connect(self.request_filter_update)
        date_container.addWidget(self.date_to)

        row1.addLayout(date_container)
        row1.addSpacing(20)

        # Quick date filters
        self.quick_filter_combo = QComboBox()
        self.quick_filter_combo.setFixedWidth(150)
        self.quick_filter_combo.addItems([
            "Custom Range", "Today", "Last 7 Days",
            "Last 30 Days", "Last 90 Days", "This Year"
        ])
        self.quick_filter_combo.currentTextChanged.connect(self.apply_quick_date_filter)
        row1.addWidget(self.quick_filter_combo)

        row1.addStretch()

        # Workflow filter
        workflow_container = QHBoxLayout()
        workflow_container.setSpacing(5)
        workflow_container.addWidget(QLabel("Workflow:"))
        self.workflow_filter = QComboBox()
        self.workflow_filter.setMinimumWidth(150)
        self.workflow_filter.addItem("All Workflows")
        self.workflow_filter.currentTextChanged.connect(self.request_filter_update)
        workflow_container.addWidget(self.workflow_filter)

        row1.addLayout(workflow_container)

        filter_layout.addLayout(row1)

        # Row 2: Search, incident type, and action
        row2 = QHBoxLayout()
        row2.setSpacing(10)

        # Search box
        search_container = QHBoxLayout()
        search_container.setSpacing(5)
        search_container.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search in all fields (supports regex)...")
        self.search_box.setMinimumWidth(250)
        self.search_box.textChanged.connect(self.request_filter_update)
        search_container.addWidget(self.search_box)

        row2.addLayout(search_container)
        row2.addSpacing(20)

        # Incident type filter
        type_container = QHBoxLayout()
        type_container.setSpacing(5)
        type_container.addWidget(QLabel("Type:"))
        self.incident_filter = QComboBox()
        self.incident_filter.setMinimumWidth(150)
        self.incident_filter.addItem("All Types")
        self.incident_filter.currentTextChanged.connect(self.request_filter_update)
        type_container.addWidget(self.incident_filter)

        row2.addLayout(type_container)

        # Action filter
        action_container = QHBoxLayout()
        action_container.setSpacing(5)
        action_container.addWidget(QLabel("Action:"))
        self.action_filter = QComboBox()
        self.action_filter.setMinimumWidth(150)
        self.action_filter.addItem("All Actions")
        self.action_filter.currentTextChanged.connect(self.request_filter_update)
        action_container.addWidget(self.action_filter)

        row2.addLayout(action_container)
        row2.addStretch()

        filter_layout.addLayout(row2)

        # Row 3: CVE, Severity, and options
        row3 = QHBoxLayout()
        row3.setSpacing(10)

        # CVE filter
        cve_container = QHBoxLayout()
        cve_container.setSpacing(5)
        cve_container.addWidget(QLabel("CVE:"))
        self.cve_filter = QLineEdit()
        self.cve_filter.setPlaceholderText("CVE-YYYY-NNNNN")
        self.cve_filter.setFixedWidth(150)
        self.cve_filter.textChanged.connect(self.request_filter_update)
        cve_container.addWidget(self.cve_filter)

        row3.addLayout(cve_container)

        # Severity filter
        severity_container = QHBoxLayout()
        severity_container.setSpacing(5)
        severity_container.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.setFixedWidth(120)
        self.severity_filter.addItems([
            "All Severities", "Critical", "High", "Medium", "Low"
        ])
        self.severity_filter.currentTextChanged.connect(self.request_filter_update)
        severity_container.addWidget(self.severity_filter)

        row3.addLayout(severity_container)

        # Regex mode checkbox
        self.regex_mode = QCheckBox("Regex Mode")
        row3.addWidget(self.regex_mode)
        self.regex_mode.toggled.connect(self.request_filter_update)

        row3.addStretch()

        # Clear filters button
        self.clear_filters_btn = QPushButton("Clear All Filters")
        self.clear_filters_btn.setObjectName("primaryButton")
        self.clear_filters_btn.setFixedWidth(120)
        self.clear_filters_btn.clicked.connect(self.clear_filters)
        row3.addWidget(self.clear_filters_btn)

        filter_layout.addLayout(row3)

        filter_group.setLayout(filter_layout)
        top_layout.addWidget(filter_group)

        # Incident table
        self.incident_table = QTableWidget()
        self.incident_table.setColumnCount(6)
        self.incident_table.setHorizontalHeaderLabels([
            "Date", "Incident Type", "Action Taken", "Workflow", "CVE", "Severity"
        ])

        # make the table read-only
        self.incident_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # Set table properties
        self.incident_table.setAlternatingRowColors(True)
        self.incident_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.incident_table.horizontalHeader().setStretchLastSection(False)
        self.incident_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.incident_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.incident_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.incident_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.incident_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.incident_table.setSortingEnabled(True)
        self.incident_table.itemSelectionChanged.connect(self.on_selection_changed)

        # Add context menu to table
        self.incident_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.incident_table.customContextMenuRequested.connect(self.show_context_menu)

        top_layout.addWidget(self.incident_table)

        # Stats bar
        stats_widget = QWidget()
        stats_widget.setObjectName("statsBar")
        stats_layout = QHBoxLayout(stats_widget)
        stats_layout.setContentsMargins(10, 5, 10, 5)

        self.stats_label = QLabel("No incidents loaded")
        self.stats_label.setStyleSheet("QLabel { font-weight: bold; }")
        stats_layout.addWidget(self.stats_label)

        # Add filter status
        self.filter_status_label = QLabel("")
        self.filter_status_label.setStyleSheet("QLabel { color: #666; }")
        stats_layout.addWidget(self.filter_status_label)

        stats_layout.addStretch()

        # CVE stats
        self.cve_stats_label = QLabel("")
        self.cve_stats_label.setStyleSheet("QLabel { color: #666; }")
        stats_layout.addWidget(self.cve_stats_label)

        top_layout.addWidget(stats_widget)

        splitter.addWidget(top_widget)

        # Bottom section: Details and Actions
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(10)

        # Tab widget for details and report
        self.tab_widget = QTabWidget()

        # Details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.tab_widget.addTab(self.details_text, "Incident Details")

        # CVE Info tab
        self.cve_info_text = QTextEdit()
        self.cve_info_text.setReadOnly(True)
        self.tab_widget.addTab(self.cve_info_text, "CVE Information")

        bottom_layout.addWidget(self.tab_widget)

        # Action buttons
        action_widget = QWidget()
        action_widget.setObjectName("actionPanel")
        action_layout = QHBoxLayout(action_widget)
        action_layout.setContentsMargins(10, 10, 10, 10)
        action_layout.setSpacing(10)

        # Export buttons
        self.export_csv_btn = QPushButton("📄 Export CSV")
        self.export_csv_btn.setObjectName("exportButton")
        self.export_csv_btn.clicked.connect(lambda: self.export_with_feedback("csv"))
        action_layout.addWidget(self.export_csv_btn)

        self.export_json_btn = QPushButton("📋 Export JSON")
        self.export_json_btn.setObjectName("exportButton")
        self.export_json_btn.clicked.connect(lambda: self.export_with_feedback("json"))
        action_layout.addWidget(self.export_json_btn)

        action_layout.addStretch()

        self.generate_report_btn = QPushButton("📊 Generate Report")
        self.generate_report_btn.setObjectName("primaryButton")
        self.generate_report_btn.clicked.connect(self.on_generate_report)
        action_layout.addWidget(self.generate_report_btn)

        bottom_layout.addWidget(action_widget)

        splitter.addWidget(bottom_widget)

        # Set splitter sizes (60% top, 40% bottom)
        splitter.setSizes([600, 400])

        layout.addWidget(splitter)

        self.setLayout(layout)

        # Apply stylesheet
        self.apply_stylesheet()

    def apply_stylesheet(self):
        """Apply the complete stylesheet"""
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #ffffff;
            }

            /* Title styling */
            QLabel#viewTitle {
                font-size: 24px;
                font-weight: bold;
                color: #333;
            }

            /* Status indicator */
            QLabel#statusIndicator {
                font-size: 16px;
            }

            /* Filter section */
            QGroupBox {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 5px 0 5px;
                color: #333;
                background-color: #f8f9fa;
            }

            /* Input controls */
            QComboBox, QLineEdit, QDateEdit {
                border: 1px solid #ced4da;
                border-radius: 4px;
                padding: 6px;
                background-color: white;
                min-height: 25px;
            }

            /* Buttons */
            QPushButton {
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: 600;
                min-height: 32px;
            }

            QPushButton#primaryButton {
                background-color: #3498db;
                color: white;
            }

            QPushButton#primaryButton:hover {
                background-color: #2980b9;
            }

            QPushButton#exportButton {
                background-color: #ecf0f1;
                color: #2c3e50;
            }

            QPushButton#exportButton:hover {
                background-color: #d5dbdb;
            }

            /* Table styling */
            QTableWidget {
                border: 1px solid #e9ecef;
                border-radius: 6px;
                gridline-color: #e9ecef;
                background-color: white;
            }

            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f1f3f4;
            }

            QTableWidget::item:selected {
                background-color: #e8f4fc;
                color: #333;
            }

            /* Tab widget */
            QTabWidget::pane {
                border: 1px solid #e9ecef;
                background-color: white;
                border-radius: 6px;
                border-top-left-radius: 0;
            }

            QTabBar::tab {
                background-color: #e9ecef;
                color: #2c3e50;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }

            QTabBar::tab:selected {
                background-color: white;
                color: #3498db;
                border: 1px solid #e9ecef;
                border-bottom: 1px solid white;
            }

            /* Text areas */
            QTextEdit {
                border: 1px solid #e9ecef;
                border-radius: 4px;
                background-color: white;
                padding: 10px;
            }

            /* Stats bar */
            QWidget#statsBar {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
            }

            /* Action panel */
            QWidget#actionPanel {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
            }
        """)

    def request_filter_update(self):
        """Request a filter update with debouncing"""
        self.pending_filter_update = True
        self.filter_timer.stop()
        self.filter_timer.start(300)  # 300ms delay

    def _apply_delayed_filter(self):
        """Apply filters after delay"""
        if self.pending_filter_update:
            self.pending_filter_update = False
            self.apply_filters()

    def apply_quick_date_filter(self, filter_type):
        """Apply quick date filters"""
        today = QDate.currentDate()

        if filter_type == "Today":
            self.date_from.setDate(today)
            self.date_to.setDate(today)
        elif filter_type == "Last 7 Days":
            self.date_from.setDate(today.addDays(-7))
            self.date_to.setDate(today)
        elif filter_type == "Last 30 Days":
            self.date_from.setDate(today.addDays(-30))
            self.date_to.setDate(today)
        elif filter_type == "Last 90 Days":
            self.date_from.setDate(today.addDays(-90))
            self.date_to.setDate(today)
        elif filter_type == "This Year":
            self.date_from.setDate(QDate(today.year(), 1, 1))
            self.date_to.setDate(today)

    def update_incidents(self, incidents):
        """Update the incident table with new data"""
        self.current_incidents = incidents
        self.update_filter_options()
        self.apply_filters()
        self.update_status("connected")

    def update_filter_options(self):
        """Update filter dropdown options based on current data"""
        # Get unique values
        workflows = set()
        incident_types = set()
        actions = set()

        for incident in self.current_incidents:
            workflows.add(incident.get("Workflow", "Unknown"))
            incident_types.add(incident.get("Incident", "Unknown"))
            actions.add(incident.get("Action", "Unknown"))

        # Update dropdowns while preserving current selections
        self._update_combo_box(self.workflow_filter, "All Workflows", sorted(workflows))
        self._update_combo_box(self.incident_filter, "All Types", sorted(incident_types))
        self._update_combo_box(self.action_filter, "All Actions", sorted(actions))

    def _update_combo_box(self, combo_box, default_item, items):
        """Update combo box items while preserving selection"""
        current_text = combo_box.currentText()
        combo_box.blockSignals(True)
        combo_box.clear()
        combo_box.addItem(default_item)
        for item in items:
            combo_box.addItem(item)

        index = combo_box.findText(current_text)
        if index >= 0:
            combo_box.setCurrentIndex(index)
        combo_box.blockSignals(False)

    def apply_filters(self):
        """Apply all active filters to the incident list"""
        if not hasattr(self, 'current_incidents'):
            return

        # Start with all incidents
        self.filtered_incidents = self.current_incidents.copy()
        active_filters = []

        # Date range filter
        date_from = self.date_from.date().toPyDate()
        date_to = self.date_to.date().toPyDate()

        # Apply date filter
        self.filtered_incidents = [
            inc for inc in self.filtered_incidents
            if self._is_date_in_range(inc.get("Date", ""), date_from, date_to)
        ]

        if self.quick_filter_combo.currentText() != "Custom Range":
            active_filters.append(f"Date: {self.quick_filter_combo.currentText()}")
        else:
            active_filters.append(f"Date: {date_from} to {date_to}")

        # Apply other filters
        filter_mappings = [
            (self.workflow_filter, "All Workflows", "Workflow", "Workflow"),
            (self.incident_filter, "All Types", "Incident", "Type"),
            (self.action_filter, "All Actions", "Action", "Action"),
            (self.severity_filter, "All Severities", "Severity", "Severity")
        ]

        for widget, default, field, label in filter_mappings:
            if widget.currentText() != default:
                filter_value = widget.currentText()
                self.filtered_incidents = [
                    inc for inc in self.filtered_incidents
                    if inc.get(field, "") == filter_value
                ]
                active_filters.append(f"{label}: {filter_value}")

        # CVE filter
        cve_text = self.cve_filter.text().strip()
        if cve_text:
            self.filtered_incidents = [
                inc for inc in self.filtered_incidents
                if cve_text.upper() in inc.get("CVE", "").upper()
            ]
            active_filters.append(f"CVE: {cve_text}")

        # Search filter (with regex support)
        search_text = self.search_box.text().strip()
        if search_text:
            if self.regex_mode.isChecked():
                try:
                    pattern = re.compile(search_text, re.IGNORECASE)
                    self.filtered_incidents = [
                        inc for inc in self.filtered_incidents
                        if self._regex_search_in_incident(inc, pattern)
                    ]
                    active_filters.append(f"Regex: {search_text}")
                except re.error:
                    # Invalid regex, fall back to simple search
                    self.filtered_incidents = [
                        inc for inc in self.filtered_incidents
                        if self._search_in_incident(inc, search_text)
                    ]
                    active_filters.append(f"Search: {search_text}")
            else:
                self.filtered_incidents = [
                    inc for inc in self.filtered_incidents
                    if self._search_in_incident(inc, search_text)
                ]
                active_filters.append(f"Search: {search_text}")

        # Update table
        self.populate_table()

        # Update stats
        self.update_stats()

        # Update filter status
        if active_filters:
            self.filter_status_label.setText(
                f"Active filters: {', '.join(active_filters[:3])}{'...' if len(active_filters) > 3 else ''}")
        else:
            self.filter_status_label.setText("")

    def _is_date_in_range(self, date_str, date_from, date_to):
        """Check if date string is within the specified range"""
        try:
            if not date_str:
                return False

            # Handle different date formats
            if ' ' in date_str:
                date_part = date_str.split(' ')[0]
            else:
                date_part = date_str

            date_obj = datetime.strptime(date_part, "%Y-%m-%d").date()
            return date_from <= date_obj <= date_to
        except Exception:
            return False

    def _search_in_incident(self, incident, search_text):
        """Search for text in all incident fields"""
        search_text = search_text.lower()
        for key, value in incident.items():
            if search_text in str(value).lower():
                return True
        return False

    def _regex_search_in_incident(self, incident, pattern):
        """Search using regex pattern in all incident fields"""
        for key, value in incident.items():
            if pattern.search(str(value)):
                return True
        return False

    def populate_table(self):
        """Populate the table with filtered incidents"""
        self.incident_table.setRowCount(len(self.filtered_incidents))

        for row, incident in enumerate(self.filtered_incidents):
            # Store the original incident index in the first cell's UserRole
            date_item = QTableWidgetItem(incident.get("Date", ""))
            date_item.setData(Qt.ItemDataRole.UserRole, self.current_incidents.index(incident))
            self.incident_table.setItem(row, 0, date_item)

            # Incident Type
            self.incident_table.setItem(row, 1, QTableWidgetItem(incident.get("Incident", "")))

            # Action Taken
            self.incident_table.setItem(row, 2, QTableWidgetItem(incident.get("Action", "")))

            # Workflow
            self.incident_table.setItem(row, 3, QTableWidgetItem(incident.get("Workflow", "")))

            # CVE
            cve_item = QTableWidgetItem(incident.get("CVE", ""))
            if incident.get("CVE"):
                cve_item.setForeground(Qt.GlobalColor.blue)
            self.incident_table.setItem(row, 4, cve_item)

            # Severity
            severity = incident.get("Severity", "Unknown")
            severity_item = QTableWidgetItem(severity)

            # Color code severity
            if severity == "Critical":
                severity_item.setBackground(Qt.GlobalColor.red)
                severity_item.setForeground(Qt.GlobalColor.white)
            elif severity == "High":
                severity_item.setBackground(Qt.GlobalColor.darkRed)
                severity_item.setForeground(Qt.GlobalColor.white)
            elif severity == "Medium":
                severity_item.setBackground(Qt.GlobalColor.darkYellow)
            elif severity == "Low":
                severity_item.setBackground(Qt.GlobalColor.darkGreen)
                severity_item.setForeground(Qt.GlobalColor.white)

            self.incident_table.setItem(row, 5, severity_item)

    def on_selection_changed(self):
        """Handle table selection changes"""
        selected_rows = self.incident_table.selectionModel().selectedRows()

        if selected_rows:
            row = selected_rows[0].row()
            # Get the original incident index from UserRole
            date_item = self.incident_table.item(row, 0)
            original_index = date_item.data(Qt.ItemDataRole.UserRole)

            if original_index is not None:
                self.current_selected_index = original_index
                incident = self.current_incidents[original_index]

                # Update details tab
                self.show_incident_details(incident)

                # Update CVE tab with cached information
                self.show_cve_info(incident, original_index)
        else:
            self.current_selected_index = -1
            self.details_text.clear()
            self.cve_info_text.clear()

    def show_incident_details(self, incident):
        """Display detailed incident information"""
        # Try to parse details if it's JSON
        details_html = ""
        details = incident.get('Details', '')

        try:
            if details and details.strip().startswith('{'):
                details_dict = json.loads(details)
                details_html = self._format_details_as_html(details_dict)
            else:
                details_html = f"<pre>{details}</pre>"
        except:
            details_html = f"<p>{details}</p>"

        html = f"""
        <h3>Incident Details</h3>
        <table style="width: 100%; border-collapse: collapse;">
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 8px; border: 1px solid #ddd; width: 25%;"><b>Date</b></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{incident.get('Date', 'N/A')}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd;"><b>Type</b></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{incident.get('Incident', 'N/A')}</td>
            </tr>
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 8px; border: 1px solid #ddd;"><b>Action Taken</b></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{incident.get('Action', 'N/A')}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd;"><b>Workflow</b></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{incident.get('Workflow', 'N/A')}</td>
            </tr>
            <tr style="background-color: #f0f0f0;">
                <td style="padding: 8px; border: 1px solid #ddd;"><b>CVE</b></td>
                <td style="padding: 8px; border: 1px solid #ddd;">{incident.get('CVE', 'None detected')}</td>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd;"><b>Severity</b></td>
                <td style="padding: 8px; border: 1px solid #ddd;">
                    <span style="color: {self._get_severity_color(incident.get('Severity', 'Unknown'))}; font-weight: bold;">
                        {incident.get('Severity', 'Unknown')}
                    </span>
                </td>
            </tr>
        </table>

        <h4>Additional Information</h4>
        {details_html}
        """
        self.details_text.setHtml(html)

    def _get_severity_color(self, severity):
        """Get color for severity level"""
        colors = {
            'Critical': '#d32f2f',
            'High': '#f57c00',
            'Medium': '#fbc02d',
            'Low': '#388e3c',
            'Unknown': '#757575'
        }
        return colors.get(severity, '#757575')

    def _format_details_as_html(self, details_dict):
        """Format details dictionary as HTML"""
        html = "<div style='font-family: monospace; font-size: 12px;'>"

        # Agent information
        if 'agent' in details_dict:
            html += f"<p><b>Agent:</b> {details_dict['agent']} (ID: {details_dict.get('agent_id', 'N/A')})</p>"

        # Rule information
        if 'rule_id' in details_dict:
            html += f"<p><b>Rule ID:</b> {details_dict['rule_id']} (Level: {details_dict.get('rule_level', 'N/A')})</p>"

        # Groups
        if 'groups' in details_dict and details_dict['groups']:
            html += f"<p><b>Groups:</b> {', '.join(details_dict['groups'])}</p>"

        # MITRE information
        if 'mitre' in details_dict and details_dict['mitre']:
            mitre = details_dict['mitre']
            html += "<h5>MITRE ATT&CK:</h5><ul style='margin: 5px 0;'>"
            for key, value in mitre.items():
                if isinstance(value, list):
                    html += f"<li><b>{key.title()}:</b> {', '.join(value)}</li>"
                else:
                    html += f"<li><b>{key.title()}:</b> {value}</li>"
            html += "</ul>"

        # Compliance
        if 'compliance' in details_dict and details_dict['compliance']:
            compliance = details_dict['compliance']
            has_compliance = any(v for v in compliance.values() if v)
            if has_compliance:
                html += "<h5>Compliance:</h5><ul style='margin: 5px 0;'>"
                for framework, items in compliance.items():
                    if items:
                        framework_name = framework.replace('_', ' ').upper()
                        html += f"<li><b>{framework_name}:</b> {', '.join(items)}</li>"
                html += "</ul>"

        html += "</div>"
        return html

    def show_cve_info(self, incident, incident_index):
        """Display CVE information for the selected incident"""
        cve_string = incident.get('CVE', '')

        if not cve_string:
            self.cve_info_text.setHtml("<p style='color: #666;'>No CVEs associated with this incident.</p>")
            return

        # Get CVEs from the incident
        cve_list = [cve.strip() for cve in cve_string.split(',') if cve.strip()]

        if not cve_list:
            self.cve_info_text.setHtml("<p style='color: #666;'>No CVEs associated with this incident.</p>")
            return

        # Create organized HTML display
        html = f"""
        <h3>CVE Information</h3>
        <p style='color: #666; margin-bottom: 20px;'>
            This incident has {len(cve_list)} associated CVE(s).
        </p>
        """

        # Create a clean table for CVE display
        html += """
        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <tr style="background-color: #f0f0f0;">
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">CVE ID</th>
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Status</th>
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Action</th>
            </tr>
        """

        for i, cve_id in enumerate(cve_list):
            row_color = "#ffffff" if i % 2 == 0 else "#f9f9f9"
            html += f"""
            <tr style="background-color: {row_color};">
                <td style="padding: 8px; border: 1px solid #ddd;">
                    <b style="color: #1976D2;">{cve_id}</b>
                </td>
                <td style="padding: 8px; border: 1px solid #ddd;">
                    <span style="color: #666;">Extracted from alert</span>
                </td>
                <td style="padding: 8px; border: 1px solid #ddd;">
                    <a href="https://nvd.nist.gov/vuln/detail/{cve_id}" style="color: #1976D2;">
                        View on NVD →
                    </a>
                </td>
            </tr>
            """

        html += "</table>"

        # ──  NEW: append enriched details if we have them  ─────────────────────────
        for cve_id in cve_list:
            if cve_id not in self.cve_cache:
                continue  # not fetched yet

            data = self.cve_cache[cve_id]
            if "error" in data:
                html += f"<p style='color:#d32f2f;'>⚠ Failed to fetch {cve_id}: {data['error']}</p>"
                continue

            desc = data.get('description', 'No description')
            sev = data.get('severity', 'Unknown')
            score = data.get('score', 'N/A')
            refs = data.get('references', [])[:5]
            prods = data.get('affected_products', [])[:5]

            html += f"""
            <details style="margin:8px 0;">
              <summary style="font-weight:600;">{cve_id} – {sev} (score {score})</summary>
              <p style="margin:8px 0;">{desc}</p>
              <ul>
                {"".join(f"<li><a href='{r.get('url', r)}'>{r.get('url', r)}</a></li>" for r in refs)}
              </ul>
              {"<p><b>Affected products:</b> " + ", ".join(prods) + "</p>" if prods else ""}
            </details>
            """

        # Add quick summary
        html += f"""
        <div style="background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin-top: 20px;">
            <h4 style="margin-top: 0;">Quick Actions:</h4>
            <ul style="margin: 5px 0;">
                <li>Click on CVE links above to view detailed vulnerability information</li>
                <li>Export this incident data using the buttons below</li>
                <li>Generate a comprehensive report for documentation</li>
            </ul>
        </div>
        """

        self.cve_info_text.setHtml(html)

    # ─────────────────────────────────────────────────────────────────────────────
    def update_cve_cache(self, cve_id: str, cve_data: dict):
        """
        Slot called by *IncidentHistoryController* when it finishes
        downloading CVE details from the NVD.

        • caches the data
        • if the incident currently shown in the CVE tab contains *cve_id*,
          re-renders the tab so the user sees the new information straight away
        """
        # 1) store
        self.cve_cache[cve_id] = cve_data or {"error": "No data returned"}

        # 2) refresh the tab iff it is relevant
        if self.current_selected_index < 0:
            return  # nothing selected

        incident = self.current_incidents[self.current_selected_index]
        if cve_id.upper() not in (incident.get("CVE") or "").upper():
            return  # not part of this incident

        # rebuild the CVE panel with the enriched cache
        self.show_cve_info(incident, self.current_selected_index)

    def show_context_menu(self, position):
        """Show context menu for table items"""
        item = self.incident_table.itemAt(position)
        if item is None:
            return

        menu = QMenu(self)

        # Copy actions
        copy_row_action = QAction("Copy Row", self)
        copy_row_action.triggered.connect(lambda: self.copy_row_to_clipboard(item.row()))
        menu.addAction(copy_row_action)

        copy_cell_action = QAction("Copy Cell", self)
        copy_cell_action.triggered.connect(lambda: self.copy_cell_to_clipboard(item))
        menu.addAction(copy_cell_action)

        menu.addSeparator()

        # CVE lookup action
        cve_column = 4  # CVE column index
        cve_item = self.incident_table.item(item.row(), cve_column)
        if cve_item and cve_item.text():
            cves = [cve.strip() for cve in cve_item.text().split(',') if cve.strip()]
            for cve in cves[:3]:  # Limit to first 3 CVEs
                lookup_action = QAction(f"Open {cve} in browser", self)
                lookup_action.triggered.connect(lambda checked, c=cve: self.open_cve_in_browser(c))
                menu.addAction(lookup_action)

        menu.exec(self.incident_table.mapToGlobal(position))

    def open_cve_in_browser(self, cve_id):
        """Open CVE in browser"""
        import webbrowser
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        webbrowser.open(url)

    def copy_row_to_clipboard(self, row):
        """Copy entire row to clipboard"""
        from PyQt6.QtWidgets import QApplication
        row_data = []
        for col in range(self.incident_table.columnCount()):
            item = self.incident_table.item(row, col)
            row_data.append(item.text() if item else "")
        QApplication.clipboard().setText("\t".join(row_data))

    def copy_cell_to_clipboard(self, item):
        """Copy cell content to clipboard"""
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(item.text())

    def update_stats(self):
        """Update statistics labels"""
        total = len(self.current_incidents)
        filtered = len(self.filtered_incidents)

        if total == 0:
            self.stats_label.setText("No incidents loaded")
        else:
            self.stats_label.setText(f"Showing {filtered} of {total} incidents")

        # Update CVE stats
        cve_count = sum(1 for inc in self.filtered_incidents if inc.get("CVE"))
        unique_cves = set()
        for inc in self.filtered_incidents:
            if inc.get("CVE"):
                cves = [cve.strip() for cve in inc["CVE"].split(",") if cve.strip()]
                unique_cves.update(cves)

        if unique_cves:
            self.cve_stats_label.setText(f"CVEs: {len(unique_cves)} unique in {cve_count} incidents")
        else:
            self.cve_stats_label.setText("")

    def clear_filters(self):
        """Clear all filters"""
        # Block signals to prevent multiple filter updates
        widgets = [self.date_from, self.date_to, self.quick_filter_combo,
                   self.workflow_filter, self.incident_filter, self.action_filter,
                   self.search_box, self.cve_filter, self.severity_filter, self.regex_mode]

        for widget in widgets:
            widget.blockSignals(True)

        # Reset all filters
        self.date_from.setDate(QDate.currentDate().addDays(-30))
        self.date_to.setDate(QDate.currentDate())
        self.quick_filter_combo.setCurrentIndex(0)
        self.workflow_filter.setCurrentIndex(0)
        self.incident_filter.setCurrentIndex(0)
        self.action_filter.setCurrentIndex(0)
        self.search_box.clear()
        self.cve_filter.clear()
        self.severity_filter.setCurrentIndex(0)
        self.regex_mode.setChecked(False)

        # Re-enable signals
        for widget in widgets:
            widget.blockSignals(False)

        # Apply filters once
        self.apply_filters()

    def export_with_feedback(self, format_type: str):
        """
        Ask the controller to export and show ONE message box
        after we get the controller’s result.
        """
        if not self.filtered_incidents:
            QMessageBox.warning(self, "No Data", "No incidents to export.")
            return

        # Disable buttons so the user can’t click twice
        self.export_csv_btn.setEnabled(False)
        self.export_json_btn.setEnabled(False)

        # tell controller to start
        self.export_requested.emit(format_type, self.filtered_incidents)

    def on_generate_report(self):
        """
        Ask the controller to generate the PDF and
        show ONE message when it finishes.
        """
        if not self.filtered_incidents:
            QMessageBox.warning(self, "No Data", "No incidents to generate report from.")
            return

        self.generate_report_btn.setEnabled(False)
        self.generate_report_requested.emit(self.filtered_incidents)

    @pyqtSlot(str)
    def on_export_completed(self, message: str):
        QMessageBox.information(self, "Export finished", message)
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)

    @pyqtSlot(str)
    def on_export_failed(self, error: str):
        QMessageBox.critical(self, "Export failed", error)
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)

    @pyqtSlot(str)
    def on_report_generated(self, pdf_path: str):
        QMessageBox.information(self, "Report Generated", f"Report saved to:\n{pdf_path}")
        self.generate_report_btn.setEnabled(True)

    def update_status(self, status):
        """Update connection status indicator"""
        if status == "connected":
            self.status_indicator.setStyleSheet("QLabel { color: #4caf50; font-size: 16px; }")
            self.status_label.setText("Connected")
        elif status == "connecting":
            self.status_indicator.setStyleSheet("QLabel { color: #ff9800; font-size: 16px; }")
            self.status_label.setText("Connecting...")
        else:
            self.status_indicator.setStyleSheet("QLabel { color: #f44336; font-size: 16px; }")
            self.status_label.setText("Disconnected")

    def show_loading(self, message="Loading..."):
        """Show loading indicator"""
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText(f"⏳ {message}")

    def hide_loading(self):
        """Hide loading indicator"""
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Refresh")

    def cleanup(self):
        """Cleanup resources when view is being destroyed"""
        if hasattr(self, 'filter_timer'):
            self.filter_timer.stop()
