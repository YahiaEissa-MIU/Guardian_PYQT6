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


class IncidentHistoryView(QWidget):
    # Signals
    refresh_requested = pyqtSignal()
    export_requested = pyqtSignal(str, list)  # format type, filtered incidents
    generate_report_requested = pyqtSignal(list)  # filtered incidents
    fetch_cve_details_requested = pyqtSignal(str)  # CVE ID

    def __init__(self, parent=None):
        super().__init__(parent)

        # Initialize data structures
        self.current_incidents = []
        self.filtered_incidents = []
        self.cve_cache = {}

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
        self.refresh_btn = QPushButton("🔄 Refresh")
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
        filter_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 5px 0 5px;
            }
        """)
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
        self.date_from.dateChanged.connect(self.apply_filters)
        date_container.addWidget(self.date_from)

        date_container.addSpacing(10)
        date_container.addWidget(QLabel("To:"))
        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        self.date_to.setDisplayFormat("yyyy-MM-dd")
        self.date_to.setFixedWidth(120)
        self.date_to.dateChanged.connect(self.apply_filters)
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
        self.workflow_filter.currentTextChanged.connect(self.apply_filters)
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
        self.search_box.textChanged.connect(self.apply_filters)
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
        self.incident_filter.currentTextChanged.connect(self.apply_filters)
        type_container.addWidget(self.incident_filter)

        row2.addLayout(type_container)

        # Action filter
        action_container = QHBoxLayout()
        action_container.setSpacing(5)
        action_container.addWidget(QLabel("Action:"))
        self.action_filter = QComboBox()
        self.action_filter.setMinimumWidth(150)
        self.action_filter.addItem("All Actions")
        self.action_filter.currentTextChanged.connect(self.apply_filters)
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
        self.cve_filter.textChanged.connect(self.apply_filters)
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
        self.severity_filter.currentTextChanged.connect(self.apply_filters)
        severity_container.addWidget(self.severity_filter)

        row3.addLayout(severity_container)

        # Regex mode checkbox
        self.regex_mode = QCheckBox("Regex Mode")
        row3.addWidget(self.regex_mode)
        self.regex_mode.toggled.connect(self.apply_filters)

        row3.addStretch()

        # Clear filters button
        self.clear_filters_btn = QPushButton("Clear All Filters")
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

        # Style the table
        self.incident_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #cccccc;
                border-radius: 5px;
                gridline-color: #e0e0e0;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                padding: 5px;
                border: 1px solid #cccccc;
                font-weight: bold;
            }
        """)

        # Add context menu to table
        self.incident_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.incident_table.customContextMenuRequested.connect(self.show_context_menu)

        top_layout.addWidget(self.incident_table)

        # Stats bar - add objectName
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
        self.tab_widget.setStyleSheet("""
               QTabWidget::pane {
                   border: 1px solid #cccccc;
                   background-color: white;
                   border-radius: 5px;
               }
               QTabBar::tab {
                   background-color: #f0f0f0;
                   padding: 8px 16px;
                   margin-right: 2px;
               }
               QTabBar::tab:selected {
                   background-color: white;
                   border-bottom: 2px solid #1976D2;
               }
           """)

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

        # Export buttons - make them smaller
        self.export_csv_btn = QPushButton("📄 Export CSV")
        self.export_csv_btn.setObjectName("exportButton")
        self.export_csv_btn.clicked.connect(lambda: self.export_requested.emit("csv", self.filtered_incidents))
        action_layout.addWidget(self.export_csv_btn)

        self.export_json_btn = QPushButton("📋 Export JSON")
        self.export_json_btn.setObjectName("exportButton")
        self.export_json_btn.clicked.connect(lambda: self.export_requested.emit("json", self.filtered_incidents))
        action_layout.addWidget(self.export_json_btn)

        action_layout.addStretch()

        self.fetch_cve_btn = QPushButton("🔍 Fetch CVE Details")
        self.fetch_cve_btn.setObjectName("secondaryButton")
        self.fetch_cve_btn.clicked.connect(self.fetch_selected_cve_details)
        self.fetch_cve_btn.setEnabled(False)
        action_layout.addWidget(self.fetch_cve_btn)

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

        # Apply the complete stylesheet at the end of init_ui
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #ffffff;
            }

            /* Title styling */
            QLabel {
                color: #333;
                background-color: transparent;  /* Make labels transparent */
            }

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
                background-color: #f8f9fa;  /* Match the group box background */
            }

            /* Labels inside filter groups */
            QGroupBox QLabel {
                background-color: transparent;
                padding: 2px;
            }

            /* Input controls */
            QComboBox, QLineEdit, QDateEdit {
                border: 1px solid #ced4da;
                border-radius: 4px;
                padding: 6px;
                background-color: white;
                min-height: 25px;
            }

            QComboBox:hover, QLineEdit:hover, QDateEdit:hover {
                border-color: #80bdff;
            }

            QComboBox:focus, QLineEdit:focus, QDateEdit:focus {
                border-color: #3498db;
                outline: none;
            }

            QComboBox::drop-down {
                border: none;
            }

            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #333;
                margin-right: 5px;
            }

            /* Buttons */
            QPushButton {
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: 600;
                min-height: 32px;
            }

            /* Primary button (Generate Report) */
            QPushButton#primaryButton {
                background-color: #3498db;
                color: white;
            }

            QPushButton#primaryButton:hover {
                background-color: #2980b9;
            }

            QPushButton#primaryButton:pressed {
                background-color: #21618c;
            }

            /* Secondary button (Fetch CVE) */
            QPushButton#secondaryButton {
                background-color: #2ecc71;
                color: white;
            }

            QPushButton#secondaryButton:hover {
                background-color: #27ae60;
            }

            QPushButton#secondaryButton:disabled {
                background-color: #95a5a6;
                color: #bdc3c7;
            }

            /* Export buttons */
            QPushButton#exportButton {
                background-color: #ecf0f1;
                color: #2c3e50;
            }

            QPushButton#exportButton:hover {
                background-color: #d5dbdb;
            }

            /* Clear filters button */
            QPushButton[text="Clear All Filters"] {
                background-color: #e74c3c;
                color: white;
            }

            QPushButton[text="Clear All Filters"]:hover {
                background-color: #c0392b;
            }

            /* Refresh button */
            QPushButton[text*="Refresh"] {
                background-color: #3498db;
                color: white;
            }

            QPushButton[text*="Refresh"]:hover {
                background-color: #2980b9;
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

            QTableWidget::item:hover {
                background-color: #f8f9fa;
            }

            QHeaderView::section {
                background-color: #f8f9fa;
                color: #333;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #e9ecef;
                font-weight: bold;
            }

            QHeaderView::section:hover {
                background-color: #e9ecef;
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
                color: #2c3e50;  /* Dark gray text */
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-weight: 500;
                min-width: 100px;
            }

            QTabBar::tab:selected {
                background-color: white;  /* White background for selected */
                color: #3498db;  /* Blue text for selected */
                border: 1px solid #e9ecef;
                border-bottom: 1px solid white;  /* Hide bottom border */
                font-weight: 600;
                padding-top: 8px;  /* Adjust for border */
            }

            QTabBar::tab:hover:!selected {
                background-color: #dfe6e9;
                color: #2c3e50;
            }

            QTabBar::tab:first:selected {
                margin-left: 0;
            }

            QTabBar::tab:only-one {
                margin: 0;
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

            /* Stats bar labels should have transparent background */
            QWidget#statsBar QLabel {
                background-color: transparent;
            }

            /* Action panel */
            QWidget#actionPanel {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
            }

            /* Checkbox */
            QCheckBox {
                spacing: 5px;
                background-color: transparent;
            }

            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #ced4da;
                border-radius: 3px;
                background-color: white;
            }

            QCheckBox::indicator:checked {
                background-color: #3498db;
                border-color: #3498db;
            }

            QCheckBox::indicator:hover {
                border-color: #3498db;
            }

            /* Scrollbars */
            QScrollBar:vertical {
                background-color: #f8f9fa;
                width: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:vertical {
                background-color: #ced4da;
                border-radius: 6px;
                min-height: 20px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #adb5bd;
            }

            QScrollBar:horizontal {
                background-color: #f8f9fa;
                height: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:horizontal {
                background-color: #ced4da;
                border-radius: 6px;
                min-width: 20px;
            }

            QScrollBar::handle:horizontal:hover {
                background-color: #adb5bd;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                border: none;
                background: none;
            }
        """)

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
            lookup_cve_action = QAction(f"Lookup {cve_item.text()}", self)
            lookup_cve_action.triggered.connect(lambda: self.fetch_cve_details_requested.emit(cve_item.text()))
            menu.addAction(lookup_cve_action)

        menu.exec(self.incident_table.mapToGlobal(position))

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

    def update_incidents(self, incidents):
        """Update the incident table with new data"""
        self.current_incidents = incidents
        self.update_filter_options()
        self.apply_filters()
        self.update_status("connected")

    def extract_cves_from_incidents(self):
        """Extract CVE codes from incident data - only for incidents without CVE data"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'

        for incident in self.current_incidents:
            # Only process if CVE field is empty
            if not incident.get('CVE'):
                cves_found = []

                # Search in all text fields for CVE patterns
                for field in ['Incident', 'Action', 'Details']:
                    if field in incident:
                        matches = re.findall(cve_pattern, str(incident[field]), re.IGNORECASE)
                        cves_found.extend(matches)

                # Remove duplicates and store
                incident['CVE'] = ', '.join(set(cves_found)) if cves_found else ''

            # Ensure Severity field exists
            if 'Severity' not in incident:
                incident['Severity'] = 'Unknown'

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

        # Update workflow filter
        current_workflow = self.workflow_filter.currentText()
        self.workflow_filter.clear()
        self.workflow_filter.addItem("All Workflows")
        for workflow in sorted(workflows):
            self.workflow_filter.addItem(workflow)

        # Restore selection if possible
        index = self.workflow_filter.findText(current_workflow)
        if index >= 0:
            self.workflow_filter.setCurrentIndex(index)

        # Update incident type filter
        current_type = self.incident_filter.currentText()
        self.incident_filter.clear()
        self.incident_filter.addItem("All Types")
        for incident_type in sorted(incident_types):
            self.incident_filter.addItem(incident_type)

        index = self.incident_filter.findText(current_type)
        if index >= 0:
            self.incident_filter.setCurrentIndex(index)

        # Update action filter
        current_action = self.action_filter.currentText()
        self.action_filter.clear()
        self.action_filter.addItem("All Actions")
        for action in sorted(actions):
            self.action_filter.addItem(action)

        index = self.action_filter.findText(current_action)
        if index >= 0:
            self.action_filter.setCurrentIndex(index)

    def apply_filters(self):
        """Apply all active filters to the incident list"""
        # Start with all incidents
        self.filtered_incidents = self.current_incidents.copy()
        active_filters = []

        # Date range filter
        date_from = self.date_from.date().toPyDate()
        date_to = self.date_to.date().toPyDate()

        # Apply date filter
        date_filtered = []
        for inc in self.filtered_incidents:
            if self._is_date_in_range(inc.get("Date", ""), date_from, date_to):
                date_filtered.append(inc)
        self.filtered_incidents = date_filtered

        if self.quick_filter_combo.currentText() != "Custom Range":
            active_filters.append(f"Date: {self.quick_filter_combo.currentText()}")
        else:
            active_filters.append(f"Date: {date_from} to {date_to}")

        # Workflow filter
        if self.workflow_filter.currentText() != "All Workflows":
            workflow = self.workflow_filter.currentText()
            self.filtered_incidents = [
                inc for inc in self.filtered_incidents
                if inc.get("Workflow", "") == workflow
            ]
            active_filters.append(f"Workflow: {workflow}")

        # Incident type filter
        if self.incident_filter.currentText() != "All Types":
            incident_type = self.incident_filter.currentText()
            self.filtered_incidents = [
                inc for inc in self.filtered_incidents
                if inc.get("Incident", "") == incident_type
            ]
            active_filters.append(f"Type: {incident_type}")

        # Action filter
        if self.action_filter.currentText() != "All Actions":
            action = self.action_filter.currentText()
            self.filtered_incidents = [
                inc for inc in self.filtered_incidents
                if inc.get("Action", "") == action
            ]
            active_filters.append(f"Action: {action}")

        # CVE filter
        cve_text = self.cve_filter.text().strip()
        if cve_text:
            self.filtered_incidents = [
                inc for inc in self.filtered_incidents
                if cve_text.upper() in inc.get("CVE", "").upper()
            ]
            active_filters.append(f"CVE: {cve_text}")

        # Severity filter
        if self.severity_filter.currentText() != "All Severities":
            severity = self.severity_filter.currentText()
            self.filtered_incidents = [
                inc for inc in self.filtered_incidents
                if inc.get("Severity", "Unknown") == severity
            ]
            active_filters.append(f"Severity: {severity}")

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
            # Handle different date formats
            if not date_str:
                return False

            # Try to parse the date string
            if ' ' in date_str:
                # Format: "YYYY-MM-DD HH:MM"
                date_part = date_str.split(' ')[0]
            else:
                date_part = date_str

            # Parse the date
            date_obj = datetime.strptime(date_part, "%Y-%m-%d").date()
            return date_from <= date_obj <= date_to
        except Exception as e:
            print(f"Error parsing date '{date_str}': {e}")
            return False  # Exclude items with unparseable dates

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
            # Date
            date_item = QTableWidgetItem(incident.get("Date", ""))
            date_item.setData(Qt.ItemDataRole.UserRole, incident)
            self.incident_table.setItem(row, 0, date_item)

            # Incident Type
            self.incident_table.setItem(row, 1,
                                        QTableWidgetItem(incident.get("Incident", "")))

            # Action Taken
            self.incident_table.setItem(row, 2,
                                        QTableWidgetItem(incident.get("Action", "")))

            # Workflow
            self.incident_table.setItem(row, 3,
                                        QTableWidgetItem(incident.get("Workflow", "")))

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
                cves = inc["CVE"].split(", ")
                unique_cves.update(cves)

        if unique_cves:
            self.cve_stats_label.setText(f"CVEs: {len(unique_cves)} unique in {cve_count} incidents")
        else:
            self.cve_stats_label.setText("")

    def clear_filters(self):
        """Clear all filters"""
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
        self.apply_filters()

    def on_selection_changed(self):
        """Handle table selection changes"""
        selected_rows = self.incident_table.selectionModel().selectedRows()

        if selected_rows:
            row = selected_rows[0].row()
            incident = self.filtered_incidents[row]

            # Update details tab
            self.show_incident_details(incident)

            # Enable/disable CVE fetch button
            self.fetch_cve_btn.setEnabled(bool(incident.get("CVE")))

            # If CVE exists and not in cache, show cached info
            if incident.get("CVE"):
                self.show_cve_info(incident)
        else:
            self.details_text.clear()
            self.cve_info_text.clear()
            self.analysis_text.clear()
            self.fetch_cve_btn.setEnabled(False)

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
                <td style="padding: 8px; border: 1px solid #ddd;"><b>Date</b></td>
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
                <td style="padding: 8px; border: 1px solid #ddd;">{incident.get('Severity', 'Unknown')}</td>
            </tr>
        </table>

        <h4>Additional Information</h4>
        {details_html}
        """
        self.details_text.setHtml(html)

    def _format_details_as_html(self, details_dict):
        """Format details dictionary as HTML"""
        html = "<div style='font-family: monospace; font-size: 12px;'>"

        # Agent information
        if 'agent' in details_dict:
            html += f"<p><b>Agent:</b> {details_dict['agent']}</p>"

        # Rule information
        if 'rule_id' in details_dict:
            html += f"<p><b>Rule ID:</b> {details_dict['rule_id']} (Level: {details_dict.get('rule_level', 'N/A')})</p>"

        # VirusTotal information
        if 'virustotal' in details_dict:
            vt = details_dict['virustotal']
            html += "<h5>VirusTotal Information:</h5><ul>"
            html += f"<li><b>File:</b> {vt.get('file', 'N/A')}</li>"
            html += f"<li><b>SHA1:</b> {vt.get('hash', 'N/A')}</li>"
            html += f"<li><b>Detections:</b> {vt.get('detections', 'N/A')}</li>"
            html += f"<li><b>Scan Date:</b> {vt.get('scan_date', 'N/A')}</li>"
            if vt.get('permalink'):
                html += f"<li><b>Report:</b> <a href='{vt['permalink']}'>View on VirusTotal</a></li>"
            html += "</ul>"

        # MITRE information
        if 'mitre' in details_dict:
            mitre = details_dict['mitre']
            html += "<h5>MITRE ATT&CK:</h5><ul>"
            if mitre.get('tactics'):
                html += f"<li><b>Tactics:</b> {', '.join(mitre['tactics'])}</li>"
            if mitre.get('techniques'):
                html += f"<li><b>Techniques:</b> {', '.join(mitre['techniques'])}</li>"
            html += "</ul>"

        # CVE sources
        if 'cve_sources' in details_dict:
            html += "<h5>CVE Sources:</h5><ul>"
            for source, cves in details_dict['cve_sources'].items():
                html += f"<li><b>{source}:</b> {', '.join(cves)}</li>"
            html += "</ul>"

        html += "</div>"
        return html

    def show_cve_info(self, incident):
        """Display CVE information"""
        cve_ids = incident.get('CVE', '').split(', ')
        if not cve_ids or not cve_ids[0]:
            self.cve_info_text.setHtml("<p>No CVE information available.</p>")
            return

        html = "<h3>CVE Information</h3>"

        for cve_id in cve_ids:
            if cve_id in self.cve_cache:
                cve_data = self.cve_cache[cve_id]
                html += self.format_cve_html(cve_id, cve_data)
            else:
                html += f"<p><b>{cve_id}</b>: Information not yet fetched. Click 'Fetch CVE Details' to retrieve.</p>"

        self.cve_info_text.setHtml(html)

    def format_cve_html(self, cve_id, cve_data):
        """Format CVE data as HTML"""
        if isinstance(cve_data, dict) and 'error' not in cve_data:
            severity = cve_data.get('severity', 'Unknown')
            score = cve_data.get('score', 'N/A')
            description = cve_data.get('description', 'No description available.')

            severity_color = {
                'CRITICAL': '#d32f2f',
                'HIGH': '#f57c00',
                'MEDIUM': '#fbc02d',
                'LOW': '#388e3c'
            }.get(severity.upper(), '#757575')

            html = f"""
            <div style="margin-bottom: 20px; border: 1px solid #ddd; padding: 10px;">
                <h4>{cve_id}</h4>
                <table style="width: 100%;">
                    <tr>
                        <td><b>Severity:</b></td>
                        <td style="color: {severity_color}; font-weight: bold;">{severity}</td>
                        <td><b>CVSS Score:</b></td>
                        <td>{score}</td>
                    </tr>
                </table>
                <p><b>Description:</b><br>{description}</p>
                <p><b>References:</b><br>
                <a href="https://nvd.nist.gov/vuln/detail/{cve_id}">View on NVD</a></p>
            </div>
            """
            return html
        else:
            return f"<p><b>{cve_id}</b>: Error fetching data</p>"

    def fetch_selected_cve_details(self):
        """Fetch CVE details for selected incident"""
        selected_rows = self.incident_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        incident = self.filtered_incidents[row]
        cve_ids = incident.get('CVE', '').split(', ')

        for cve_id in cve_ids:
            if cve_id and cve_id not in self.cve_cache:
                self.fetch_cve_details_requested.emit(cve_id)

    def update_cve_cache(self, cve_id, cve_data):
        """Update CVE cache with new data"""
        self.cve_cache[cve_id] = cve_data

        # Update severity in incidents
        for incident in self.current_incidents:
            if cve_id in incident.get('CVE', ''):
                # Update severity based on CVE data
                if isinstance(cve_data, dict) and 'severity' in cve_data:
                    incident['Severity'] = cve_data['severity']

        # Refresh display
        self.apply_filters()
        self.on_selection_changed()

    def on_generate_report(self):
        """Generate report for filtered incidents"""
        if not self.filtered_incidents:
            QMessageBox.warning(self, "No Data", "No incidents to generate report from.")
            return

        self.generate_report_requested.emit(self.filtered_incidents)

    def update_status(self, status):
        """Update connection status indicator"""
        if status == "connected":
            self.status_indicator.setStyleSheet("QLabel { color: green; font-size: 16px; }")
            self.status_label.setText("Connected")
        elif status == "connecting":
            self.status_indicator.setStyleSheet("QLabel { color: orange; font-size: 16px; }")
            self.status_label.setText("Connecting...")
        else:
            self.status_indicator.setStyleSheet("QLabel { color: red; font-size: 16px; }")
            self.status_label.setText("Disconnected")

    def show_loading(self, message="Loading..."):
        """Show loading indicator"""
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText(f"⏳ {message}")

    def hide_loading(self):
        """Hide loading indicator"""
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("🔄 Refresh")
