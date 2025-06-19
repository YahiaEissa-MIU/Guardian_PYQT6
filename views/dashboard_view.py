from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QFrame, QGridLayout, QSizePolicy,
                             QGraphicsDropShadowEffect, QSpacerItem, QScrollArea)
from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSignal, QThread, QPropertyAnimation, QEasingCurve, QMargins
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QBrush
# At the top of dashboard_view.py, verify this import

from PyQt6.QtCharts import QChart, QChartView, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis

import time
from datetime import datetime


class StatCard(QFrame):
    """Enhanced statistics card with professional styling"""

    def __init__(self, parent, title, icon=None, icon_color=None):
        super().__init__(parent)
        self.title = title
        self.icon = icon
        self.icon_color = icon_color
        self.is_valid = True

        # Configure appearance
        self.setObjectName("statCard")
        self.setStyleSheet("""
            #statCard {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
        """)
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        # Add drop shadow for depth
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setOffset(0, 2)
        shadow.setColor(QColor(0, 0, 0, 35))
        self.setGraphicsEffect(shadow)

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 15, 20, 15)
        main_layout.setSpacing(5)

        # Title row
        title_layout = QHBoxLayout()
        title_layout.setSpacing(5)

        # Title
        title_label = QLabel(self.title)
        title_label.setObjectName("cardTitle")
        title_label.setStyleSheet("color: #7f8c8d; font-size: 14px; font-weight: bold;")
        title_layout.addWidget(title_label)

        title_layout.addStretch()

        # Icon
        if self.icon:
            icon_label = QLabel(self.icon)
            icon_label.setFixedSize(24, 24)
            icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            if self.icon_color:
                icon_label.setStyleSheet(f"color: {self.icon_color}; font-size: 16px;")
            title_layout.addWidget(icon_label)

        main_layout.addLayout(title_layout)

        # Value
        self.value_label = QLabel("0")
        self.value_label.setObjectName("cardValue")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_label.setStyleSheet("font-size: 28px; font-weight: bold; margin-top: 5px;")
        main_layout.addWidget(self.value_label)

        # Add stretchable space
        main_layout.addStretch()

    def update_value(self, value, color=None):
        """Update the card's value safely"""
        if not self.is_valid:
            return False

        try:
            self.value_label.setText(str(value))
            if color:
                self.value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
            return True
        except Exception as e:
            print(f"StatCard update error: {e}")
            self.is_valid = False
            return False


class AlertTrendChart(QChartView):
    """Chart showing alert trends over time with responsive design"""

    def __init__(self, parent=None):
        print("Initializing AlertTrendChart...")
        super().__init__(parent)

        # Configure appearance
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setBackgroundBrush(QBrush(QColor("transparent")))

        # Make chart responsive
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # REMOVE fixed height, use minimum height instead
        # Allow the chart to shrink if needed
        self.setMinimumHeight(250)

        # Create the chart
        self.chart = QChart()
        self.chart.setTitle("Alert Trend (7 Days)")
        self.chart.setTitleFont(QFont("Segoe UI", 12, QFont.Weight.Medium))
        self.chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        # Style the chart
        self.chart.setBackgroundVisible(False)
        self.chart.setMargins(QMargins(0, 0, 0, 0))
        self.chart.setPlotAreaBackgroundVisible(False)

        # Configure legend
        self.chart.legend().setVisible(True)
        self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.chart.legend().setFont(QFont("Segoe UI", 9))

        # Set the chart
        self.setChart(self.chart)

        # Initialize chart with empty data
        self.setup_chart()

        print("AlertTrendChart initialized")

    def setup_chart(self):
        """Set up the initial chart structure with axes and empty series"""
        # Create bar series
        self.series = QBarSeries()
        self.series.setBarWidth(0.8)  # Width of bars relative to category width

        # Define colors for alert levels
        self.critical_color = QColor("#e74c3c")  # Red
        self.high_color = QColor("#f39c12")  # Orange
        self.medium_color = QColor("#3498db")  # Blue
        self.low_color = QColor("#2ecc71")  # Green

        # Create data sets with colors
        critical = QBarSet("Critical")
        critical.setColor(self.critical_color)
        critical.setLabelColor(QColor("white"))

        high = QBarSet("High")
        high.setColor(self.high_color)
        high.setLabelColor(QColor("white"))

        medium = QBarSet("Medium")
        medium.setColor(self.medium_color)
        medium.setLabelColor(QColor("white"))

        low = QBarSet("Low")
        low.setColor(self.low_color)
        low.setLabelColor(QColor("white"))

        # Add initial empty data (7 days)
        for i in range(7):
            critical.append(0)
            high.append(0)
            medium.append(0)
            low.append(0)

        # Add data sets to series
        self.series.append(critical)
        self.series.append(high)
        self.series.append(medium)
        self.series.append(low)

        # Add series to chart
        self.chart.addSeries(self.series)

        # Set up X axis (days)
        self.categories = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        self.axis_x = QBarCategoryAxis()
        self.axis_x.append(self.categories)
        self.axis_x.setLabelsFont(QFont("Segoe UI", 9))
        self.chart.addAxis(self.axis_x, Qt.AlignmentFlag.AlignBottom)
        self.series.attachAxis(self.axis_x)

        # Set up Y axis (count)
        self.axis_y = QValueAxis()
        self.axis_y.setRange(0, 10)
        self.axis_y.setTickCount(6)
        self.axis_y.setLabelFormat("%d")
        self.axis_y.setLabelsFont(QFont("Segoe UI", 9))
        self.axis_y.setGridLineVisible(True)
        self.axis_y.setGridLineColor(QColor("#e0e0e0"))
        self.chart.addAxis(self.axis_y, Qt.AlignmentFlag.AlignLeft)
        self.series.attachAxis(self.axis_y)

    def update_data(self, alert_data):
        """Update chart with new alert data

        Args:
            alert_data (dict): Dictionary with day index keys (0-6) and values containing
                              alert counts per category (critical, high, medium, low)
        """
        try:
            print(f"Updating alert trend chart with {len(alert_data)} data points")

            # Clear existing series
            self.chart.removeAllSeries()

            # Create new series with updated data
            self.series = QBarSeries()
            self.series.setBarWidth(0.8)  # Width of bars relative to category width

            # Create data sets
            critical = QBarSet("Critical")
            critical.setColor(self.critical_color)
            critical.setLabelColor(QColor("white"))

            high = QBarSet("High")
            high.setColor(self.high_color)
            high.setLabelColor(QColor("white"))

            medium = QBarSet("Medium")
            medium.setColor(self.medium_color)
            medium.setLabelColor(QColor("white"))

            low = QBarSet("Low")
            low.setColor(self.low_color)
            low.setLabelColor(QColor("white"))

            # Set data and find maximum value
            max_value = 10  # Default minimum max

            for i in range(7):
                day_data = alert_data.get(i, {"critical": 0, "high": 0, "medium": 0, "low": 0})

                critical.append(day_data.get("critical", 0))
                high.append(day_data.get("high", 0))
                medium.append(day_data.get("medium", 0))
                low.append(day_data.get("low", 0))

                # Calculate maximum for y-axis scaling
                day_sum = sum(day_data.values())
                if day_sum > max_value:
                    max_value = day_sum

            # Add data sets to series
            self.series.append(critical)
            self.series.append(high)
            self.series.append(medium)
            self.series.append(low)

            # Add series to chart
            self.chart.addSeries(self.series)

            # Reattach axes
            self.series.attachAxis(self.axis_x)
            self.series.attachAxis(self.axis_y)

            # Update y-axis range with some padding
            self.axis_y.setRange(0, max_value + 2)

            # Adjust tick count based on the maximum value
            if max_value <= 5:
                self.axis_y.setTickCount(6)  # 0, 1, 2, 3, 4, 5
            elif max_value <= 10:
                self.axis_y.setTickCount(6)  # 0, 2, 4, 6, 8, 10
            elif max_value <= 20:
                self.axis_y.setTickCount(5)  # 0, 5, 10, 15, 20
            else:
                # For larger values, create reasonable tick spacing
                tick_count = min(11, max_value // 5 + 2)
                self.axis_y.setTickCount(tick_count)

        except Exception as e:
            print(f"Error updating alert chart: {e}")
            import traceback
            traceback.print_exc()

    def resizeEvent(self, event):
        """Handle resize events to ensure the chart scales properly"""
        super().resizeEvent(event)
        # Adjust chart margins based on size
        if self.width() < 400:
            # Compact layout for small sizes
            self.chart.setMargins(QMargins(5, 5, 5, 5))
        else:
            # Normal margins for larger sizes
            self.chart.setMargins(QMargins(10, 10, 10, 10))


class SystemHealthChart(QChartView):
    """Pie chart showing system health metrics with responsive design"""

    def __init__(self, parent=None):
        print("Initializing SystemHealthChart...")
        super().__init__(parent)

        # Configure appearance
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setBackgroundBrush(QBrush(QColor("transparent")))

        # Make chart responsive
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumHeight(250)

        # Create the chart
        self.chart = QChart()
        self.chart.setTitle("System Health")
        self.chart.setTitleFont(QFont("Segoe UI", 12, QFont.Weight.Medium))
        self.chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)

        # Style the chart
        self.chart.setBackgroundVisible(False)
        self.chart.setMargins(QMargins(0, 0, 0, 0))
        self.chart.setPlotAreaBackgroundVisible(False)

        # Configure legend
        self.chart.legend().setVisible(True)
        self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.chart.legend().setFont(QFont("Segoe UI", 9))

        # Set the chart
        self.setChart(self.chart)

        # Define health status colors
        self.healthy_color = QColor("#2ecc71")  # Green
        self.warning_color = QColor("#f39c12")  # Orange
        self.critical_color = QColor("#e74c3c")  # Red

        # Create initial empty series
        self.series = QPieSeries()
        slice = self.series.append("No Data", 1)
        slice.setColor(QColor("#95a5a6"))  # Gray for no data

        self.chart.addSeries(self.series)

        print("SystemHealthChart initialized")

    def update_data(self, health_data):
        try:
            print(f"Updating system health chart with {len(health_data)} data points")

            # Clear existing series
            self.chart.removeAllSeries()

            # Create new series
            self.series = QPieSeries()

            # Add slices
            if health_data and sum(health_data.values()) > 0:
                total = sum(health_data.values())

                for name, value in health_data.items():
                    # Skip zero values
                    if value <= 0:
                        continue

                    # Calculate percentage for legend display
                    percentage = (value / total) * 100

                    # Create the slice with percentage in legend
                    slice = self.series.append(f"{name} ({percentage:.1f}%)", value)

                    # Set color based on category
                    if "healthy" in name.lower():
                        slice.setColor(self.healthy_color)
                    elif "warning" in name.lower():
                        slice.setColor(self.warning_color)
                    elif "critical" in name.lower():
                        slice.setColor(self.critical_color)
                        # Optionally highlight critical slices
                        slice.setExploded(True)
                        slice.setExplodeDistanceFactor(0.1)
                    else:
                        slice.setColor(QColor("#3498db"))  # Default blue

                    # Make slice visible
                    slice.setLabelVisible(False)  # No direct labels
            else:
                # Default data if none provided
                slice = self.series.append("No Data", 1)
                slice.setColor(QColor("#95a5a6"))  # Gray for no data

            # IMPORTANT: Set appearance BEFORE adding to chart
            self.series.setLabelsVisible(False)

            # Add the series to the chart
            self.chart.addSeries(self.series)

            # Force update
            self.chart.update()
            self.update()

        except Exception as e:
            print(f"Error updating health chart: {e}")
            import traceback
            traceback.print_exc()

    def resizeEvent(self, event):
        """Handle resize events to ensure the chart scales properly"""
        super().resizeEvent(event)

        # Adjust legend based on size
        if self.width() < 400:
            # For small sizes, move legend to bottom
            self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
            self.chart.legend().setMaximumWidth(self.width())
        else:
            # For larger sizes, keep legend at right
            self.chart.legend().setAlignment(Qt.AlignmentFlag.AlignRight)
            self.chart.legend().setMaximumWidth(self.width() // 2)

        # Adjust chart margins based on size
        if self.width() < 400:
            self.chart.setMargins(QMargins(5, 5, 5, 5))
        else:
            self.chart.setMargins(QMargins(10, 10, 10, 10))

        # Always keep labels off, regardless of chart size
        if hasattr(self, 'series'):
            self.series.setLabelsVisible(False)


class StatusUpdateWorker(QThread):
    """Background worker to fetch dashboard updates"""
    update_ready = pyqtSignal(dict)

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.running = True

    def run(self):
        while self.running:
            try:
                # This would normally call controller methods to get data
                if self.controller:
                    data = self.controller.get_dashboard_data()
                    if data is None:
                        print("Warning: Controller returned None data")
                        # Either skip the emission or use sample data
                        continue  # Skip this update cycle
                    else:
                        self.update_ready.emit(data)

                # Sleep for 30 seconds
                for _ in range(30):
                    if not self.running:
                        break
                    time.sleep(1)

            except Exception as e:
                print(f"Status update worker error: {e}")
                time.sleep(5)

    def stop(self):
        self.running = False


class DashboardView(QWidget):
    """Main dashboard view for Guardian SOAR application"""

    def __init__(self, *args, **kwargs):
        print(f"DashboardView init called with args={args}, kwargs={kwargs}")

        # Extract parent from args or kwargs
        parent = None
        if args and isinstance(args[0], QWidget):
            parent = args[0]
            print(f"Parent widget obtained: {parent}")
            print(f"Parent size: {parent.size()}")
            print(f"Parent visibility: {parent.isVisible()}")
        elif 'parent' in kwargs:
            parent = kwargs['parent']

        # Initialize QWidget with parent
        super().__init__(parent)

        # IMPORTANT: Set appropriate size policies
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Apply base styling
        self.setStyleSheet("""
            QWidget {
                background-color: #ffffff;  /* White background like other pages */
                font-family: 'Segoe UI', Arial, sans-serif;
            }
        """)

        # Initialize other properties
        self.controller = None
        self.stat_cards = {}
        self.view_id = id(self)
        self.is_destroyed = False

        print(f"Creating PyQt6 DashboardView with ID: {self.view_id}")

        # Setup UI with proper layout
        self.setup_ui()

        # Print size again to diagnose
        print(f"Dashboard size AFTER setup_ui: {self.size()}")

        # Ensure visibility
        self.show()

        # Setup update worker
        self.update_worker = None

        # Important: Force initial sizing after showing
        QTimer.singleShot(100, self.update_size_to_parent)

    def update_size_to_parent(self):
        """Force the view to update its size to match the parent"""
        if self.parent() and self.parent().size().isValid():
            parent_size = self.parent().size()
            if parent_size.width() > 0 and parent_size.height() > 0:
                self.resize(parent_size)
                print(f"Updated dashboard size to match parent: {parent_size.width()}x{parent_size.height()}")

                # Also update the layout
                self.layout().update()
                self.updateGeometry()

    def resizeEvent(self, event):
        """Handle resize events correctly"""
        super().resizeEvent(event)

        # Only update once we have charts initialized
        if hasattr(self, 'alert_chart') and hasattr(self, 'health_chart'):
            size = self.size()
            print(f"Dashboard resize: {size.width()}x{size.height()}")

            # Update layout spacing based on size
            if size.width() < 600:
                self.layout().setContentsMargins(10, 10, 10, 10)
                self.layout().setSpacing(10)
            else:
                self.layout().setContentsMargins(15, 15, 15, 15)
                self.layout().setSpacing(15)

            # Update layout
            self.layout().update()

    def setup_ui(self):
        # Use QVBoxLayout to fill the entire widget
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Add header
        self.create_header(main_layout)

        # Stats section
        self.create_stat_cards(main_layout)

        # Charts section
        self.create_charts(main_layout)

        # SOAR Status section
        self.create_soar_status(main_layout)

        # Add stretch to push everything up
        main_layout.addStretch(1)

        # Apply the layout
        self.setLayout(main_layout)

        # Refresh data
        self.refresh_dashboard()

        # Force a resize event to make sure layout adjusts
        self.updateGeometry()

    def create_header(self, parent_layout):
        print("Creating header section")

        # Simple header without frame
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 10)  # Only bottom margin

        # Title
        title = QLabel("Security Dashboard")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #333;
        """)
        header_layout.addWidget(title)

        # Spacer
        header_layout.addStretch()

        # Refresh button with consistent blue
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        refresh_btn.clicked.connect(self.refresh_dashboard)
        header_layout.addWidget(refresh_btn)

        parent_layout.addLayout(header_layout)
        print("Header section created")

    def create_stat_cards(self, parent_layout):
        print("Creating stat cards section")
        # Container for stat cards
        stats_container = QFrame()
        stats_container.setStyleSheet("background-color: transparent;")
        stats_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        # Grid layout for stats
        stats_grid = QGridLayout(stats_container)
        stats_grid.setContentsMargins(0, 0, 0, 0)
        stats_grid.setSpacing(20)

        # Define stat cards configuration
        stats_config = [
            {
                "title": "Active Threats",
                "icon": "🛡️",
                "color": "#e74c3c",
                "position": (0, 0)
            },
            {
                "title": "System Status",
                "icon": "⚡",
                "color": "#2ecc71",
                "position": (0, 1)
            },
            {
                "title": "Total Alerts",
                "icon": "🔔",
                "color": "#f1c40f",
                "position": (0, 2)
            },
            {
                "title": "Last Scan",
                "icon": "🔄",
                "color": "#3498db",
                "position": (0, 3)
            }
        ]

        # Create stat cards
        self.stat_cards = {}
        for stat in stats_config:
            card = StatCard(
                stats_container,
                stat["title"],
                stat["icon"],
                stat["icon_color"] if "icon_color" in stat else stat["color"]
            )
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

            # Store card reference
            self.stat_cards[stat["title"]] = {
                "card": card,
                "color": stat["color"]
            }

            # Add to grid
            stats_grid.addWidget(card, stat["position"][0], stat["position"][1])

        # Make columns equally sized
        for i in range(4):
            stats_grid.setColumnStretch(i, 1)

        parent_layout.addWidget(stats_container)
        print("Stat cards section created")

    def create_charts(self, parent_layout):
        print("Creating charts...")
        # Create a container frame for the charts
        charts_container = QFrame()
        charts_container.setStyleSheet("background-color: transparent;")
        charts_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Create layout for charts container
        charts_layout = QHBoxLayout(charts_container)
        charts_layout.setContentsMargins(0, 0, 0, 0)
        charts_layout.setSpacing(20)

        # Alert trend chart container
        trend_chart_container = QFrame()
        trend_chart_container.setStyleSheet("background-color: white; border-radius: 8px; border: 1px solid #e0e0e0;")
        trend_chart_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        trend_chart_layout = QVBoxLayout(trend_chart_container)
        trend_chart_layout.setContentsMargins(15, 15, 15, 15)

        # Alert trend chart - IMPORTANT CHANGES HERE
        print("Creating AlertTrendChart...")
        self.alert_chart = AlertTrendChart(trend_chart_container)
        self.alert_chart.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        # REMOVE FIXED HEIGHT: self.alert_chart.setMinimumHeight(250)
        trend_chart_layout.addWidget(self.alert_chart)

        # Health chart container
        health_chart_container = QFrame()
        health_chart_container.setStyleSheet("background-color: white; border-radius: 8px; border: 1px solid #e0e0e0;")
        health_chart_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        health_chart_layout = QVBoxLayout(health_chart_container)
        health_chart_layout.setContentsMargins(15, 15, 15, 15)

        # System health chart - IMPORTANT CHANGES HERE
        print("Creating SystemHealthChart...")
        self.health_chart = SystemHealthChart(health_chart_container)
        self.health_chart.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        # REMOVE FIXED HEIGHT: self.health_chart.setMinimumHeight(250)
        health_chart_layout.addWidget(self.health_chart)

        # Add both chart containers to the charts layout
        charts_layout.addWidget(trend_chart_container, 1)  # 1 = stretch factor
        charts_layout.addWidget(health_chart_container, 1)  # 1 = stretch factor

        parent_layout.addWidget(charts_container, 1)  # 1 = stretch factor
        print("Charts created and added to layout")

    def create_soar_status(self, parent_layout):
        """Create the SOAR Automation Status section"""
        print("Creating SOAR status section")
        # SOAR Status container
        soar_container = QFrame()
        soar_container.setStyleSheet("background-color: white; border-radius: 8px; border: 1px solid #e0e0e0;")
        soar_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        soar_layout = QVBoxLayout(soar_container)
        soar_layout.setContentsMargins(20, 20, 20, 20)
        soar_layout.setSpacing(15)

        # Header
        soar_header = QHBoxLayout()

        # Title
        soar_title = QLabel("SOAR Automation Status")
        soar_title.setObjectName("sectionTitle")
        soar_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50;")
        soar_header.addWidget(soar_title)

        # Spacer
        soar_header.addStretch()

        # View details button
        view_details_btn = QPushButton("View Workflows")
        view_details_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        view_details_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f6da9;
            }
        """)
        view_details_btn.clicked.connect(self.view_workflows)
        soar_header.addWidget(view_details_btn)

        soar_layout.addLayout(soar_header)

        # Create grid container for workflow statuses
        workflow_grid = QGridLayout()
        workflow_grid.setHorizontalSpacing(20)
        workflow_grid.setVerticalSpacing(15)

        # Workflow statuses
        workflow_statuses = [
            {"name": "Malware Response", "status": "Active", "color": "#2ecc71"},
            {"name": "System Scan", "status": "Scheduled", "color": "#3498db"},
            {"name": "Threat Hunting", "status": "Idle", "color": "#95a5a6"},
            {"name": "Network Defense", "status": "Active", "color": "#2ecc71"}
        ]

        # Create status indicators
        self.workflow_labels = {}
        for i, workflow in enumerate(workflow_statuses):
            row, col = i // 2, i % 2

            # Container for each workflow
            workflow_frame = QFrame()
            workflow_frame.setObjectName("workflowStatusItem")
            workflow_frame.setStyleSheet("background-color: #f8f9fa; border-radius: 6px;")
            workflow_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

            workflow_layout = QHBoxLayout(workflow_frame)
            workflow_layout.setContentsMargins(15, 12, 15, 12)

            # Status indicator
            status_indicator = QFrame()
            status_indicator.setFixedSize(12, 12)
            status_indicator.setStyleSheet(f"background-color: {workflow['color']}; border-radius: 6px;")
            workflow_layout.addWidget(status_indicator)

            # Name
            name_label = QLabel(workflow["name"])
            name_label.setObjectName("workflowName")
            name_label.setStyleSheet("font-weight: 500;")
            workflow_layout.addWidget(name_label)

            workflow_layout.addStretch()

            # Status
            status_label = QLabel(workflow["status"])
            status_label.setObjectName("workflowStatus")
            status_label.setStyleSheet(f"color: {workflow['color']}; font-weight: bold;")
            workflow_layout.addWidget(status_label)

            self.workflow_labels[workflow["name"]] = {
                "status_label": status_label,
                "indicator": status_indicator
            }

            workflow_grid.addWidget(workflow_frame, row, col)

        # Make columns stretch equally
        for i in range(2):
            workflow_grid.setColumnStretch(i, 1)

        soar_layout.addLayout(workflow_grid)
        parent_layout.addWidget(soar_container)
        print("SOAR status section created")

    def view_workflows(self):
        """Open workflows view"""
        print("View Workflows button clicked")
        if self.controller:
            try:
                # This would navigate to workflows view in a real implementation
                print("Opening workflows view")
            except Exception as e:
                print(f"Error navigating to workflows: {e}")

    def showEvent(self, event):
        """Handle show events to ensure the view is properly sized"""
        super().showEvent(event)

        # Use a timer to let the event finish processing
        QTimer.singleShot(100, self.update_size_to_parent)

    def refresh_dashboard(self):
        """Refresh all dashboard data"""
        if self.controller:
            try:
                # Update data
                data = self.controller.get_dashboard_data()
                self.update_dashboard(data)

            except Exception as e:
                print(f"Dashboard refresh error: {e}")

    def update_dashboard(self, data):
        """Update all dashboard components with new data"""
        try:

            # Update stat cards
            self.update_stat_cards(data)

            # Update charts
            self.update_charts(data)

            # Update SOAR status
            self.update_soar_status(data)

        except Exception as e:
            print(f"Error updating dashboard: {e}")
            import traceback
            traceback.print_exc()

    def update_stat_cards(self, data):
        """Update all stat cards with data"""
        # Map data keys to card titles
        key_mapping = {
            "active_threats": "Active Threats",
            "system_status": "System Status",
            "total_alerts": "Total Alerts",
            "last_scan": "Last Scan"
        }

        # Update each card
        for key, title in key_mapping.items():
            if title in self.stat_cards and key in data:
                card_info = self.stat_cards[title]
                card_info["card"].update_value(data[key], card_info["color"])

    def update_charts(self, data):
        """Update chart displays"""
        # Update alert trend chart
        if hasattr(self, 'alert_chart') and "alert_trend" in data:
            print(f"Updating alert trend chart with {len(data['alert_trend'])} data points")
            self.alert_chart.update_data(data["alert_trend"])

        # Update system health chart
        if hasattr(self, 'health_chart') and "system_health" in data:
            print(f"Updating system health chart with {len(data['system_health'])} data points")
            self.health_chart.update_data(data["system_health"])

    def update_soar_status(self, data):
        """Update SOAR workflow status indicators"""
        if "workflows" in data and hasattr(self, 'workflow_labels'):
            for workflow_name, workflow_data in data["workflows"].items():
                if workflow_name in self.workflow_labels:
                    status = workflow_data.get("status", "Unknown")
                    color = self.get_status_color(status)

                    # Update status label
                    self.workflow_labels[workflow_name]["status_label"].setText(status)
                    self.workflow_labels[workflow_name]["status_label"].setStyleSheet(f"color: {color};")

                    # Update indicator color
                    self.workflow_labels[workflow_name]["indicator"].setStyleSheet(
                        f"background-color: {color}; border-radius: 6px;"
                    )

    def get_status_color(self, status):
        """Get color for workflow status"""
        status_colors = {
            "Active": "#2ecc71",  # Green
            "Running": "#2ecc71",  # Green
            "Scheduled": "#3498db",  # Blue
            "Pending": "#f39c12",  # Orange
            "Idle": "#95a5a6",  # Gray
            "Failed": "#e74c3c",  # Red
            "Warning": "#f1c40f"  # Yellow
        }
        return status_colors.get(status, "#95a5a6")  # Default to gray

    def set_controller(self, controller):
        """Set the controller and start data updates"""
        self.controller = controller

        # Start the update worker
        if self.controller and not self.is_destroyed:
            self.start_update_worker()

            # Initial update
            QTimer.singleShot(100, self.refresh_dashboard)

    def start_update_worker(self):
        """Start background worker for updates"""
        if self.update_worker is None:
            self.update_worker = StatusUpdateWorker(self.controller)
            self.update_worker.update_ready.connect(self.update_dashboard)
            self.update_worker.start()

    def stop_update_worker(self):
        """Stop the update worker"""
        if self.update_worker and self.update_worker.isRunning():
            self.update_worker.stop()
            self.update_worker.wait()
            self.update_worker = None

    def closeEvent(self, event):
        """Handle window close event"""
        self.is_destroyed = True
        self.stop_update_worker()
        super().closeEvent(event)


# Add this stylesheet for professional appearance
DASHBOARD_STYLESHEET = """
    QWidget {
        font-family: 'Segoe UI', Arial, sans-serif;
    }

    #dashboardTitle {
        font-size: 22px;
        font-weight: bold;
        color: #2c3e50;
    }

    #lastUpdateLabel {
        color: #7f8c8d;
        font-size: 12px;
    }

    #statCard {
        background-color: white;
        border-radius: 8px;
        border: 1px solid #e0e0e0;
    }

    #cardTitle {
        color: #7f8c8d;
        font-size: 14px;
        font-weight: bold;
    }

    #cardValue {
        font-size: 24px;
        font-weight: bold;
    }

    #soarStatusContainer, #statsContainer {
        background-color: white;
        border-radius: 8px;
        border: 1px solid #e0e0e0;
        padding: 10px;
    }

    #sectionTitle {
        font-size: 16px;
        font-weight: bold;
        color: #2c3e50;
        margin-bottom: 10px;
    }

    #workflowStatusItem {
        background-color: #f8f9fa;
        border-radius: 6px;
    }

    #workflowName {
        font-weight: 500;
    }

    #workflowStatus {
        font-weight: bold;
    }

    QPushButton {
        background-color: #3498db;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 8px 15px;
        font-weight: bold;
    }

    QPushButton:hover {
        background-color: #2980b9;
    }

    QPushButton:pressed {
        background-color: #1f6da9;
    }
"""