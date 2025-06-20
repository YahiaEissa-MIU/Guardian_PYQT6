import sys
import os
import psutil
from datetime import datetime
import importlib
from PyQt6.QtWidgets import (QApplication, QMainWindow, QFrame, QLabel,
                             QPushButton, QHBoxLayout, QVBoxLayout, QGridLayout,
                             QWidget, QMessageBox)
from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSignal
from PyQt6.QtGui import QIcon, QPixmap, QFontMetrics
import ctypes
from router import Router
from utils.config_manager import ConfigManager

# Force reload view modules on application start
view_modules = [
    'views.alerts_view',
    'views.incident_history_view',
    'views.dashboard_view',
    'views.settings_view',
    'views.workflows_view',
]

for module_name in view_modules:
    try:
        if module_name in sys.modules:
            importlib.reload(sys.modules[module_name])
            print(f"Reloaded module: {module_name}")
    except Exception as e:
        print(f"Error reloading {module_name}: {e}")

# Add debugging to check module paths
for module_name in view_modules:
    if module_name in sys.modules:
        module = sys.modules[module_name]
        if hasattr(module, '__file__'):
            print(f"Loading {module_name} from: {module.__file__}")

            # Check if class has VERSION attribute
            module_parts = module_name.split('.')
            class_name = module_parts[-1].replace('_view', '').title() + 'View'
            if hasattr(module, class_name) and hasattr(getattr(module, class_name), 'VERSION'):
                view_class = getattr(module, class_name)
                print(f"  {class_name} version: {view_class.VERSION}")


class StatusBar(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setFixedHeight(25)
        self.setup_status_bar()
        self.start_updates()

    def setup_status_bar(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 0, 5, 0)

        # CPU Usage
        self.cpu_label = QLabel("CPU: 0%")
        self.cpu_label.setStyleSheet("font-size: 11px;")
        layout.addWidget(self.cpu_label)

        # Memory Usage
        self.memory_label = QLabel("Memory: 0%")
        self.memory_label.setStyleSheet("font-size: 11px;")
        layout.addWidget(self.memory_label)

        # Spacer to push time label to the right
        layout.addStretch()

        # Time
        self.time_label = QLabel("")
        self.time_label.setStyleSheet("font-size: 11px;")
        layout.addWidget(self.time_label)

        self.setLayout(layout)

    def start_updates(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)  # Update every second

    def update_status(self):
        # Update CPU
        cpu_percent = psutil.cpu_percent()
        self.cpu_label.setText(f"CPU: {cpu_percent}%")

        # Update Memory
        memory = psutil.virtual_memory()
        self.memory_label.setText(f"Memory: {memory.percent}%")

        # Update Time
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.setText(current_time)


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config_manager = ConfigManager()

        # Window setup
        self.setWindowTitle("Guardian")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)
        self.sidebar_visible = True

        # Light theme colors only
        self.colors = {
            "sidebar": "#F0F2F5",
            "main_content": "#FFFFFF",
            "button_hover": "#E3E5E8",
            "text": "#1A1D21",
            "nav_bar": "#E8EAED",
            "button_active": "#D4D7DC",
            "accent": "#4361EE",
            "border": "#E1E3E6",
            "header": "#0A0C10",
            "status_bar": "#E8EAED"
        }

        # Create central widget (main container)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Create main layout
        self.main_layout = QGridLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Load icons
        self.load_icons()

        # Create UI elements
        self.create_navigation_bar()
        self.create_sidebar()
        self.create_main_content()
        self.create_status_bar()

        # Apply theme styles
        self.apply_theme()

        # Initialize Router
        try:
            self.router = Router(self)
            # Show dashboard by default
            self.router.show("dashboard")
        except Exception as e:
            print(f"Error initializing router: {e}")
            import traceback
            print(traceback.format_exc())
            # Fallback simple content for testing
            from PyQt6.QtWidgets import QLabel, QVBoxLayout
            test_layout = QVBoxLayout(self.main_content_frame)
            test_label = QLabel("Development Mode - Router Not Available")
            test_label.setStyleSheet("font-size: 24px; color: red;")
            test_layout.addWidget(test_label)

        # Initialize notification count
        self.notification_count = 0
        self.start_notification_check()

        # Show dashboard by default
        self.router.show("dashboard")

    def load_icons(self):
        # Define icon paths (removed theme toggle icons)
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "icons")
        icon_files = {
            "dashboard": "dashboard.png",
            "alerts": "alert.png",
            "incident": "incident.png",
            "about": "about.png",
            "settings": "settings.png",
            "menu": "menu.png",
            "close": "close.png"
        }

        # Load icons
        self.icons = {}
        for name, file in icon_files.items():
            try:
                path = os.path.join(icon_path, file)
                self.icons[name] = QIcon(path)
            except Exception as e:
                print(f"Failed to load icon {file}: {e}")
                self.icons[name] = QIcon()  # Empty icon

    def create_navigation_bar(self):
        self.nav_bar = QFrame()
        self.nav_bar.setFixedHeight(50)

        # Layout for navigation bar
        nav_layout = QHBoxLayout(self.nav_bar)
        nav_layout.setContentsMargins(10, 5, 10, 5)

        # Menu toggle button
        self.toggle_button = QPushButton()
        self.toggle_button.setIcon(self.icons["menu"])
        self.toggle_button.setIconSize(QSize(20, 20))
        self.toggle_button.setFixedSize(40, 40)
        self.toggle_button.clicked.connect(self.toggle_sidebar)
        nav_layout.addWidget(self.toggle_button)

        # Application title
        self.nav_title = QLabel("Guardian")
        self.nav_title.setStyleSheet("font-size: 20px; font-weight: bold;")
        nav_layout.addWidget(self.nav_title)

        # Push any additional buttons to right
        nav_layout.addStretch()

        # Add navigation bar to main layout
        self.main_layout.addWidget(self.nav_bar, 0, 0, 1, 2)

    def create_sidebar(self):
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setFixedWidth(200)

        # Sidebar layout
        sidebar_layout = QVBoxLayout(self.sidebar_frame)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(2)

        # Button configurations
        button_configs = [
            ("dashboard", " Dashboard", self.icons["dashboard"],
             lambda: self.handle_navigation("dashboard")),
            ("alerts", " Alerts", self.icons["alerts"],
             lambda: self.handle_navigation("alerts")),
            ("incident_history", " Incident History", self.icons["incident"],
             lambda: self.handle_navigation("incident_history")),
            ("workflows", " Workflows", self.icons["about"],
             lambda: self.handle_navigation("workflows")),
            ("settings", " Settings", self.icons["settings"],
             lambda: self.handle_navigation("settings")),
        ]

        # Create buttons
        self.sidebar_buttons = {}
        self.notification_badges = {}

        for btn_id, text, icon, command in button_configs:
            # Create button container
            button_container = QFrame()
            container_layout = QHBoxLayout(button_container)
            container_layout.setContentsMargins(5, 2, 5, 2)

            # Create the button
            button = QPushButton(text)
            button.setIcon(icon)
            button.setIconSize(QSize(20, 20))
            button.setFixedHeight(40)
            button.clicked.connect(command)

            # Set initial styling with hover effect
            button.setStyleSheet(f"""
                QPushButton {{
                    text-align: left; 
                    padding-left: 10px;
                    background-color: transparent;
                    color: {self.colors['text']};
                    border: none;
                    border-radius: 5px;
                }}
                QPushButton:hover {{
                    background-color: rgba(52, 152, 219, 0.3);  /* Semi-transparent #3498db */
                }}
                QPushButton:pressed {{
                    background-color: rgba(52, 152, 219, 0.5);  /* Slightly more opaque when pressed */
                }}
            """)

            container_layout.addWidget(button)
            sidebar_layout.addWidget(button_container)

            self.sidebar_buttons[btn_id] = button

        # Add stretch to push buttons to the top
        sidebar_layout.addStretch()

        # Add sidebar to main layout
        self.main_layout.addWidget(self.sidebar_frame, 1, 0)

    def create_main_content(self):
        self.main_content_frame = QFrame()
        self.main_content_frame.setContentsMargins(10, 10, 10, 10)

        # Create a layout for the main content
        main_content_layout = QGridLayout(self.main_content_frame)
        main_content_layout.setContentsMargins(0, 0, 0, 0)

        # Add main content to main layout
        self.main_layout.addWidget(self.main_content_frame, 1, 1)

        # Configure layout weights
        self.main_layout.setColumnStretch(1, 1)
        self.main_layout.setRowStretch(1, 1)

    def create_status_bar(self):
        self.status_bar = StatusBar(self)
        self.main_layout.addWidget(self.status_bar, 2, 0, 1, 2)

    def resizeEvent(self, event):
        """Handle window resize to ensure views are properly sized"""
        super().resizeEvent(event)

        # Update main content frame to fill available space
        if hasattr(self, 'router') and self.router and self.router.views:
            # Find the currently visible view
            current_view = None
            for name, view in self.router.views.items():
                if view.isVisible():
                    current_view = name
                    break

            # Resize the current view
            if current_view:
                QTimer.singleShot(50, lambda: self.router.update_view_size(current_view))

    def apply_theme(self):
        """Apply light theme colors to all components"""
        colors = self.colors

        # Apply theme to app stylesheet
        self.setStyleSheet(f"""
               QMainWindow, QWidget {{ background-color: {colors['main_content']}; color: {colors['text']}; }}
               QPushButton {{ 
                   background-color: transparent; 
                   color: {colors['text']}; 
                   border: none; 
                   border-radius: 5px; 
                   padding: 5px; 
               }}
               QPushButton:hover {{ background-color: {colors['button_hover']}; }}
               QPushButton:pressed {{ background-color: {colors['button_active']}; }}
           """)

        # Navigation bar
        self.nav_bar.setStyleSheet(f"""
               background-color: {colors['nav_bar']}; 
               border-bottom: 1px solid {colors['border']};
           """)

        # Sidebar
        self.sidebar_frame.setStyleSheet(f"""
               background-color: {colors['sidebar']};
               border-right: 1px solid {colors['border']};
           """)

        # Main content
        self.main_content_frame.setStyleSheet(f"""
               background-color: {colors['main_content']};
               border-radius: 8px;
           """)

        # Status bar
        self.status_bar.setStyleSheet(f"""
               background-color: {colors['status_bar']}; 
               color: {colors['text']};
               border-top: 1px solid {colors['border']};
           """)

        # Update nav title color
        self.nav_title.setStyleSheet(f"""
               font-size: 20px; 
               font-weight: bold; 
               color: {colors['header']};
           """)

    def toggle_sidebar(self):
        """Toggle sidebar visibility"""
        if self.sidebar_visible:
            self.sidebar_frame.hide()
            self.toggle_button.setIcon(self.icons["menu"])
        else:
            self.sidebar_frame.show()
            self.toggle_button.setIcon(self.icons["close"])
        self.sidebar_visible = not self.sidebar_visible

    def start_notification_check(self):
        """Start periodic notification check"""
        self.notification_timer = QTimer(self)
        self.notification_timer.timeout.connect(self.check_notifications)
        self.notification_timer.start(30000)  # Check every 30 seconds

    def check_notifications(self):
        """Check for new notifications"""
        try:
            # This is a placeholder - implement your actual notification checking logic
            # For demonstration, we'll just toggle between 0 and 3 notifications
            self.notification_count = 3 if self.notification_count == 0 else 0

            if "alerts" in self.notification_badges:
                badge = self.notification_badges["alerts"]
                if badge:
                    # Using QTimer to defer the update (similar to after() in tkinter)
                    QTimer.singleShot(100, lambda: badge.update_count(self.notification_count))
        except Exception as e:
            print(f"Error updating notifications: {e}")

    def handle_navigation(self, page_name):
        """Handle navigation and update active button"""
        self.router.show(page_name)
        self.set_active_button(page_name)

    def set_active_button(self, button_id):
        """Highlight the active button"""
        for btn_id, button in self.sidebar_buttons.items():
            if btn_id == button_id:
                # Active button styling
                button.setStyleSheet(f"""
                    QPushButton {{
                        text-align: left; 
                        padding-left: 10px;
                        background-color: #3498db;
                        color: white;
                        border: none;
                        border-radius: 5px;
                    }}
                    QPushButton:hover {{
                        background-color: #2980b9;  /* Darker blue on hover */
                    }}
                """)
            else:
                # Inactive button styling with semi-transparent hover
                button.setStyleSheet(f"""
                    QPushButton {{
                        text-align: left; 
                        padding-left: 10px;
                        background-color: transparent;
                        color: {self.colors['text']};
                        border: none;
                        border-radius: 5px;
                    }}
                    QPushButton:hover {{
                        background-color: rgba(52, 152, 219, 0.3);  /* Semi-transparent #3498db */
                    }}
                    QPushButton:pressed {{
                        background-color: rgba(52, 152, 219, 0.5);
                    }}
                """)


def check_admin():
    try:
        if sys.platform == 'win32':
            print("Checking administrator privileges...")
            if ctypes.windll.shell32.IsUserAnAdmin():
                print("Running with administrator privileges")
                return True
            else:
                print("Not running with administrator privileges")
                if not ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1):
                    print("Failed to restart with administrator privileges")
                    return False
                sys.exit(0)
        return True  # For non-Windows platforms, just return True
    except Exception as e:
        print(f"Error checking admin privileges: {e}")
        return False


if __name__ == "__main__":
    app = QApplication(sys.argv)

    if not check_admin():
        QMessageBox.critical(None, "Error", "Administrator privileges required!")
        sys.exit(1)

    window = App()
    window.show()
    sys.exit(app.exec())
