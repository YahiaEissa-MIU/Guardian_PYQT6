# views/settings_view.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QFrame, QScrollArea, QLineEdit,
                             QGridLayout, QMessageBox, QSizePolicy, QCheckBox,
                             QComboBox, QListWidget, QListWidgetItem)
from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSlot
from PyQt6.QtGui import QFont
import asyncio


class SettingsView(QWidget):
    """Settings view for Guardian SOAR application using PyQt6"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.controller = None
        self._is_fetching = False  # Add this flag
        # Set size policy and attributes
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        # Apply background style directly to the view
        self.setStyleSheet("""
            SettingsView {
                background-color: #f0f0f0;
            }
        """)

        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(0)

        # Create scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: none;
            }
        """)

        # Create scroll content widget
        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: transparent;")

        # Scroll content layout
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 20, 0)  # Right margin for scrollbar
        self.scroll_layout.setSpacing(15)

        # Set the scroll widget
        self.scroll_area.setWidget(self.scroll_content)

        # Add scroll area to main layout
        self.main_layout.addWidget(self.scroll_area)

        # Flag to track if content is created
        self.content_created = False

        print("SettingsView initialized")

    def showEvent(self, event):
        """Handle show event"""
        super().showEvent(event)

        # Ensure we're on top
        self.raise_()

        # Create content if not already created
        if not self.content_created and self.controller:
            self.create_settings_page()

    def hideEvent(self, event):
        """Handle hide event"""
        super().hideEvent(event)

    def set_controller(self, controller):
        """Set the controller for this view"""
        print(f"Setting controller: {controller}")
        self.controller = controller
        if self.controller:
            self.controller.set_view(self)

            # Connect to controller signals
            self.controller.agent_config_updated.connect(self.handle_agent_config_update)

            # Create content if view is visible
            if self.isVisible():
                QTimer.singleShot(100, self.create_settings_page)

    def clear_layout(self, layout):
        """Clear all widgets from a layout"""
        if layout is None:
            return

        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            else:
                self.clear_layout(item.layout())

    def create_settings_page(self):
        """Create the main settings page layout"""
        if self.content_created:
            return

        print("Creating settings page...")

        # Clear existing layout
        self.clear_layout(self.scroll_layout)

        # Create header
        self.create_header(self.scroll_layout)

        # Create settings sections
        self.create_api_connection_settings(self.scroll_layout)
        self.create_agent_settings(self.scroll_layout)
        self.create_shuffle_settings(self.scroll_layout)

        # Add stretch to push content to the top
        self.scroll_layout.addStretch(1)

        # Update fields with controller data if available
        if self.controller:
            self.update_fields(self.controller.get_current_settings())

        self.content_created = True
        print("Settings page created")

    def create_header(self, parent_layout):
        """Create the header section with title and description"""
        header_widget = QFrame()
        header_widget.setObjectName("settingsHeader")
        header_widget.setStyleSheet("""
            #settingsHeader {
                background-color: transparent;
                border: none;
            }
        """)

        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 15)

        # Title
        title = QLabel("Guardian Settings")
        title.setObjectName("headerTitle")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #2c3e50;")

        # Description
        description = QLabel("Configure your security preferences and connections")
        description.setObjectName("headerDescription")
        description.setStyleSheet("color: #7f8c8d; font-size: 14px;")

        # Add to layout
        header_layout.addWidget(title)
        header_layout.addWidget(description)

        # Add header widget to parent layout
        parent_layout.addWidget(header_widget)

    def create_section_frame(self, parent_layout, title, description):
        """Create a section frame with title and description"""
        section_frame = QFrame()
        section_frame.setObjectName("sectionFrame")
        section_frame.setFrameShape(QFrame.Shape.StyledPanel)
        section_frame.setStyleSheet("""
            #sectionFrame {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
                padding: 5px;
            }
        """)

        section_layout = QVBoxLayout(section_frame)
        section_layout.setContentsMargins(15, 15, 15, 15)
        section_layout.setSpacing(10)

        # Title
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50;")

        # Description
        desc_label = QLabel(description)
        desc_label.setObjectName("sectionDescription")
        desc_label.setStyleSheet("color: #7f8c8d; font-size: 14px;")
        desc_label.setWordWrap(True)

        # Add to layout
        section_layout.addWidget(title_label)
        section_layout.addWidget(desc_label)

        # Content container
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 10, 0, 0)
        content_layout.setSpacing(10)

        # Add content widget to section layout
        section_layout.addWidget(content_widget)

        # Add section to parent layout
        parent_layout.addWidget(section_frame)

        return content_layout

    def create_api_connection_settings(self, parent_layout):
        """Create the API connection settings section"""
        content_layout = self.create_section_frame(
            parent_layout,
            "API Connection",
            "Configure Wazuh API connection settings"
        )

        # Create the form fields
        self.wazuh_url_input = QLineEdit()
        self.wazuh_username_input = QLineEdit()
        self.wazuh_password_input = QLineEdit()
        self.wazuh_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        # Style the form fields
        form_style = """
            QLineEdit {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
                min-height: 16px;
            }
            QLineEdit:focus {
                border: 1px solid #3498db;
            }
        """
        self.wazuh_url_input.setStyleSheet(form_style)
        self.wazuh_username_input.setStyleSheet(form_style)
        self.wazuh_password_input.setStyleSheet(form_style)

        # Set placeholders
        self.wazuh_url_input.setPlaceholderText("Enter Wazuh server URL")
        self.wazuh_username_input.setPlaceholderText("Enter username")
        self.wazuh_password_input.setPlaceholderText("Enter password")

        # Create form layout
        form_layout = QGridLayout()
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(10)

        # Add form fields
        self.add_form_field(form_layout, "Server URL:", self.wazuh_url_input, 0)
        self.add_form_field(form_layout, "Username:", self.wazuh_username_input, 1)
        self.add_form_field(form_layout, "Password:", self.wazuh_password_input, 2)

        # Create form widget
        form_widget = QWidget()
        form_widget.setLayout(form_layout)
        content_layout.addWidget(form_widget)

        # Add buttons layout
        button_layout = QHBoxLayout()

        # Save settings button
        self.wazuh_save_btn = QPushButton("Save Settings")
        self.wazuh_save_btn.setStyleSheet("""
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
        self.wazuh_save_btn.setFixedSize(150, 32)
        self.wazuh_save_btn.clicked.connect(self.on_save_wazuh_settings)

        button_layout.addStretch()
        button_layout.addWidget(self.wazuh_save_btn)
        button_layout.addStretch()

        button_widget = QWidget()
        button_widget.setLayout(button_layout)
        content_layout.addWidget(button_widget)

    def create_agent_settings(self, parent_layout):
        """Create the agent configuration settings section"""
        content_layout = self.create_section_frame(
            parent_layout,
            "Agent Configuration",
            "Configure Wazuh agent connection settings (requires administrator privileges)"
        )

        # Create the form field
        self.agent_ip_input = QLineEdit()
        self.agent_ip_input.setPlaceholderText("Enter Wazuh manager IP")

        # Style the form field
        form_style = """
            QLineEdit {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
                min-height: 16px;
            }
            QLineEdit:focus {
                border: 1px solid #3498db;
            }
        """
        self.agent_ip_input.setStyleSheet(form_style)

        # Create form layout
        form_layout = QGridLayout()
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(10)

        # Add form field
        self.add_form_field(form_layout, "Manager IP:", self.agent_ip_input, 0)

        # Create form widget
        form_widget = QWidget()
        form_widget.setLayout(form_layout)
        content_layout.addWidget(form_widget)

        # Add update button
        button_layout = QHBoxLayout()
        self.agent_update_btn = QPushButton("Update Agent Configuration")
        self.agent_update_btn.setStyleSheet("""
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
        self.agent_update_btn.setFixedSize(250, 32)
        self.agent_update_btn.clicked.connect(self.on_update_agent_config)
        button_layout.addStretch()
        button_layout.addWidget(self.agent_update_btn)
        button_layout.addStretch()

        button_widget = QWidget()
        button_widget.setLayout(button_layout)
        content_layout.addWidget(button_widget)

    def create_shuffle_settings(self, parent_layout):
        """Create the Shuffle SOAR settings section"""
        content_layout = self.create_section_frame(
            parent_layout,
            "Shuffle SOAR Integration",
            "Configure Shuffle SOAR connection settings and select multiple workflows"
        )

        # Create the form fields
        self.shuffle_url_input = QLineEdit()
        self.shuffle_api_key_input = QLineEdit()
        self.shuffle_api_key_input.setEchoMode(QLineEdit.EchoMode.Password)

        # Style the form fields
        form_style = """
            QLineEdit {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 8px;
                min-height: 16px;
            }
            QLineEdit:focus {
                border: 1px solid #3498db;
            }
        """
        self.shuffle_url_input.setStyleSheet(form_style)
        self.shuffle_api_key_input.setStyleSheet(form_style)

        # Set placeholders
        self.shuffle_url_input.setPlaceholderText("Enter Shuffle server URL")
        self.shuffle_api_key_input.setPlaceholderText("Enter Shuffle API key")

        # Create form layout
        form_layout = QGridLayout()
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(10)

        # Add form fields
        self.add_form_field(form_layout, "Server URL:", self.shuffle_url_input, 0)
        self.add_form_field(form_layout, "API Key:", self.shuffle_api_key_input, 1)

        # Create form widget
        form_widget = QWidget()
        form_widget.setLayout(form_layout)
        content_layout.addWidget(form_widget)

        # Add workflow selection section
        workflow_widget = QWidget()
        workflow_layout = QVBoxLayout(workflow_widget)
        workflow_layout.setContentsMargins(0, 10, 0, 0)
        workflow_layout.setSpacing(5)

        # Workflow label
        workflow_label = QLabel("Available Workflows:")
        workflow_label.setStyleSheet("color: #2c3e50; font-weight: bold;")
        workflow_layout.addWidget(workflow_label)

        # Create workflow list widget
        self.workflow_list = QListWidget()
        self.workflow_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.workflow_list.setMaximumHeight(120)
        self.workflow_list.setStyleSheet("""
            QListWidget {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 3px;
                border-bottom: 1px solid #f0f0f0;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #ecf0f1;
            }
            QListWidget::item:selected:hover {
                background-color: #2980b9;
            }
        """)
        workflow_layout.addWidget(self.workflow_list)

        # Selected workflows label
        self.selected_workflows_label = QLabel("Selected: None")
        self.selected_workflows_label.setStyleSheet("color: #7f8c8d; font-size: 12px;")
        self.selected_workflows_label.setWordWrap(True)
        workflow_layout.addWidget(self.selected_workflows_label)

        # Connect selection change
        self.workflow_list.itemSelectionChanged.connect(self.update_selected_workflows_label)

        content_layout.addWidget(workflow_widget)

        # Add buttons layout
        button_layout = QHBoxLayout()

        # Fetch workflows button
        self.fetch_workflows_btn = QPushButton("Fetch Workflows")
        self.fetch_workflows_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
            QPushButton:pressed {
                background-color: #5d6d7e;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.fetch_workflows_btn.setFixedSize(130, 32)
        self.fetch_workflows_btn.clicked.connect(self.on_fetch_workflows)

        # Save settings button
        self.shuffle_save_btn = QPushButton("Save Settings")
        self.shuffle_save_btn.setStyleSheet("""
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
        self.shuffle_save_btn.setFixedSize(150, 32)
        self.shuffle_save_btn.clicked.connect(self.on_save_shuffle_settings)

        button_layout.addStretch()
        button_layout.addWidget(self.fetch_workflows_btn)
        button_layout.addWidget(self.shuffle_save_btn)
        button_layout.addStretch()

        button_widget = QWidget()
        button_widget.setLayout(button_layout)
        content_layout.addWidget(button_widget)

    def add_form_field(self, layout, label_text, input_widget, row):
        """Helper method to add a form field to a layout"""
        label = QLabel(label_text)
        label.setStyleSheet("color: #2c3e50;")
        label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        label.setMinimumWidth(100)

        # Add widgets to layout
        layout.addWidget(label, row, 0)
        layout.addWidget(input_widget, row, 1)

    @pyqtSlot()
    def on_fetch_workflows(self):
        """Fetch available workflows from Shuffle"""
        # Prevent multiple simultaneous fetches
        if self._is_fetching:
            return

        print("Fetching workflows...")

        # Validate inputs
        url = self.shuffle_url_input.text().strip()
        api_key = self.shuffle_api_key_input.text().strip()

        if not url or not api_key:
            QMessageBox.warning(self, "Warning", "Please enter Shuffle URL and API Key first.")
            return

        # Set fetching flag
        self._is_fetching = True

        # Disable button during fetch
        self.fetch_workflows_btn.setEnabled(False)
        self.fetch_workflows_btn.setText("Fetching...")

        if self.controller:
            # Update controller with current values
            self.controller.shuffle_url = url
            self.controller.shuffle_api_key = api_key

            # Run async function
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                workflows = loop.run_until_complete(self.controller.get_available_workflows())

                # Clear and populate list
                self.workflow_list.clear()

                if workflows:
                    for workflow in workflows:
                        item = QListWidgetItem(workflow['name'])
                        item.setData(Qt.ItemDataRole.UserRole, workflow['id'])
                        self.workflow_list.addItem(item)

                        # Select if previously selected
                        if hasattr(self.controller, 'shuffle_workflows') and workflow[
                            'name'] in self.controller.shuffle_workflows:
                            item.setSelected(True)

                    self.update_selected_workflows_label()
                    QMessageBox.information(self, "Success", f"Found {len(workflows)} workflows")
                else:
                    QMessageBox.warning(self, "Warning", "No workflows found or connection failed.")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to fetch workflows: {str(e)}")
            finally:
                loop.close()
                self._is_fetching = False  # Reset flag
                self.fetch_workflows_btn.setEnabled(True)
                self.fetch_workflows_btn.setText("Fetch Workflows")

    def update_selected_workflows_label(self):
        """Update the label showing selected workflows"""
        selected_items = self.workflow_list.selectedItems()
        if selected_items:
            workflow_names = [item.text() for item in selected_items]
            self.selected_workflows_label.setText(f"Selected ({len(workflow_names)}): {', '.join(workflow_names)}")
        else:
            self.selected_workflows_label.setText("Selected: None")

    # Controller interaction methods
    def on_save_wazuh_settings(self):
        """Save Wazuh API settings"""
        print("Saving Wazuh settings...")
        if self.controller:
            settings = {
                "wazuh_url": self.wazuh_url_input.text(),
                "wazuh_username": self.wazuh_username_input.text(),
                "wazuh_password": self.wazuh_password_input.text()
            }

            self.controller.save_settings(settings)
        else:
            print("Warning: No controller available to save settings")

    def on_update_agent_config(self):
        """Update agent configuration"""
        print("Updating agent configuration...")
        if self.controller:
            ip = self.agent_ip_input.text().strip()
            self.controller.update_agent_config(ip)
        else:
            print("Warning: No controller available to update agent")

    def on_save_shuffle_settings(self):
        """Save Shuffle SOAR settings"""
        print("Saving Shuffle settings...")

        # Get selected workflows
        selected_items = self.workflow_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select at least one workflow.")
            return

        selected_workflows = [item.text() for item in selected_items]

        if self.controller:
            settings = {
                "shuffle_url": self.shuffle_url_input.text(),
                "shuffle_api_key": self.shuffle_api_key_input.text(),
                "shuffle_workflows": selected_workflows  # Now a list
            }

            self.controller.save_shuffle_settings(settings)
        else:
            print("Warning: No controller available to save Shuffle settings")

    def get_agent_ip(self):
        """Get the agent IP from the entry field"""
        if hasattr(self, 'agent_ip_input'):
            return self.agent_ip_input.text().strip()
        else:
            print("Error: agent_ip_input not found in SettingsView")
            return None

    def handle_connection_test_result(self, success, message):
        """Handle Wazuh connection test result"""
        if success:
            QMessageBox.information(self, "Connection Test", message)
        else:
            QMessageBox.critical(self, "Connection Test", message)

    def handle_shuffle_test_result(self, success, message):
        """Handle Shuffle connection test result"""
        if success:
            QMessageBox.information(self, "Shuffle Connection Test", message)
        else:
            QMessageBox.critical(self, "Shuffle Connection Test", message)

    def handle_agent_config_update(self, success, message):
        """Handle agent configuration update result"""
        if success:
            QMessageBox.information(self, "Agent Configuration", message)
        else:
            QMessageBox.critical(self, "Agent Configuration", message)

    def update_fields(self, settings):
        """Update the view's fields with values from the controller"""
        print(f"Updating fields with settings: {settings}")

        try:
            # Update Wazuh fields
            if "wazuh_url" in settings:
                self.wazuh_url_input.setText(settings["wazuh_url"])
            if "wazuh_username" in settings:
                self.wazuh_username_input.setText(settings["wazuh_username"])
            if "wazuh_password" in settings:
                self.wazuh_password_input.setText(settings["wazuh_password"])

            # Update Shuffle fields
            if "shuffle_url" in settings:
                self.shuffle_url_input.setText(settings["shuffle_url"])
            if "shuffle_api_key" in settings:
                self.shuffle_api_key_input.setText(settings["shuffle_api_key"])

            # Handle multiple workflows
            if "shuffle_workflows" in settings:
                workflows = settings["shuffle_workflows"]
                if workflows:
                    # Update the label to show saved workflows
                    self.selected_workflows_label.setText(f"Selected ({len(workflows)}): {', '.join(workflows)}")

        except Exception as e:
            print(f"Error updating fields: {e}")

    def show_error(self, title, message):
        """Show error message dialog"""
        print(f"Showing error: {title} - {message}")
        QMessageBox.critical(self, title, message)

    def show_info(self, title, message):
        """Show information message dialog"""
        print(f"Showing info: {title} - {message}")
        QMessageBox.information(self, title, message)

    def refresh(self):
        """Refresh the view's content"""
        print("Refreshing settings view")
        if self.controller:
            self.update_fields(self.controller.get_current_settings())
