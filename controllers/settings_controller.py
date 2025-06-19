# controllers/settings_controller.py
import asyncio
import ctypes
import json
import os
import subprocess
import sys
from datetime import datetime

import aiohttp
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from PyQt6.QtWidgets import QMessageBox
from models.incident_history_model import IncidentHistoryModel
from models.wazuh_config import WazuhConfig
from typing import Callable, List, Dict, Any, Optional
import threading
from utils.config_manager import ConfigManager


def get_app_data_dir():
    """Get or create application data directory"""
    try:
        if sys.platform == "win32":
            app_data = os.path.join(os.environ['APPDATA'], 'Guardian')
        else:
            app_data = os.path.join(os.path.expanduser('~'), '.guardian')

        # Create directory if it doesn't exist
        os.makedirs(app_data, exist_ok=True)

        # Define config file paths
        wazuh_config = os.path.join(app_data, 'wazuh_config.json')
        shuffle_config = os.path.join(app_data, 'shuffle_config.json')

        # Initialize empty config files if they don't exist
        for config_file in [wazuh_config, shuffle_config]:
            if not os.path.exists(config_file):
                with open(config_file, 'w') as f:
                    json.dump({}, f)

        return app_data
    except Exception as e:
        print(f"Error creating app data directory: {e}")
        return None


class SettingsController(QObject):
    # Define signals for PyQt6
    config_changed = pyqtSignal(object)
    agent_config_updated = pyqtSignal(bool, str)

    def __init__(self):
        super().__init__()
        print("Initializing SettingsController...")
        self.app_data_dir = get_app_data_dir()
        self.wazuh_config_path = os.path.join(self.app_data_dir, 'wazuh_config.json')
        self.shuffle_config_path = os.path.join(self.app_data_dir, 'shuffle_config.json')
        self.config_manager = ConfigManager()
        self.wazuh_config = self.config_manager.wazuh_config
        self.incident_model = self.config_manager.incident_model

        # UI Variables - Using regular Python attributes instead of ctk.StringVar
        self.wazuh_url = ""
        self.wazuh_username = ""
        self.wazuh_password = ""

        # UI Variables for Shuffle
        self.shuffle_url = ""
        self.shuffle_api_key = ""
        self.shuffle_workflows = []

        # For tracking connection test status
        self.is_testing = False

        # Agent Configuration initialization
        self.agent_config_path = self.get_agent_config_path()
        self.view = None

        # Load any existing configurations
        self.load_existing_configurations()
        print("SettingsController initialized")

    def load_existing_configurations(self):
        """Load existing configurations if they exist"""
        try:
            print("Loading existing configurations...")

            # Load Wazuh config
            wazuh_config_path = os.path.join(self.app_data_dir, 'wazuh_config.json')
            if os.path.exists(wazuh_config_path):
                print(f"Loading Wazuh config from: {wazuh_config_path}")
                self.wazuh_config = WazuhConfig.load_from_file(wazuh_config_path)
                if self.wazuh_config.is_configured:
                    self.wazuh_url = self.wazuh_config.url
                    self.wazuh_username = self.wazuh_config.username
                    self.wazuh_password = self.wazuh_config.password
                    print("Wazuh config loaded successfully")

            # Load Shuffle config
            shuffle_config_path = os.path.join(self.app_data_dir, 'shuffle_config.json')
            if os.path.exists(shuffle_config_path):
                print(f"Loading Shuffle config from: {shuffle_config_path}")
                self.incident_model = IncidentHistoryModel.load_from_file(shuffle_config_path)
                if self.incident_model.is_configured:
                    self.shuffle_url = self.incident_model.shuffle_url
                    self.shuffle_api_key = self.incident_model.shuffle_api_key
                    self.shuffle_workflows = self.incident_model.workflow_names  # Changed from workflow_name
                    print("Shuffle config loaded successfully")

        except Exception as e:
            print(f"Error loading configurations: {e}")

    def set_view(self, view):
        """Set the view for this controller"""
        self.view = view
        # Update the view with current settings
        if hasattr(view, 'update_fields'):
            view.update_fields(self.get_current_settings())
        print("View set for SettingsController")

    def get_current_settings(self) -> Dict[str, Any]:
        """Return current settings as a dictionary for populating the view"""
        return {
            "wazuh_url": self.wazuh_url,
            "wazuh_username": self.wazuh_username,
            "wazuh_password": self.wazuh_password,
            "shuffle_url": self.shuffle_url,
            "shuffle_api_key": self.shuffle_api_key,
            "shuffle_workflows": self.shuffle_workflows  # Changed to list
        }

    def save_settings(self, settings: Dict[str, Any]) -> bool:
        """Saves Wazuh settings after validation"""
        try:
            # Update instance variables with new values from view
            self.wazuh_url = settings.get("wazuh_url", "").strip()
            self.wazuh_username = settings.get("wazuh_username", "").strip()
            self.wazuh_password = settings.get("wazuh_password", "").strip()

            if not self.validate_settings():
                return False

            # Create new config with current values
            new_config = WazuhConfig(
                url=self.wazuh_url,
                username=self.wazuh_username,
                password=self.wazuh_password,
                suspicious_paths=self.wazuh_config.suspicious_paths,
                last_modified=datetime.now()
            )

            # Save configuration first
            config_path = os.path.join(self.app_data_dir, 'wazuh_config.json')
            if new_config.save_to_file(config_path):
                # Update the config manager directly
                self.config_manager.update_wazuh_config(new_config)

                # Test connection after saving
                if new_config.validate_connection():
                    self.wazuh_config = new_config
                    # No need to notify observers - the config manager already did that
                    QMessageBox.information(None, "Success", "Settings saved and connection verified!")
                    self.config_changed.emit(new_config)
                    return True
                else:
                    # Still update wazuh_config for consistency, even if connection failed
                    self.wazuh_config = new_config
                    QMessageBox.warning(None, "Warning", "Settings saved but connection test failed.")
                    self.config_changed.emit(new_config)
                    return True

            QMessageBox.critical(None, "Error", "Failed to save settings!")
            return False

        except Exception as e:
            print(f"Error saving settings: {e}")
            QMessageBox.critical(None, "Error", f"Failed to save settings: {str(e)}")
            return False

    def validate_settings(self) -> bool:
        """Validates the current settings"""
        if not self.wazuh_url:
            QMessageBox.critical(None, "Error", "Wazuh URL cannot be empty!")
            return False

        if not self.wazuh_username:
            QMessageBox.critical(None, "Error", "Username cannot be empty!")
            return False

        if not self.wazuh_password:
            QMessageBox.critical(None, "Error", "Password cannot be empty!")
            return False

        return True

    def get_agent_config_path(self):
        """Get the path to the Wazuh agent configuration file"""
        if sys.platform == "win32":
            return "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"
        return "/var/ossec/etc/ossec.conf"

    def is_admin(self):
        """Check if the program has administrator privileges"""
        try:
            if sys.platform == "win32":
                return ctypes.windll.shell32.IsUserAnAdmin()
            return os.geteuid() == 0
        except:
            return False

    def update_agent_config(self, manager_ip: str):
        """Update the Wazuh agent configuration with proper UI feedback"""
        if not manager_ip:
            self.agent_config_updated.emit(False, "Please enter a valid manager IP address")
            return

        # Show a warning that this operation requires admin privileges
        reply = QMessageBox.question(
            None,
            "Administrator Privileges Required",
            "Updating the agent configuration requires administrator privileges. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.No:
            return

        # Start the update in a separate thread to keep UI responsive
        thread = threading.Thread(target=self.update_config_thread, args=(manager_ip,))
        thread.daemon = True
        thread.start()

    def update_config_thread(self, manager_ip):
        try:
            print(f"Starting configuration update for IP: {manager_ip}")

            # Create backup
            print("Creating backup...")
            self.backup_agent_config()

            # Modify configuration
            print("Modifying configuration...")
            self.modify_agent_config(manager_ip)

            # Restart service
            print("Restarting service...")
            self.restart_agent_service()

            # Verify the change
            print("Verifying changes...")
            with open(self.agent_config_path, 'r') as f:
                content = f.read()
                if manager_ip not in content:
                    raise Exception("Failed to verify IP address change in configuration")

            # Show success message
            # Use signal to communicate with UI thread
            self.agent_config_updated.emit(True,
                                           "Agent configuration updated successfully. The agent will restart to apply changes.")

        except Exception as e:
            # Use signal to communicate with UI thread
            self.agent_config_updated.emit(False, f"Failed to update agent configuration: {str(e)}")
            print(f"Error updating agent config: {str(e)}")

    def check_file_permissions(self):
        """Check if we have the necessary permissions to modify the config file"""
        try:
            # Check if file exists
            if not os.path.exists(self.agent_config_path):
                return False, "Configuration file not found"

            # Check read permission
            if not os.access(self.agent_config_path, os.R_OK):
                return False, "No read permission"

            # Check write permission
            if not os.access(self.agent_config_path, os.W_OK):
                return False, "No write permission"

            return True, "Permissions OK"
        except Exception as e:
            return False, str(e)

    def backup_agent_config(self):
        """Create a backup of the current agent configuration"""
        try:
            import shutil
            backup_path = f"{self.agent_config_path}.backup"
            shutil.copy2(self.agent_config_path, backup_path)
        except Exception as e:
            raise Exception(f"Failed to create backup: {str(e)}")

    def modify_agent_config(self, new_ip):
        """Modify the agent configuration file with the new IP"""
        try:
            import xml.etree.ElementTree as ET

            # Parse the configuration file
            tree = ET.parse(self.agent_config_path)
            root = tree.getroot()

            # Find and update the manager IP address
            for client in root.findall(".//client"):
                for server in client.findall("server"):
                    ip_elem = server.find("address")
                    if ip_elem is not None:
                        ip_elem.text = new_ip

            # Save the modified configuration
            tree.write(self.agent_config_path)

        except Exception as e:
            raise Exception(f"Failed to modify configuration: {str(e)}")

    def restart_agent_service(self):
        """Restart the Wazuh agent service"""
        try:
            if sys.platform == "win32":
                # Use subprocess.CREATE_NO_WINDOW to hide the CMD window
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

                # Stop service
                subprocess.run(
                    ["net", "stop", "WazuhSvc"],
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    check=True
                )

                # Start service
                subprocess.run(
                    ["net", "start", "WazuhSvc"],
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    check=True
                )
            else:
                subprocess.run(["systemctl", "restart", "wazuh-agent"], check=True)
        except Exception as e:
            raise Exception(f"Failed to restart agent service: {str(e)}")

    def save_shuffle_settings(self, settings: Dict[str, Any]) -> bool:
        """Saves Shuffle settings after validation"""
        try:
            print("Attempting to save Shuffle settings...")

            # Update instance variables with new values
            raw_url = settings.get("shuffle_url", "").strip()
            self.shuffle_api_key = settings.get("shuffle_api_key", "").strip()
            self.shuffle_workflows = settings.get("shuffle_workflows", [])

            # Validate inputs
            if not raw_url or not self.shuffle_api_key:
                QMessageBox.critical(None, "Error", "URL and API Key are required!")
                return False

            # Process the URL based on port
            if not raw_url.startswith(('http://', 'https://')):
                if ':3443' in raw_url:
                    # User wants HTTPS (webhook port)
                    self.shuffle_url = f"https://{raw_url}"
                else:
                    # Default to HTTP on port 3001
                    base_ip = raw_url.split(':')[0]
                    self.shuffle_url = f"http://{base_ip}:3001"
            else:
                self.shuffle_url = raw_url

            # Workflows are optional
            if not self.shuffle_workflows:
                response = QMessageBox.question(
                    None,
                    "No Workflows Selected",
                    "No workflows selected. Save connection settings anyway?\n\nYou can select workflows later.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if response == QMessageBox.StandardButton.No:
                    return False

            print(f"Processed Shuffle URL: {self.shuffle_url}")
            print(f"Selected workflows: {self.shuffle_workflows}")

            # Update incident model configuration
            updated_model = IncidentHistoryModel(
                shuffle_url=self.shuffle_url,
                shuffle_api_key=self.shuffle_api_key,
                workflow_names=self.shuffle_workflows,
                is_configured=bool(self.shuffle_url and self.shuffle_api_key),
                last_modified=datetime.now()
            )

            # Save to file
            config_path = os.path.join(self.app_data_dir, 'shuffle_config.json')
            print(f"Saving to path: {config_path}")

            if updated_model.save_to_file(config_path):
                print("Save successful")

                # Update the config manager
                self.config_manager.update_shuffle_config(updated_model)

                # Update local incident model
                self.incident_model = updated_model

                # Emit signal about the change
                self.config_changed.emit(updated_model)

                if self.shuffle_workflows:
                    QMessageBox.information(None, "Success",
                                            f"Shuffle settings saved successfully!\n{len(self.shuffle_workflows)} "
                                            f"workflow(s) configured.")
                else:
                    QMessageBox.information(None, "Success",
                                            "Shuffle connection settings saved!\n\nClick 'Fetch Workflows' to select "
                                            "workflows.")
                return True

            print("Save failed")
            QMessageBox.critical(None, "Error", "Failed to save Shuffle settings!")
            return False

        except Exception as e:
            print(f"Error saving Shuffle settings: {e}")
            QMessageBox.critical(None, "Error", f"Failed to save Shuffle settings: {str(e)}")
            return False

    async def get_available_workflows(self):
        """Fetch all available workflows from Shuffle"""
        try:
            if not self.shuffle_url or not self.shuffle_api_key:
                return []

            url = self.shuffle_url

            # Process URL if it doesn't have protocol
            if not url.startswith(('http://', 'https://')):
                if ':3443' in url:
                    url = f"https://{url}"
                else:
                    base_ip = url.split(':')[0]
                    url = f"http://{base_ip}:3001"

            headers = {
                "Authorization": f"Bearer {self.shuffle_api_key}",
                "Content-Type": "application/json"
            }

            # Create SSL context for HTTPS
            ssl_context = None
            if url.startswith('https://'):
                import ssl
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            async with aiohttp.ClientSession() as session:
                api_url = f"{url}/api/v1/workflows"
                print(f"Fetching workflows from: {api_url}")

                async with session.get(api_url, headers=headers, ssl=ssl_context) as response:
                    if response.status == 200:
                        workflows = await response.json()
                        return [{"name": w.get("name"), "id": w.get("id")} for w in workflows]
                    else:
                        print(f"Failed to fetch workflows: {response.status}")
                        error_text = await response.text()
                        print(f"Error response: {error_text}")
                        return []
        except Exception as e:
            print(f"Error fetching available workflows: {e}")
            import traceback
            traceback.print_exc()
            return []

    def update_from_view(self, settings: Dict[str, Any]):
        """Update controller data from view inputs"""
        # Update Wazuh settings
        if "wazuh_url" in settings:
            self.wazuh_url = settings["wazuh_url"]
        if "wazuh_username" in settings:
            self.wazuh_username = settings["wazuh_username"]
        if "wazuh_password" in settings:
            self.wazuh_password = settings["wazuh_password"]

        # Update Shuffle settings
        if "shuffle_url" in settings:
            self.shuffle_url = settings["shuffle_url"]
        if "shuffle_api_key" in settings:
            self.shuffle_api_key = settings["shuffle_api_key"]
        if "shuffle_workflows" in settings:
            self.shuffle_workflows = settings["shuffle_workflows"]
