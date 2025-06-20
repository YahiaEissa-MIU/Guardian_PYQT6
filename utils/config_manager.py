# utils/config_manager.py
from models.wazuh_config import WazuhConfig
from models.incident_history_model import IncidentHistoryModel
import os
import sys
import json
from datetime import datetime
import logging


class ConfigManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize configuration manager"""
        print("Initializing ConfigManager...")
        if sys.platform == "win32":
            self.app_data_dir = os.path.join(os.environ['APPDATA'], 'Guardian')
        else:
            self.app_data_dir = os.path.join(os.path.expanduser('~'), '.guardian')

        os.makedirs(self.app_data_dir, exist_ok=True)

        self.wazuh_config_path = os.path.join(self.app_data_dir, 'wazuh_config.json')
        self.shuffle_config_path = os.path.join(self.app_data_dir, 'shuffle_config.json')

        # Load configurations
        print("Loading configurations in ConfigManager...")
        self.wazuh_config = self._load_wazuh_config()
        self.incident_model = self._load_shuffle_config()

        # Observer lists
        self.wazuh_observers = []
        self.shuffle_observers = []

        print("ConfigManager initialization complete")

    # In ConfigManager class

    def _load_wazuh_config(self):
        """Load Wazuh configuration with proper error handling"""
        try:
            print(f"Loading Wazuh config from: {self.wazuh_config_path}")
            if os.path.exists(self.wazuh_config_path) and os.path.getsize(self.wazuh_config_path) > 0:
                with open(self.wazuh_config_path, 'r') as f:
                    try:
                        config_data = json.load(f)
                        print(f"Loaded Wazuh config data: {config_data}")

                        # Handle missing or invalid date format
                        last_modified = datetime.now()
                        if 'last_modified' in config_data:
                            try:
                                last_modified = datetime.fromisoformat(config_data['last_modified'])
                            except (ValueError, TypeError):
                                pass

                        config = WazuhConfig(
                            url=config_data.get('url', ''),
                            username=config_data.get('username', ''),
                            password=config_data.get('password', ''),
                            suspicious_paths=config_data.get('suspicious_paths', []),
                            last_modified=last_modified,
                            is_configured=config_data.get('is_configured', False)
                        )

                        # Additional validity check
                        if config.url and config.username and config.password:
                            config.is_configured = True
                            print("Loaded configured Wazuh config")
                            return config
                    except json.JSONDecodeError:
                        print("Invalid JSON in Wazuh config file")

            print("Creating new empty Wazuh configuration")
            return WazuhConfig.create_empty()
        except Exception as e:
            print(f"Error loading Wazuh config: {e}")
            return WazuhConfig.create_empty()

    def _load_shuffle_config(self):
        """Load Shuffle configuration with proper error handling"""
        try:
            print(f"Loading Shuffle config from: {self.shuffle_config_path}")
            if os.path.exists(self.shuffle_config_path):
                with open(self.shuffle_config_path, 'r') as f:
                    config_data = json.load(f)
                    print(f"Loaded Shuffle config data: {config_data}")

                    # Handle backward compatibility
                    workflow_names = config_data.get('workflow_names', [])
                    if not workflow_names and 'workflow_name' in config_data:
                        # Convert old single workflow to list
                        workflow_names = [config_data['workflow_name']]

                    model = IncidentHistoryModel(
                        shuffle_url=config_data.get('shuffle_url', ''),
                        shuffle_api_key=config_data.get('shuffle_api_key', ''),
                        workflow_names=workflow_names,  # Changed from workflow_name
                        last_modified=datetime.fromisoformat(
                            config_data.get('last_modified', datetime.now().isoformat())
                        ),
                        is_configured=config_data.get('is_configured', False)
                    )

                    if model.is_configured:
                        print("Loaded configured Shuffle model")
                        return model

            print("Creating new empty Shuffle configuration")
            return IncidentHistoryModel.create_empty()
        except Exception as e:
            print(f"Error loading Shuffle config: {e}")
            return IncidentHistoryModel.create_empty()

    def update_wazuh_config(self, new_config: WazuhConfig):
        """Update Wazuh configuration and notify observers"""
        try:
            print("Updating Wazuh configuration...")
            self.wazuh_config = new_config

            # Ensure the configuration is marked as configured if valid
            self.wazuh_config.is_configured = bool(
                self.wazuh_config.url and
                self.wazuh_config.username and
                self.wazuh_config.password
            )

            # Save to file
            config_dict = {
                "url": self.wazuh_config.url,
                "username": self.wazuh_config.username,
                "password": self.wazuh_config.password,
                "suspicious_paths": self.wazuh_config.suspicious_paths,
                "last_modified": datetime.now().isoformat(),
                "is_configured": self.wazuh_config.is_configured
            }

            with open(self.wazuh_config_path, 'w') as f:
                json.dump(config_dict, f, indent=4)

            print("Wazuh configuration updated and saved")
            self.notify_wazuh_observers()

        except Exception as e:
            print(f"Error updating Wazuh config: {e}")
            logging.error(f"Error updating Wazuh config: {e}")

    def update_shuffle_config(self, new_config: IncidentHistoryModel):
        """Update Shuffle configuration and notify observers"""
        try:
            print("Updating Shuffle configuration...")
            self.incident_model = new_config

            # Ensure the configuration is marked as configured if valid
            self.incident_model.is_configured = bool(
                self.incident_model.shuffle_url and
                self.incident_model.shuffle_api_key
                # Note: workflows are optional now
            )

            # Save to file
            config_dict = {
                "shuffle_url": self.incident_model.shuffle_url,
                "shuffle_api_key": self.incident_model.shuffle_api_key,
                "workflow_names": self.incident_model.workflow_names,  # Changed from workflow_name
                "last_modified": datetime.now().isoformat(),
                "is_configured": self.incident_model.is_configured
            }

            with open(self.shuffle_config_path, 'w') as f:
                json.dump(config_dict, f, indent=4)

            print("Shuffle configuration updated and saved")
            self.notify_shuffle_observers()

        except Exception as e:
            print(f"Error updating Shuffle config: {e}")
            logging.error(f"Error updating Shuffle config: {e}")

    def add_wazuh_observer(self, observer):
        """Add observer for Wazuh configuration changes"""
        if observer not in self.wazuh_observers:
            print(f"Adding Wazuh observer: {observer}")
            self.wazuh_observers.append(observer)

    def add_shuffle_observer(self, observer):
        """Add observer for Shuffle configuration changes"""
        if observer not in self.shuffle_observers:
            print(f"Adding Shuffle observer: {observer}")
            self.shuffle_observers.append(observer)

    def remove_wazuh_observer(self, observer):
        """Remove observer for Wazuh configuration changes"""
        if observer in self.wazuh_observers:
            print(f"Removing Wazuh observer: {observer}")
            self.wazuh_observers.remove(observer)

    def remove_shuffle_observer(self, observer):
        """Remove observer for Shuffle configuration changes"""
        if observer in self.shuffle_observers:
            print(f"Removing Shuffle observer: {observer}")
            self.shuffle_observers.remove(observer)

    def notify_wazuh_observers(self):
        """Notify all Wazuh configuration observers"""
        print(f"Notifying {len(self.wazuh_observers)} Wazuh observers")
        for observer in self.wazuh_observers:
            try:
                observer(self.wazuh_config)
                print(f"Successfully notified Wazuh observer: {observer}")
            except Exception as e:
                print(f"Error notifying Wazuh observer {observer}: {e}")
                logging.error(f"Error notifying Wazuh observer: {e}")

    def notify_shuffle_observers(self):
        """Notify all Shuffle configuration observers"""
        print(f"Notifying {len(self.shuffle_observers)} Shuffle observers")
        for observer in self.shuffle_observers:
            try:
                observer(self.incident_model)
                print(f"Successfully notified Shuffle observer: {observer}")
            except Exception as e:
                print(f"Error notifying Shuffle observer {observer}: {e}")
                logging.error(f"Error notifying Shuffle observer: {e}")

    def get_wazuh_config(self):
        """Get current Wazuh configuration"""
        return self.wazuh_config

    def get_shuffle_config(self):
        """Get current Shuffle configuration"""
        return self.incident_model

    def reset_wazuh_config(self):
        """Reset Wazuh configuration to empty state"""
        self.wazuh_config = WazuhConfig.create_empty()
        self.update_wazuh_config(self.wazuh_config)

    def reset_shuffle_config(self):
        """Reset Shuffle configuration to empty state"""
        self.incident_model = IncidentHistoryModel.create_empty()
        self.update_shuffle_config(self.incident_model)