# models/wazuh_config.py
import sys
from dataclasses import dataclass, field
from typing import List, Optional
import json
import os
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
import urllib3


@dataclass
class WazuhConfig:
    url: str = field(default="")
    username: str = field(default="")
    password: str = field(default="")
    suspicious_paths: List[str] = field(default_factory=lambda: [
        "system32", "program files", "windows", "desktop",
        "documents", "downloads", "pictures",
        "appdata\\local", "appdata\\roaming"
    ])
    last_modified: datetime = field(default_factory=datetime.now)
    is_configured: bool = field(default=False)

    def __post_init__(self):
        """Post initialization validation and setup"""
        # Clean up URL format
        if self.url:
            # Remove any existing protocol
            url = self.url.replace('http://', '').replace('https://', '')
            # Remove any existing port
            if ':' in url:
                host = url.split(':')[0]
                self.url = host  # Store just the host
            else:
                self.url = url

        self.is_configured = all([
            self.url,
            self.username,
            self.password
        ])

    def get_base_url(self) -> str:
        """Returns properly formatted base URL"""
        if not self.url:
            return ""
        return f"https://{self.url}:55000"

    @classmethod
    def create_empty(cls) -> 'WazuhConfig':
        """Creates a new instance with empty credentials"""
        return cls()

    @classmethod
    def load_from_file(cls, filepath: str = "wazuh_config.json") -> 'WazuhConfig':
        """Loads configuration from file or returns empty config if file doesn't exist"""
        try:
            if os.path.exists(filepath):
                print(f"Loading configuration from {filepath}")
                with open(filepath, 'r') as f:
                    config_data = json.load(f)
                    print(f"Loaded config data: {config_data}")

                    # Convert last_modified string to datetime
                    if 'last_modified' in config_data:
                        config_data['last_modified'] = datetime.fromisoformat(
                            config_data['last_modified']
                        )

                    return cls(**config_data)
            print(f"No configuration file found at {filepath}, creating empty configuration")
            return cls.create_empty()
        except Exception as e:
            print(f"Error loading Wazuh config: {e}")
            return cls.create_empty()

    def save_to_file(self, filepath: str = None) -> bool:
        """Saves current configuration to file"""
        try:
            if filepath is None:
                # Get the default config path
                app_data = os.path.join(os.environ['APPDATA'], 'Guardian') if sys.platform == "win32" \
                    else os.path.join(os.path.expanduser('~'), '.guardian')
                filepath = os.path.join(app_data, 'wazuh_config.json')

            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            config_dict = {
                "url": self.url,
                "username": self.username,
                "password": self.password,
                "suspicious_paths": self.suspicious_paths,
                "last_modified": self.last_modified.isoformat(),
                "is_configured": self.is_configured
            }

            with open(filepath, 'w') as f:
                json.dump(config_dict, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def validate_connection(self) -> bool:
        """Validates the Wazuh connection"""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            base_url = self.get_base_url()
            if not base_url:
                print("Invalid base URL")
                return False

            print(f"\nTesting connection to: {base_url}")

            # Step 1: Authenticate
            auth_endpoint = f"{base_url}/security/user/authenticate"
            auth_response = requests.get(
                auth_endpoint,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False,
                timeout=5
            )

            if auth_response.status_code != 200:
                print(f"Authentication failed: {auth_response.text}")
                return False

            try:
                auth_data = auth_response.json()
                token = auth_data.get('data', {}).get('token')
                print(f"Token received: {'Yes' if token else 'No'}")
            except json.JSONDecodeError as e:
                print(f"Failed to parse authentication response: {e}")
                return False

            if not token:
                print("No token received")
                return False

            # Step 2: Test API access with token
            headers = {'Authorization': f'Bearer {token}'}
            test_endpoint = f"{base_url}/manager/info"
            print(f"Testing API access at: {test_endpoint}")

            test_response = requests.get(
                test_endpoint,
                headers=headers,
                verify=False,
                timeout=5
            )

            print(f"Test response status: {test_response.status_code}")
            print(f"Test response content: {test_response.text}")

            if test_response.status_code != 200:
                print(f"API test failed: {test_response.text}")
                return False

            self.is_configured = True
            print("Connection test successful")
            return True

        except requests.exceptions.RequestException as e:
            print(f"Connection error: {str(e)}")
            print(f"Error type: {type(e).__name__}")
            if isinstance(e, requests.exceptions.ConnectionError):
                print("Failed to establish connection. Check if the server is reachable.")
            elif isinstance(e, requests.exceptions.Timeout):
                print("Connection timed out. Server might be slow or unreachable.")
            elif isinstance(e, requests.exceptions.SSLError):
                print("SSL verification failed. Check your SSL settings.")
            return False
        except Exception as e:
            print(f"Validation error: {str(e)}")
            print(f"Error type: {type(e).__name__}")
            return False

    def add_suspicious_path(self, path: str) -> bool:
        """Add a new suspicious path and save the configuration"""
        print(f"Adding suspicious path: {path}")
        if path and path not in self.suspicious_paths:
            self.suspicious_paths.append(path)
            return self.save_to_file()
        return False

    def remove_suspicious_path(self, path: str) -> bool:
        """Remove a suspicious path and save the configuration"""
        print(f"Removing suspicious path: {path}")
        if path in self.suspicious_paths:
            self.suspicious_paths.remove(path)
            return self.save_to_file()
        return False