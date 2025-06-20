# controllers/alerts_controller.py

import requests
import urllib3
from datetime import datetime, timedelta
import logging

from PyQt6.QtCore import QTimer

from utils.alert_manager import AlertManager
from utils.config_manager import ConfigManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class AlertsController:
    def __init__(self, view=None):
        print("Initializing AlertsController...")
        self.alert_manager = AlertManager.get_instance()
        self.view = view
        self.config_manager = ConfigManager()
        self.wazuh_config = self.config_manager.get_wazuh_config()
        self._token = None
        self._token_timestamp = None
        self.windows_agent_id = None

        # First disconnect to avoid multiple connections
        try:
            self.alert_manager.alerts_updated.disconnect(self.on_alerts_updated)
        except Exception:
            # Ignore if not already connected
            pass

        # Connect with a direct reference to the method
        print("AlertsController: Explicitly connecting to alerts_updated signal")
        self.alert_manager.alerts_updated.connect(self.on_alerts_updated)

        # Also add as observer for backward compatibility
        print("AlertsController: Adding as observer to alert_manager")
        self.alert_manager.add_observer(self)

        # Also add as observer for backward compatibility
        self.alert_manager.add_observer(self)

        # Track whether an update is already pending
        self._update_pending = False

        # Register with config manager to get updates
        self.config_manager.add_wazuh_observer(self.on_config_change)

        # Create a persistent session
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 5

        # Initialize with system checks if config exists
        if self.wazuh_config and self.wazuh_config.url:
            self.get_windows_agent_id()

    # Add a callback for alerts_updated signal
    def on_alerts_updated(self):
        """Called when alerts are acknowledged"""
        print("AlertsController: Received alerts_updated signal!")

        if not self.view:
            print("AlertsController: View not available for refresh")
            return

        try:
            # Use QTimer to ensure this happens outside the signal handler context
            from PyQt6.QtCore import QTimer

            # Store a flag to track whether update is pending
            if not hasattr(self, '_update_pending') or not self._update_pending:
                self._update_pending = True
                print("AlertsController: Scheduling deferred update_alerts")
                QTimer.singleShot(100, self._perform_deferred_update)
            else:
                print("AlertsController: Update already pending, not scheduling another")

        except Exception as e:
            print(f"AlertsController: Error in on_alerts_updated: {e}")
            import traceback
            traceback.print_exc()

    def _perform_deferred_update(self):
        """Execute the deferred update with proper error handling"""
        try:
            print("AlertsController: Executing deferred update_alerts")
            self._update_pending = False

            if self.view:
                # This should call the view's update_alerts method
                self.update_alerts()
            else:
                print("AlertsController: View no longer available for update")

        except Exception as e:
            print(f"AlertsController: Error in deferred update: {e}")
            self._update_pending = False
            import traceback
            traceback.print_exc()

    def _safe_update_alerts(self):
        """Safely update alerts with error handling"""
        try:
            print("AlertsController: Executing deferred update_alerts")
            if self.view:
                self.update_alerts()
            else:
                print("AlertsController: View no longer available for deferred update")
        except Exception as e:
            print(f"AlertsController: Error in _safe_update_alerts: {e}")

    def set_view(self, view):
        """Set the view and trigger initial update"""
        print(f"AlertsController: Setting view {id(view)}")
        self.view = view

        # Pass alert manager to view if available
        if self.view and hasattr(self.view, 'set_alert_manager'):
            self.view.set_alert_manager(self.alert_manager)

        # Initial update
        if self.view:
            self.update_alerts()

    def get_wazuh_token(self):
        """Get authentication token from Wazuh"""
        try:
            if self._token and self._token_timestamp:
                if (datetime.now() - self._token_timestamp).seconds < 3000:
                    return self._token

            if not self.wazuh_config or not self.wazuh_config.url:
                print("No valid configuration available")
                return None

            print("Requesting new Wazuh token...")

            # Fix URL format handling
            url = self.wazuh_config.url.strip()
            # Remove protocol if present
            if url.startswith(('http://', 'https://')):
                url = url.split('://', 1)[1]

            # Format base URL correctly
            base_url = f"https://{url}"
            if not ':' in url:  # No port specified
                base_url = f"{base_url}:55000"

            print(f"Using base URL: {base_url}")  # Debug output

            response = self.session.post(
                f"{base_url}/security/user/authenticate",
                auth=(self.wazuh_config.username, self.wazuh_config.password)
            )

            if response.status_code == 200:
                self._token = response.json()['data']['token']
                self._token_timestamp = datetime.now()
                self.session.headers.update({'Authorization': f'Bearer {self._token}'})
                print("Successfully obtained token")
                return self._token

            print(f"Failed to get token. Status: {response.status_code}")
            return None
        except Exception as e:
            print(f"Error getting token: {e}")
            return None

    def get_windows_agent_id(self):
        """Get the ID of the Windows agent"""
        try:
            if self.windows_agent_id:  # Return if already set
                return self.windows_agent_id

            if self.get_wazuh_token():
                queries = [
                    {'q': 'os.platform=windows', 'select': 'id,name,os'},
                    {'q': 'os.name=windows', 'select': 'id,name,os'},
                    None  # Try without filter as last resort
                ]

                for query in queries:
                    response = self.fetch_data('agents', query)
                    if response and 'data' in response:
                        agents = response['data'].get('affected_items', [])
                        for agent in agents:
                            if agent.get('os', {}).get('platform') == 'windows' or \
                                    agent.get('os', {}).get('name', '').lower() == 'windows':
                                self.windows_agent_id = agent['id']
                                print(f"Found Windows agent with ID: {self.windows_agent_id}")
                                return self.windows_agent_id

                print("No Windows agents found")
            return None
        except Exception as e:
            print(f"Error fetching agents: {e}")
            return None

    def fetch_data(self, endpoint, params=None):
        """Fetch data from Wazuh API with error handling"""
        try:
            if not self._token:
                if not self.get_wazuh_token():
                    return None

            base_url = f"https://{self.wazuh_config.url}"
            if not base_url.endswith(':55000'):
                base_url = f"{base_url}:55000"

            response = self.session.get(
                f"{base_url}/{endpoint}",
                params=params
            )

            if response.status_code == 200:
                return response.json()
            print(f"Error response from {endpoint}: {response.status_code}")
            return None
        except Exception as e:
            print(f"Error fetching {endpoint}: {e}")
            return None

    # AlertsController.py - Update the update_alerts method to match Dashboard
    def update_alerts(self):
        """Update alerts display using immediate checks"""
        print("\n=== Starting Alerts Update ===")
        print("AlertsController: Initializing alerts update process...")

        if not self.view:
            print("Error: View not set")
            return

        try:
            all_alerts = []
            windows_id = self.get_windows_agent_id()

            if windows_id and self.get_wazuh_token():
                print(f"Fetching alerts for Windows agent ID: {windows_id}")

                # CRITICAL: Match exact query parameters used in dashboard
                syscheck_response = self.fetch_data(f'syscheck/{windows_id}', {
                    'limit': 100,  # Match dashboard's limit
                    'sort': 'date'  # Match dashboard's sort order (ascending, not descending)
                })

                if syscheck_response and 'data' in syscheck_response:
                    items = syscheck_response['data'].get('affected_items', [])
                    print(f"Found {len(items)} potential alerts")
                    suspicious_count = 0
                    acknowledged_count = 0

                    # Debug counters by severity
                    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

                    for item in items:
                        # Use IDENTICAL filtering logic as dashboard
                        file_path = item.get('file', '').lower()
                        event_type = item.get('type', '').lower()
                        timestamp_str = item.get('date', '')

                        # Format alert ID exactly as dashboard does
                        alert_id = f"{timestamp_str}_{file_path}"

                        # Check acknowledgment exactly as dashboard does
                        if self.alert_manager.is_acknowledged(alert_id):
                            acknowledged_count += 1
                            print(f"Skipping acknowledged alert: {alert_id}")
                            continue

                        # Process alert with EXACTLY matching logic from DashboardController._get_all_alerts
                        is_suspicious = False
                        severity = "low"
                        alert_type = "File Change"

                        # Check suspicious paths exactly as dashboard
                        if any(path in file_path for path in self.wazuh_config.suspicious_paths):
                            is_suspicious = True
                            severity = "medium"
                            description = "Suspicious Path Access"

                        # Check event type exactly as dashboard
                        if event_type in ['modified', 'deleted']:
                            is_suspicious = True
                            severity = "high"
                            description = f"File {event_type.capitalize()}"

                        # Check for ransomware indicators exactly as dashboard
                        if 'readme' in file_path and 'ransom' in file_path:
                            is_suspicious = True
                            severity = "critical"
                            description = "Ransomware Note Detected"

                        # Only add if suspicious (identical to dashboard logic)
                        if is_suspicious:
                            suspicious_count += 1
                            formatted_timestamp = self.format_timestamp(timestamp_str)

                            # Count for debugging
                            severity_counts[severity] += 1

                            # Create alert object
                            alert = {
                                "id": alert_id,
                                "timestamp": formatted_timestamp,
                                "severity": severity,
                                "description": description,
                                "location": file_path,
                                "source": "Wazuh",
                                "raw_data": str(item)
                            }

                            all_alerts.append(alert)

                    # Sort alerts by severity
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    sorted_alerts = sorted(all_alerts,
                                           key=lambda x: severity_order.get(x["severity"], 999))

                    print(
                        f"Processing complete. Found {suspicious_count} suspicious alerts, showing {len(sorted_alerts)} unacknowledged")
                    print(f"Alert severity counts: {severity_counts}")
                    print(f"Acknowledged count: {acknowledged_count}")
                    print(f"Total suspicious alerts (including acknowledged): {suspicious_count + acknowledged_count}")

                    self.view.update_alerts(sorted_alerts)
                else:
                    print("No syscheck response or data")
                    self.view.update_alerts([])
            else:
                print("No windows ID or token available")
                self.view.update_alerts([])

        except Exception as e:
            print(f"Error in alerts update: {e}")
            import traceback
            traceback.print_exc()
            if self.view:
                self.view.update_alerts([])

    def format_timestamp(self, timestamp_str):
        """Format ISO timestamp to more readable format"""
        try:
            # Parse ISO format timestamp
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            # Format for display
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            # Return original if parsing fails
            return timestamp_str

    def acknowledge_alert(self):
        if not self.view or not hasattr(self.view, 'selected_alert_id'):
            print("No view or no selected alert")
            return

        alert_id = self.view.selected_alert_id
        if alert_id:
            print(f"Acknowledging alert: {alert_id}")

            # Disable view interaction during acknowledgment to prevent multiple clicks
            if hasattr(self.view, 'disable_interactions'):
                self.view.disable_interactions()

            # Add to alert manager but DO NOT manually update alerts
            self.alert_manager.add_acknowledged_alert(alert_id)

            # Re-enable view with a delay
            if hasattr(self.view, 'enable_interactions'):
                QTimer.singleShot(500, self.view.enable_interactions)
        else:
            print("No alert selected for acknowledgment")

    def apply_filters(self, alerts):
        """Apply filters from the view to the alerts list"""
        try:
            if not self.view:
                return alerts

            filtered_alerts = []

            # Get filter settings from view
            severity_filter = "all"
            status_filter = "all"
            time_filter = "all time"

            if hasattr(self.view, 'severity_filter'):
                severity_filter = self.view.severity_filter.currentText().lower()

            if hasattr(self.view, 'status_filter'):
                status_filter = self.view.status_filter.currentText().lower()

            if hasattr(self.view, 'time_filter'):
                time_filter = self.view.time_filter.currentText().lower()

            # Apply filters
            for alert in alerts:
                # Skip if acknowledged and we're only showing active
                is_acknowledged = self.alert_manager.is_acknowledged(alert["id"])

                if status_filter == "active" and is_acknowledged:
                    continue

                if status_filter == "acknowledged" and not is_acknowledged:
                    continue

                # Filter by severity
                if severity_filter != "all" and alert["severity"].lower() != severity_filter:
                    continue

                # Time filter would go here if needed
                # (would need to parse timestamp and compare with current time)

                # Alert passed all filters
                filtered_alerts.append(alert)

            return filtered_alerts

        except Exception as e:
            print(f"Error applying filters: {e}")
            return alerts

    def on_config_change(self, new_config):
        """Handle configuration updates"""
        print(f"AlertsController: Received new configuration. URL: {new_config.url}")
        try:
            self.wazuh_config = new_config
            self._token = None
            self._token_timestamp = None

            self.session.close()
            self.session = requests.Session()
            self.session.verify = False
            self.session.timeout = 5

            self.windows_agent_id = None  # Clear cached agent ID

            if self.wazuh_config.url and self.view:
                print("Configuration changed, updating alerts view")
                self.update_alerts()

        except Exception as e:
            print(f"Error updating configuration: {e}")
            import traceback
            traceback.print_exc()

    def cleanup(self):
        """Clean up resources before controller destruction"""
        print("AlertsController: Cleaning up resources")
        try:
            # Disconnect alert manager signals
            if hasattr(self, 'alert_manager'):
                try:
                    # More robust disconnection with explicit error handling
                    try:
                        self.alert_manager.alerts_updated.disconnect(self.on_alerts_updated)
                        print("Disconnected alerts_updated signal")
                    except TypeError:
                        # Signal wasn't connected
                        print("alerts_updated signal was not connected")
                    except RuntimeError as e:
                        # C++ object might be deleted
                        print(f"Runtime error disconnecting signal: {e}")
                    except Exception as e:
                        print(f"Error disconnecting alerts_updated: {e}")

                    # Remove as observer (legacy pattern)
                    self.alert_manager.remove_observer(self)
                    print("Removed from alert manager observers")
                except Exception as e:
                    print(f"Error cleaning up alert manager connections: {e}")

            # Disconnect config manager
            if hasattr(self, 'config_manager'):
                try:
                    self.config_manager.remove_wazuh_observer(self.on_config_change)
                    print("Removed from config manager observers")
                except Exception as e:
                    print(f"Error removing from config observers: {e}")

            # Close session if it exists
            if hasattr(self, 'session'):
                try:
                    self.session.close()
                    print("Closed HTTP session")
                except Exception as e:
                    print(f"Error closing session: {e}")

            # Clear references
            self.view = None
            print("AlertsController cleanup complete")
        except Exception as e:
            print(f"Error during AlertsController cleanup: {e}")
