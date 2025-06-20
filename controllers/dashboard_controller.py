# controllers/dashboard_controller.py
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import logging
import os
import random
from utils import config_manager
from utils.alert_manager import AlertManager

try:
    from models import WazuhConfig
except ImportError:
    from stubs import WazuhConfig

from utils import alert_manager


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def setup_debug_logging():
    log_dir = os.path.join(os.environ['APPDATA'], 'Guardian', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    debug_logger = logging.getLogger('guardian_debug')
    debug_logger.setLevel(logging.DEBUG)

    log_file = os.path.join(log_dir, 'sync_debug.log')
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))
    debug_logger.addHandler(file_handler)

    return debug_logger


debug_logger = setup_debug_logging()


class DashboardController:
    def __init__(self):
        debug_logger.info("=== DashboardController Initialization ===")
        self.view = None
        self.config_manager = config_manager.ConfigManager()
        self.wazuh_config = self.config_manager.wazuh_config
        debug_logger.info(f"Initial wazuh_config: {self.wazuh_config.__dict__ if self.wazuh_config else None}")

        self._token = None
        self._token_timestamp = None
        self.acknowledged_alerts = set()
        self.windows_agent_id = None

        # Get the singleton instance
        self.alert_manager = AlertManager.get_instance()

        # Connect to signal for PyQt-style updates
        self.alert_manager.alerts_updated.connect(self.on_alerts_updated)

        # Also use old observer pattern for backward compatibility
        self.alert_manager.add_observer(self)

        # Create a persistent session
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 2
        debug_logger.info("DashboardController initialized")

        # Load acknowledged alerts
        self.load_acknowledged_alerts()
        debug_logger.info("Acknowledged alerts loaded")

        # Add as observer
        self.config_manager.add_wazuh_observer(self.on_config_change)

        # Store historical data for trend chart
        self.alert_history = self._initialize_alert_history()

    def _initialize_alert_history(self):
        """Initialize 7-day alert history structure"""
        history = {}
        for i in range(7):
            history[i] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        return history

    def on_alerts_updated(self):
        """Called when alerts are acknowledged"""
        if self.view:
            # Check if view is still valid before updating
            try:
                if hasattr(self.view, 'isVisible') and self.view.isVisible():
                    self.view.refresh_dashboard()
                else:
                    print("DashboardController: View is not visible, skipping refresh")
            except RuntimeError as e:
                if "C++ object" in str(e):
                    print("DashboardController: View has been deleted, removing signal connection")
                    # Disconnect from the signal to prevent future calls
                    try:
                        self.alert_manager.alerts_updated.disconnect(self.on_alerts_updated)
                    except Exception:
                        pass

    def load_acknowledged_alerts(self):
        """Load acknowledged alerts from file"""
        try:
            with open('acknowledged_alerts.txt', 'r') as f:
                self.acknowledged_alerts = set(line.strip() for line in f)
            print(f"Loaded {len(self.acknowledged_alerts)} acknowledged alerts")
        except FileNotFoundError:
            print("No acknowledged alerts file found")
            self.acknowledged_alerts = set()

    def set_view(self, view):
        """Set the view for this controller"""
        self.view = view
        print("View set for DashboardController")

        # Update the view with data if available
        if self.view:
            self.view.set_controller(self)

    def get_dashboard_data(self):
        """Get all dashboard data formatted for the PyQt6 Dashboard view"""
        debug_logger.info("=== Getting Dashboard Data ===")

        try:
            # Collect all alerts
            all_alerts = self._get_all_alerts()

            # Count alerts by severity
            alert_counts = self._count_alerts_by_severity(all_alerts)

            # Get system status
            system_status = self.get_system_status()

            # Update alert trend history with today's data
            today_index = datetime.now().weekday()
            self.alert_history[today_index] = {
                "critical": alert_counts.get("critical", 0),
                "high": alert_counts.get("high", 0),
                "medium": alert_counts.get("medium", 0),
                "low": alert_counts.get("low", 0)
            }

            # Format data for the dashboard view
            current_time = datetime.now().strftime("%I:%M %p")

            # Get agent status for health chart
            agent_status = self._get_agent_status()

            # Create workflow data (example/mocked data for now)
            workflow_data = self._get_workflow_data()

            # Format data for dashboard
            dashboard_data = {
                "active_threats": alert_counts.get("critical", 0) + alert_counts.get("high", 0),
                "system_status": system_status,
                "total_alerts": sum(alert_counts.values()),
                "last_scan": f"Last checked at {current_time}",
                "alert_trend": self.alert_history,
                "system_health": agent_status,
                "workflows": workflow_data
            }

            debug_logger.info(f"Dashboard data prepared: {dashboard_data}")
            return dashboard_data

        except Exception as e:
            error_msg = f"Error getting dashboard data: {e}"
            debug_logger.error(error_msg)
            import traceback
            debug_logger.error(traceback.format_exc())

            # Return simplified data
            return self._get_fallback_data()

    def _get_all_alerts(self):
        """Get all alerts from Wazuh"""
        all_alerts = []

        try:
            windows_id = self.get_windows_agent_id()
            debug_logger.info(f"Windows agent ID: {windows_id}")

            if windows_id and self.get_wazuh_token():
                print(f"Fetching alerts for Windows agent ID: {windows_id}")
                syscheck_response = self.fetch_data(f'syscheck/{windows_id}', {
                    'limit': 100,
                    'sort': 'date'
                })

                if syscheck_response and 'data' in syscheck_response:
                    items = syscheck_response['data'].get('affected_items', [])
                    print(f"Found {len(items)} potential alerts")

                    for item in items:
                        try:
                            file_path = item.get('file', '').lower()
                            event_type = item.get('type', '').lower()
                            timestamp_str = item.get('date', '')

                            # Check if alert is acknowledged using AlertManager
                            alert_id = f"{timestamp_str}_{file_path}"
                            if self.alert_manager.is_acknowledged(alert_id):
                                print(f"Skipping acknowledged alert: {alert_id}")
                                continue

                            # Process alert only if not acknowledged
                            is_suspicious = False
                            severity = "low"
                            alert_type = "File Change"

                            if any(path in file_path for path in self.wazuh_config.suspicious_paths):
                                is_suspicious = True
                                severity = "medium"

                            if event_type in ['modified', 'deleted']:
                                is_suspicious = True
                                severity = "high"

                            if 'readme' in file_path and 'ransom' in file_path:
                                is_suspicious = True
                                severity = "critical"
                                alert_type = "Ransomware Note Detected"

                            if is_suspicious:
                                all_alerts.append({
                                    "timestamp": timestamp_str,
                                    "severity": severity,
                                    "type": alert_type,
                                    "file": file_path
                                })

                        except Exception as e:
                            print(f"Error processing alert item: {e}")
                            continue

                    # Sort alerts by severity
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    sorted_alerts = sorted(
                        all_alerts,
                        key=lambda x: severity_order.get(x['severity'], 999)
                    )
                    all_alerts = sorted_alerts

            return all_alerts
        except Exception as e:
            debug_logger.error(f"Error getting alerts: {e}")
            return []

    def _count_alerts_by_severity(self, alerts):
        """Count alerts by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for alert in alerts:
            severity = alert.get('severity', 'low')
            if severity in counts:
                counts[severity] += 1

        return counts

    def _get_agent_status(self):
        """Get agent status counts for system health chart"""
        try:
            print("Fetching agent status data...")
            response = self.fetch_data('agents/summary/status')

            print(f"Agent status response: {response}")  # Debug print

            if response and 'data' in response:
                data = response['data']

                # Create health data from response
                health_data = {
                    "Healthy": data.get('active', 0),
                    "Warning": data.get('disconnected', 0),
                    "Critical": data.get('never_connected', 0) + data.get('pending', 0)
                }

                # Check if all values are zero
                if sum(health_data.values()) > 0:
                    print(f"Using real health data: {health_data}")
                    return health_data
                else:
                    print("All health metrics are zero, using alternate API")
                    # Try an alternate approach - get agent list
                    agents_response = self.fetch_data('agents', {'limit': 500})
                    if agents_response and 'data' in agents_response and 'affected_items' in agents_response['data']:
                        agents = agents_response['data']['affected_items']

                        # Count by status
                        healthy = sum(1 for a in agents if a.get('status') == 'active')
                        warning = sum(1 for a in agents if a.get('status') == 'disconnected')
                        critical = sum(1 for a in agents if a.get('status') in ['never_connected', 'pending'])

                        if healthy + warning + critical > 0:
                            return {
                                "Healthy": healthy,
                                "Warning": warning,
                                "Critical": critical
                            }

            # Use fixed fallback data if all else fails
            print("Using fallback health data")
            return {
                "Healthy": 1,  # Changed from 75 to ensure non-zero values
                "Warning": 1,  # Changed from 15
                "Critical": 1  # Changed from 10
            }
        except Exception as e:
            print(f"Error getting agent status: {e}")
            import traceback
            traceback.print_exc()

            # Guaranteed fallback data that will always work
            return {
                "Healthy": 1,
                "Warning": 1,
                "Critical": 1
            }

    def _get_workflow_data(self):
        """Get SOAR workflow status data"""
        # This would normally come from your SOAR integration
        # For now using sample data
        return {
            "Malware Response": {"status": "Active", "last_run": "10 min ago"},
            "System Scan": {"status": "Scheduled", "last_run": "2 hours ago"},
            "Threat Hunting": {"status": "Idle", "last_run": "Yesterday"},
            "Network Defense": {"status": "Active", "last_run": "5 min ago"}
        }

    def _get_fallback_data(self):
        """Get fallback data when API calls fail"""
        current_time = datetime.now().strftime("%I:%M %p")

        return {
            "active_threats": 0,
            "system_status": "Unknown",
            "total_alerts": 0,
            "last_scan": f"Last checked at {current_time}",
            "alert_trend": self.alert_history,
            "system_health": {
                "Healthy": 70,
                "Warning": 20,
                "Critical": 10
            },
            "workflows": self._get_workflow_data()
        }

    def get_windows_agent_id(self):
        """Get the ID of the Windows agent"""
        try:
            if self.windows_agent_id:  # Return if already set
                return self.windows_agent_id

            print("\n=== Getting Windows Agent ID ===")
            if not self.get_wazuh_token():
                print("Failed to get token for Windows agent ID fetch")
                return None

            queries = [
                {'q': 'os.platform=windows', 'select': 'id,name'},
                {'q': 'os.name=windows', 'select': 'id,name'},
                None
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
            print(f"Error getting Windows agent ID: {e}")
            return None

    def on_config_change(self, new_config: WazuhConfig):
        """Observer method for configuration changes"""
        print(f"DashboardController: Received new configuration. URL: {new_config.url}")
        try:
            # Update configuration
            self.wazuh_config = new_config

            # Reset connection-related attributes
            self._token = None
            self._token_timestamp = None

            # Close existing session and create new one
            self.session.close()
            self.session = requests.Session()
            self.session.verify = False
            self.session.timeout = 2

            print("DashboardController: Updating dashboard with new configuration...")
            # Refresh dashboard with new settings
            if self.view:
                self.view.refresh_dashboard()
            print("DashboardController: Dashboard updated with new configuration")

        except Exception as e:
            print(f"DashboardController: Error updating configuration: {e}")
            if self.view:
                self.view.show_error(f"Failed to update dashboard with new settings: {e}")

    def get_wazuh_token(self):
        """Get authentication token from Wazuh"""
        try:
            # Use existing token if valid
            if self._token and self._token_timestamp:
                if (datetime.now() - self._token_timestamp).seconds < 3000:
                    return self._token

            print("DashboardController: Requesting new Wazuh token...")
            base_url = f"https://{self.wazuh_config.url}"
            if not base_url.endswith(':55000'):
                base_url = f"{base_url}:55000"

            response = self.session.post(
                f"{base_url}/security/user/authenticate",
                auth=(self.wazuh_config.username, self.wazuh_config.password),
                timeout=2
            )

            if response.status_code == 200:
                self._token = response.json()['data']['token']
                self._token_timestamp = datetime.now()
                self.session.headers.update({'Authorization': f'Bearer {self._token}'})
                print("DashboardController: Successfully obtained new token")
                return self._token

            print(f"DashboardController: Failed to get token. Status: {response.status_code}")
            return None
        except Exception as e:
            print(f"DashboardController: Token error: {e}")
            return None

    def get_system_status(self):
        """Get system status focusing on critical services"""
        try:
            print("DashboardController: Checking system status...")
            data = self.fetch_data("manager/status")
            if data and 'data' in data and 'affected_items' in data['data'] and data['data']['affected_items']:
                services = data['data']['affected_items'][0]

                # Critical services that must be running
                critical_services = [
                    'wazuh-analysisd',
                    'wazuh-execd',
                    'wazuh-remoted',
                    'wazuh-syscheckd',
                    'wazuh-modulesd',
                    'wazuh-db',
                    'wazuh-apid'
                ]

                critical_services_status = all(
                    services.get(service) == 'running'
                    for service in critical_services
                )

                status = "HEALTHY" if critical_services_status else "WARNING"
                print(f"DashboardController: System status: {status}")
                return status
            return "UNKNOWN"
        except Exception as e:
            print(f"DashboardController: Status error: {e}")
            return "UNKNOWN"

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
                params=params,
                timeout=2
            )

            if response.status_code == 200:
                return response.json()
            print(f"DashboardController: Error response from {endpoint}: {response.status_code}")
            return None
        except requests.exceptions.Timeout:
            print(f"DashboardController: Timeout fetching {endpoint}")
            return None
        except Exception as e:
            print(f"DashboardController: Error fetching {endpoint}: {e}")
            return None
