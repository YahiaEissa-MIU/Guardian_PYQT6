# controllers/alerts_controller.py

import requests
import urllib3
from datetime import datetime, timedelta
import logging

from PyQt6.QtCore import QTimer
from utils.wazuh_api import WazuhApi
from utils.alert_manager import AlertManager
from utils.config_manager import ConfigManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class AlertsController:
    def __init__(self, view=None, api_client: WazuhApi | None = None):
        print("Initializing AlertsController...")
        self.alert_manager = AlertManager.get_instance()
        self.view = view
        self.config_manager = ConfigManager()
        self.wazuh_config = self.config_manager.get_wazuh_config()
        self.windows_agent_id = None

        # ---- NEW PAGINATION FIELDS ----
        self.limit = 250  # default page size
        self.offset = 0  # zero-based offset
        self.total = 0  # will be set on each fetch
        self.current_agent_id = None
        # --------------------------------

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
        self.api = api_client or WazuhApi(self.wazuh_config)

        # Initialize with system checks if config exists
        if self.wazuh_config and self.wazuh_config.url:
            self.get_windows_agent_id()

            # fetching first page
        if self.wazuh_config and self.wazuh_config.url:
            self.update_alerts()

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

    def get_windows_agent_id(self):
        try:
            if self.wazuh_config.agent_id:
                self.windows_agent_id = self.wazuh_config.agent_id
                data = self.api.get("agents", {"agents_list": self.windows_agent_id})
                items = data.get("data", {}).get("affected_items", [])
                if items and items[0].get("status") == "active":
                    return self.windows_agent_id
            return None
        except Exception as e:
            print(f"Agent lookup failed: {e}")
            return None

    def update_alerts(self):
        """Fetch one page of syscheck alerts, transform & send to the view."""
        print("\n=== Fetching Alerts (limit={}, offset={}) ===".format(self.limit, self.offset))

        if not self.view:
            return

        agent_id = self.get_windows_agent_id()
        if not agent_id:
            return

        start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        params = {
            'limit': self.limit,
            'offset': self.offset,
            'q': f'date>{start_date}',
            'sort': '-date'
        }

        response = self.api.get(f'syscheck/{agent_id}', params)
        if not response or 'data' not in response:
            return

        data = response['data']
        items = data.get('affected_items', [])
        self.total = data.get('total_affected_items', len(items))

        alerts = []
        seen_ids = set()
        date_counts = {}

        for item in items:
            path = item.get('file', '').lower()
            ev_type = item.get('type', '').lower()

            # ✅ Safe timestamp fallback order
            ts = item.get("date") or item.get("timestamp") or item.get("mtime") or ""
            if not ts:
                continue

            # Normalize to readable format
            formatted_ts = self.format_timestamp(ts)

            aid = f"{formatted_ts}_{path}"
            if aid in seen_ids:
                continue
            seen_ids.add(aid)

            date_only = formatted_ts.split(' ')[0]  # 'YYYY-MM-DD'
            date_counts[date_only] = date_counts.get(date_only, 0) + 1

            if self.alert_manager.is_acknowledged(aid):
                continue

            # classify
            desc, sev = "File Change", "low"
            if 'registry' in path:
                desc, sev = "Registry Change", "medium"
            elif any(p in path for p in self.wazuh_config.suspicious_paths):
                desc, sev = "Suspicious Path Access", "medium"

            if ev_type == 'deleted':
                desc += " – Deleted"
                sev = "high"
            elif ev_type == 'modified':
                desc += " – Modified"
                sev = sev if sev == "high" else "medium"
            elif ev_type == 'added':
                desc += " – Added"

            alerts.append({
                "id": aid,
                "timestamp": formatted_ts,
                "severity": sev,
                "description": desc,
                "location": path,
                "raw_data": item,
            })

        print("Top dates:", sorted(date_counts.items(), key=lambda x: x[1], reverse=True)[:3])
        print(f"Total matching alerts: {self.total}")

        filtered = self.apply_filters(alerts)
        self.view.update_alerts(filtered)

        if hasattr(self.view, 'update_pagination_info'):
            self.view.update_pagination_info(
                offset=self.offset,
                limit=self.limit,
                total=self.total
            )

    # ---- NEW PAGINATION HELPERS ----

    def next_page(self):
        """Advance to the next page, if possible."""
        if self.offset + self.limit < self.total:
            self.offset += self.limit
            self.update_alerts()

    def prev_page(self):
        """Go back one page, if possible."""
        if self.offset > 0:
            self.offset = max(0, self.offset - self.limit)
            self.update_alerts()

    def set_limit(self, new_limit: int):
        """Change page size (resets to first page)."""
        self.limit = new_limit
        self.offset = 0
        self.update_alerts()

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

    def check_recent_security_events(self):
        """Check for recent security events instead of just syscheck"""
        windows_id = self.get_windows_agent_id()
        if not windows_id:
            return

        print(f"\n=== Checking Recent Security Events (Today: 2025-06-20) ===")

        # Try different endpoints
        endpoints_to_check = [
            ('security/events', {'agent.id': windows_id, 'limit': 100}),
            (f'agents/{windows_id}/logs/summary', {}),
            ('alerts', {'agent_id': windows_id, 'limit': 100}),
        ]

        for endpoint, params in endpoints_to_check:
            print(f"\nChecking endpoint: {endpoint}")
            response = self.api.get(endpoint, params)

            if response and 'data' in response:
                if 'affected_items' in response['data']:
                    items = response['data']['affected_items']
                    print(f"Found {len(items)} items")

                    # Show first few items
                    for i, item in enumerate(items[:3]):
                        timestamp = item.get('timestamp', item.get('date', 'No timestamp'))
                        print(f"  Item {i + 1}: {timestamp}")

    def check_agent_status(self):
        """Check if the agent is active and when it last reported"""
        windows_id = self.get_windows_agent_id()
        if not windows_id:
            return

        print(f"\n=== Agent Status Check (Current Date: 2025-06-20) ===")

        # Get agent details
        response = self.api.get('agents', {'agents_list': windows_id})

        if response and 'data' in response:
            agents = response['data'].get('affected_items', [])
            if agents:
                agent = agents[0]
                print(f"Agent Name: {agent.get('name')}")
                print(f"Agent Status: {agent.get('status')}")
                print(f"Last Keep Alive: {agent.get('lastKeepAlive')}")
                print(f"Date Add: {agent.get('dateAdd')}")
                print(f"OS: {agent.get('os', {}).get('name')} {agent.get('os', {}).get('version')}")

                # Check if agent is active
                if agent.get('status') != 'active':
                    print("\n⚠️  WARNING: Agent is not active!")

        # Check agent's recent activity
        stats_response = self.api.get(f'agents/{windows_id}/stats/analysisd', {})
        if stats_response and 'data' in stats_response:
            print("\nAgent Analysis Stats:")
            stats = stats_response['data']
            print(f"Total events: {stats.get('total_events', 0)}")
            print(f"Last event time: {stats.get('last_event_time', 'N/A')}")

    def on_config_change(self, new_config):
        """Handle configuration updates"""
        print(f"AlertsController: Received new configuration. URL: {new_config.url}")
        try:
            self.wazuh_config = new_config

            self.api.update_config(new_config)

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
