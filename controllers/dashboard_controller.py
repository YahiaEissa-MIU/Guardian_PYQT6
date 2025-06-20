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
from datetime import datetime
from utils import alert_manager
from utils.config_manager import ConfigManager

cfg_mgr = ConfigManager()
import time, requests, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from models import WazuhConfig
except ImportError:
    from stubs import WazuhConfig


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
        """Collect everything the dashboard needs in one call."""
        try:
            all_alerts = self._get_all_alerts()

            # ① count per-severity once …
            counts = self._count_alerts_by_severity(all_alerts)

            # ② build a per-day, per-severity bucket for the chart
            trend = self._build_trend_series(all_alerts)  # <- helper below
            self.alert_history = trend  # keep in memory

            system_status = self.get_system_status()
            current_time = datetime.now().strftime("%I:%M %p")
            health_data = self._get_system_health()  # renamed in §3
            workflow_data = self._get_workflow_data()

            return {
                # Active threats = the truly scary stuff
                "active_threats": counts.get("critical", 0) + counts.get("high", 0),

                # Only MEDIUMs go in the big yellow number now
                "total_alerts": counts.get("medium", 0),

                "system_status": system_status,
                "last_scan": f"Last checked at {current_time}",

                "alert_trend": trend,
                "system_health": health_data,
                "workflows": workflow_data,
            }

        except Exception as e:
            debug_logger.exception("Error building dashboard data")
            return self._get_fallback_data()

    def _build_trend_series(self, alerts):
        """Return a dict {0..6: {critical,high,medium,low}} for the last 7 days."""
        trend = {i: {"critical": 0, "high": 0, "medium": 0, "low": 0} for i in range(7)}

        for alert in alerts:
            ts = alert.get("timestamp") or alert.get("date") or ""
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                idx = dt.weekday()  # 0 = Mon … 6 = Sun
            except Exception:
                continue

            sev = alert.get("severity", "low").lower()
            if sev in trend[idx]:
                trend[idx][sev] += 1

        return trend

    def _get_all_alerts(self, days_back: int = 7):
        """Return un-acknowledged alerts from the last *days_back* days."""
        alerts: list[dict] = []

        try:
            agent_id = self.get_windows_agent_id()
            if not agent_id or not self.get_wazuh_token():
                return alerts

            # Anything newer than midnight N days ago
            start_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")

            params = {
                "limit": 1000,  # plenty for a week
                "q": f"date>{start_date}",
                "sort": "-date",  # newest first
            }

            resp = self.fetch_data(f"syscheck/{agent_id}", params)
            if not (resp and resp.get("data", {}).get("affected_items")):
                return alerts

            for item in resp["data"]["affected_items"]:
                ts = item.get("date") or item.get("mtime") or ""
                fp = item.get("file", "").lower()
                typ = item.get("type", "").lower()
                aid = f"{ts}_{fp}"

                # skip acknowledged
                if self.alert_manager.is_acknowledged(aid):
                    continue

                # classify severity
                sev = "low"
                if typ in ("modified", "deleted"):
                    sev = "high"
                if any(p in fp for p in self.wazuh_config.suspicious_paths):
                    sev = "medium"
                if 'readme' in fp and 'ransom' in fp:
                    sev = "critical"

                alerts.append({"timestamp": ts, "severity": sev})

            return alerts

        except Exception as e:
            debug_logger.error(f"_get_all_alerts error: {e}")
            return alerts

    def _build_trend_series(self, alerts: list[dict]) -> dict:
        """
        Return {0..6: {critical,high,medium,low}} using weekday indexes
        (0 = Mon … 6 = Sun). Missing days stay at zero.
        """
        series = {i: {"critical": 0, "high": 0, "medium": 0, "low": 0} for i in range(7)}

        for alert in alerts:
            ts = alert.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue

            wd = dt.weekday()  # 0-6
            sev = alert.get("severity", "low").lower()
            if sev in series[wd]:
                series[wd][sev] += 1

        return series

    def _count_alerts_by_severity(self, alerts):
        """Count alerts by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for alert in alerts:
            severity = alert.get('severity', 'low')
            if severity in counts:
                counts[severity] += 1

        return counts

    def _get_system_health(self):
        """
        Categorise core Wazuh services:
          • Healthy  = running
          • Warning  = stopped
          • Critical = any other (failed, unknown, etc.)
        """
        try:
            resp = self.fetch_data("manager/status")
            if resp and resp.get("data", {}).get("affected_items"):
                svc_states = resp["data"]["affected_items"][0]

                healthy = sum(1 for s in svc_states.values() if s == "running")
                warning = sum(1 for s in svc_states.values() if s == "stopped")
                critical = sum(1 for s in svc_states.values()
                               if s not in ("running", "stopped"))

                # never all zero – fall back to at least one “Healthy”
                if healthy + warning + critical == 0:
                    healthy = 1

                return {"Healthy": healthy, "Warning": warning, "Critical": critical}

        except Exception as e:
            print(f"Health check failed: {e}")

        # safe fallback
        return {"Healthy": 1, "Warning": 1, "Critical": 1}

    def _get_workflow_data(self) -> dict:
        """
        Talk to Shuffle and return
        { "Workflow Name": {"status": "...", "updated": <epoch>} }.

        Fallbacks: returns last-known good data or a dummy entry.
        """
        #  -------- in-memory cache --------
        if getattr(self, "_wf_cache", None):
            # fresh < 30 s? use it
            if time.time() - self._wf_cache_ts < 30:
                return self._wf_cache

        shuffle = cfg_mgr.get_shuffle_config()
        if not (shuffle.is_configured and shuffle.shuffle_url and shuffle.shuffle_api_key):
            return {"No workflows configured": {"status": "Idle", "updated": 0}}

        url = shuffle.shuffle_url.rstrip("/")
        hdrs = {"Authorization": f"Bearer {shuffle.shuffle_api_key}"}

        try:
            r = requests.get(f"{url}/api/v1/workflows", headers=hdrs,
                             timeout=4, verify=False)
            r.raise_for_status()
            wanted = {n.lower() for n in shuffle.workflow_names}
            out = {}
            for wf in r.json():
                if wf["name"].lower() not in wanted:
                    continue
                out[wf["name"]] = {
                    "status": wf.get("status") or ("Enabled" if wf.get("enabled") else "Disabled"),
                    "updated": wf.get("updated") or wf.get("created", 0)
                }

            # cache
            self._wf_cache = out
            self._wf_cache_ts = time.time()
            return out or {"No workflows found": {"status": "Idle", "updated": 0}}

        except Exception as e:
            debug_logger.error(f"Shuffle fetch failed: {e}")
            return getattr(self, "_wf_cache",
                           {"Shuffle unreachable": {"status": "Warning", "updated": 0}})

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

    def get_windows_agent_id(self) -> str | None:
        """
        Return an *active* Windows agent-ID.

        Order of preference
        -------------------
        1. user-configured ID (self.wazuh_config.agent_id) – if still active
        2. cached discovery from a previous call (self.windows_agent_id)
        3. first active Windows agent found via /agents?status=active
        """

        def _agent_alive(aid: str) -> bool:
            """Quick “ping” – only fetch id+status to avoid 404 for deleted agents."""
            res = self.fetch_data(f"agents/{aid}?select=id,status")
            if res and res.get("data", {}).get("affected_items"):
                return res["data"]["affected_items"][0].get("status") == "active"
            return False

        # ── 1. check user-configured (w/o / w leading zeros) ─────────────
        cfg_id = (self.wazuh_config.agent_id or "").strip()
        if cfg_id:
            for candidate in (cfg_id, str(int(cfg_id))):  # “018” → “18”
                if _agent_alive(candidate):
                    self.windows_agent_id = candidate
                    return candidate
                debug_logger.warning(f"Configured agent_id '{candidate}' inactive / 404")

        # ── 2. cached discovery from earlier call ──────────────────────
        if self.windows_agent_id and _agent_alive(self.windows_agent_id):
            return self.windows_agent_id

        # ── 3. auto-discover first active Windows agent ────────────────
        agents = self.fetch_data("agents", {"status": "active", "limit": 500})
        if agents and agents.get("data", {}).get("affected_items"):
            for a in agents["data"]["affected_items"]:
                os_name = (a.get("os", {}) or {}).get("name", "").lower()
                if "windows" in os_name:
                    self.windows_agent_id = a["id"]
                    debug_logger.info(f"Discovered Windows agent: {a['name']} ({a['id']})")
                    return a["id"]

        debug_logger.error("No active Windows agents found.")
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
