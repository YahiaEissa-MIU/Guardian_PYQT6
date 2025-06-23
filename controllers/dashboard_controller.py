"""
Guardian – Dashboard controller
2025-06 · single Wazuh client · safe agent discovery · no recursion
"""
from __future__ import annotations

import os, time, logging, requests, urllib3
from typing   import Any
from datetime import datetime, timedelta

from PyQt6.QtCore import QTimer                       # ← NEW (for deferred save)

from utils.wazuh_api      import WazuhApi
from utils.alert_manager  import AlertManager
from utils.config_manager import ConfigManager
from models.wazuh_config  import WazuhConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── logging helper ────────────────────────────────────────────────────────────
def _logger() -> logging.Logger:
    logdir = os.path.join(os.getenv("APPDATA", "."), "Guardian", "logs")
    os.makedirs(logdir, exist_ok=True)
    lg = logging.getLogger("guardian_debug")
    if not lg.handlers:
        lg.setLevel(logging.DEBUG)
        fh = logging.FileHandler(os.path.join(logdir, "dashboard_debug.log"))
        fh.setFormatter(
            logging.Formatter("%(asctime)s – %(levelname)s – %(message)s"))
        lg.addHandler(fh)
    return lg


dbg = _logger()


# ── controller ────────────────────────────────────────────────────────────────
class DashboardController:
    """
    Supplies everything the DashboardView needs via `get_dashboard_data`.
    """

    # ──────────────────────── init / teardown ──────────────────────────────
    def __init__(self, api_client: WazuhApi | None = None) -> None:
        dbg.info("=== DashboardController init ===")

        self.config_manager      = ConfigManager()
        self.wazuh_config        = self.config_manager.get_wazuh_config()
        self.api                 = api_client or WazuhApi(self.wazuh_config)

        self.alert_manager       = AlertManager.get_instance()
        self.alert_manager.alerts_updated.connect(self.on_alerts_updated)

        self.config_manager.add_wazuh_observer(self.on_config_change)

        # runtime fields
        self.view                = None
        self.windows_agent_id: str | None = None
        self._agent_saved        = False              # ← NEW  (save-once flag)
        self.alert_history       = self._empty_history()
        self._wf_cache, self._wf_cache_ts = None, 0.0

        self._load_acknowledged()

    # ─────────────────────── public hooks (called by view) ─────────────────
    def set_view(self, view):
        self.view = view
        self.view.set_controller(self)

    def on_alerts_updated(self):
        if self.view:
            try:
                self.view.refresh_dashboard()
            except RuntimeError:
                # view already deleted → detach
                try:
                    self.alert_manager.alerts_updated.disconnect(
                        self.on_alerts_updated)
                except Exception:
                    pass

    def on_config_change(self, new_cfg: WazuhConfig):
        dbg.info("DashboardController - received new config")
        self.wazuh_config      = new_cfg
        self.api.update_config(new_cfg)
        self.windows_agent_id  = None         # force re-check
        if self.view:
            self.view.refresh_dashboard()

    # ─────────────────────── data API (consumed by view) ───────────────────
    def get_dashboard_data(self) -> dict[str, Any]:
        try:
            alerts    = self._collect_alerts(7)
            counts    = self._count(alerts)
            trend     = self._trend(alerts)
            health    = self._system_health()
            workflows = self._workflow_status()
            now       = datetime.now().strftime("%I:%M %p")

            return {
                "active_threats": counts["critical"] + counts["high"],
                "total_alerts":   counts["medium"],
                "system_status":  self._system_status(),
                "last_scan":      f"Last checked at {now}",
                "alert_trend":    trend,
                "system_health":  health,
                "workflows":      workflows,
            }
        except Exception as e:
            dbg.error(f"dashboard error: {e}", exc_info=True)
            return self._fallback()

    # ─────────────────────── agent discovery (safe) ─────────────────────────
    def _get_agent_id(self) -> str | None:
        # ① cached?
        if self.windows_agent_id and self._agent_ok(self.windows_agent_id):
            return self.windows_agent_id

        # ② configured?
        cfg_id = self.wazuh_config.agent_id
        if cfg_id and self._agent_ok(cfg_id):
            self.windows_agent_id = cfg_id
            return cfg_id
        if cfg_id:
            dbg.info("Configured agent not active – discovering …")

        # ③ discover first active Windows agent
        try:
            resp = self.api.get("agents", {"status": "active", "limit": 1000})
            for ag in resp.get("data", {}).get("affected_items", []):
                if ag["id"] == "000":
                    continue
                if ag.get("os", {}).get("platform", "").lower() != "windows":
                    continue
                self.windows_agent_id = ag["id"]
                dbg.info(f"Discovered agent {ag['name']} ({ag['id']})")
                self._persist_agent_once(ag["id"], ag["name"])
                return ag["id"]
        except Exception as e:
            dbg.error(f"agent discovery failed: {e}", exc_info=True)
        return None

    def _agent_ok(self, ag_id: str) -> bool:
        try:
            data = self.api.get(f"agents/{ag_id}")
            items = data.get("data", {}).get("affected_items", [])
            return bool(items and items[0].get("status") == "active")
        except Exception:
            return False

    # ---------- defered persistence (no recursion) -------------------------
    def _persist_agent_once(self, ag_id: str, ag_name: str):
        if self._agent_saved:
            return
        self._agent_saved = True

        def _save():
            try:
                self.wazuh_config.agent_id   = ag_id
                self.wazuh_config.agent_name = ag_name
                self.config_manager.update_wazuh_config(self.wazuh_config)
                dbg.info(f"Persisted agent {ag_name} ({ag_id}) to config")
            except Exception as e:
                dbg.error(f"agent persist failed: {e}", exc_info=True)

        QTimer.singleShot(0, _save)           # fire after current event loop turn

    # ─────────────────────── alert helpers ─────────────────────────────────
    def _collect_alerts(self, days_back=7) -> list[dict]:
        out: list[dict] = []
        ag = self._get_agent_id()
        if not ag:
            return out

        start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        data = self.api.get(f"syscheck/{ag}", {
            "limit": 1000,
            "q": f"date>{start}",
            "sort": "-date"
        })

        for it in data.get("data", {}).get("affected_items", []):
            ts_raw = it.get("mtime") or it.get("date") or it.get("timestamp") or ""
            if not ts_raw:
                continue

            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).isoformat()
            except Exception:
                ts = datetime.utcnow().isoformat()  # fallback to current time

            path = it.get("file", "").lower()
            typ = it.get("type", "").lower()
            aid = f"{ts}_{path}"
            if self.alert_manager.is_acknowledged(aid):
                continue

            sev = "low"
            if typ in ("modified", "deleted"):
                sev = "high"
            if any(p in path for p in self.wazuh_config.suspicious_paths):
                sev = "medium"
            if "readme" in path and "ransom" in path:
                sev = "critical"

            out.append({"timestamp": ts, "severity": sev})

        return out

    def _count(self, alerts):
        base = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            base[a["severity"]] += 1
        return base

    def _trend(self, alerts):
        out = self._empty_history()
        for a in alerts:
            try:
                ts = a["timestamp"]
                ts = ts.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts)
                weekday = dt.weekday()
                out[weekday][a["severity"]] += 1
            except Exception:
                continue
        return out

    # ─────────────────────── manager status / health ───────────────────────
    def _system_status(self) -> str:
        try:
            svcs = self.api.get("manager/status")["data"]["affected_items"][0]
            crit = ('wazuh-analysisd','wazuh-execd','wazuh-remoted',
                    'wazuh-syscheckd','wazuh-modulesd','wazuh-db','wazuh-apid')
            return "HEALTHY" if all(svcs.get(s) == "running" for s in crit) else "WARNING"
        except Exception:
            return "UNKNOWN"

    def _system_health(self) -> dict[str,int]:
        try:
            svcs = self.api.get("manager/status")["data"]["affected_items"][0]
            healthy  = sum(v == "running" for v in svcs.values())
            warning  = sum(v == "stopped" for v in svcs.values())
            critical = sum(v not in ("running","stopped") for v in svcs.values())
            return {"Healthy":max(healthy,1),"Warning":warning,"Critical":critical}
        except Exception:
            return {"Healthy":1,"Warning":1,"Critical":1}

    # ─────────────────────── Shuffle workflow status ───────────────────────
    def _workflow_status(self) -> dict[str,dict]:
        if self._wf_cache and time.time() - self._wf_cache_ts < 30:
            return self._wf_cache
        sh = self.config_manager.get_shuffle_config()
        if not sh.is_configured:
            return {"No workflows configured":{"status":"Idle","updated":0}}
        try:
            r = requests.get(f"{sh.shuffle_url.rstrip('/')}/api/v1/workflows",
                             headers={"Authorization":f"Bearer {sh.shuffle_api_key}"},
                             verify=False, timeout=4)
            r.raise_for_status()
            wanted = {n.lower() for n in sh.workflow_names}
            out = { wf["name"]: {
                        "status":  wf.get("status") or ("Enabled" if wf.get("enabled") else "Disabled"),
                        "updated": wf.get("updated") or wf.get("created",0)
                    }
                    for wf in r.json() if wf["name"].lower() in wanted }
            self._wf_cache, self._wf_cache_ts = out or {
                "No workflows found":{"status":"Idle","updated":0}}, time.time()
            return self._wf_cache
        except Exception as e:
            dbg.error(f"Shuffle error: {e}")
            return {"Shuffle unreachable":{"status":"Warning","updated":0}}

    # ─────────────────────── misc helpers ──────────────────────────────────
    @staticmethod
    def _empty_history():
        return {i: {"critical":0,"high":0,"medium":0,"low":0} for i in range(7)}

    def _load_acknowledged(self):
        try:
            with open("acknowledged_alerts.txt") as f:
                self.alert_history = {ln.strip() for ln in f}
        except FileNotFoundError:
            pass

    def _fallback(self):
        now = datetime.now().strftime("%I:%M %p")
        return {
            "active_threats":0,"total_alerts":0,"system_status":"UNKNOWN",
            "last_scan":f"Last checked at {now}","alert_trend":self.alert_history,
            "system_health":{"Healthy":1,"Warning":1,"Critical":1},
            "workflows":self._workflow_status()
        }
