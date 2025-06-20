# controllers/workflows_controller.py
from PyQt6.QtCore import QObject, pyqtSignal, QThread
import requests, time
from datetime import datetime
from utils.config_manager import ConfigManager


class WorkflowsController(QObject):
    """
    Polls Shuffle for each configured workflow and emits `workflows_updated`
    with a list[dict] ready for WorkflowsView.update_workflows()
    """
    workflows_updated = pyqtSignal(list)          # → view.update_workflows

    REFRESH_SECONDS = 30                          # background poll interval

    # ────────────────────────────────────────────────────────────────
    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        self.cfg_mgr = ConfigManager()
        self.view = None                          # set by Router
        self._running = False
        self._worker  = None

        # wire polling thread & fire an immediate fetch
        self.start_worker()

    # ────────────────────────────────────────────────────────────────
    # Router calls this right after view is created
    def set_view(self, view) -> None:
        self.view = view
        self.workflows_updated.connect(self.view.update_workflows)
        # first paint
        self.refresh_workflows()

    # ────────────────────────────────────────────────────────────────
    # public API (called by view Refresh button or Router)
    def refresh_workflows(self) -> None:
        self.workflows_updated.emit(self._fetch_once())

    # ────────────────────────────────────────────────────────────────
    # background polling thread
    def start_worker(self) -> None:
        if self._running:
            return

        self._running = True
        self._worker = QThread()

        def loop():
            while self._running:
                self.workflows_updated.emit(self._fetch_once())
                for _ in range(self.REFRESH_SECONDS * 10):
                    if not self._running:
                        break
                    time.sleep(0.1)

        self._worker.run = loop
        self._worker.start()

    # ────────────────────────────────────────────────────────────────
    def stop(self) -> None:
        self._running = False
        if self._worker and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait(1000)

    cleanup = stop        # Router already looks for cleanup()

    # ────────────────────────────────────────────────────────────────
    # internal helpers
    def _current_shuffle_creds(self):
        m = self.cfg_mgr.get_shuffle_config()
        return m.shuffle_url, m.shuffle_api_key, m.workflow_names or []

    def _ensure_url(self, url: str) -> str:
        if url.startswith(('http://', 'https://')):
            return url.rstrip('/')
        return ("https://" if ':3443' in url else "http://") + url.rstrip('/')

    def _fetch_once(self) -> list[dict]:
        """Return list of workflows the user selected in Settings."""
        url, api_key, names = self._current_shuffle_creds()
        if not (url and api_key and names):
            return []

        url = self._ensure_url(url)
        wanted = {n.lower() for n in names}

        try:
            r = requests.get(f"{url}/api/v1/workflows",
                             headers={"Authorization": f"Bearer {api_key}"},
                             timeout=8, verify=False)
            if r.status_code != 200:
                return []

            out = []
            for wf in r.json():
                if wf.get("name", "").lower() not in wanted:
                    continue
                updated_raw = wf.get("updated") or wf.get("created")
                # convert timestamps that look like seconds / ms since epoch
                if isinstance(updated_raw, (int, float)):
                    updated = int(updated_raw)
                else:
                    updated = updated_raw     # already a string
                out.append({
                    "name":    wf.get("name", "Unknown"),
                    "status":  wf.get("status") or
                               ("Enabled" if wf.get("enabled") else "Disabled"),
                    "id":      wf.get("id", ""),
                    "updated": updated
                })
            return out
        except Exception:        # network / JSON etc.
            return []
