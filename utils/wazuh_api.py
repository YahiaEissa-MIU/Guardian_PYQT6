"""
A very small helper that:
 • keeps one `requests.Session`
 • refreshes the JWT token automatically
 • silently no-ops while Wazuh is still un-configured
"""
from __future__ import annotations
import requests, urllib3
from datetime import datetime
from typing import Optional
from models.wazuh_config import WazuhConfig     # or stubs.WazuhConfig during dev

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhApi:
    def __init__(self, cfg: Optional[WazuhConfig] = None) -> None:
        self._session: Optional[requests.Session] = None
        self._token: Optional[str] = None
        self._token_ts: Optional[datetime] = None
        self.update_config(cfg)

    # ───────────────────────────────────────────────────────────── public

    def update_config(self, cfg: Optional[WazuhConfig]) -> None:
        """Hot-swap credentials without recreating callers."""
        self._cfg = cfg
        # always reset token + session – safest
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
        self._session = requests.Session()
        self._session.verify = False
        self._token = None
        self._token_ts = None

    def get(self, endpoint: str, params: dict | None = None) -> dict:
        if not self._ready():
            return {}
        if not self._ensure_token():
            return {}
        try:
            r = self._session.get(f"{self._base_url()}/{endpoint}",
                                  params=params, timeout=8)
            if r.status_code == 200:
                return r.json()
            print(f"WazuhApi GET {endpoint} → {r.status_code}")
        except Exception as e:
            print(f"WazuhApi GET error {endpoint}: {e}")
        return {}

    def close(self) -> None:
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────────── internal

    def _ready(self) -> bool:
        return bool(self._cfg and self._cfg.is_configured and self._cfg.url)

    def _base_url(self) -> str:
        url = self._cfg.url.strip()
        if url.startswith(("http://", "https://")):
            url = url.split("://", 1)[1]
        if ":" not in url:
            url = f"{url}:55000"
        return f"https://{url}"

    def _ensure_token(self) -> bool:
        # still no creds?
        if not self._ready():
            return False
        # reuse token < 50 min old
        if self._token and (datetime.now() - self._token_ts).seconds < 3000:
            return True
        try:
            r = self._session.post(f"{self._base_url()}/security/user/authenticate",
                                   auth=(self._cfg.username, self._cfg.password),
                                   timeout=4)
            if r.status_code == 200:
                self._token = r.json()["data"]["token"]
                self._token_ts = datetime.now()
                self._session.headers.update(
                    {"Authorization": f"Bearer {self._token}"})
                return True
        except Exception as e:
            print(f"WazuhApi token error: {e}")
        return False
