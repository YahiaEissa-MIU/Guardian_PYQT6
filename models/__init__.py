# models/__init__.py
from .wazuh_config import WazuhConfig
from .incident_history_model import IncidentHistoryModel


__all__ = [
    'WazuhConfig',
    'IncidentHistoryModel',
]
