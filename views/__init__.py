# views/__init__.py
from .dashboard_view import DashboardView
from .settings_view import SettingsView
from .alerts_view import AlertsView
from .Incident_history_view import IncidentHistoryView

__all__ = [
    'DashboardView',
    'SettingsView',
    'AlertsView',
    'IncidentHistoryView',
]
