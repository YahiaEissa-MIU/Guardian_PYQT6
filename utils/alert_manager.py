from PyQt6.QtCore import QObject, pyqtSignal
import os
import json
from datetime import datetime


class AlertManager(QObject):
    """
    Manages alert acknowledgment status and notifies subscribers of changes.
    Implements both signal-based notifications and backward-compatible observer pattern.
    """
    # Define signals
    alerts_updated = pyqtSignal()
    alert_acknowledged = pyqtSignal(str)  # Emits alert_id

    # Singleton instance
    __instance = None

    @staticmethod
    def get_instance():
        """Static method to get the singleton instance"""
        if AlertManager.__instance is None:
            AlertManager()
        return AlertManager.__instance

    def __init__(self):
        """Initialize the AlertManager once"""
        if AlertManager.__instance is not None:
            return

        # Initialize QObject properly
        super().__init__()

        # Set this instance as the singleton
        AlertManager.__instance = self

        # Initialize other attributes
        self._acknowledged_alerts = set()
        self._storage_file = self._get_storage_path()
        self._observers = []  # For backward compatibility
        self.load_acknowledged_alerts()

    def _get_storage_path(self):
        """Get the path to the acknowledged alerts storage file in AppData"""
        app_data_dir = os.path.join(os.getenv('APPDATA', os.path.expanduser('~')), 'Guardian')
        os.makedirs(app_data_dir, exist_ok=True)
        return os.path.join(app_data_dir, 'acknowledged_alerts.json')

    def load_acknowledged_alerts(self):
        """Load acknowledged alerts from storage file"""
        try:
            if os.path.exists(self._storage_file):
                with open(self._storage_file, 'r') as f:
                    data = json.load(f)
                    self._acknowledged_alerts = set(data.get('acknowledged_alerts', []))
                print(f"Loaded {len(self._acknowledged_alerts)} acknowledged alerts")
            else:
                print("No acknowledged alerts file found, creating new file")
                self._acknowledged_alerts = set()
                self._save_acknowledged_alerts()
        except Exception as e:
            print(f"Error loading acknowledged alerts: {e}")
            self._acknowledged_alerts = set()

    def _save_acknowledged_alerts(self):
        """Save acknowledged alerts to storage file"""
        try:
            data = {
                'acknowledged_alerts': list(self._acknowledged_alerts),
                'last_updated': datetime.now().isoformat()
            }
            with open(self._storage_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving acknowledged alerts: {e}")

    def add_acknowledged_alert(self, alert_id):
        """Mark an alert as acknowledged"""
        if alert_id not in self._acknowledged_alerts:
            print(f"AlertManager: Adding acknowledged alert: {alert_id}")
            self._acknowledged_alerts.add(alert_id)
            self._save_acknowledged_alerts()

            # CRITICAL: Use deferred signals with QTimer to prevent crashes
            from PyQt6.QtCore import QTimer

            # Use lambdas with the specific alert_id to avoid reference issues
            QTimer.singleShot(100, lambda aid=alert_id: self._safe_emit_acknowledged(aid))
            QTimer.singleShot(500, self._safe_emit_updated)

            print(f"AlertManager: Queued notifications for alert {alert_id}")
            return True
        return False

    def _safe_emit_acknowledged(self, alert_id):
        """Safely emit alert_acknowledged signal"""
        try:
            print(f"AlertManager: Emitting alert_acknowledged for {alert_id}")
            self.alert_acknowledged.emit(alert_id)
        except Exception as e:
            print(f"Error in _safe_emit_acknowledged: {e}")

    def _safe_emit_updated(self):
        """Safely emit alerts_updated signal and notify observers"""
        try:
            print(f"AlertManager: Emitting alerts_updated")
            self.alerts_updated.emit()

            # Defer observer notifications
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(100, self._notify_observers)
        except Exception as e:
            print(f"Error in _safe_emit_updated: {e}")

    def is_acknowledged(self, alert_id):
        """Check if an alert is acknowledged"""
        return alert_id in self._acknowledged_alerts

    def get_all_acknowledged_alerts(self):
        """Get all acknowledged alert IDs"""
        return self._acknowledged_alerts.copy()

    def clear_acknowledged_alerts(self):
        """Clear all acknowledged alerts"""
        self._acknowledged_alerts.clear()
        self._save_acknowledged_alerts()

        # Emit Qt signal
        self.alerts_updated.emit()

        # Notify legacy observers
        self._notify_observers()

        return True

    # Backward compatibility methods for old observer pattern
    def add_observer(self, observer):
        """Add an observer (for backward compatibility)"""
        print(f"Adding observer {observer} to AlertManager")
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer):
        """Remove an observer (for backward compatibility)"""
        if observer in self._observers:
            self._observers.remove(observer)

    def _notify_observers(self):
        """Notify all observers (backward compatibility)"""
        for observer in self._observers:
            if hasattr(observer, 'on_alerts_updated'):
                try:
                    observer.on_alerts_updated()
                except Exception as e:
                    print(f"Error notifying observer {observer}: {e}")