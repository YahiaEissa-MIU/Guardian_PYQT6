from typing import Dict, Optional, Type
import logging
import os
from dataclasses import dataclass
from PyQt6.QtWidgets import QVBoxLayout, QSizePolicy, QMessageBox
from PyQt6.QtCore import QTimer, Qt
from views.alerts_view import AlertsView
from views.Incident_history_view import IncidentHistoryView
from controllers import SettingsController, AlertsController, WorkflowsController
from controllers.incident_history_controller import IncidentHistoryController
from controllers.dashboard_controller import DashboardController
from utils.config_manager import ConfigManager
from utils.alert_manager import AlertManager
import views
from views.workflows_view import WorkflowsView
from models import IncidentHistoryModel, WazuhConfig

try:
    from views import (
        dashboard_view, SettingsView,

    )
except ImportError:
    from stubs import (
        AboutSystemView
    )

# Use a simple QWidget as fallback for views if there are import issues
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel


# Configure logging
def setup_debug_logging():
    log_dir = os.path.join(os.environ['APPDATA'], 'Guardian', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Configure file handler for debug logging
    debug_logger = logging.getLogger('guardian_debug')
    debug_logger.setLevel(logging.DEBUG)

    log_file = os.path.join(log_dir, 'sync_debug.log')
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))
    debug_logger.addHandler(file_handler)

    return debug_logger


# Initialize loggers
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
debug_logger = setup_debug_logging()


@dataclass
class ViewConfiguration:
    """Configuration for a view including its dependencies"""
    view_class: Type
    controller_class: Optional[Type] = None
    model_class: Optional[Type] = None
    needs_refresh: bool = False
    observes_settings: bool = False
    requires_special_init: bool = False


class Router:
    """Router for managing application views and their dependencies"""

    # Define view configurations
    VIEW_CONFIGS = {
        "dashboard": ViewConfiguration(
            view_class=views.dashboard_view.DashboardView,
            controller_class=DashboardController,
            needs_refresh=True,
            observes_settings=True
        ),
        "incident_history": ViewConfiguration(
            view_class=IncidentHistoryView,
            controller_class=IncidentHistoryController,
            model_class=None,  # Model is managed by ConfigManager
            observes_settings=True,
            requires_special_init=True
        ),
        "settings": ViewConfiguration(
            view_class=views.settings_view.SettingsView,
            controller_class=SettingsController
        ),
        "alerts": ViewConfiguration(
            view_class=AlertsView,
            controller_class=AlertsController,
            needs_refresh=True,
            observes_settings=True
        ),
        "workflows": ViewConfiguration(
            view_class=WorkflowsView,
            controller_class=WorkflowsController,
            observes_settings=True,  # page should reload if Shuffle creds change
        ),
    }

    def __init__(self, root):
        """Initialize router with root window"""
        self.root = root
        self.views: Dict = {}
        self.controllers: Dict = {}
        self.models: Dict = {}

        # Initialize ConfigManager early to ensure it's available to all components
        self.config_manager = ConfigManager()
        debug_logger.info("ConfigManager initialized")

        # Load and verify configurations
        self.verify_configurations()

        # Initialize AlertManager
        alert_manager = AlertManager.get_instance()
        alert_manager.load_acknowledged_alerts()

        # Initialize core components
        self.initialize_core_components()
        logger.info("Router initialized")

        # Ensure observers are properly registered
        self.register_configuration_observers()

    def verify_configurations(self):
        """Verify all configurations are properly loaded at startup"""
        try:
            # Get current configurations
            wazuh_config = self.config_manager.get_wazuh_config()
            shuffle_config = self.config_manager.get_shuffle_config()

            # Log current configuration state
            debug_logger.info("=== Configuration Verification ===")
            debug_logger.info(f"Wazuh configured: {wazuh_config.is_configured}")
            if wazuh_config.is_configured:
                debug_logger.info(f"Wazuh URL: {wazuh_config.url}")
                debug_logger.info(f"Wazuh username: {wazuh_config.username}")

            debug_logger.info(f"Shuffle configured: {shuffle_config.is_configured}")
            if shuffle_config.is_configured:
                debug_logger.info(f"Shuffle URL: {shuffle_config.shuffle_url}")
                debug_logger.info(f"Workflows: {shuffle_config.workflow_names}")

        except Exception as e:
            debug_logger.error(f"Error during configuration verification: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())

    def register_configuration_observers(self):
        """Register all controllers that need to observe configuration changes"""
        try:
            debug_logger.info("Registering configuration observers...")

            # Register DashboardController if it exists
            if 'dashboard' in self.controllers:
                controller = self.controllers['dashboard']
                self.config_manager.add_wazuh_observer(controller.on_config_change)
                debug_logger.info(f"Added Wazuh observer: {controller.on_config_change}")

            # Register AlertsController if it exists
            if 'alerts' in self.controllers:
                controller = self.controllers['alerts']
                self.config_manager.add_wazuh_observer(controller.on_config_change)
                debug_logger.info(f"Added Wazuh observer: {controller.on_config_change}")

            # Register IncidentHistoryController if it exists
            if 'incident_history' in self.controllers:
                controller = self.controllers['incident_history']
                # IncidentHistoryController uses the model from ConfigManager directly
                # No need to add observer here as the model has its own observer pattern
                debug_logger.info(f"IncidentHistoryController uses ConfigManager's incident model")

            # Register WorkflowsController if it exists
            if 'workflows' in self.controllers:
                self.config_manager.add_shuffle_observer(
                    lambda m: self.controllers['workflows'].controller.refresh_workflows()
                )

        except Exception as e:
            debug_logger.error(f"Error registering configuration observers: {e}")

    def initialize_core_components(self):
        """Initialize essential models and controllers"""
        try:
            # Initialize settings controller first
            self.settings_controller = SettingsController()
            self.controllers['settings'] = self.settings_controller

            # Initialize DashboardController early
            self.controllers['dashboard'] = DashboardController()

            # Initialize AlertsController early
            self.controllers['alerts'] = AlertsController()

            # Initialize IncidentHistoryController early
            self.controllers['incident_history'] = IncidentHistoryController()

            logger.info("Core components initialized")

            # Ensure controllers have the current configuration
            self.sync_controllers_with_config()

        except Exception as e:
            logger.error(f"Error initializing core components: {e}")
            debug_logger.error(f"Error initializing core components: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())
            raise

    def sync_controllers_with_config(self):
        """Ensure all controllers have the latest configuration"""
        try:
            wazuh_config = self.config_manager.get_wazuh_config()
            shuffle_config = self.config_manager.get_shuffle_config()

            # Update settings controller
            if 'settings' in self.controllers:
                controller = self.controllers['settings']
                if hasattr(controller, 'wazuh_config'):
                    controller.wazuh_config = wazuh_config

            # Update dashboard controller
            if 'dashboard' in self.controllers:
                controller = self.controllers['dashboard']
                if hasattr(controller, 'wazuh_config'):
                    controller.wazuh_config = wazuh_config

            # Update alerts controller
            if 'alerts' in self.controllers:
                controller = self.controllers['alerts']
                if hasattr(controller, 'wazuh_config'):
                    controller.wazuh_config = wazuh_config

            # IncidentHistoryController uses ConfigManager directly

            debug_logger.info("Controllers synchronized with latest configuration")

        except Exception as e:
            debug_logger.error(f"Error syncing controllers with config: {e}")

    def create_view(self, name: str) -> None:
        try:
            # Check if the configuration and view class exist
            if name not in self.VIEW_CONFIGS:
                logger.error(f"No view configuration found for: {name}")
                return

            config = self.VIEW_CONFIGS[name]

            # Check if view class is available
            view_class = config.view_class
            if view_class is None:
                logger.error(f"View class is None for {name}")
                return

            # Additional debug info
            logger.info(f"Creating view {name} with class {view_class.__name__}")

            # If view already exists and is still valid, don't recreate it
            if name in self.views:
                try:
                    view = self.views[name]
                    if hasattr(view, 'isVisible'):
                        debug_logger.info(f"View {name} already exists and is valid")
                        return
                except Exception as e:
                    debug_logger.info(f"View {name} exists but is invalid, recreating: {e}")
                    self.safely_destroy_view(name)

            # Get or create controller
            controller = None
            if config.controller_class:
                try:
                    if name in self.controllers:
                        controller = self.controllers[name]
                        debug_logger.info(f"Using existing controller for {name}")
                    else:
                        controller = config.controller_class()
                        self.controllers[name] = controller
                except Exception as controller_err:
                    debug_logger.error(f"Error creating controller for {name}: {controller_err}")
                    import traceback
                    debug_logger.error(traceback.format_exc())

            # Create view
            debug_logger.info(f"Creating new view for {name}")
            try:
                parent = self.root.main_content_frame
                view = view_class(parent)
                self.views[name] = view

                # Special initialization for incident_history view
                if name == "incident_history" and config.requires_special_init:
                    self._setup_incident_history_view(view, controller)

            except Exception as view_err:
                debug_logger.error(f"Error creating view {name}: {view_err}")
                import traceback
                debug_logger.error(traceback.format_exc())

                # Create fallback placeholder view
                try:
                    placeholder = QWidget(self.root.main_content_frame)
                    layout = QVBoxLayout(placeholder)
                    label = QLabel(f"Error loading {name} view")
                    label.setStyleSheet("font-size: 18px; color: red; font-weight: bold;")
                    details = QLabel(f"Error: {str(view_err)}")
                    details.setStyleSheet("color: red;")
                    details.setWordWrap(True)
                    layout.addWidget(label)
                    layout.addWidget(details)
                    layout.addStretch()
                    self.views[name] = placeholder
                except Exception as placeholder_err:
                    debug_logger.error(f"Even placeholder creation failed: {placeholder_err}")
                return

            # Set up view-controller relationship
            if controller and view:
                try:
                    if hasattr(view, 'set_controller'):
                        view.set_controller(controller)

                    if hasattr(view, "set_router"):
                        view.set_router(self)

                    if hasattr(controller, 'set_view'):
                        controller.set_view(view)
                except Exception as relation_err:
                    debug_logger.error(f"Error setting up view-controller relation for {name}: {relation_err}")

            logger.info(f"Created view: {name}")

        except Exception as e:
            logger.error(f"Error creating view {name}: {e}")
            debug_logger.error(f"Error creating view {name}: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())

    def _setup_incident_history_view(self, view, controller):
        """Special setup for incident history view with all signal connections"""
        try:
            # Defer the signal connections to ensure view is fully initialized
            def connect_signals():
                try:
                    # Connect view signals to controller
                    view.refresh_requested.connect(controller.refresh_incidents)
                    view.export_requested.connect(controller.export_incidents)
                    view.generate_report_requested.connect(controller.generate_report)
                    view.fetch_cve_details_requested.connect(controller.fetch_cve_details)

                    # Connect the new filter_requested signal
                    view.filter_requested.connect(controller.request_filter)

                    # Connect controller signals to view
                    controller.incidents_updated.connect(view.update_incidents)
                    controller.cve_data_updated.connect(view.update_cve_cache)
                    controller.export_completed.connect(
                        lambda msg: QMessageBox.information(view, "Export Complete", msg)
                    )
                    controller.export_failed.connect(
                        lambda msg: QMessageBox.critical(view, "Export Failed", msg)
                    )
                    controller.report_generated.connect(
                        lambda path: QMessageBox.information(
                            view,
                            "Report Generated",
                            f"Report saved to: {path}"
                        )
                    )
                    controller.status_updated.connect(view.update_status)

                    # Load initial data if available
                    model = controller.model
                    if model and hasattr(model, 'incidents') and model.incidents:
                        view.update_incidents(model.incidents)

                    debug_logger.info("Incident history view setup completed")

                except Exception as e:
                    debug_logger.error(f"Error connecting signals: {e}")
                    import traceback
                    debug_logger.error(traceback.format_exc())

            # Use QTimer to defer signal connections
            QTimer.singleShot(0, connect_signals)

        except Exception as e:
            debug_logger.error(f"Error setting up incident history view: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())

    def _create_error_placeholder(self, name: str, error_msg: str) -> QWidget:
        """Create an error placeholder widget"""
        from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
        placeholder = QWidget(self.root.main_content_frame)
        layout = QVBoxLayout(placeholder)
        label = QLabel(f"Error loading {name} view")
        label.setStyleSheet("font-size: 18px; color: red; font-weight: bold;")
        details = QLabel(f"Error: {error_msg}")
        details.setStyleSheet("color: red;")
        details.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(details)
        layout.addStretch()
        placeholder.setLayout(layout)
        return placeholder

    def show(self, name: str) -> None:
        try:
            debug_logger.info(f"=== Router Show: {name} ===")

            # Hide all views first (don't destroy yet)
            for view_name, view in self.views.items():
                if view and view_name != name:
                    view.hide()
                    view.setParent(None)  # Remove from parent temporarily

            # Clear the main content frame layout
            main_layout = self.root.main_content_frame.layout()
            if main_layout:
                # Remove all widgets from layout without destroying them
                while main_layout.count():
                    item = main_layout.takeAt(0)
                    if item.widget():
                        item.widget().setParent(None)
            else:
                # Create new layout if none exists
                main_layout = QVBoxLayout(self.root.main_content_frame)
                main_layout.setContentsMargins(0, 0, 0, 0)
                main_layout.setSpacing(0)

            # Now safely destroy all other views except the one we're showing
            views_to_destroy = [v for v in list(self.views.keys()) if v != name]
            for view_name in views_to_destroy:
                # First disconnect all signals related to this view
                if view_name in self.controllers and hasattr(self.controllers[view_name], 'cleanup'):
                    try:
                        self.controllers[view_name].cleanup()
                    except Exception as e:
                        debug_logger.error(f"Error cleaning up controller for {view_name}: {e}")
                self.safely_destroy_view(view_name)

            # Sync controllers with latest configuration
            self.sync_controllers_with_config()

            # Create view if needed
            if name not in self.views:
                self.create_view(name)

            # Show the view
            if name in self.views and self.views[name]:
                view = self.views[name]

                # Set parent and add to layout
                view.setParent(self.root.main_content_frame)
                main_layout.addWidget(view)

                # Ensure the view fills the available space
                view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

                # Show and raise the view
                view.show()
                view.raise_()  # Bring to front

                # Force update geometry
                view.updateGeometry()
                self.root.main_content_frame.updateGeometry()

                # For incident history view, refresh data on show if configured
                if name == "incident_history" and name in self.controllers:
                    controller = self.controllers[name]
                    if controller.model and controller.model.is_configured:
                        # Refresh in background without blocking UI
                        QTimer.singleShot(500, controller.refresh_incidents)

                if name == "workflows" and name in self.controllers:
                    self.controllers["workflows"].refresh_workflows()

                # Resize view after a short delay
                QTimer.singleShot(100, lambda: self.update_view_size(name))

            debug_logger.info(f"Successfully showed view: {name}")

        except Exception as e:
            debug_logger.error(f"Error showing view {name}: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())

    def update_view_size(self, name):
        """Force a view to update its size to match the main content frame"""
        if name in self.views and self.views[name]:
            view = self.views[name]
            parent_size = self.root.main_content_frame.size()
            view.resize(parent_size)
            view.updateGeometry()
            debug_logger.info(f"Forced view {name} to size {parent_size.width()}x{parent_size.height()}")

    def cleanup(self):
        """Cleanup resources when closing the application"""
        try:
            debug_logger.info("=== Router Cleanup ===")

            # Cleanup controllers
            for name, controller in self.controllers.items():
                debug_logger.info(f"Cleaning up controller: {name}")
                if hasattr(controller, 'cleanup'):
                    try:
                        controller.cleanup()
                    except Exception as e:
                        debug_logger.error(f"Error cleaning up controller {name}: {e}")

                # Special cleanup for incident history controller
                if name == "incident_history" and hasattr(controller, 'cve_workers'):
                    # Wait for any active CVE fetch workers to complete
                    for worker in controller.cve_workers:
                        if worker.isRunning():
                            worker.quit()
                            worker.wait(1000)  # Wait up to 1 second

            # Remove observers
            for name, controller in self.controllers.items():
                if name in ["dashboard", "alerts"] and hasattr(controller, 'on_config_change'):
                    debug_logger.info(f"Removing {name} from Wazuh observers")
                    self.config_manager.remove_wazuh_observer(controller.on_config_change)

            # Cleanup views
            for name in list(self.views.keys()):
                debug_logger.info(f"Destroying view: {name}")
                self.safely_destroy_view(name)

            logger.info("Router cleanup completed")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            debug_logger.error(f"Error during cleanup: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())

    def safely_destroy_view(self, name):
        """Safely destroy a view and clean up resources"""
        if name not in self.views:
            return

        try:
            debug_logger.info(f"Safely destroying view: {name}")
            view = self.views[name]

            # Disconnect signals
            if hasattr(view, 'blockSignals'):
                view.blockSignals(True)

            # Special handling for incident_history view
            if name == 'incident_history':
                try:
                    # Disconnect all signals
                    view.refresh_requested.disconnect()
                    view.export_requested.disconnect()
                    view.generate_report_requested.disconnect()
                    view.fetch_cve_details_requested.disconnect()
                except Exception:
                    pass  # Signals might not be connected

            # Remove from layout if needed
            if hasattr(view, 'parent') and view.parent() and hasattr(view.parent(), 'layout'):
                parent_layout = view.parent().layout()
                if parent_layout:
                    parent_layout.removeWidget(view)

            # Cleanup controller if exists
            if name in self.controllers and hasattr(self.controllers[name], 'cleanup'):
                try:
                    debug_logger.info(f"Cleaning up controller for {name}")
                    self.controllers[name].cleanup()
                except Exception as e:
                    debug_logger.error(f"Error during controller cleanup: {e}")

            # Delete the view
            view.hide()
            view.deleteLater()
            del self.views[name]

            debug_logger.info(f"View {name} destroyed successfully")

        except Exception as e:
            debug_logger.error(f"Error destroying view {name}: {e}")
            import traceback
            debug_logger.error(traceback.format_exc())
