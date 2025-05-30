from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)


class DetectionConfig(AppConfig):
    """Configuration for the detection app"""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'detection'
    verbose_name = 'DDoS Detection System'

    def ready(self):
        """Initialize the detection system when Django starts"""
        import os

        # Only run in the main process, not in management commands or migrations
        if (os.environ.get('RUN_MAIN', None) != 'true' and
                'runserver' not in os.sys.argv):
            return

        try:
            logger.info("D4DoS Detection System app is ready")

            # Import signals if you have any
            # from . import signals

            # You can add initialization code here if needed
            # For now, we'll keep it simple and not auto-start the engine

        except Exception as e:
            logger.error(f"Error initializing D4DoS Detection System: {e}")
            # Don't raise the exception to prevent Django from failing to start