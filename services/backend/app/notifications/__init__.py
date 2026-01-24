"""
Analytical-Intelligence v1 - Notifications Module
"""

from app.notifications.types import DetectionAlert, SEVERITY_ORDER, severity_meets_threshold
from app.notifications.bus import NotificationBus, get_notification_bus, set_notification_bus
from app.notifications.telegram import TelegramNotifier

__all__ = [
    "DetectionAlert",
    "SEVERITY_ORDER",
    "severity_meets_threshold",
    "NotificationBus",
    "get_notification_bus",
    "set_notification_bus",
    "TelegramNotifier",
]
