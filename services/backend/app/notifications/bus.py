"""
Analytical-Intelligence v1 - Notification Bus
Async queue-based notification dispatcher with rate limiting, dedup, and retry.
"""

import asyncio
import hashlib
import logging
import time
from collections import deque
from typing import Optional, Dict, Any

from app.config import settings
from app.notifications.types import DetectionAlert, severity_meets_threshold
from app.notifications.telegram import TelegramNotifier

logger = logging.getLogger(__name__)


class NotificationBus:
    """
    Async notification bus with:
    - Queue-based non-blocking dispatch
    - Severity gating
    - Rate limiting (sliding window)
    - Deduplication (time-based)
    - Retry with exponential backoff
    - Soft-fail (never crashes on errors)
    """

    def __init__(self):
        self._queue: asyncio.Queue[DetectionAlert] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._telegram: Optional[TelegramNotifier] = None

        # Rate limiting: timestamps of sent messages (sliding window)
        self._send_timestamps: deque = deque()
        self._rate_limit: int = settings.telegram_rate_limit_per_min

        # Deduplication: {hash -> expiry_time}
        self._dedup_cache: Dict[str, float] = {}
        self._dedup_window: int = settings.telegram_dedup_window_seconds

        # Retry config
        self._retry_delays = [0.5, 1.0, 2.0]  # Exponential backoff

    def start(self) -> None:
        """Start the notification worker."""
        if self._running:
            return

        if not settings.telegram_enabled:
            logger.info("Telegram notifications disabled (TELEGRAM_ENABLED=false)")
            return

        if not settings.telegram_bot_token:
            logger.warning("Telegram enabled but TELEGRAM_BOT_TOKEN not set - notifications disabled")
            return

        self._running = True
        self._telegram = TelegramNotifier()
        self._worker_task = asyncio.create_task(self._worker())
        logger.info("NotificationBus started")

    async def stop(self) -> None:
        """Stop the notification worker gracefully."""
        if not self._running:
            return

        self._running = False

        if self._worker_task:
            # Signal worker to stop by putting None
            await self._queue.put(None)  # type: ignore
            try:
                await asyncio.wait_for(self._worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._worker_task.cancel()
            self._worker_task = None

        if self._telegram:
            await self._telegram.close()
            self._telegram = None

        logger.info("NotificationBus stopped")

    def enqueue_alert(self, alert: DetectionAlert) -> None:
        """
        Enqueue an alert for async processing.
        This is fast and safe - never blocks or raises.
        """
        if not self._running:
            return

        try:
            # Fire-and-forget enqueue
            self._queue.put_nowait(alert)
        except asyncio.QueueFull:
            logger.warning("Notification queue full, alert dropped")
        except Exception as e:
            logger.error(f"Failed to enqueue alert: {e}")

    async def _worker(self) -> None:
        """Background worker that processes the queue."""
        logger.debug("NotificationBus worker started")

        while self._running:
            try:
                # Wait for next alert
                alert = await self._queue.get()

                # None signals shutdown
                if alert is None:
                    break

                await self._process_alert(alert)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"NotificationBus worker error: {e}")

        logger.debug("NotificationBus worker stopped")

    async def _process_alert(self, alert: DetectionAlert) -> None:
        """Process a single alert with all checks."""
        try:
            severity = alert.get("severity", "INFO")

            # 1. Severity gating
            if not severity_meets_threshold(severity, settings.telegram_min_severity):
                logger.debug(f"Alert skipped (severity {severity} < {settings.telegram_min_severity})")
                return

            # 2. Deduplication check
            alert_hash = self._compute_alert_hash(alert)
            now = time.time()
            self._cleanup_dedup_cache(now)

            if alert_hash in self._dedup_cache:
                logger.debug(f"Alert skipped (duplicate within {self._dedup_window}s)")
                return

            # 3. Rate limit check
            self._cleanup_rate_window(now)
            if len(self._send_timestamps) >= self._rate_limit:
                logger.warning(f"Alert skipped (rate limit {self._rate_limit}/min exceeded)")
                return

            # 4. Send with retry
            success = await self._send_with_retry(alert)

            if success:
                # Record for dedup and rate limit
                self._dedup_cache[alert_hash] = now + self._dedup_window
                self._send_timestamps.append(now)

        except Exception as e:
            # Soft-fail: log and continue
            logger.error(f"Failed to process alert: {e}")

    async def _send_with_retry(self, alert: DetectionAlert) -> bool:
        """Send alert with exponential backoff retry."""
        if not self._telegram:
            return False

        for attempt, delay in enumerate(self._retry_delays + [None], start=1):
            try:
                await self._telegram.send_detection_alert(alert)
                logger.info(f"Telegram alert sent: {alert.get('label', 'unknown')} ({alert.get('severity', 'unknown')})")
                return True

            except Exception as e:
                error_msg = str(e)
                # Don't log token in errors
                if "bot" in error_msg.lower():
                    error_msg = "Telegram API error (check token/chat_id)"

                if delay is not None:
                    logger.warning(f"Telegram send failed (attempt {attempt}/3): {error_msg}, retrying in {delay}s")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Telegram send failed after 3 attempts: {error_msg}")

        return False

    def _compute_alert_hash(self, alert: DetectionAlert) -> str:
        """Compute dedup hash from alert key fields."""
        key_parts = [
            alert.get("label", ""),
            alert.get("severity", ""),
            alert.get("device_id", ""),
            alert.get("src_ip", ""),
            alert.get("dst_ip", ""),
            str(alert.get("dst_port", "")),
            alert.get("model_name", ""),
        ]
        key_str = "|".join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _cleanup_dedup_cache(self, now: float) -> None:
        """Remove expired entries from dedup cache."""
        expired = [k for k, exp in self._dedup_cache.items() if exp <= now]
        for k in expired:
            del self._dedup_cache[k]

    def _cleanup_rate_window(self, now: float) -> None:
        """Remove timestamps older than 60 seconds."""
        cutoff = now - 60
        while self._send_timestamps and self._send_timestamps[0] < cutoff:
            self._send_timestamps.popleft()


# Global bus instance (set by main.py lifespan)
_notification_bus: Optional[NotificationBus] = None


def set_notification_bus(bus: Optional[NotificationBus]) -> None:
    """Set the global notification bus instance."""
    global _notification_bus
    _notification_bus = bus


def get_notification_bus() -> Optional[NotificationBus]:
    """Get the global notification bus instance."""
    return _notification_bus
