"""
Analytical-Intelligence v1 - Telegram Notifier
"""

import logging
from typing import Optional

import httpx

from app.config import settings
from app.notifications.types import DetectionAlert

logger = logging.getLogger(__name__)

# Telegram API base URL
TELEGRAM_API_BASE = "https://api.telegram.org/bot"


class TelegramNotifier:
    """
    Async Telegram notifier using httpx.
    Reuses a single AsyncClient for connection pooling.
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._token: str = settings.telegram_bot_token
        self._chat_id: str = settings.telegram_chat_id
        self._timeout: int = settings.telegram_timeout_seconds
        self._parse_mode: str = settings.telegram_parse_mode
        self._disable_preview: bool = settings.telegram_disable_web_preview

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def send_message(self, text: str) -> None:
        """
        Send a message to the configured Telegram chat.
        Raises exception on failure (caller should handle).
        """
        if not self._token:
            raise ValueError("Telegram bot token not configured")

        url = f"{TELEGRAM_API_BASE}{self._token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": self._parse_mode,
            "disable_web_page_preview": self._disable_preview,
        }

        client = await self._get_client()
        response = await client.post(url, json=payload)

        if response.status_code == 429:
            # Rate limited - extract retry-after if available
            retry_after = response.headers.get("Retry-After", "unknown")
            raise httpx.HTTPStatusError(
                f"Rate limited. Retry after: {retry_after}s",
                request=response.request,
                response=response,
            )

        response.raise_for_status()

    async def send_detection_alert(self, alert: DetectionAlert) -> None:
        """
        Format and send a detection alert.
        """
        text = self._format_alert(alert)
        await self.send_message(text)

    def _format_alert(self, alert: DetectionAlert) -> str:
        """
        Format a detection alert as a readable HTML message.
        """
        severity = alert.get("severity", "UNKNOWN").upper()
        label = alert.get("label", "Unknown Attack")
        timestamp = alert.get("timestamp", "")
        device_id = alert.get("device_id", "unknown")
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")
        src_port = alert.get("src_port")
        dst_port = alert.get("dst_port")
        protocol = alert.get("protocol", "")
        model_name = alert.get("model_name", "")
        score = alert.get("score", 0.0)
        reason = alert.get("reason", "")

        # Severity emoji
        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "🔴",
            "MEDIUM": "🟠",
            "LOW": "🟡",
            "INFO": "ℹ️",
        }.get(severity, "⚠️")

        lines = [
            f"{severity_emoji} <b>{severity}</b> | <b>{label}</b>",
            f"🕒 {timestamp}" if timestamp else None,
            f"🖥️ device: {device_id}",
        ]

        # Network flow info
        if src_ip or dst_ip:
            flow = f"🌐 {src_ip or '?'}"
            if dst_ip:
                flow += f" → {dst_ip}"
                if dst_port:
                    flow += f":{dst_port}"
            if protocol:
                flow += f" ({protocol.upper()})"
            lines.append(flow)

        # Model info
        if model_name:
            model_line = f"🤖 model: {model_name}"
            if score:
                model_line += f" | score={score:.2f}"
            lines.append(model_line)

        # Reason
        if reason:
            # Truncate long reasons
            reason_short = reason[:100] + "..." if len(reason) > 100 else reason
            lines.append(f"🧾 {reason_short}")

        # Dashboard link
        if settings.public_dashboard_base_url:
            base = settings.public_dashboard_base_url.rstrip("/")
            lines.append(f"🔗 <a href=\"{base}/alerts\">Dashboard</a>")

        # Filter None values and join
        return "\n".join(line for line in lines if line)
