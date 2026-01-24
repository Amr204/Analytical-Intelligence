"""
Analytical-Intelligence v1 - Telegram Test Script
Run inside container: python -m app.notifications.telegram_test
"""

import asyncio
import sys
from datetime import datetime

from app.config import settings
from app.notifications.telegram import TelegramNotifier
from app.notifications.types import DetectionAlert


async def main():
    """Send a test message to verify Telegram configuration."""
    print("=" * 60)
    print("Telegram Integration Test")
    print("=" * 60)

    # Check configuration
    print(f"\nConfiguration:")
    print(f"  TELEGRAM_ENABLED:      {settings.telegram_enabled}")
    print(f"  TELEGRAM_CHAT_ID:      {settings.telegram_chat_id}")
    print(f"  TELEGRAM_MIN_SEVERITY: {settings.telegram_min_severity}")
    print(f"  TELEGRAM_BOT_TOKEN:    {'***SET***' if settings.telegram_bot_token else 'NOT SET'}")

    if not settings.telegram_enabled:
        print("\n⚠️  TELEGRAM_ENABLED is false. Set to true to enable alerts.")
        return

    if not settings.telegram_bot_token:
        print("\n❌ TELEGRAM_BOT_TOKEN is not set. Cannot send test message.")
        sys.exit(1)

    print("\n📤 Sending test message...")

    notifier = TelegramNotifier()

    try:
        # Send simple test message
        await notifier.send_message(
            "✅ <b>Analytical-Intelligence</b>\n\n"
            "Telegram integration test successful!\n"
            f"🕒 {datetime.utcnow().isoformat()}Z"
        )
        print("✅ Simple message sent successfully!")

        # Send sample alert
        sample_alert: DetectionAlert = {
            "detection_id": 0,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "device_id": "test-device",
            "model_name": "test",
            "label": "Test Alert",
            "score": 0.99,
            "severity": "HIGH",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "dst_port": 22,
            "protocol": "TCP",
            "reason": "This is a test alert to verify formatting",
        }

        await notifier.send_detection_alert(sample_alert)
        print("✅ Sample alert sent successfully!")

        print("\n" + "=" * 60)
        print("🎉 All tests passed! Check your Telegram group for messages.")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Failed to send message: {e}")
        print("\nTroubleshooting:")
        print("  - Verify TELEGRAM_BOT_TOKEN is correct")
        print("  - Verify bot is added to the group")
        print("  - Verify TELEGRAM_CHAT_ID is correct")
        sys.exit(1)

    finally:
        await notifier.close()


if __name__ == "__main__":
    asyncio.run(main())
