# 📱 Telegram Alerts Integration

> Real-time security alerts delivered to your Telegram group

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Bot Setup](#bot-setup)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Message Format](#message-format)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Implementation Details](#implementation-details)

---

## Overview

Analytical-Intelligence can send real-time alerts to a Telegram group when high-severity detections occur. This is **optional** and **non-blocking** — if Telegram is disabled or unavailable, ingestion continues normally.

**Features:**
- Severity-based filtering (only HIGH/CRITICAL by default)
- Rate limiting (max 20 messages/minute)
- Deduplication (skip duplicate alerts within 60s)
- Exponential retry (handles temporary failures)
- Soft-fail (Telegram errors never break ingestion)

---

## Prerequisites

1. **Telegram Account** — you need one to create a bot
2. **Telegram Group** — where alerts will be sent
3. **Bot Token** — obtained from @BotFather
4. **Chat ID** — the group's unique identifier

---

## Bot Setup

### Step 1: Create a Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Follow prompts to set name and username
4. Save the **bot token** (looks like `123456789:ABCdefGHIjklMNOpqrSTUvwxYZ`)

> [!WARNING]
> **Never share or commit your bot token!** Treat it like a password.  
> If leaked, revoke it immediately via `/revoke` in @BotFather.

### Step 2: Add Bot to Group

1. Create a Telegram group (or use existing)
2. Add your bot as a member
3. The bot needs permission to send messages

### Step 3: Get Chat ID

Option A — **Use getUpdates API**:
```bash
curl "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
```
Send a message in the group, then check the response for `"chat":{"id":-123456789}`.  
Group IDs are **negative numbers**.

Option B — **Use @userinfobot**:
1. Add @userinfobot to your group temporarily
2. It will post the chat ID
3. Remove the bot when done

### Step 4: Privacy Mode (Recommended)

By default, bots only see messages starting with `/`. To see all messages:

1. Open @BotFather
2. Send `/mybots` → select your bot
3. **Bot Settings** → **Group Privacy** → **Turn off**

This is optional — the alert bot doesn't need to read messages, just send them.

---

## Configuration

All settings are via environment variables with safe defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGRAM_ENABLED` | `false` | Enable/disable Telegram alerts |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | `-5228638760` | Target group chat ID |
| `TELEGRAM_MIN_SEVERITY` | `HIGH` | Minimum severity to alert |
| `TELEGRAM_RATE_LIMIT_PER_MIN` | `20` | Max messages per minute |
| `TELEGRAM_DEDUP_WINDOW_SECONDS` | `60` | Skip duplicates within window |
| `TELEGRAM_TIMEOUT_SECONDS` | `10` | API request timeout |
| `TELEGRAM_STARTUP_TEST` | `false` | Send test on startup |
| `PUBLIC_DASHBOARD_BASE_URL` | _(empty)_ | Optional: add dashboard link |

**Severity levels:** `INFO < LOW < MEDIUM < HIGH < CRITICAL`

---

## Deployment

### Quick Setup

1. **Copy environment template:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env`:**
   ```env
   TELEGRAM_ENABLED=true
   TELEGRAM_BOT_TOKEN=your_token_here
   TELEGRAM_CHAT_ID=-5228638760
   ```

3. **Restart services:**
   ```bash
   docker compose -f docker-compose.analysis.yml up -d --build
   ```

4. **(Optional) Verify with startup test:**
   ```env
   TELEGRAM_STARTUP_TEST=true
   ```
   Then restart. A test message will appear in your group.  
   Set back to `false` after verification.

### Test Script

Run the built-in test script inside the container:
```bash
docker compose -f docker-compose.analysis.yml exec backend \
  python -m app.notifications.telegram_test
```

This sends a test message and sample alert to verify configuration.

---

## Message Format

Alerts use HTML formatting for readability:

```
🚨 CRITICAL | DDoS
🕒 2026-01-23T12:34:56Z
🖥️ device: sensor-01
🌐 192.168.88.101 → 192.168.88.108:80 (TCP)
🤖 model: Network-RF | score=0.97
🧾 High volume traffic detected
🔗 Dashboard
```

**Icons:**
- 🚨 CRITICAL
- 🔴 HIGH
- 🟠 MEDIUM
- 🟡 LOW
- ℹ️ INFO

---

## Troubleshooting

### 401 Unauthorized
**Cause:** Invalid bot token  
**Fix:** Verify `TELEGRAM_BOT_TOKEN` is correct. Get a new token from @BotFather if needed.

### 400 Bad Request: chat not found
**Cause:** Bot not in group or wrong chat ID  
**Fix:** 
1. Ensure bot is added to the group
2. Verify `TELEGRAM_CHAT_ID` is correct (negative for groups)
3. Send a message in the group and check `/getUpdates`

### 429 Too Many Requests
**Cause:** Rate limited by Telegram  
**Fix:** Reduce `TELEGRAM_RATE_LIMIT_PER_MIN` or wait. The bus respects `Retry-After` headers.

### Messages not appearing
**Cause:** Bot lacks permission or privacy mode  
**Fix:**
1. Make bot an admin (optional but helps)
2. Check @BotFather → Bot Settings → Group Privacy

### No errors but no alerts
**Cause:** Severity below threshold or dedup  
**Fix:**
1. Check `TELEGRAM_MIN_SEVERITY` setting
2. Try lowering to `MEDIUM` or `LOW` for testing
3. Check backend logs: `docker compose logs backend | grep -i telegram`

### Startup test fails
Check the logs:
```bash
docker compose -f docker-compose.analysis.yml logs backend | grep -i telegram
```

---

## Security

> [!CAUTION]
> **Never commit tokens to Git!**

### Best Practices

1. **Token in `.env` only** — never in code or compose files
2. **`.env` in `.gitignore`** — already configured
3. **Rotate if leaked** — use @BotFather `/revoke` command
4. **Private group** — use a private Telegram group
5. **Limit bot permissions** — only needs "send messages"

### If Token is Leaked

1. Go to @BotFather
2. Send `/mybots` → select bot → **API Token** → **Revoke**
3. Generate new token
4. Update `.env` and restart

---

## Implementation Details

> For developers/maintainers

### Architecture

```
Detection → NotificationBus.enqueue_alert() → Queue → Worker → TelegramNotifier
                (non-blocking)              (async)  (rate limit, dedup, retry)
```

### Files

| File | Purpose |
|------|---------|
| `app/notifications/types.py` | Severity constants, DetectionAlert type |
| `app/notifications/telegram.py` | TelegramNotifier with httpx |
| `app/notifications/bus.py` | NotificationBus with queue/worker |
| `app/notifications/__init__.py` | Module exports |
| `app/notifications/telegram_test.py` | CLI test script |
| `app/config.py` | Settings (telegram_* variables) |

### Hook Points

Alerts are enqueued after detection insert in:
- `app/ingest/flow_ingest.py` — Network ML detections
- `app/ingest/auth_ingest.py` — SSH detections

### Deduplication Key

```
(attack_type, severity, device_id, src_ip, dst_ip, dst_port, model_name)
```

### Rate Limiting

Simple sliding window: tracks timestamps of sent messages, rejects if count ≥ limit within 60s.

### Retry Strategy

3 attempts with exponential backoff: 0.5s, 1s, 2s.  
Respects HTTP 429 `Retry-After` header.

---

**Need help?** Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or backend logs.
