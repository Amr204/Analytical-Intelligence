#!/usr/bin/env python3
"""
Analytical-Intelligence v1 - Suricata Collector Agent
Tails Suricata eve.json and sends alerts to the analysis server.
"""

import sys
import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import requests

# Add parent directory for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.ip_utils import load_agent_config, print_config_banner

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
CONFIG = None
EVE_PATH = os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
SPOOL_DIR = Path("/app/spool")
SPOOL_FILE = SPOOL_DIR / "pending_alerts.ndjson"

# Deduplication settings - increased from 2s to 10s for better flood control
DEDUP_WINDOW_SECONDS = 10
dedup_cache = {}  # (sid, src_ip, dst_ip, dst_port) -> last_seen_timestamp

# Allowlist for local AI rules (reject all external/ET rules)
LOCAL_SID_MIN = 1000000
LOCAL_SID_MAX = 1009999

# Debug mode: set SURICATA_ACCEPT_ALL=true to send ALL alerts (for debugging)
ACCEPT_ALL_ALERTS = os.environ.get("SURICATA_ACCEPT_ALL", "false").lower() == "true"

# Spool size limits to prevent infinite backlog
SPOOL_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
SPOOL_MAX_LINES = 3000  # Max alerts to keep

# Retry settings
MAX_RETRIES = 5
RETRY_BASE_DELAY = 1  # seconds
RETRY_MAX_DELAY = 60  # seconds

# Spool settings (TTL and replay throttling)
SPOOL_TTL_SECONDS = 900  # 15 minutes - drop older alerts on replay
REPLAY_BATCH_SIZE = 10  # Process this many alerts per batch
REPLAY_BATCH_DELAY = 0.5  # Seconds to sleep between batches

# Stats logging interval
STATS_LOG_INTERVAL = 60  # Log counter stats every N seconds

# Counters
stats = {
    "lines_read": 0,
    "json_parsed": 0,
    "alerts_seen": 0,
    "alerts_sent": 0,
    "alerts_deduped": 0,
    "alerts_filtered": 0,
    "alerts_spooled": 0,
    "alerts_replayed": 0,
    "send_errors": 0,
    "file_reopens": 0,
}


def is_ai_local_rule(alert: dict) -> bool:
    """
    Check if alert is from our local AI rules (not ET/external noise).
    
    Accept ONLY if:
    - Signature starts with "AI " (our naming convention)
    - OR SID is in the local range (1000000-1009999)
    
    This filters out all Emerging Threats (ET) and other external rules.
    """
    try:
        sig = alert.get("alert", {})
        signature = sig.get("signature", "")
        sid = sig.get("signature_id", sig.get("sid", 0))
        
        if signature.startswith("AI "):
            return True
        if LOCAL_SID_MIN <= sid <= LOCAL_SID_MAX:
            return True
        return False
    except Exception:
        return False


def is_ddos_rule(alert: dict) -> bool:
    """
    Check if this is a DDoS rule (distributed attack).
    For DDoS rules, we ignore src_ip in dedup key to aggregate multi-source attacks.
    """
    try:
        sig = alert.get("alert", {})
        signature = sig.get("signature", "")
        return "AI DDoS:" in signature
    except Exception:
        return False


def is_duplicate(alert: dict) -> bool:
    """
    Check if alert is a duplicate within DEDUP_WINDOW_SECONDS.
    
    Dedup key varies by rule type:
    - DDoS rules: (sid, dst_ip, dst_port) - ignores src_ip for multi-source attacks
    - Other rules: (sid, src_ip, dst_ip, dst_port)
    """
    try:
        sig = alert.get("alert", {})
        sid = sig.get("signature_id", sig.get("sid", 0))
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dest_ip", alert.get("dst_ip", ""))
        dst_port = alert.get("dest_port", alert.get("dst_port", 0))
        
        # DDoS-aware dedup key
        if is_ddos_rule(alert):
            key = (sid, dst_ip, dst_port)  # Ignore src_ip
        else:
            key = (sid, src_ip, dst_ip, dst_port)
        
        now = time.time()
        
        if key in dedup_cache:
            if now - dedup_cache[key] < DEDUP_WINDOW_SECONDS:
                return True
        
        dedup_cache[key] = now
        
        # Clean old entries periodically
        if len(dedup_cache) > 10000:
            cutoff = now - DEDUP_WINDOW_SECONDS * 2
            old_keys = [k for k, v in dedup_cache.items() if v < cutoff]
            for k in old_keys:
                del dedup_cache[k]
        
        return False
    except Exception:
        return False


def normalize_alert(raw_alert: dict) -> dict:
    """
    Normalize Suricata EVE alert to backend schema.
    """
    sig = raw_alert.get("alert", {})
    
    return {
        "device_id": CONFIG["device_id"],
        "hostname": CONFIG["hostname"],
        "device_ip": CONFIG["device_ip"],
        "timestamp": raw_alert.get("timestamp"),
        "alert": {
            "signature": sig.get("signature", f"sid:{sig.get('signature_id', 'unknown')}"),
            "category": sig.get("category", "Unknown"),
            "severity": sig.get("severity", 3),
            "action": sig.get("action", "allowed"),
            "gid": sig.get("gid", 1),
            "sid": sig.get("signature_id", sig.get("sid", 0)),
            "rev": sig.get("rev", 1),
            "metadata": sig.get("metadata", {}),
        },
        "raw": {
            "src_ip": raw_alert.get("src_ip", ""),
            "src_port": raw_alert.get("src_port", 0),
            "dest_ip": raw_alert.get("dest_ip", ""),
            "dest_port": raw_alert.get("dest_port", 0),
            "proto": raw_alert.get("proto", ""),
            "flow_id": raw_alert.get("flow_id"),
            "app_proto": raw_alert.get("app_proto", ""),
        }
    }


def send_alert(payload: dict) -> bool:
    """
    Send alert to backend with retry logic.
    """
    url = f"{CONFIG['analyzer_url']}/api/v1/ingest/suricata"
    headers = {
        "INGEST_API_KEY": CONFIG["ingest_api_key"],
        "Content-Type": "application/json"
    }
    
    delay = RETRY_BASE_DELAY
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            
            if response.status_code in (200, 201):
                try:
                    resp_json = response.json()
                    # Check if backend logically rejected it (e.g. device not approved)
                    if resp_json.get("status") == "rejected":
                        msg = resp_json.get("message", "Unknown rejection")
                        logger.critical(f"⛔ BACKEND REJECTED ALERT: {msg}")
                        logger.critical(f"👉 ACTION REQUIRED: Go to Analysis Server UI -> Devices -> Approve this device ({CONFIG['device_id']})")
                        # Return True to dequeue it (don't retry rejected alerts)
                        return True
                except:
                    pass
                return True
            elif response.status_code == 401:
                logger.error("Authentication failed - check INGEST_API_KEY")
                return False
            else:
                logger.warning(f"Server returned {response.status_code}: {response.text[:100]}")
                
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error (attempt {attempt + 1}/{MAX_RETRIES})")
        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout (attempt {attempt + 1}/{MAX_RETRIES})")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return False
        
        if attempt < MAX_RETRIES - 1:
            time.sleep(delay)
            delay = min(delay * 2, RETRY_MAX_DELAY)
    
    return False


def spool_alert(payload: dict):
    """
    Save alert to local spool for later replay.
    Wraps payload with spool timestamp for TTL enforcement.
    """
    try:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        
        # Enforce spool size limits before adding
        enforce_spool_limit()
        
        # Wrap with spool timestamp for TTL enforcement
        wrapped = {
            "_spool_ts": time.time(),
            "payload": payload
        }
        with open(SPOOL_FILE, "a") as f:
            f.write(json.dumps(wrapped) + "\n")
        stats["alerts_spooled"] += 1
        logger.debug("Alert spooled for later delivery")
    except Exception as e:
        logger.error(f"Failed to spool alert: {e}")


def enforce_spool_limit():
    """
    Enforce spool size limits to prevent infinite backlog.
    If spool exceeds size limits, drop oldest entries.
    """
    if not SPOOL_FILE.exists():
        return
    
    try:
        file_size = SPOOL_FILE.stat().st_size
        
        # Check byte limit
        if file_size > SPOOL_MAX_BYTES:
            logger.warning(f"Spool file exceeds {SPOOL_MAX_BYTES/1024/1024:.1f}MB, trimming...")
            with open(SPOOL_FILE, "r") as f:
                lines = f.readlines()
            
            # Keep only the newest half
            keep_count = len(lines) // 2
            if keep_count > 0:
                with open(SPOOL_FILE, "w") as f:
                    f.writelines(lines[-keep_count:])
                logger.info(f"Trimmed {len(lines) - keep_count} oldest spooled alerts")
            return
        
        # Check line limit
        with open(SPOOL_FILE, "r") as f:
            lines = f.readlines()
        
        if len(lines) > SPOOL_MAX_LINES:
            logger.warning(f"Spool exceeds {SPOOL_MAX_LINES} lines, trimming...")
            # Keep only the newest SPOOL_MAX_LINES/2 entries
            keep_count = SPOOL_MAX_LINES // 2
            with open(SPOOL_FILE, "w") as f:
                f.writelines(lines[-keep_count:])
            logger.info(f"Trimmed {len(lines) - keep_count} oldest spooled alerts")
            
    except Exception as e:
        logger.error(f"Failed to enforce spool limit: {e}")


def replay_spooled_alerts():
    """
    Attempt to send spooled alerts with TTL enforcement and rate limiting.
    
    - Drops alerts older than SPOOL_TTL_SECONDS (15 min)
    - Processes in batches with sleep to avoid flooding
    """
    if not SPOOL_FILE.exists():
        return
    
    try:
        with open(SPOOL_FILE, "r") as f:
            lines = f.readlines()
        
        if not lines:
            return
        
        logger.info(f"Replaying {len(lines)} spooled alerts...")
        
        now = time.time()
        remaining = []
        batch_count = 0
        dropped_ttl = 0
        
        for line in lines:
            try:
                wrapped = json.loads(line.strip())
                
                # Handle both old format (raw payload) and new format (wrapped)
                if "_spool_ts" in wrapped:
                    spool_ts = wrapped["_spool_ts"]
                    payload = wrapped["payload"]
                    
                    # TTL check - drop alerts older than threshold
                    if now - spool_ts > SPOOL_TTL_SECONDS:
                        dropped_ttl += 1
                        continue
                else:
                    # Legacy format - no timestamp, assume fresh
                    payload = wrapped
                
                if send_alert(payload):
                    stats["alerts_replayed"] += 1
                    batch_count += 1
                    
                    # Rate limiting: sleep after each batch
                    if batch_count >= REPLAY_BATCH_SIZE:
                        time.sleep(REPLAY_BATCH_DELAY)
                        batch_count = 0
                else:
                    # Keep for next attempt (re-wrap with original timestamp)
                    remaining.append(line)
                    
            except json.JSONDecodeError:
                continue
        
        if dropped_ttl > 0:
            logger.info(f"Dropped {dropped_ttl} stale alerts (TTL exceeded)")
        
        # Rewrite spool with remaining alerts
        if remaining:
            with open(SPOOL_FILE, "w") as f:
                f.writelines(remaining)
        else:
            SPOOL_FILE.unlink(missing_ok=True)
            
    except Exception as e:
        logger.error(f"Failed to replay spooled alerts: {e}")


def process_alert(raw_alert: dict):
    """
    Process a single alert: filter, normalize, dedup, and send.
    
    Filtering order:
    1. Skip non-alert events (stats, flow, etc.)
    2. Allowlist check (only AI local rules) - bypassed if ACCEPT_ALL
    3. Deduplication
    4. Normalize and send
    """
    # Skip non-alert events (stats, flow, dns, etc.)
    event_type = raw_alert.get("event_type", "")
    if event_type != "alert":
        return
    
    stats["alerts_seen"] += 1
    
    # Allowlist check - ONLY process our local AI rules
    # Bypassed if SURICATA_ACCEPT_ALL=true (for debugging)
    if not ACCEPT_ALL_ALERTS and not is_ai_local_rule(raw_alert):
        stats["alerts_filtered"] += 1
        # Log periodically to avoid spam
        if stats["alerts_filtered"] % 100 == 1:
            sig = raw_alert.get("alert", {}).get("signature", "unknown")
            sid = raw_alert.get("alert", {}).get("signature_id", 0)
            logger.debug(f"Filtered non-AI rule: {sig} (SID:{sid})")
        return
    
    # Deduplication (DDoS-aware)
    if is_duplicate(raw_alert):
        stats["alerts_deduped"] += 1
        return
    
    # Normalize to backend schema
    payload = normalize_alert(raw_alert)
    
    # Tag external rules if ACCEPT_ALL mode  
    if ACCEPT_ALL_ALERTS and not is_ai_local_rule(raw_alert):
        payload["raw"]["debug_external_rule"] = True
    
    # Send to backend
    if send_alert(payload):
        stats["alerts_sent"] += 1
        if stats["alerts_sent"] % 10 == 0:
            logger.info(f"Sent {stats['alerts_sent']} alerts (seen: {stats['alerts_seen']}, filtered: {stats['alerts_filtered']}, deduped: {stats['alerts_deduped']})")
    else:
        stats["send_errors"] += 1
        spool_alert(payload)


def tail_eve_file():
    """
    Tail the eve.json file and process new alerts.
    Similar to 'tail -F' behavior with:
    - Inode change detection (log rotation)
    - File truncation detection (size decreased)
    - Periodic stats logging
    """
    logger.info(f"Tailing {EVE_PATH}...")
    if ACCEPT_ALL_ALERTS:
        logger.warning("ACCEPT_ALL mode enabled - sending ALL alerts (debug)")
    
    # Wait for file to exist
    while not os.path.exists(EVE_PATH):
        logger.info(f"Waiting for {EVE_PATH} to be created...")
        time.sleep(5)
    
    # Start from end of file
    with open(EVE_PATH, "r") as f:
        f.seek(0, 2)  # Seek to end
        current_pos = f.tell()
    
    last_replay_check = time.time()
    last_stats_log = time.time()
    last_inode = os.stat(EVE_PATH).st_ino
    last_size = os.stat(EVE_PATH).st_size
    
    while True:
        try:
            # Check for file rotation (inode change) or truncation (size decreased)
            try:
                stat_info = os.stat(EVE_PATH)
                current_inode = stat_info.st_ino
                current_size = stat_info.st_size
                
                if current_inode != last_inode:
                    logger.info("Detected log rotation (inode change), reopening from start...")
                    current_pos = 0
                    last_inode = current_inode
                    last_size = current_size
                    stats["file_reopens"] += 1
                elif current_size < current_pos:
                    # File was truncated (smaller than our position)
                    logger.info("Detected file truncation, reopening from start...")
                    current_pos = 0
                    last_size = current_size
                    stats["file_reopens"] += 1
                else:
                    last_size = current_size
                    
            except FileNotFoundError:
                logger.warning(f"{EVE_PATH} not found, waiting...")
                time.sleep(5)
                continue
            
            # Read new lines
            with open(EVE_PATH, "r") as f:
                f.seek(current_pos)
                for line in f:
                    stats["lines_read"] += 1
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                        stats["json_parsed"] += 1
                        process_alert(event)
                    except json.JSONDecodeError:
                        logger.debug(f"Invalid JSON line: {line[:100]}")
                        continue
                
                current_pos = f.tell()
            
            # Periodic stats logging
            if time.time() - last_stats_log > STATS_LOG_INTERVAL:
                logger.info(
                    f"[STATS] lines_read={stats['lines_read']}, json_parsed={stats['json_parsed']}, "
                    f"alerts_seen={stats['alerts_seen']}, sent={stats['alerts_sent']}, "
                    f"filtered={stats['alerts_filtered']}, deduped={stats['alerts_deduped']}, "
                    f"errors={stats['send_errors']}, reopens={stats['file_reopens']}"
                )
                last_stats_log = time.time()
            
            # Periodically try to replay spooled alerts
            if time.time() - last_replay_check > 60:
                replay_spooled_alerts()
                last_replay_check = time.time()
            
            # Short sleep to avoid busy loop
            time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"Error in tail loop: {e}")
            time.sleep(5)


def check_analyzer_connection() -> bool:
    """Check connectivity to analysis server."""
    logger.info("Checking connectivity to analysis server...")
    try:
        resp = requests.get(f"{CONFIG['analyzer_url']}/api/v1/health", timeout=10)
        if resp.status_code == 200:
            logger.info("✓ Connected to analysis server")
            return True
        else:
            logger.warning(f"Server returned status {resp.status_code}")
            return False
    except Exception as e:
        logger.warning(f"Could not connect to analysis server: {e}")
        logger.warning("Will continue anyway and retry...")
        return False


def main():
    global CONFIG
    
    # Load configuration
    try:
        CONFIG = load_agent_config()
    except (ValueError, RuntimeError) as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    
    # Print banner
    print_config_banner(CONFIG, "Suricata Collector Agent")
    logger.info(f"EVE Path: {EVE_PATH}")
    logger.info(f"Spool Dir: {SPOOL_DIR}")
    logger.info(f"Dedup Window: {DEDUP_WINDOW_SECONDS}s")
    logger.info(f"Local SID Range: {LOCAL_SID_MIN}-{LOCAL_SID_MAX}")
    logger.info(f"Stats Interval: {STATS_LOG_INTERVAL}s")
    if ACCEPT_ALL_ALERTS:
        logger.warning("ACCEPT_ALL_ALERTS=true - sending ALL rules (debug mode)")
    else:
        logger.info("Allowlist: Only AI rules (AI prefix or local SID)")
    
    # Check connectivity
    check_analyzer_connection()
    
    # Replay any spooled alerts first
    replay_spooled_alerts()
    
    # Start tailing
    tail_eve_file()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        logger.info(f"Final stats: {stats}")
        sys.exit(0)
