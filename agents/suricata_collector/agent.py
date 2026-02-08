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

# Deduplication settings
DEDUP_WINDOW_SECONDS = 2
dedup_cache = {}  # (sid, src_ip, dst_ip, dst_port) -> last_seen_timestamp

# Retry settings
MAX_RETRIES = 5
RETRY_BASE_DELAY = 1  # seconds
RETRY_MAX_DELAY = 60  # seconds

# Counters
stats = {
    "alerts_read": 0,
    "alerts_sent": 0,
    "alerts_deduped": 0,
    "alerts_spooled": 0,
    "alerts_replayed": 0,
    "send_errors": 0,
}


def is_duplicate(alert: dict) -> bool:
    """
    Check if alert is a duplicate within DEDUP_WINDOW_SECONDS.
    Deduplicates on (sid, src_ip, dst_ip, dst_port) tuple.
    """
    try:
        sig = alert.get("alert", {})
        sid = sig.get("signature_id", sig.get("sid", 0))
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dest_ip", alert.get("dst_ip", ""))
        dst_port = alert.get("dest_port", alert.get("dst_port", 0))
        
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
    """
    try:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        with open(SPOOL_FILE, "a") as f:
            f.write(json.dumps(payload) + "\n")
        stats["alerts_spooled"] += 1
        logger.debug("Alert spooled for later delivery")
    except Exception as e:
        logger.error(f"Failed to spool alert: {e}")


def replay_spooled_alerts():
    """
    Attempt to send any spooled alerts.
    """
    if not SPOOL_FILE.exists():
        return
    
    try:
        with open(SPOOL_FILE, "r") as f:
            lines = f.readlines()
        
        if not lines:
            return
        
        logger.info(f"Replaying {len(lines)} spooled alerts...")
        
        remaining = []
        for line in lines:
            try:
                payload = json.loads(line.strip())
                if send_alert(payload):
                    stats["alerts_replayed"] += 1
                else:
                    remaining.append(line)
            except json.JSONDecodeError:
                continue
        
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
    Process a single alert: normalize, dedup, and send.
    """
    stats["alerts_read"] += 1
    
    # Skip non-alert events
    if raw_alert.get("event_type") != "alert":
        return
    
    # Deduplication
    if is_duplicate(raw_alert):
        stats["alerts_deduped"] += 1
        return
    
    # Normalize to backend schema
    payload = normalize_alert(raw_alert)
    
    # Send to backend
    if send_alert(payload):
        stats["alerts_sent"] += 1
        if stats["alerts_sent"] % 10 == 0:
            logger.info(f"Sent {stats['alerts_sent']} alerts (read: {stats['alerts_read']}, deduped: {stats['alerts_deduped']})")
    else:
        stats["send_errors"] += 1
        spool_alert(payload)


def tail_eve_file():
    """
    Tail the eve.json file and process new alerts.
    Similar to 'tail -F' behavior.
    """
    logger.info(f"Tailing {EVE_PATH}...")
    
    # Wait for file to exist
    while not os.path.exists(EVE_PATH):
        logger.info(f"Waiting for {EVE_PATH} to be created...")
        time.sleep(5)
    
    # Start from end of file
    with open(EVE_PATH, "r") as f:
        f.seek(0, 2)  # Seek to end
        current_pos = f.tell()
    
    last_replay_check = time.time()
    last_inode = os.stat(EVE_PATH).st_ino
    
    while True:
        try:
            # Check for file rotation (inode change)
            try:
                current_inode = os.stat(EVE_PATH).st_ino
                if current_inode != last_inode:
                    logger.info("Detected log rotation, reopening file...")
                    current_pos = 0
                    last_inode = current_inode
            except FileNotFoundError:
                logger.warning(f"{EVE_PATH} not found, waiting...")
                time.sleep(5)
                continue
            
            # Read new lines
            with open(EVE_PATH, "r") as f:
                f.seek(current_pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        alert = json.loads(line)
                        process_alert(alert)
                    except json.JSONDecodeError:
                        logger.debug(f"Invalid JSON line: {line[:100]}")
                        continue
                
                current_pos = f.tell()
            
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
