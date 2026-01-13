#!/usr/bin/env python3
"""
Analytical-Intelligence v1 - Suricata Shipper Agent
Tails eve.json and sends alert events to the analysis server in real-time.
"""

import sys
import os
import json
import time
import logging
from datetime import datetime
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

# Configuration (loaded at startup)
CONFIG = None
EVE_JSON_PATH = os.environ.get("EVE_JSON_PATH", "/var/log/suricata/eve.json")


def send_suricata_event(event: dict) -> bool:
    """Send a Suricata event to the analysis server."""
    try:
        payload = {
            "device_id": CONFIG["device_id"],
            "hostname": CONFIG["hostname"],
            "device_ip": CONFIG["device_ip"],
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = requests.post(
            f"{CONFIG['analyzer_url']}/api/v1/ingest/suricata",
            headers={
                "INGEST_API_KEY": CONFIG["ingest_api_key"],
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=5
        )
        
        if response.status_code in (200, 201):
            return True
        else:
            logger.warning(f"Server returned {response.status_code}: {response.text[:100]}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send event: {e}")
        return False


def tail_file(filepath: str):
    """
    Tail a file like 'tail -F', handling file rotation.
    Yields new lines as they appear.
    """
    logger.info(f"Starting to tail: {filepath}")
    
    # Wait for file to exist
    while not os.path.exists(filepath):
        logger.info(f"Waiting for {filepath} to be created...")
        time.sleep(2)
    
    while True:
        try:
            with open(filepath, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                current_inode = os.fstat(f.fileno()).st_ino
                
                while True:
                    line = f.readline()
                    
                    if line:
                        yield line
                    else:
                        # Check if file was rotated
                        try:
                            if os.stat(filepath).st_ino != current_inode:
                                logger.info("File rotated, reopening...")
                                break
                        except FileNotFoundError:
                            logger.warning("File disappeared, waiting...")
                            time.sleep(1)
                            break
                        
                        # No new line, sleep briefly
                        time.sleep(0.1)
                        
        except FileNotFoundError:
            logger.warning(f"File not found: {filepath}, waiting...")
            time.sleep(5)
        except PermissionError:
            logger.error(f"Permission denied: {filepath}")
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error reading file: {e}")
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
    print_config_banner(CONFIG, "Suricata Shipper Agent")
    logger.info(f"EVE JSON path: {EVE_JSON_PATH}")
    
    # Check connectivity
    check_analyzer_connection()
    
    # Start tailing
    alert_count = 0
    error_count = 0
    
    for line in tail_file(EVE_JSON_PATH):
        line = line.strip()
        if not line:
            continue
        
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        # Only send alert events (not stats, flow, http, etc.)
        event_type = event.get("event_type", "")
        if event_type != "alert":
            continue
        
        if send_suricata_event(event):
            alert_count += 1
            sig = event.get("alert", {}).get("signature", "unknown")[:50]
            logger.info(f"Alert #{alert_count}: {sig}")
        else:
            error_count += 1


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
