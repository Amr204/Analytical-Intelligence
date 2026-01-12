#!/usr/bin/env python3
"""
Mini-SIEM v1 - Suricata Shipper Agent
Tails eve.json and sends alert events to the analysis server in real-time.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
import requests

# Configuration from environment
ANALYZER_URL = os.environ.get("ANALYZER_URL", "http://192.168.1.20:8000")
API_KEY = os.environ.get("X_API_KEY", "test-api-key-12345")
DEVICE_ID = os.environ.get("DEVICE_ID", "sensor-01")
HOSTNAME = os.environ.get("HOSTNAME", "sensor-server")
DEVICE_IP = os.environ.get("DEVICE_IP", "192.168.1.10")
EVE_JSON_PATH = os.environ.get("EVE_JSON_PATH", "/var/log/suricata/eve.json")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def send_suricata_event(event: dict) -> bool:
    """Send a Suricata event to the analysis server."""
    try:
        payload = {
            "device_id": DEVICE_ID,
            "hostname": HOSTNAME,
            "device_ip": DEVICE_IP,
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = requests.post(
            f"{ANALYZER_URL}/api/v1/ingest/suricata",
            headers={
                "X-API-Key": API_KEY,
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


def main():
    logger.info("=" * 50)
    logger.info("Mini-SIEM Suricata Shipper Agent")
    logger.info("=" * 50)
    logger.info(f"Analyzer URL: {ANALYZER_URL}")
    logger.info(f"Device ID: {DEVICE_ID}")
    logger.info(f"EVE JSON: {EVE_JSON_PATH}")
    logger.info("=" * 50)
    
    # Check connectivity
    logger.info("Checking connectivity to analysis server...")
    try:
        resp = requests.get(f"{ANALYZER_URL}/api/v1/health", timeout=10)
        if resp.status_code == 200:
            logger.info("✓ Connected to analysis server")
        else:
            logger.warning(f"Server returned status {resp.status_code}")
    except Exception as e:
        logger.warning(f"Could not connect to analysis server: {e}")
        logger.warning("Will continue anyway and retry...")
    
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
