#!/usr/bin/env python3
"""
Mini-SIEM v1 - Auth Log Collector Agent
Tails /var/log/auth.log and sends each line to the analysis server in real-time.
"""

import os
import sys
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
AUTH_LOG_PATH = os.environ.get("AUTH_LOG_PATH", "/var/log/auth.log")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def send_auth_event(line: str) -> bool:
    """Send an auth.log line to the analysis server."""
    try:
        payload = {
            "device_id": DEVICE_ID,
            "hostname": HOSTNAME,
            "device_ip": DEVICE_IP,
            "line": line.strip(),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = requests.post(
            f"{ANALYZER_URL}/api/v1/ingest/auth",
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
            logger.error("Make sure the container has read access to auth.log")
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            time.sleep(5)


def main():
    logger.info("=" * 50)
    logger.info("Mini-SIEM Auth Collector Agent")
    logger.info("=" * 50)
    logger.info(f"Analyzer URL: {ANALYZER_URL}")
    logger.info(f"Device ID: {DEVICE_ID}")
    logger.info(f"Auth log: {AUTH_LOG_PATH}")
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
    sent_count = 0
    error_count = 0
    
    for line in tail_file(AUTH_LOG_PATH):
        line = line.strip()
        if not line:
            continue
        
        # Skip lines that don't look like auth events
        if "sshd" not in line.lower() and "pam" not in line.lower():
            continue
        
        if send_auth_event(line):
            sent_count += 1
            if sent_count % 10 == 0:
                logger.info(f"Sent {sent_count} events")
        else:
            error_count += 1
            if error_count % 10 == 0:
                logger.warning(f"Failed to send {error_count} events")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
