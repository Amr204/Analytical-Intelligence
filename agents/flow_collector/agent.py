#!/usr/bin/env python3
"""
Analytical-Intelligence v1 - Flow Collector Agent
Captures network flows using NFStream and sends them to the analysis server.
"""

import sys
import os
import logging
from datetime import datetime
import requests

# Add parent directory for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.ip_utils import load_agent_config, print_config_banner

# Try to import nfstream
try:
    from nfstream import NFStreamer
except ImportError:
    print("ERROR: nfstream not installed")
    print("Install with: pip install nfstream")
    sys.exit(1)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration (loaded at startup)
CONFIG = None
IDLE_TIMEOUT = int(os.environ.get("FLOW_IDLE_TIMEOUT", "2"))
ACTIVE_TIMEOUT = int(os.environ.get("FLOW_ACTIVE_TIMEOUT", "5"))


def send_flow_event(flow: dict) -> bool:
    """Send a flow event to the analysis server."""
    try:
        payload = {
            "device_id": CONFIG["device_id"],
            "hostname": CONFIG["hostname"],
            "device_ip": CONFIG["device_ip"],
            "flow": flow,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = requests.post(
            f"{CONFIG['analyzer_url']}/api/v1/ingest/flow",
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


def flow_to_dict(flow) -> dict:
    """Convert NFStream flow object to dictionary."""
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "bidirectional_duration_ms": flow.bidirectional_duration_ms,
        "bidirectional_packets": flow.bidirectional_packets,
        "bidirectional_bytes": flow.bidirectional_bytes,
        "src2dst_packets": flow.src2dst_packets,
        "src2dst_bytes": flow.src2dst_bytes,
        "dst2src_packets": flow.dst2src_packets,
        "dst2src_bytes": flow.dst2src_bytes,
        "bidirectional_mean_ps": flow.bidirectional_mean_ps,
        "bidirectional_stddev_ps": flow.bidirectional_stddev_ps,
        "bidirectional_max_ps": flow.bidirectional_max_ps,
        "bidirectional_min_ps": flow.bidirectional_min_ps,
        "src2dst_mean_ps": flow.src2dst_mean_ps,
        "src2dst_stddev_ps": flow.src2dst_stddev_ps,
        "src2dst_max_ps": flow.src2dst_max_ps,
        "src2dst_min_ps": flow.src2dst_min_ps,
        "dst2src_mean_ps": flow.dst2src_mean_ps,
        "dst2src_stddev_ps": flow.dst2src_stddev_ps,
        "dst2src_max_ps": flow.dst2src_max_ps,
        "dst2src_min_ps": flow.dst2src_min_ps,
        # IAT features
        "bidirectional_mean_piat_ms": flow.bidirectional_mean_piat_ms,
        "bidirectional_stddev_piat_ms": flow.bidirectional_stddev_piat_ms,
        "bidirectional_max_piat_ms": flow.bidirectional_max_piat_ms,
        "bidirectional_min_piat_ms": flow.bidirectional_min_piat_ms,
        "src2dst_mean_piat_ms": flow.src2dst_mean_piat_ms,
        "dst2src_mean_piat_ms": flow.dst2src_mean_piat_ms,
        # TCP flags
        "bidirectional_syn_packets": flow.bidirectional_syn_packets,
        "bidirectional_fin_packets": flow.bidirectional_fin_packets,
        "bidirectional_rst_packets": flow.bidirectional_rst_packets,
        "bidirectional_psh_packets": flow.bidirectional_psh_packets,
        "bidirectional_ack_packets": flow.bidirectional_ack_packets,
        "bidirectional_urg_packets": flow.bidirectional_urg_packets,
        "bidirectional_ece_packets": flow.bidirectional_ece_packets,
        "bidirectional_cwr_packets": flow.bidirectional_cwr_packets,
    }


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
    print_config_banner(CONFIG, "Flow Collector Agent")
    logger.info(f"Idle timeout: {IDLE_TIMEOUT}s")
    logger.info(f"Active timeout: {ACTIVE_TIMEOUT}s")
    
    # Check connectivity
    check_analyzer_connection()
    
    # Create NFStreamer
    net_iface = CONFIG["net_iface"]
    logger.info(f"Starting NFStream on {net_iface}...")
    
    try:
        streamer = NFStreamer(
            source=net_iface,
            idle_timeout=IDLE_TIMEOUT,
            active_timeout=ACTIVE_TIMEOUT,
            accounting_mode=1,  # IP/Port based
            statistical_analysis=True,
            n_dissections=0,  # No deep packet inspection
        )
    except Exception as e:
        logger.error(f"Failed to create NFStreamer: {e}")
        logger.error("Make sure you have the right permissions (CAP_NET_RAW)")
        sys.exit(1)
    
    logger.info("Capturing flows...")
    
    flow_count = 0
    sent_count = 0
    
    for flow in streamer:
        flow_count += 1
        
        # Skip very short flows (likely noise)
        if flow.bidirectional_packets < 2:
            continue
        
        flow_dict = flow_to_dict(flow)
        
        if send_flow_event(flow_dict):
            sent_count += 1
            if sent_count % 100 == 0:
                logger.info(f"Sent {sent_count} flows (captured {flow_count})")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
