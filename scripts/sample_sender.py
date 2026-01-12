#!/usr/bin/env python3
"""
Mini-SIEM v1 - Sample Event Sender
Sends fake auth/suricata/flow events for testing.
"""

import argparse
import json
import random
import time
from datetime import datetime
import requests


def send_auth_event(url: str, api_key: str, device_id: str):
    """Send a sample auth.log event."""
    event_types = [
        f"Jan 12 10:00:00 server sshd[{random.randint(1000,9999)}]: Failed password for invalid user admin from 192.168.1.{random.randint(100,200)} port {random.randint(40000,60000)} ssh2",
        f"Jan 12 10:00:00 server sshd[{random.randint(1000,9999)}]: Failed password for root from 10.0.0.{random.randint(1,50)} port {random.randint(40000,60000)} ssh2",
        f"Jan 12 10:00:00 server sshd[{random.randint(1000,9999)}]: Accepted password for user1 from 192.168.1.50 port {random.randint(40000,60000)} ssh2",
        f"Jan 12 10:00:00 server sshd[{random.randint(1000,9999)}]: Invalid user hacker from 203.0.113.{random.randint(1,255)} port {random.randint(40000,60000)}",
        f"Jan 12 10:00:00 server sshd[{random.randint(1000,9999)}]: Connection closed by 192.168.1.100 port {random.randint(40000,60000)} [preauth]",
    ]
    
    payload = {
        "device_id": device_id,
        "hostname": "sensor-server",
        "device_ip": "192.168.1.10",
        "line": random.choice(event_types),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    resp = requests.post(
        f"{url}/api/v1/ingest/auth",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=10
    )
    return resp.status_code, resp.text


def send_suricata_event(url: str, api_key: str, device_id: str):
    """Send a sample Suricata alert event."""
    alerts = [
        {
            "event_type": "alert",
            "alert": {
                "signature_id": 2001219,
                "signature": "ET SCAN Potential SSH Scan",
                "category": "Attempted Information Leak",
                "severity": 2,
                "action": "allowed"
            },
            "src_ip": f"192.168.1.{random.randint(100,200)}",
            "src_port": random.randint(40000, 60000),
            "dest_ip": "192.168.1.10",
            "dest_port": 22,
            "proto": "TCP"
        },
        {
            "event_type": "alert",
            "alert": {
                "signature_id": 2100498,
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "category": "Potentially Bad Traffic",
                "severity": 1,
                "action": "allowed"
            },
            "src_ip": f"10.0.0.{random.randint(1,50)}",
            "src_port": 80,
            "dest_ip": "192.168.1.10",
            "dest_port": random.randint(40000, 60000),
            "proto": "TCP"
        },
        {
            "event_type": "alert",
            "alert": {
                "signature_id": 2002910,
                "signature": "ET SCAN Potential VNC Scan",
                "category": "Attempted Information Leak",
                "severity": 2,
                "action": "allowed"
            },
            "src_ip": f"203.0.113.{random.randint(1,255)}",
            "src_port": random.randint(40000, 60000),
            "dest_ip": "192.168.1.10",
            "dest_port": 5900,
            "proto": "TCP"
        },
        {
            "event_type": "alert",
            "alert": {
                "signature_id": 2024364,
                "signature": "ET DOS Possible NTP DDoS Inbound",
                "category": "Attempted Denial of Service",
                "severity": 1,
                "action": "allowed"
            },
            "src_ip": f"198.51.100.{random.randint(1,255)}",
            "src_port": 123,
            "dest_ip": "192.168.1.10",
            "dest_port": random.randint(1024, 65535),
            "proto": "UDP"
        },
    ]
    
    payload = {
        "device_id": device_id,
        "hostname": "sensor-server",
        "device_ip": "192.168.1.10",
        "event": random.choice(alerts),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    resp = requests.post(
        f"{url}/api/v1/ingest/suricata",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=10
    )
    return resp.status_code, resp.text


def send_flow_event(url: str, api_key: str, device_id: str):
    """Send a sample network flow event."""
    flow = {
        "src_ip": f"192.168.1.{random.randint(1,254)}",
        "dst_ip": f"10.0.0.{random.randint(1,254)}",
        "src_port": random.randint(40000, 65535),
        "dst_port": random.choice([22, 80, 443, 3389, 8080, 21]),
        "protocol": random.choice([6, 17]),  # TCP or UDP
        "bidirectional_duration_ms": random.randint(100, 50000),
        "bidirectional_packets": random.randint(4, 1000),
        "bidirectional_bytes": random.randint(200, 100000),
        "src2dst_packets": random.randint(2, 500),
        "src2dst_bytes": random.randint(100, 50000),
        "dst2src_packets": random.randint(2, 500),
        "dst2src_bytes": random.randint(100, 50000),
        "bidirectional_mean_ps": random.uniform(50, 1500),
        "bidirectional_stddev_ps": random.uniform(0, 500),
        "bidirectional_max_ps": random.randint(60, 1500),
        "bidirectional_min_ps": random.randint(40, 100),
        "src2dst_mean_ps": random.uniform(50, 1500),
        "dst2src_mean_ps": random.uniform(50, 1500),
    }
    
    payload = {
        "device_id": device_id,
        "hostname": "sensor-server",
        "device_ip": "192.168.1.10",
        "flow": flow,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    resp = requests.post(
        f"{url}/api/v1/ingest/flow",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json=payload,
        timeout=10
    )
    return resp.status_code, resp.text


def main():
    parser = argparse.ArgumentParser(description="Send sample events to Mini-SIEM")
    parser.add_argument("--url", default="http://localhost:8000", help="Backend URL")
    parser.add_argument("--api-key", default="test-api-key-12345", help="API Key")
    parser.add_argument("--device-id", default="sensor-01", help="Device ID")
    parser.add_argument("--count", type=int, default=10, help="Number of events to send")
    parser.add_argument("--interval", type=float, default=0.5, help="Interval between events (seconds)")
    parser.add_argument("--type", choices=["auth", "suricata", "flow", "all"], default="all", help="Event type")
    args = parser.parse_args()
    
    print(f"Sending {args.count} events to {args.url}")
    print(f"Event type: {args.type}")
    print("-" * 50)
    
    for i in range(args.count):
        try:
            if args.type == "auth" or args.type == "all":
                status, resp = send_auth_event(args.url, args.api_key, args.device_id)
                print(f"[{i+1}/{args.count}] AUTH:     Status={status}")
            
            if args.type == "suricata" or args.type == "all":
                status, resp = send_suricata_event(args.url, args.api_key, args.device_id)
                print(f"[{i+1}/{args.count}] SURICATA: Status={status}")
            
            if args.type == "flow" or args.type == "all":
                status, resp = send_flow_event(args.url, args.api_key, args.device_id)
                print(f"[{i+1}/{args.count}] FLOW:     Status={status}")
            
            if args.interval > 0 and i < args.count - 1:
                time.sleep(args.interval)
                
        except requests.exceptions.RequestException as e:
            print(f"[{i+1}/{args.count}] ERROR: {e}")
    
    print("-" * 50)
    print("Done!")


if __name__ == "__main__":
    main()
