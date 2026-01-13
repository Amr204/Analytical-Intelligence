#!/usr/bin/env python3
"""
Analytical-Intelligence v1 - IP Utilities (Shared Module)
Auto-detects device IP and normalizes analyzer URL.
"""

import json
import os
import socket
import subprocess
import logging

logger = logging.getLogger(__name__)


def get_ip_from_iface(iface: str) -> str:
    """
    Get the IPv4 address from a network interface.
    Uses `ip -j addr show dev <iface>` and parses JSON output.
    
    Args:
        iface: Network interface name (e.g., ens33, eth0)
    
    Returns:
        IPv4 address as string, or empty string if not found.
    """
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            logger.warning(f"ip command failed for interface {iface}: {result.stderr}")
            return ""
        
        data = json.loads(result.stdout)
        if not data:
            logger.warning(f"No data returned for interface {iface}")
            return ""
        
        # Find IPv4 address
        for addr_info in data[0].get("addr_info", []):
            if addr_info.get("family") == "inet":
                ip = addr_info.get("local", "")
                if ip:
                    logger.info(f"Detected IP {ip} from interface {iface}")
                    return ip
        
        logger.warning(f"No IPv4 address found on interface {iface}")
        return ""
        
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout getting IP from interface {iface}")
        return ""
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse ip command output: {e}")
        return ""
    except Exception as e:
        logger.error(f"Error getting IP from interface {iface}: {e}")
        return ""


def get_ip_via_route(target_host: str, target_port: int = 80) -> str:
    """
    Fallback method: Get local IP by creating a socket to target and reading local address.
    This finds the IP that would be used to reach the target.
    
    Args:
        target_host: Host to "connect" to (no actual connection made)
        target_port: Port to use (default 80)
    
    Returns:
        Local IPv4 address as string, or empty string if failed.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        # This doesn't actually send data, just determines the route
        s.connect((target_host, target_port))
        ip = s.getsockname()[0]
        s.close()
        logger.info(f"Detected IP {ip} via route to {target_host}")
        return ip
    except Exception as e:
        logger.error(f"Failed to detect IP via route method: {e}")
        return ""


def detect_device_ip(iface: str, analyzer_host: str = None) -> str:
    """
    Detect device IP using interface method, with route fallback.
    
    Args:
        iface: Network interface name
        analyzer_host: Analyzer host for route fallback method
    
    Returns:
        Detected IP address
    
    Raises:
        RuntimeError: If IP cannot be detected
    """
    # Try interface method first
    ip = get_ip_from_iface(iface)
    if ip:
        return ip
    
    # Fallback to route method if analyzer_host is provided
    if analyzer_host:
        # Extract host from URL if needed
        host = analyzer_host
        if host.startswith("http://"):
            host = host[7:]
        if host.startswith("https://"):
            host = host[8:]
        if ":" in host:
            host = host.split(":")[0]
        if "/" in host:
            host = host.split("/")[0]
        
        ip = get_ip_via_route(host)
        if ip:
            return ip
    
    raise RuntimeError(
        f"Could not detect device IP from interface '{iface}'. "
        f"Please set DEVICE_IP explicitly in your .env file."
    )


def normalize_analyzer_url(host_or_url: str, port: int = 8000) -> str:
    """
    Normalize analyzer host/URL to a full URL.
    
    Args:
        host_or_url: Either a hostname/IP or a full URL
        port: Port to use if not specified (default 8000)
    
    Returns:
        Full URL like http://host:port
    """
    if not host_or_url:
        raise ValueError("ANALYZER_HOST or ANALYZER_URL must be set")
    
    # If already a URL, return as-is (optionally strip trailing slash)
    if host_or_url.startswith("http://") or host_or_url.startswith("https://"):
        return host_or_url.rstrip("/")
    
    # Build URL from host
    return f"http://{host_or_url}:{port}"


def get_required_env(name: str) -> str:
    """Get required environment variable or raise error."""
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required environment variable {name} is not set")
    return value


def get_optional_env(name: str, default: str = "") -> str:
    """Get optional environment variable with default."""
    return os.environ.get(name, default)


def load_agent_config() -> dict:
    """
    Load and validate agent configuration from environment variables.
    
    Returns:
        Dictionary with all configuration values
    
    Raises:
        ValueError: If required variables are missing
        RuntimeError: If IP detection fails
    """
    # Required variables
    device_id = get_required_env("DEVICE_ID")
    hostname = get_required_env("HOSTNAME")
    ingest_api_key = get_required_env("INGEST_API_KEY")
    
    # Analyzer URL (one of ANALYZER_URL or ANALYZER_HOST required)
    analyzer_url = get_optional_env("ANALYZER_URL")
    analyzer_host = get_optional_env("ANALYZER_HOST")
    analyzer_port = int(get_optional_env("ANALYZER_PORT", "8000"))
    
    if not analyzer_url and not analyzer_host:
        raise ValueError(
            "Either ANALYZER_URL or ANALYZER_HOST must be set in environment"
        )
    
    # Normalize to full URL
    analyzer_url = normalize_analyzer_url(
        analyzer_url or analyzer_host,
        analyzer_port
    )
    
    # Network interface (optional, default ens33)
    net_iface = get_optional_env("NET_IFACE", "ens33")
    
    # Device IP (optional, auto-detect if not set)
    device_ip = get_optional_env("DEVICE_IP")
    if not device_ip:
        # Extract host for route fallback
        host = analyzer_host or analyzer_url
        device_ip = detect_device_ip(net_iface, host)
    
    return {
        "device_id": device_id,
        "hostname": hostname,
        "device_ip": device_ip,
        "ingest_api_key": ingest_api_key,
        "analyzer_url": analyzer_url,
        "net_iface": net_iface,
    }


def print_config_banner(config: dict, agent_name: str):
    """Print a clear configuration banner on startup."""
    print("=" * 60)
    print(f"Analytical-Intelligence {agent_name}")
    print("=" * 60)
    print(f"  NET_IFACE:    {config['net_iface']}")
    print(f"  DEVICE_IP:    {config['device_ip']} {'(auto-detected)' if not os.environ.get('DEVICE_IP') else '(manual)'}")
    print(f"  DEVICE_ID:    {config['device_id']}")
    print(f"  HOSTNAME:     {config['hostname']}")
    print(f"  ANALYZER_URL: {config['analyzer_url']}")
    print("=" * 60)
