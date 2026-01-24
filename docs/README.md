# Reports Module

This folder documents the Reports feature in Analytical-Intelligence v1.

## Available Report Types

### 1. Auth Detections (`type=auth`)
- **Model**: SSH LSTM
- **Description**: Detections from SSH authentication log analysis
- **Attack Types**: Brute Force, Password Spray, SSH Attacks
- **Use Case**: Review SSH-based threats and failed authentication patterns

### 2. Network Detections (`type=network`)
- **Model**: Network RF (Random Forest)
- **Description**: Detections from network flow analysis
- **Attack Types**: DoS, DDoS, Port Scanning, Brute Force (network-level)
- **Use Case**: Review network-based threats and anomalous traffic patterns

### 3. By Device (`type=device`)
- **Model**: All models
- **Description**: All detections filtered by a specific device
- **Requires**: `device_id` parameter
- **Use Case**: Device-specific security audit or incident investigation

## Available Filters

| Filter | Description | Values |
|--------|-------------|--------|
| `severity` | Alert severity level | CRITICAL, HIGH, MEDIUM, LOW |
| `device_id` | Specific device ID | Any registered device |
| `last_minutes` | Time window | 60 (1h), 1440 (24h), 10080 (7d), 43200 (30d) |

## Export Formats

### CSV Export
- Standard comma-separated values format
- Compatible with Excel, Google Sheets, and all data analysis tools
- Maximum 5,000 rows per export

### XLSX Export (Excel)
- Native Microsoft Excel format
- Formatted spreadsheet with proper column types
- Maximum 5,000 rows per export
- Requires `openpyxl` package (included in requirements)

## API Endpoint

```
GET /api/v1/reports/export
```

### Query Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `type` | Yes | - | Report type: `auth`, `network`, or `device` |
| `format` | No | `csv` | Export format: `csv` or `xlsx` |
| `severity` | No | - | Filter by severity |
| `device_id` | No | - | Filter by device (required for `type=device`) |
| `last_minutes` | No | - | Time window in minutes |

### Example Requests

```bash
# Export all auth detections as CSV
curl -O "http://localhost:8000/api/v1/reports/export?type=auth&format=csv"

# Export high-severity network detections from last 24 hours as Excel
curl -O "http://localhost:8000/api/v1/reports/export?type=network&format=xlsx&severity=HIGH&last_minutes=1440"

# Export all detections for a specific device
curl -O "http://localhost:8000/api/v1/reports/export?type=device&device_id=sensor-01&format=csv"
```

## UI Access

Navigate to: `http://<server>:8000/reports`

The Reports page provides:
1. Interactive filter form
2. Real-time data preview (limited to 200 rows)
3. Export buttons for CSV and XLSX download
