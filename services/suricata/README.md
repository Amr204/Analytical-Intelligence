# Suricata IDS Service

Rule-based Intrusion Detection System for network traffic analysis.

## Overview

Suricata monitors network traffic on sensor servers using the ET Open ruleset. Alerts are written to `eve.json` and consumed by the `suricata_collector` agent.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_IFACE` | `ens33` | Network interface to monitor |
| `SURICATA_PROFILE` | `balanced` | Rule profile: `balanced`, `low-noise`, `aggressive` |
| `RULES_UPDATE` | `0` | Set to `1` to update rules on startup |
| `MAX_EVE_MB` | `200` | Max eve.json size before rotation |

### Profiles

- **balanced** (default): Attack-focused rules, disables noisy info/policy rules
- **low-noise**: High-confidence attack signatures only
- **aggressive**: Most detection categories enabled

## Directory Structure

```
services/suricata/
├── Dockerfile
├── entrypoint.sh
├── etc/
│   ├── suricata.yaml    # Main config
│   ├── enable.conf      # Rules to enable (per profile)
│   ├── disable.conf     # Rules to disable (per profile)
│   └── local.rules      # Custom rules (SID >= 1000000)
├── log/                 # Mounted: eve.json, fast.log, etc.
└── rules/               # Mounted: suricata.rules (from suricata-update)
```

## Usage

```bash
# Start with default profile
docker compose -f docker-compose.sensor.yml up -d suricata

# Update rules on startup
SURICATA_RULES_UPDATE=1 docker compose -f docker-compose.sensor.yml up -d suricata

# Check logs
tail -f ./services/suricata/log/eve.json

# View Suricata stats
docker exec ai_db-suricata cat /var/log/suricata/stats.log
```

## Custom Rules

Add rules to `etc/local.rules` with SIDs >= 1000000:

```
alert tcp any any -> $HOME_NET 22 (msg:"Custom SSH Alert"; sid:1000001; rev:1;)
```

## Troubleshooting

1. **No alerts generated**: Check interface name, ensure traffic is flowing
2. **Permission denied**: Verify NET_ADMIN and NET_RAW capabilities
3. **Rules too noisy**: Switch to `low-noise` profile
4. **eve.json not created**: Check Suricata logs: `docker logs ai_db-suricata`
