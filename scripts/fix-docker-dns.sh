#!/usr/bin/env bash
set -euo pipefail

sudo mkdir -p /etc/docker

if [ ! -f /etc/docker/daemon.json ]; then
  sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "dns": ["1.1.1.1", "8.8.8.8"]
}
JSON
  echo "[+] Created /etc/docker/daemon.json with DNS servers."
else
  echo "[i] /etc/docker/daemon.json already exists; not overwriting."
fi

sudo systemctl restart docker
echo "[+] Docker restarted."

docker run --rm busybox nslookup pypi.org >/dev/null && echo "[+] DNS inside container OK."
