#!/bin/sh
# Stop the service before the files go (an upgrade keeps it set up).
set -e
case "$1" in
  upgrade|1) exit 0 ;;
esac
if [ -d /run/systemd/system ]; then
  systemctl disable --now gatecontrol-agent.service >/dev/null 2>&1 || true
fi
# the firewall table of the agent
command -v nft >/dev/null 2>&1 && nft delete table inet gatecontrol >/dev/null 2>&1 || true
exit 0
