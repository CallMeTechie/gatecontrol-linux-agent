#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
# purge (Debian): settings and token of this device go too
if [ "$1" = "purge" ]; then
  rm -rf /etc/gatecontrol-agent /var/lib/gatecontrol-agent
fi
exit 0
