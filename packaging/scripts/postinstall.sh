#!/bin/sh
# gatecontrol-agent: account, directories, systemd (Debian, Raspberry Pi OS, Arch, RPM)
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/gatecontrol-agent.conf || true
fi
if ! getent passwd gatecontrol >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/gatecontrol-agent --no-create-home --shell /usr/sbin/nologin gatecontrol 2>/dev/null || \
    adduser --system --group --home /var/lib/gatecontrol-agent --no-create-home gatecontrol
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/gatecontrol-agent.conf || true
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  # already set up: the new version runs at once
  if [ -s /var/lib/gatecontrol-agent/token ]; then
    systemctl try-restart gatecontrol-agent.service || true
  fi
fi
if [ ! -s /var/lib/gatecontrol-agent/token ]; then
  echo "gatecontrol-agent: set up with  sudo gatecontrol-agent enroll https://<server> <code>"
fi
exit 0
