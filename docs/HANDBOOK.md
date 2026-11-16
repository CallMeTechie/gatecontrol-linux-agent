<!-- version: 1.0.0 -->
# gatecontrol-agent – Handbook

The agent makes a Linux computer – with or without a desktop – reachable in GateControl's plugin **Remote access**:
SSH in GateControl's terminal (with tmux) and, when there is one, the desktop over RDP or VNC.

## 1. Install

| System | Command |
|---|---|
| Debian, Ubuntu, Raspberry Pi OS | `sudo apt install ./gatecontrol-agent_<version>_<arch>.deb` (`arch`: amd64, arm64, armhf) |
| CachyOS, Arch | `sudo pacman -U gatecontrol-agent-<version>-1-x86_64.pkg.tar.zst` or from the AUR (`paru -S gatecontrol-agent`, once published) |
| Fedora, openSUSE (no promise) | `sudo dnf install ./gatecontrol-agent-<version>-1.x86_64.rpm` |

The package creates the account `gatecontrol`, the directories `/etc/gatecontrol-agent` and
`/var/lib/gatecontrol-agent` and the service `gatecontrol-agent.service` (it starts after the set-up).

## 2. Set up

1. In the portal under **My devices › Add device** create a code (or get one from an administrator). It is valid
   for 10 minutes and only once.
2. On the Linux computer: `sudo gatecontrol-agent enroll https://gate.example.org 7F3A-91C2-0B5D-E448`

Options: `--name <device name>` (default: host name), `--wg wg-quick` (when netlink is not possible, e.g. in a
container; needs `wireguard-tools`), `--interface <name>` (default `wg-gc`). The agent routes **only GateControl's
VPN network** – no default route, no DNS.

## 3. Share SSH

`sudo gatecontrol-agent share ssh --as alice --tmux` — GateControl makes a key of its own for this device (the
private half stays in the server's vault); the agent adds the public half to `~alice/.ssh/authorized_keys`, valid
only from the server (`from="10.8.0.1"`), without forwarding. `--install-tmux` installs tmux when missing.
`root` cannot be shared. `share ssh off` takes the share and the key back. The host key is reported at sign-up and
pinned by GateControl, so the first connection is checked already.

## 4. Share the desktop

`sudo gatecontrol-agent share desktop` — detected are **KRdp** (KDE Plasma), **GNOME Remote Desktop**, **wayvnc**
(Raspberry Pi OS with labwc), **xrdp** (a session of its own, no mirror) and **x11vnc**; `--kind` / `--port`
override it. Switch the desktop server on in the desktop's settings. The helper types the desktop server's
credentials in the session; GateControl stores none.

## 5. Codes and confirmation

* Default **code only**: `gatecontrol-agent code` shows the code (9 digits, 10 minutes, once). After each session
  and when it runs out, the agent fetches a new one.
* `sudo gatecontrol-agent share open` allows “No code for permitted people” (unless an administrator locked it);
  `share code` switches back.
* Confirmation: default `code` – handing out the code allows exactly one session. `sudo gatecontrol-agent confirm
  ask` makes each request wait 30 seconds for `sudo gatecontrol-agent allow <id>` (`--view`) or `deny <id>`.

## 6. State

`gatecontrol-agent status` (`--json` for scripts); the log is in the journal (`journalctl -u gatecontrol-agent`),
never with tokens, keys or codes.

## 7. Firewall

An nftables table `inet gatecontrol` of its own, only for packets coming in on `wg-gc` and only for ports 22, 3389,
5900 (and an own desktop port): SSH only from the GateControl server while shared, the desktop port only during a
session for exactly one address (≤ 8 h), everything else on those ports from the VPN is dropped. With **ufw** or
**firewalld** allow incoming on `wg-gc` there (`sudo ufw allow in on wg-gc`).

## 8. Sign off

`sudo gatecontrol-agent unenroll` signs off at the plugin and removes interface, firewall table, the SSH key and all
files. Also lock the device under **My devices** so its token becomes invalid.

## 9. Errors

Exit codes: 0 ok, 1 usage, 2 refused by the server, 3 network, 4 not set up, 5 service not reachable. A missing
plugin (`http_404`): install Remote access ≥ 1.6.0; until then the agent holds the VPN only.
