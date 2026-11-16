# gatecontrol-agent

Der Linux-Agent von GateControl für das Plugin **„Fernzugriff“** · *The Linux agent of GateControl for the plugin “Remote access”*

Ein einziges statisches Programm (Go, ohne Laufzeit) als systemd-Dienst. Es hält den WireGuard-Tunnel zum
GateControl-Server, meldet das Gerät beim Plugin an und gibt **SSH (mit tmux)** und – wer einen Desktop hat – den
**Desktop** (KRdp, GNOME Remote Desktop, wayvnc, xrdp, x11vnc) frei. Standard: **nur mit Code**. Die Firewall
(nftables) öffnet den Desktop-Port je Sitzung für genau eine Adresse.

| Distribution | Paket | Architektur |
|---|---|---|
| Debian 12/13, Ubuntu 22.04/24.04 | `.deb` | amd64, arm64 |
| Raspberry Pi OS (Bookworm) | `.deb` | arm64, armhf |
| CachyOS / Arch | `.pkg.tar.zst`, `PKGBUILD` (AUR) | x86_64 (aarch64) |
| Fedora, openSUSE | `.rpm` nebenbei, **ohne Paketquelle und ohne Zusage** | x86_64, aarch64 |

## Schnellstart (DE)

```sh
sudo apt install ./gatecontrol-agent_1.0.0_arm64.deb          # oder: sudo pacman -U gatecontrol-agent-1.0.0-1-x86_64.pkg.tar.zst
sudo gatecontrol-agent enroll https://gate.example.org 7F3A-91C2-0B5D-E448   # Code aus „Meine Geräte › Gerät hinzufügen“
sudo gatecontrol-agent share ssh --as pi --tmux
sudo gatecontrol-agent share desktop                           # nur mit Desktop
gatecontrol-agent status
gatecontrol-agent code                                         # Code für die Person, die helfen soll
sudo gatecontrol-agent allow <id>                              # die Anfrage am Gerät bestätigen (Standard)
```

Alles Weitere: [docs/HANDBUCH.md](docs/HANDBUCH.md).

## Quick start (EN)

```sh
sudo apt install ./gatecontrol-agent_1.0.0_amd64.deb
sudo gatecontrol-agent enroll https://gate.example.org 7F3A-91C2-0B5D-E448   # code from “My devices › Add device”
sudo gatecontrol-agent share ssh --as alice --tmux
sudo gatecontrol-agent share desktop
gatecontrol-agent status
gatecontrol-agent code
sudo gatecontrol-agent allow <id>                              # confirm the request at the device (default)
```

More: [docs/HANDBOOK.md](docs/HANDBOOK.md).

## Voraussetzungen · Requirements

* GateControl mit Plugin **Fernzugriff ≥ 1.6.0** (Linux-Geräte) · GateControl with the plugin Remote access ≥ 1.6.0
* Kernel mit WireGuard (≥ 5.6), `nftables`; für SSH `openssh-server`, empfohlen `tmux`
* Das Recht „Eigene Geräte freigeben“ · the right “Share own devices”

## Sicherheit · Security

* Dienst als eigener Benutzer `gatecontrol`, nur `CAP_NET_ADMIN`, systemd-Härtung (`ProtectSystem=strict`,
  `NoNewPrivileges`, Systemaufruf-Filter …). Was root braucht (`authorized_keys`, Einrichtung), macht die CLI
  unter `sudo` selbst – kein sudoers-Eintrag, kein Fernbefehl.
* Token nur in `/var/lib/gatecontrol-agent/token` (0600); im Journal stehen nie Token, Schlüssel oder Codes.
* GateControls SSH-Schlüssel gilt nur vom Server aus (`from="<Hub>"`), der Host-Schlüssel wird beim Anmelden angeheftet.
* Nur das VPN-Netz wird geroutet (keine Standardroute, kein DNS).

## Entwicklung · Development

```sh
make test lint build packages     # Go ≥ 1.25, golangci-lint v2, nfpm v2.45
```

CI (`.github/workflows/ci.yml`): Lint, `go test -race`, Build amd64/arm64/armhf, Pakete als Artefakte.
Release (`release.yml`, nur bei Tags `v*`): Pakete + vorbereitetes, signiertes apt-Archiv als Artefakt.
Secrets (Namen, keine Werte): `APT_SIGNING_KEY` (ASCII-armored privater GPG-Schlüssel), `APT_SIGNING_KEY_ID`,
`APT_SIGNING_PASSPHRASE`. Ohne sie wird das apt-Archiv übersprungen. Veröffentlicht wird nichts automatisch.

## License

UNLICENSED / private. See [LICENSE](LICENSE).
