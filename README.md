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

## Herunterladen · Download

Alle Versionen mit Paketen, `SHA256SUMS` und `PKGBUILD`: **[Releases](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases)**.
Diese Links zeigen immer auf die neueste Version · these links always give the newest version:

| System | Paket · package |
|---|---|
| Debian, Ubuntu (amd64) | [`gatecontrol-agent_amd64.deb`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_amd64.deb) |
| Debian, Ubuntu, Raspberry Pi OS 64 bit (arm64) | [`gatecontrol-agent_arm64.deb`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_arm64.deb) |
| Raspberry Pi OS 32 bit (armhf) | [`gatecontrol-agent_armhf.deb`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_armhf.deb) |
| CachyOS / Arch (x86_64) | [`gatecontrol-agent_x86_64.pkg.tar.zst`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.pkg.tar.zst) |
| Arch Linux ARM (aarch64) | [`gatecontrol-agent_aarch64.pkg.tar.zst`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_aarch64.pkg.tar.zst) |
| Fedora, openSUSE (x86_64, ohne Zusage) | [`gatecontrol-agent_x86_64.rpm`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.rpm) |
| Fedora, openSUSE (aarch64, ohne Zusage) | [`gatecontrol-agent_aarch64.rpm`](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_aarch64.rpm) |

```sh
# Debian, Ubuntu, Raspberry Pi OS – arch: amd64, arm64 oder armhf (dpkg --print-architecture)
arch=$(dpkg --print-architecture)
curl -LO https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_$arch.deb && sudo apt install ./gatecontrol-agent_$arch.deb

# CachyOS, Arch
curl -LO https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.pkg.tar.zst && sudo pacman -U gatecontrol-agent_x86_64.pkg.tar.zst

# Fedora (ohne Zusage)
curl -LO https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.rpm && sudo dnf install ./gatecontrol-agent_x86_64.rpm
```

Prüfen · verify: `SHA256SUMS` von der Release-Seite laden, dann `sha256sum -c --ignore-missing SHA256SUMS`.

## Schnellstart (DE)

```sh
sudo apt install ./gatecontrol-agent_arm64.deb                # oder: sudo pacman -U gatecontrol-agent_x86_64.pkg.tar.zst
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
sudo apt install ./gatecontrol-agent_amd64.deb             # see “Download” above
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

Release (`.github/workflows/release.yml`) – automatisch beim Merge auf `main`, nie von Hand (keine Tags,
keine Versionen setzen). Die erste Zeile des Merge-Commits (PR-Titel) entscheidet: `ci`/`docs`/`test`/`style`/`chore`
→ kein Release, `chore(deps)` → Release, `feat` → Minor, alles andere → Patch; der erste Release ist 1.0.0.
Der Workflow hebt `VERSION` an, macht aus `[Unreleased]` im CHANGELOG die Version, committet
„chore: bump version to X.Y.Z“, baut alle Pakete (`make packages`), `SHA256SUMS`, `PKGBUILD` und die Kopien ohne
Versionsnummer (`scripts/release-assets.sh`), pusht, taggt `vX.Y.Z` und legt das GitHub-Release an. Die Version
kommt aus der Datei `VERSION` (Makefile → `-ldflags` → `gatecontrol-agent --version`, nfpm → Pakete).
Ein signiertes apt-Archiv wird als Artefakt vorbereitet, aber nicht veröffentlicht. Secrets (Namen, keine Werte):
`APT_SIGNING_KEY` (ASCII-armored privater GPG-Schlüssel), `APT_SIGNING_KEY_ID`, `APT_SIGNING_PASSPHRASE`; ohne sie
wird das apt-Archiv übersprungen. Details: [docs/RELEASE.md](docs/RELEASE.md).

## License

UNLICENSED / private. See [LICENSE](LICENSE).
