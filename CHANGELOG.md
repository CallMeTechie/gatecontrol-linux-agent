# Changelog

Releases entstehen automatisch beim Merge auf `main` (`.github/workflows/release.yml`); der Abschnitt
`[Unreleased]` wird dabei zur Version. · Releases are made automatically on a merge to `main`; the
`[Unreleased]` section then becomes the version.

## [Unreleased] · Unveröffentlicht (1.0.0)

* Erster Stand: `enroll` mit dem Einrichtungscode, WireGuard über netlink (oder wg-quick) nur für das VPN-Netz,
  Anmeldung beim Plugin Fernzugriff (`host/register`, `platform: linux`), Herzschlag, Host-Schlüssel,
  Bestätigung jeder Anfrage am Gerät (Standard `confirm ask`: `allow`/`deny`; `confirm code` nur bewusst, mit Warnung),
  tmux-Erkennung, Desktop-Erkennung (KRdp, GNOME Remote Desktop, wayvnc, xrdp, x11vnc), Codes und Anfragen,
  nftables je Sitzung, systemd-Dienst mit Härtung, Pakete `.deb`, `.pkg.tar.zst`, `.rpm` (nebenbei).
* Automatische Releases: jeder Merge auf `main` (außer ci/docs/test/style/chore) hebt die Version in `VERSION`
  an, taggt `vX.Y.Z` und legt ein GitHub-Release mit allen Paketen, `SHA256SUMS` und `PKGBUILD` an – dazu je
  Architektur eine Kopie ohne Versionsnummer, die über
  `https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/<name>` immer die neueste
  Version liefert (`gatecontrol-agent_amd64.deb`, `_arm64.deb`, `_armhf.deb`, `_x86_64.pkg.tar.zst`,
  `_aarch64.pkg.tar.zst`, `_x86_64.rpm`, `_aarch64.rpm`). `gatecontrol-agent --version` und die Pakete tragen
  die Version aus `VERSION`. · Automatic releases with packages and fixed “latest” download links.
