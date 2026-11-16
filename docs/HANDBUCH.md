<!-- version: 1.0.0 -->
# gatecontrol-agent – Handbuch

Der Agent macht einen Linux-Rechner – mit oder ohne Desktop – im Plugin **Fernzugriff** von GateControl erreichbar:
SSH im Terminal von GateControl (mit tmux) und, wenn vorhanden, der Desktop über RDP oder VNC.

## 1. Installieren

Die Pakete liegen auf der Seite **[Releases](https://github.com/CallMeTechie/gatecontrol-linux-agent/releases)** (alle Versionen, mit `SHA256SUMS`).
Die folgenden Befehle laden immer die neueste Version:

| System | Befehl |
|---|---|
| Debian, Ubuntu, Raspberry Pi OS | `curl -LO https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_amd64.deb && sudo apt install ./gatecontrol-agent_amd64.deb` (statt `amd64`: `arm64` oder `armhf`, siehe `dpkg --print-architecture`) |
| CachyOS, Arch | `curl -LO https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.pkg.tar.zst && sudo pacman -U gatecontrol-agent_x86_64.pkg.tar.zst` (ARM: `aarch64`) oder aus dem AUR (`paru -S gatecontrol-agent`, sobald veröffentlicht; das `PKGBUILD` liegt jedem Release bei) |
| Fedora, openSUSE (ohne Zusage) | `curl -LO https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.rpm && sudo dnf install ./gatecontrol-agent_x86_64.rpm` (ARM: `aarch64`) |

Eine bestimmte Version: auf der Release-Seite die Datei mit Versionsnummer nehmen, z. B.
`gatecontrol-agent_1.0.0-1_arm64.deb`. Installiert ist: `gatecontrol-agent --version`.

Das Paket legt den Benutzer `gatecontrol` an, die Verzeichnisse `/etc/gatecontrol-agent` und
`/var/lib/gatecontrol-agent` und den Dienst `gatecontrol-agent.service` (er startet erst nach der Einrichtung).
Eine eigene apt-Paketquelle folgt (siehe Abschnitt 9).

## 2. Einrichten

1. Im Portal unter **Meine Geräte › Gerät hinzufügen** einen Code erzeugen (oder vom Admin geben lassen).
   Der Code gilt 10 Minuten und nur einmal.
2. Auf dem Linux-Rechner:

```
sudo gatecontrol-agent enroll https://gate.example.org 7F3A-91C2-0B5D-E448
  Server ............ gate.example.org  ok
  Gerätename ........ pi-garten
  WireGuard ......... wg-gc 10.8.0.41  (netlink)
  Host-Schlüssel .... ssh-ed25519 SHA256:k9Q…  wird gemeldet
```

Optionen: `--name <gerätename>` (Standard: Hostname), `--wg wg-quick` (wenn netlink nicht geht, z. B. im Container;
braucht `wireguard-tools`), `--interface <name>` (Standard `wg-gc`).

Der Agent routet **nur das VPN-Netz** von GateControl – keine Standardroute, kein DNS. Der Rest des Rechners
bleibt, wie er ist.

## 3. SSH freigeben

```
sudo gatecontrol-agent share ssh --as pi --tmux
  SSH freigegeben für pi · Schlüssel von GateControl eingetragen · tmux 3.3a gefunden
```

* GateControl erzeugt einen eigenen Schlüssel für dieses Gerät (der private Teil bleibt im Tresor des Servers).
  Der Agent trägt den öffentlichen Teil in `~pi/.ssh/authorized_keys` ein – nur gültig vom Server aus
  (`from="10.8.0.1"`), ohne Weiterleitungen. Eigene Zeilen bleiben unberührt.
* `--install-tmux` installiert tmux, wenn es fehlt. Ohne tmux gibt es eine normale Shell, die mit der Verbindung endet.
* `root` kann nicht freigegeben werden.
* `sudo gatecontrol-agent share ssh off` nimmt die Freigabe und den Schlüssel zurück.

Der Host-Schlüssel des Rechners wird bei der Anmeldung an GateControl gemeldet und dort angeheftet; schon die
erste Verbindung wird geprüft.

## 4. Desktop freigeben

```
sudo gatecontrol-agent share desktop
  Desktop: wayvnc (wayland) · vnc 5900 nur im VPN  bereit
```

Erkannt werden: **KRdp** (KDE Plasma), **GNOME Remote Desktop**, **wayvnc** (Raspberry Pi OS mit labwc),
**xrdp** (eigene Sitzung, kein Spiegel) und **x11vnc**. Mit `--kind <art>` und `--port <port>` lässt sich die
Erkennung übersteuern. Den Desktop-Server selbst schaltest du in den Einstellungen des Desktops ein (unter Wayland
geht unbeaufsichtigter Zugriff nur über diese Server). Zugangsdaten des Desktop-Servers gibt die helfende Person
in der Sitzung ein; GateControl speichert sie nicht.

## 5. Codes und Bestätigung

* Standard ist **nur mit Code**: `gatecontrol-agent code` zeigt den Code (9 Ziffern, 10 Minuten, einmal).
  Nach jeder Sitzung und nach Ablauf holt der Agent selbst einen neuen.
* `sudo gatecontrol-agent share open` erlaubt „Ohne Code für Berechtigte“ (wenn der Admin es nicht sperrt),
  `share code` schaltet zurück.
* **Bestätigung am Gerät (Standard `ask`):** Der Code allein verbindet nicht. Jede Anfrage wartet 30 Sekunden auf
  dich: `gatecontrol-agent requests` zeigt sie (auch `status` und das Journal),
  `sudo gatecontrol-agent allow <id>` erlaubt (`--view` nur ansehen), `sudo gatecontrol-agent deny <id>` lehnt ab.
* **Nur für Geräte ohne Bildschirm, an denen niemand sitzt:** `sudo gatecontrol-agent confirm code` – dann genügt der
  Code, wer ihn hat, verbindet sich ohne Rückfrage (die CLI warnt). Zurück mit `sudo gatecontrol-agent confirm ask`.

## 6. Zustand

```
gatecontrol-agent status
  gatecontrol-agent 1.0.0 · läuft seit 12 Tagen · pi-garten
  VPN ............... verbunden · 10.8.0.41 · Handshake vor 38 s
  Server ............ erreichbar · Fernzugriff · Gerät 100007
  Freigaben
    SSH ............. an · als pi · tmux 3.3a · nur mit Code
    Desktop ......... an · wayvnc · vnc 5900 · nur mit Code
```

`status --json` für Skripte. Das Protokoll steht im Journal: `journalctl -u gatecontrol-agent` (ohne Token,
Schlüssel und Codes). Mehr Ausgabe: `GATECONTROL_AGENT_LOG=debug` in einer Drop-in-Datei des Dienstes.

## 7. Firewall

Der Agent legt eine eigene nftables-Tabelle `inet gatecontrol` an. Sie betrifft **nur** Pakete, die über `wg-gc`
hereinkommen, und nur die Ports 22, 3389, 5900 (und einen eigenen Desktop-Port):

* SSH (22) nur vom GateControl-Server (Hub-Adresse), solange SSH freigegeben ist.
* Der Desktop-Port nur während einer Sitzung, nur für genau eine Adresse, höchstens 8 Stunden.
* Alles andere auf diesen Ports aus dem VPN wird verworfen. LAN und andere Schnittstellen bleiben unberührt.

Läuft **ufw** oder **firewalld**, muss dort eingehend auf `wg-gc` erlaubt sein (`sudo ufw allow in on wg-gc`) –
deren Sperre gewinnt sonst.

## 8. Abmelden

`sudo gatecontrol-agent unenroll` meldet das Gerät beim Plugin ab, entfernt Schnittstelle, Firewall-Tabelle,
den SSH-Schlüssel und alle Dateien. Sperre das Gerät zusätzlich unter **Meine Geräte**, damit sein Token
ungültig wird.

## 9. Pakete, Paketquelle

Jeder Merge auf `main` (außer `ci`/`docs`/`test`/`style`/`chore`) erzeugt automatisch ein Release: neue Version,
Tag `vX.Y.Z`, alle Pakete (nfpm), `SHA256SUMS`, `PKGBUILD` für das AUR, dazu je Architektur eine Kopie ohne
Versionsnummer für die festen Links aus Abschnitt 1 (Ablauf: [RELEASE.md](RELEASE.md)).
Eine signierte apt-Paketquelle und ein Ein-Befehl-Skript (`curl … | sudo sh`) sind vorbereitet, aber noch nicht
veröffentlicht. Für RPM gibt es keine Paketquelle.

## 10. Fehler

| Meldung | Abhilfe |
|---|---|
| Code stimmt nicht / abgelaufen (`invalid_or_expired`) | neuen Code erzeugen |
| keine Freigabe erlaubt (`no_share_right`) | Admin: Recht „Eigene Geräte freigeben“ |
| Plugin fehlt (`http_404`) | Fernzugriff ≥ 1.6.0 installieren; der Agent hält bis dahin nur das VPN |
| Dienst antwortet nicht | `systemctl status gatecontrol-agent`, `journalctl -u gatecontrol-agent` |
| WireGuard geht nicht (`wg_failed`) | Kernel-Modul `wireguard`; sonst `enroll --wg wg-quick` |

Exit-Codes der CLI: 0 ok, 1 Bedienfehler, 2 vom Server abgelehnt, 3 Netz, 4 nicht eingerichtet, 5 Dienst nicht erreichbar.
