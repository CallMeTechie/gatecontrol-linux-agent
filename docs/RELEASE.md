# Releases

Releases entstehen **automatisch beim Merge auf `main`** (`.github/workflows/release.yml`). Versionen und Tags werden
nie von Hand gesetzt. · Releases are made automatically on a merge to `main`; versions and tags are never set by hand.

## Ablauf · Flow

1. **decide** – die erste Zeile des Merge-Commits (bei Squash-Merge der PR-Titel):
   `ci`, `docs`, `test`, `style`, `chore` → kein Release (die Änderung geht mit dem nächsten `fix`/`feat` raus);
   `chore(deps)` → Release; alles andere (`feat`, `fix`, …) → Release.
2. **test** – `go vet`, `go test -race`.
3. **release** (nur einer zur Zeit, `concurrency`):
   * Version aus der Datei `VERSION`: `0.0.0` → `1.0.0` (erster Release), `feat` → Minor, sonst Patch.
   * `VERSION` und `CHANGELOG.md` anpassen: ein handgeschriebener Abschnitt `## [Unreleased]` wird zur Version
     (`## [X.Y.Z] — Datum`), sonst entsteht ein Eintrag aus dem PR-Titel (`scripts/changelog-release`, getestet).
   * Commit `chore: bump version to X.Y.Z` (lokal), dann `make packages`, `scripts/release-assets.sh`
     und Prüfung von `gatecontrol-agent --version` und der Paketversion.
   * Erst danach: Push auf `main`, Tag `vX.Y.Z` (nur auf dem Commit, der auf `main` gelandet ist), GitHub-Release
     mit `generate_release_notes` und allen Dateien. Hat sich `main` inzwischen bewegt, wird neu aufgesetzt und
     aus dem getaggten Stand neu gebaut.
4. **apt-archive** – signiertes apt-Archiv aus den `.deb` als Artefakt (nicht veröffentlicht); nur mit dem Secret
   `APT_SIGNING_KEY` (dazu `APT_SIGNING_KEY_ID`, `APT_SIGNING_PASSPHRASE`), sonst übersprungen.

Keine Schleife, kein doppelter Bau: der Bump-Commit ist ein `chore` (→ kein Release), und Pushes mit `GITHUB_TOKEN`
(Commit und Tag) starten ohnehin keinen Workflow. Den früheren Auslöser „Tag `v*`“ gibt es nicht mehr.

## Version

Die einzige Quelle ist die Datei `VERSION`. Das Makefile liest sie
(`-X …/internal/version.Version=$(VERSION)` → `gatecontrol-agent --version`, User-Agent) und gibt sie an nfpm
(`version: ${VERSION}` in `nfpm.yaml`, Paketrelease `1`). Das `PKGBUILD` im Release bekommt `pkgver=X.Y.Z`.
Lokal: `make packages` baut mit der Version aus `VERSION`; `make packages VERSION=1.2.3` überschreibt sie.

## Dateien eines Releases · Release assets

| Datei | Inhalt |
|---|---|
| `gatecontrol-agent_X.Y.Z-1_{amd64,arm64,armhf}.deb` | Debian, Ubuntu, Raspberry Pi OS |
| `gatecontrol-agent-X.Y.Z-1-{x86_64,aarch64}.pkg.tar.zst` | CachyOS, Arch |
| `gatecontrol-agent-X.Y.Z-1.{x86_64,aarch64}.rpm` | Fedora, openSUSE (ohne Zusage) |
| `gatecontrol-agent_{amd64,arm64,armhf}.deb`, `gatecontrol-agent_{x86_64,aarch64}.pkg.tar.zst`, `gatecontrol-agent_{x86_64,aarch64}.rpm` | dieselben Pakete ohne Versionsnummer |
| `PKGBUILD`, `gatecontrol-agent.install` | für das AUR (baut aus dem Quell-Tarball des Tags) |
| `SHA256SUMS` | Prüfsummen aller Dateien (`sha256sum -c --ignore-missing SHA256SUMS`) |

Feste Links auf die neueste Version · fixed links to the newest version:

```
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_amd64.deb
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_arm64.deb
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_armhf.deb
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.pkg.tar.zst
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_aarch64.pkg.tar.zst
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_x86_64.rpm
https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/gatecontrol-agent_aarch64.rpm
```

Diese Namen sind eine Zusage (README, Handbuch, Plugin Fernzugriff verweisen darauf) – nicht umbenennen.

## Voraussetzung · Requirement

Der Release-Job pusht den Bump-Commit mit `GITHUB_TOKEN` direkt auf `main` (`permissions: contents: write`).
Ein Branch-Schutz oder Ruleset auf `main`, das Pull Requests oder Statusprüfungen verlangt, muss
`github-actions` das Umgehen erlauben – sonst scheitert der Schritt „Push version bump and tag“, und es
entsteht weder Tag noch Release.
