#!/usr/bin/env bash
# Build a flat, signed apt archive from the .deb files:  scripts/apt-archive.sh <dist> <out>
#   <out>/pool/*.deb, <out>/dists/stable/main/binary-<arch>/Packages(.gz), Release, InRelease, Release.gpg,
#   <out>/gatecontrol-agent.gpg (public key for /etc/apt/keyrings)
# Needs APT_SIGNING_KEY (+ _KEY_ID, _PASSPHRASE) in the environment; never prints them.
set -euo pipefail
dist="$1"; out="$2"
: "${APT_SIGNING_KEY:?APT_SIGNING_KEY missing}"
: "${APT_SIGNING_KEY_ID:?APT_SIGNING_KEY_ID missing}"
command -v apt-ftparchive >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq apt-utils; }
export GNUPGHOME; GNUPGHOME="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME"' EXIT
printf '%s' "$APT_SIGNING_KEY" | gpg --batch --quiet --import
mkdir -p "$out/pool"
cp "$dist"/*.deb "$out/pool/"
cd "$out"
for arch in amd64 arm64 armhf; do
  d="dists/stable/main/binary-$arch"
  mkdir -p "$d"
  apt-ftparchive --arch "$arch" packages pool > "$d/Packages"
  gzip -9kf "$d/Packages"
done
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=GateControl \
  -o APT::FTPArchive::Release::Label=gatecontrol-agent \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64 armhf" \
  -o APT::FTPArchive::Release::Components=main \
  release dists/stable > dists/stable/Release
pass=(--pinentry-mode loopback --passphrase-fd 0)
printf '%s' "${APT_SIGNING_PASSPHRASE:-}" | gpg --batch --yes "${pass[@]}" -u "$APT_SIGNING_KEY_ID" --clearsign -o dists/stable/InRelease dists/stable/Release
printf '%s' "${APT_SIGNING_PASSPHRASE:-}" | gpg --batch --yes "${pass[@]}" -u "$APT_SIGNING_KEY_ID" -abs -o dists/stable/Release.gpg dists/stable/Release
gpg --batch --export "$APT_SIGNING_KEY_ID" > gatecontrol-agent.gpg
echo "apt archive ready in $out (not published)"
