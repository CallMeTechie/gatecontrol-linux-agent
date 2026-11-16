#!/usr/bin/env bash
# Release assets from the packages of `make packages`:  scripts/release-assets.sh <version> [dist]
#   <dist>/latest/   one copy per architecture under a name without the version, so
#                    https://github.com/CallMeTechie/gatecontrol-linux-agent/releases/latest/download/<name>
#                    always gives the newest release (gatecontrol-agent_amd64.deb, …_x86_64.rpm, …)
#   <dist>/aur/      PKGBUILD (pkgver of this release) and gatecontrol-agent.install for the AUR
#   <dist>/SHA256SUMS over all of them (flat names, as they appear on the release page)
# Fails when a package is missing, so the release never goes out half.
set -euo pipefail
version="${1:?usage: release-assets.sh <version> [dist]}"
dist="${2:-dist}"
root="$(cd "$(dirname "$0")/.." && pwd)"

# versioned name (nfpm) → name without version
declare -A latest=(
  ["gatecontrol-agent_${version}-1_amd64.deb"]="gatecontrol-agent_amd64.deb"
  ["gatecontrol-agent_${version}-1_arm64.deb"]="gatecontrol-agent_arm64.deb"
  ["gatecontrol-agent_${version}-1_armhf.deb"]="gatecontrol-agent_armhf.deb"
  ["gatecontrol-agent-${version}-1-x86_64.pkg.tar.zst"]="gatecontrol-agent_x86_64.pkg.tar.zst"
  ["gatecontrol-agent-${version}-1-aarch64.pkg.tar.zst"]="gatecontrol-agent_aarch64.pkg.tar.zst"
  ["gatecontrol-agent-${version}-1.x86_64.rpm"]="gatecontrol-agent_x86_64.rpm"
  ["gatecontrol-agent-${version}-1.aarch64.rpm"]="gatecontrol-agent_aarch64.rpm"
)

rm -rf "$dist/latest" "$dist/aur"
mkdir -p "$dist/latest" "$dist/aur"
for f in "${!latest[@]}"; do
  [ -f "$dist/$f" ] || { echo "missing package: $dist/$f" >&2; exit 1; }
  cp "$dist/$f" "$dist/latest/${latest[$f]}"
done

sed "s/^pkgver=.*/pkgver=${version}/" "$root/packaging/arch/PKGBUILD" > "$dist/aur/PKGBUILD"
cp "$root/packaging/arch/gatecontrol-agent.install" "$dist/aur/"
grep -qx "pkgver=${version}" "$dist/aur/PKGBUILD"

(
  cd "$dist"
  sha256sum -- *.deb *.pkg.tar.zst *.rpm
  (cd latest && sha256sum -- *)
  (cd aur && sha256sum -- *)
) > "$dist/SHA256SUMS.tmp"
mv "$dist/SHA256SUMS.tmp" "$dist/SHA256SUMS"
echo "release assets for ${version} ready in ${dist}:"
cat "$dist/SHA256SUMS"
