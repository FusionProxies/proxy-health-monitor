#!/usr/bin/env bash
# Build release binaries for Windows, macOS and Linux (amd64 and arm64) into
# dist/, plus checksums.txt. Pure Go (no cgo), so it runs on any OS with Go.
#
#   scripts/build-release.sh v0.1.0
set -euo pipefail

version="${1:-dev}"
cd "$(dirname "$0")/.."
rm -rf dist
mkdir -p dist

ldflags="-s -w -X github.com/FusionProxies/proxy-health-monitor/internal/version.Version=${version}"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

for t in $targets; do
  os="${t%/*}"
  arch="${t#*/}"
  out="dist/proxy-monitor_${os}_${arch}"
  [ "$os" = "windows" ] && out="${out}.exe"
  echo "building ${out}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$out" ./cmd/proxy-monitor
done

cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum proxy-monitor_* > checksums.txt
else
  shasum -a 256 proxy-monitor_* > checksums.txt
fi
cat checksums.txt
