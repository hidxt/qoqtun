#!/usr/bin/env bash
# qoqtun RC packaging: static server/client binaries for
# windows/linux/darwin x amd64/arm64, tar.gz/zip archives, SHA256
# checksums and a `go version -m` SBOM. Desktop packaging is performed
# by `wails build` on each native platform (documented).
#
# Usage: bash scripts/release.sh <version> [dist-dir]
set -euo pipefail

VERSION="${1:?usage: release.sh <version> [dist-dir]}"
DIST="${2:-dist}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf "$DIST"
mkdir -p "$DIST"

LDFLAGS="-s -w -X main.version=$VERSION"

build_one() {
  local goos="$1" goarch="$2" name="$3"
  local dir="$DIST/$name-$VERSION-$goos-$goarch"
  mkdir -p "$dir"
  # go (a native program) needs a native path; bash/tar use the msys one
  local native_dir="$dir"
  if command -v cygpath >/dev/null 2>&1; then native_dir="$(cygpath -w "$dir")"; fi
  local bin="$native_dir/$name"
  echo "== build $name $goos/$goarch =="
  (cd "$ROOT" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$bin" "./cmd/${name#qoqtun-}")
  # SBOM: module build info
  (cd "$ROOT" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go version -m "$bin" > "$dir/$name.sbom.txt" 2>/dev/null || true)
  # archive
  (cd "$DIST" && tar czf "$name-$VERSION-$goos-$goarch.tar.gz" "$name-$VERSION-$goos-$goarch")
  echo "  -> $name-$VERSION-$goos-$goarch.tar.gz"
}

for os in windows linux darwin; do
  for arch in amd64 arm64; do
    name="qoqtun-server"
    build_one "$os" "$arch" "qoqtun-server"
    build_one "$os" "$arch" "qoqtun-client"
  done
done

# Windows: rename binary to .exe and keep the tar.gz (Windows 10+ ships
# tar; a real zip is produced when the `zip` tool is available, e.g. CI)
echo "== windows exe naming =="
for arch in amd64 arm64; do
  for name in qoqtun-server qoqtun-client; do
    dir="$DIST/$name-$VERSION-windows-$arch"
    [ -f "$dir/$name" ] && mv "$dir/$name" "$dir/$name.exe"
    (cd "$DIST" && rm -f "$name-$VERSION-windows-$arch.tar.gz" && \
      tar czf "$name-$VERSION-windows-$arch.tar.gz" "$name-$VERSION-windows-$arch")
    if command -v zip >/dev/null 2>&1; then
      (cd "$DIST" && zip -qr "$name-$VERSION-windows-$arch.zip" "$name-$VERSION-windows-$arch")
    fi
  done
done

# checksums + aggregate SBOM (glob tolerates missing .zip without `zip`)
echo "== checksums =="
(cd "$DIST" && shopt -s nullglob && sha256sum *.tar.gz *.zip > SHA256SUMS.txt && cat SHA256SUMS.txt | head -3)
echo "== aggregate SBOM =="
(cd "$DIST" && cat */qoqtun-server.sbom.txt 2>/dev/null | head -12 > SBOM.txt || true)

echo
echo "artifacts in $DIST:"
ls "$DIST"
