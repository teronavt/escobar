#!/usr/bin/env bash
# Build a distribution-labelled DEB using a precompiled static Go binary.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <version> <ubuntu-release> <amd64|arm64>" >&2
  exit 2
fi
version="$1"
ubuntu="$2"
arch="$3"

[[ "$version" =~ ^[0-9][0-9A-Za-z.+:~\-]*$ ]] || { echo 'Invalid Debian version' >&2; exit 2; }
[[ "$ubuntu" =~ ^(24\.04|26\.04|26\.10)$ ]] || { echo 'Unsupported Ubuntu release' >&2; exit 2; }
[[ "$arch" == amd64 || "$arch" == arm64 ]] || { echo 'Unsupported architecture' >&2; exit 2; }
[[ -f build/escobar ]] || { echo 'Missing build/escobar' >&2; exit 2; }
[[ -f README.md && -f LICENSE && -f packaging/escobar@.service ]] || { echo 'Missing required package input' >&2; exit 2; }

pkg_version="${version}-1ubuntu${ubuntu}"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
chmod 0755 "$root"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/systemd/system" "$root/usr/share/doc/escobar"
install -m 0755 build/escobar "$root/usr/bin/escobar"
install -m 0644 packaging/escobar@.service "$root/usr/lib/systemd/system/escobar@.service"
install -m 0644 README.md "$root/usr/share/doc/escobar/README.md"
install -m 0644 LICENSE "$root/usr/share/doc/escobar/copyright"
installed_kb="$(du -sk "$root/usr" | awk '{print $1}')"
cat > "$root/DEBIAN/control" <<EOF
Package: escobar
Version: ${pkg_version}
Section: net
Priority: optional
Architecture: ${arch}
Maintainer: Escobar fork maintainers <teronavt@users.noreply.github.com>
Installed-Size: ${installed_kb}
Homepage: https://github.com/teronavt/escobar
Description: Local HTTP forwarding proxy with Kerberos/SPNEGO support
 Escobar relays HTTP and HTTPS CONNECT requests via an authenticated
 upstream corporate proxy. Supports Kerberos and Basic authentication.
 Includes an opt-in systemd template; no credentials are packaged.
EOF
mkdir -p dist
dpkg-deb --root-owner-group --build "$root" "dist/escobar_${pkg_version}_${arch}.deb"
