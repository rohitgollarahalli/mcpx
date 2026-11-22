#!/bin/sh
# Install the latest mcpx release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/rohitgollarahalli/mcpx/main/install.sh | sh
#
# Environment:
#   MCPX_VERSION   release to install, e.g. v0.2.0 (default: latest)
#   INSTALL_DIR    where to put the binary (default: $HOME/.local/bin)
#   MCPX_BASE_URL  download base for a mirror or testing
#                  (default: https://github.com/rohitgollarahalli/mcpx/releases/download)
#
# The archive is verified against the release's checksums.txt (SHA-256)
# before anything is installed.
set -eu

REPO="rohitgollarahalli/mcpx"
INSTALL_DIR="${INSTALL_DIR:-${HOME:?set HOME or INSTALL_DIR}/.local/bin}"
BASE_URL="${MCPX_BASE_URL:-https://github.com/$REPO/releases/download}"

say() { printf 'mcpx-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # fetch URL OUTFILE
	if have curl; then
		curl -fsSL --proto '=https,file' --tlsv1.2 -o "$2" "$1"
	elif have wget; then
		wget -q -O "$2" "$1"
	else
		die "need curl or wget"
	fi
}

latest_version() {
	# The /releases/latest page redirects to /releases/tag/<tag>.
	url="https://github.com/$REPO/releases/latest"
	if have curl; then
		loc=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "$url")
	else
		loc=$(wget -q -S --spider "$url" 2>&1 | tr -d '\r' | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1)
	fi
	tag=${loc##*/}
	case "$tag" in
	v[0-9]*) printf '%s\n' "$tag" ;;
	*) die "could not determine the latest release (got '$loc'); set MCPX_VERSION" ;;
	esac
}

sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | cut -d ' ' -f 1
	elif have shasum; then
		shasum -a 256 "$1" | cut -d ' ' -f 1
	else
		die "need sha256sum or shasum to verify the download"
	fi
}

os=$(uname -s)
case "$os" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported OS '$os' (on Windows, download the zip from https://github.com/$REPO/releases)" ;;
esac

arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture '$arch'" ;;
esac

version="${MCPX_VERSION:-}"
[ "$version" != latest ] || version=""
[ -n "$version" ] || version=$(latest_version)
case "$version" in v[0-9]* | [0-9]*) ;; *) die "MCPX_VERSION must look like v1.2.3 (got '$version')" ;; esac
case "$version" in v*) ;; *) version="v$version" ;; esac
plain=${version#v}

archive="mcpx_${plain}_${os}_${arch}.tar.gz"
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t mcpx)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

say "downloading mcpx $version for $os/$arch"
fetch "$BASE_URL/$version/$archive" "$tmp/$archive" || die "download failed: $BASE_URL/$version/$archive"
fetch "$BASE_URL/$version/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt"

want=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
got=$(sha256_of "$tmp/$archive")
[ "$want" = "$got" ] || die "checksum mismatch for $archive (want $want, got $got)"

tar -xzf "$tmp/$archive" -C "$tmp" mcpx
mkdir -p "$INSTALL_DIR"
# Install via a temp name and rename, so a running mcpx is never half-written.
cp "$tmp/mcpx" "$INSTALL_DIR/.mcpx.new"
chmod 0755 "$INSTALL_DIR/.mcpx.new"
mv -f "$INSTALL_DIR/.mcpx.new" "$INSTALL_DIR/mcpx"

installed=$("$INSTALL_DIR/mcpx" --version) || die "installed $INSTALL_DIR/mcpx but it does not run on this system"
say "installed $installed to $INSTALL_DIR/mcpx"
case ":$PATH:" in
*":$INSTALL_DIR:"*) ;;
*) say "note: $INSTALL_DIR is not on your PATH; add it, e.g. export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
say "try it: mcpx scan"
